"""Issue #30 阶段 2：`--from-files` 离线批量检测 + UEBA 基线偏离注入。

覆盖三件事：

1. 没有 ClickHouse 也能跑完整流水线（目录 → 行 → NormalizedLog → 线索落盘）；
2. `*truth*` 标注文件不进检测，时间顺序不被打乱；
3. 离线基线偏离真的注入到 `DetectionContext.baseline_deviations`，
   并且 `--no-ueba` 能干净地关掉。
"""

from __future__ import annotations

import dataclasses
import json
import runpy
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "data" / "full_chain_logs"

# 偏离证据对下游（评分/调查）的 9 字段契约
CONTRACT_FIELDS = {
    "feature",
    "profile_group",
    "expected",
    "actual",
    "deviation_type",
    "severity",
    "confidence",
    "evidence_source",
    "sample_days",
}


@pytest.fixture(scope="module")
def script() -> dict:
    """把 `scripts/detect_clues.py` 当模块加载（它不在包里，与仓库现有做法一致）。"""
    return runpy.run_path(str(REPO_ROOT / "scripts" / "detect_clues.py"))


@pytest.fixture(scope="module")
def offline_logs(script) -> list:
    from src.detection.from_full_chain import to_normalized

    rows = script["load_from_files"](DATASET)
    logs = [to_normalized(row) for row in rows]
    logs.sort(key=lambda log: (log.event_time, log.event_id))
    return logs


def _run(script, monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["detect_clues.py", *argv])
    return script["main"]()


def test_load_from_files_skips_truth_and_reads_all_cases(script):
    rows = script["load_from_files"](DATASET)

    assert len(rows) == 200
    # truth 文件里没有 log_id，混进来会变成脏日志
    assert all(isinstance(row.get("log_id"), str) and row["log_id"] for row in rows)
    assert len({row["log_id"] for row in rows}) == len(rows)


def test_load_from_files_accepts_jsonl_and_wrapper(tmp_path, script):
    (tmp_path / "plain.jsonl").write_text(
        "\n".join(json.dumps({"log_id": f"L{i}", "timestamp": "2026-10-29T18:10:00Z"}) for i in range(2)),
        encoding="utf-8",
    )
    (tmp_path / "wrapped.json").write_text(
        json.dumps({"logs": [{"log_id": "W1", "timestamp": "2026-10-29T18:10:00Z"}]}),
        encoding="utf-8",
    )
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "case_truth.json").write_text(json.dumps([{"is_malicious": True}]), encoding="utf-8")

    rows = script["load_from_files"](tmp_path)

    assert sorted(row["log_id"] for row in rows) == ["L0", "L1", "W1"]


def test_missing_directory_exits_with_error(script):
    with pytest.raises(SystemExit) as exc:
        script["load_from_files"](REPO_ROOT / "data" / "no-such-dir")
    assert "不存在" in str(exc.value.code)


def test_empty_directory_runs_without_clues(tmp_path, script, monkeypatch):
    assert _run(script, monkeypatch, "--from-files", str(tmp_path)) == 0

    output = tmp_path / "clues.json"
    (tmp_path / "noise.json").write_text(json.dumps([]), encoding="utf-8")
    assert _run(script, monkeypatch, "--from-files", str(tmp_path), "--output", str(output)) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == []


def test_offline_window_anchors_on_batch_latest_timestamp(script):
    rows = [
        {"log_id": "OLD", "timestamp": "2026-10-29T10:00:00Z"},
        {"log_id": "NEW", "timestamp": "2026-10-29T12:00:00Z"},
    ]
    kept = script["select_offline_rows"](rows, window_minutes=60)
    assert [row["log_id"] for row in kept] == ["NEW"]


def test_offline_pipeline_writes_clues_in_time_order(tmp_path, script, monkeypatch):
    output = tmp_path / "clues" / "w3_clues_baseline.json"

    assert _run(
        script, monkeypatch,
        "--from-files", str(DATASET),
        "--output", str(output),
    ) == 0

    clues = json.loads(output.read_text(encoding="utf-8"))
    assert clues, "全链路样本上应当能检出线索"
    stamps = [clue["event_time"] for clue in clues]
    assert stamps == sorted(stamps)
    assert all(clue["event_id"] for clue in clues)
    assert {clue["risk_level"] for clue in clues} <= {"low", "medium", "high", "critical"}


def test_ueba_deviations_are_injected_into_detection_context(offline_logs):
    from src.detection.context_builder import ContextRegistry, UEBABaselineProvider

    provider = UEBABaselineProvider(offline_logs)
    registry = ContextRegistry(baseline_provider=provider)
    assert provider.user_count >= 5

    contexts = [registry.build(log) for log in offline_logs]
    # 基线只覆盖有用户的历史样本；没用户的日志必须老实标 False
    assert any(ctx.baseline_available for ctx in contexts)
    assert any(
        ctx.baseline_deviations
        for ctx, log in zip(contexts, offline_logs)
        if log.user_id and ctx.baseline_available
    )

    kinds = set()
    for context in contexts:
        for deviation in context.baseline_deviations:
            assert CONTRACT_FIELDS <= set(deviation)
            kinds.add(deviation["deviation_type"])
    # 单会话用户拿不到足够历史，必须给出「历史不足 / 置信度低」而不是「一切正常」
    assert kinds & {"insufficient_history", "low_baseline_confidence"}
    assert kinds <= {
        "insufficient_history",
        "low_baseline_confidence",
        "new_source_ip",
        "outside_active_hours",
        "sensitive_resource_access",
    }


def test_baseline_deviations_reach_the_clue_payload(tmp_path, script, monkeypatch):
    from src.detection.rules import DetectionContext

    output = tmp_path / "clues.json"
    assert _run(
        script, monkeypatch,
        "--from-files", str(DATASET),
        "--output", str(output),
    ) == 0

    clues = json.loads(output.read_text(encoding="utf-8"))
    with_deviations = [clue for clue in clues if clue["baseline_deviations"]]
    assert with_deviations, "基线偏离必须进入线索证据，否则等于没接入"
    for clue in with_deviations:
        for deviation in clue["baseline_deviations"]:
            assert CONTRACT_FIELDS <= set(deviation)
    # 证据字段与 DetectionContext 的契约同名同义
    assert "baseline_deviations" in {f.name for f in dataclasses.fields(DetectionContext)}


def test_seen_source_is_chronological_not_whole_batch(offline_logs):
    from src.detection.context_builder import UEBABaselineProvider

    provider = UEBABaselineProvider(offline_logs)
    same_user = [log for log in offline_logs if log.user_id and log.src_ip]
    first = same_user[0]
    later = [
        log
        for log in same_user
        if log.user_id == first.user_id
        and log.src_ip == first.src_ip
        and log.event_time > first.event_time
    ]

    # 首次落地必须是「新来源」（否则攻击首跳不会被报出来）
    assert provider.seen_source(first) is False
    assert later, "样本里应当存在同一用户同一 IP 的后续日志"
    # 同批后续日志不再重复算新来源
    assert all(provider.seen_source(log) is True for log in later)
    # 没有用户或来源时无从判断，保持 None 而不是猜 False
    assert provider.seen_source([log for log in offline_logs if not log.user_id][0]) is None


def test_no_ueba_flag_keeps_pipeline_output_clean(tmp_path, script, monkeypatch):
    output = tmp_path / "clues.json"

    assert _run(
        script, monkeypatch,
        "--from-files", str(DATASET),
        "--no-ueba",
        "--output", str(output),
    ) == 0

    clues = json.loads(output.read_text(encoding="utf-8"))
    assert clues
    assert all(not clue["baseline_deviations"] for clue in clues)


def test_acceptance_output_is_reproducible(tmp_path, script, monkeypatch):
    """Issue #30 验收命令的等义复现（输出落到临时目录，避免污染工作区）。"""
    output = tmp_path / "w3_clues_baseline.json"

    assert _run(
        script, monkeypatch,
        "--from-files", "data/full_chain_logs",
        "--output", str(output),
    ) == 0

    first = json.loads(output.read_text(encoding="utf-8"))
    assert _run(
        script, monkeypatch,
        "--from-files", "data/full_chain_logs",
        "--output", str(output),
    ) == 0
    second = json.loads(output.read_text(encoding="utf-8"))

    # 补充规则的事件 ID 是随机 UUID（共享模块的既有行为），因此比对稳定字段
    def fingerprint(clue):
        return (clue["event_time"], clue["attack_type"], clue["risk_level"], tuple(clue["rule_hits"]))

    assert len(first) == len(second)
    assert [fingerprint(clue) for clue in first] == [fingerprint(clue) for clue in second]
