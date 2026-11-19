"""V2 多轮调查实跑：输出 ``data/agent_traces/v2/``（沿用 V1 归档规范）。

与 ``run_v1_traces.py`` 的关系
----------------------------
复用其 ``run_one`` / 脱敏 / 场景发现逻辑，只改变三件事：

1. 输出目录换成 ``v2/``，控制器标为 ``rule_based_v2_controller``；
2. 额外落盘 Week 3 的 RAG 事实（检索状态、卡片触发的补查、错题复查、证据分组）；
3. 标注运行来源 ``origin``：``local_replay``（本地回放）或 ``platform``（恒脑实跑）。

用法::

    # 本地回放（缺 BGE/Qdrant 时用词面降级检索，轨迹里会标 degraded）
    SECLOG_SEARCH_MODE=lexical_fallback python tests/run_v2_traces.py

    # 平台实跑导出后归档（由平台导出 11 字段结果 + 轨迹，本脚本负责规范化）
    SECLOG_RUN_ORIGIN=platform python tests/run_v2_traces.py --from-platform <dir>

产物::

    data/agent_traces/v2/<CASE>.json         严格 11 字段结论（原样保存，不改写）
    data/agent_traces/v2/<CASE>.trace.json   运行元数据 + 每轮调用 + RAG 事实
    data/agent_traces/v2/SUMMARY.md          汇总
    data/agent_traces/v2/EVALUATION.md       用现有评测器算分（不改评分逻辑）
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
TESTS = REPO / "tests"
for path in (str(SRC), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

DATASET = REPO / "data" / "full_chain_logs"
OUT_DIR = REPO / "data" / "agent_traces" / "v2"

os.environ.setdefault("SECLOG_DATA_SOURCE", "dataset_replay")
# Week 3：本机没有向量检索依赖时用词面降级，轨迹里会如实标 degraded
os.environ.setdefault("SECLOG_SEARCH_MODE", "lexical_fallback")

import run_v1_traces as base  # noqa: E402

CONTROLLER = "rule_based_v2_controller"


def _load_eval_runner():
    """按路径加载现有算分脚本（**不修改**其评分逻辑）。"""
    path = REPO / "scripts" / "eval_runner.py"
    spec = importlib.util.spec_from_file_location("eval_runner_w3", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _origin() -> str:
    return os.environ.get("SECLOG_RUN_ORIGIN", "local_replay").strip() or "local_replay"


def run(cases: list[str], origin: str) -> list[dict]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for case_id in cases:
        output = base.run_one(case_id, controller=CONTROLLER, origin=origin, include_rag=True)
        (OUT_DIR / f"{case_id}.json").write_text(
            json.dumps(output["result"], ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (OUT_DIR / f"{case_id}.trace.json").write_text(
            json.dumps(output["trace"], ensure_ascii=False, indent=2), encoding="utf-8"
        )
        evaluation = output["trace"].get("evaluation") or {}
        rows.append(
            {
                "case_id": case_id,
                "result": output["result"],
                "trace": output["trace"],
                "evaluation": evaluation,
                "verify_ok": output["verify_ok"],
            }
        )
        print(
            f"[{'OK ' if output['verify_ok'] else 'BAD'}] {case_id} -> {output['result']['attack_type']} / "
            f"{output['result']['risk_level']} 证据{len(output['result']['evidence_log_ids'])}条 "
            f"轮次{output['trace']['run']['rounds']} 检索={output['trace'].get('rag', {}).get('retrieval_state')}"
        )
    return rows


def write_summary(rows: list[dict], origin: str) -> Path:
    first = rows[0]["trace"]["run"] if rows else {}
    code = first.get("code_version") or {}
    env = first.get("env") or {}
    rag_states = sorted({row["trace"].get("rag", {}).get("retrieval_state") for row in rows})
    lines = [
        "# V2 调查报告汇总（Week 3）",
        "",
        f"- 运行来源：`{origin}`"
        + ("（本地回放，**不是**恒脑平台实跑）" if origin.startswith("local") else "（恒脑平台实跑导出）"),
        f"- 运行时间：{first.get('started_at', '未知')}（run_id `{first.get('run_id', '-')}`）",
        f"- 控制器：`{CONTROLLER}`（`src/ai_engine/investigation.py`）",
        f"- 数据源：`{first.get('data_source') or '未知'}`（配置模式 `{env.get('data_source_mode', '-')}`）",
        f"- 检索模式：`{env.get('search_mode', '-')}`；各案例检索状态：{('、'.join(f'`{s}`' for s in rag_states)) or '无'}",
        f"- 代码版本：`{code.get('commit') or '未知'}`（分支 `{code.get('branch') or '-'}`，工作区"
        f"{'**有未提交改动**' if code.get('dirty_worktree') else '干净'}）",
        "- 标准答案仅用于本表与 EVALUATION.md 的评测对照，未参与任何调查步骤；结论原样保存，未人工改写",
        "",
        "| 场景 | 结论 | 风险 | 恶意 | 证据数 | 轮次 | 契约校验 | 检索状态 | 卡片补查 | 错题复查 | 覆盖 truth 分类 | 证据召回 |",
        "| :--- | :--- | :--- | :--- | --: | --: | :--- | :--- | --: | --: | :--- | --: |",
    ]
    for row in rows:
        trace = row["trace"]
        rag = trace.get("rag") or {}
        evaluation = row["evaluation"] or {}
        result = row["result"]
        lines.append(
            f"| {row['case_id']} | {result['attack_type']} | {result['risk_level']} | {result['is_malicious']} | "
            f"{len(result['evidence_log_ids'])} | {trace['run']['rounds']} | "
            f"{'通过' if row['verify_ok'] else '**失败**'} | `{rag.get('retrieval_state')}` | "
            f"{len(rag.get('card_triggered_queries') or [])} | {len(rag.get('revision_checks') or [])} | "
            f"{evaluation.get('attack_type_covers_truth')} | {evaluation.get('evidence_recall')} |"
        )
    lines += [
        "",
        "> 上表数字均由本次实际运行得出；`EVALUATION.md` 由 `scripts/eval_runner.py` 现场算分生成。",
    ]
    path = OUT_DIR / "SUMMARY.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_evaluation(rows: list[dict]) -> Path:
    """用现有评测器算分：只喂 11 字段结果文件，不动评分逻辑与标准答案。"""
    runner = _load_eval_runner()
    agent_paths = [str(OUT_DIR / f"{row['case_id']}.json") for row in rows]
    markdown = runner.run_eval(
        [str(DATASET)],
        agent_paths=agent_paths,
        logs_dir=DATASET,
        round_title=f"V2 单轮评测报告（{_origin()}）",
    )
    path = OUT_DIR / "EVALUATION.md"
    path.write_text(markdown, encoding="utf-8")
    return path


def main(argv: list[str]) -> int:
    cases = [item for item in argv[1:] if not item.startswith("-")]
    if not cases:
        cases = base.list_scenarios()
    if not cases:
        print("数据集中没有任何场景，无法运行")
        return 2
    origin = _origin()
    rows = run(cases, origin)
    summary = write_summary(rows, origin)
    evaluation = write_evaluation(rows)
    print(f"\n产物目录：{OUT_DIR}\n汇总：{summary.name}，评测：{evaluation.name}")
    return 0 if all(row["verify_ok"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
