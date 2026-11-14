"""V1 多轮调查实跑：用真实日志包跑出可核验的 AgentResults 与调查轨迹。

用法：
    .venv/Scripts/python tests/run_v1_traces.py            # 全部场景
    .venv/Scripts/python tests/run_v1_traces.py CHAIN-CASE-01

产物：
    data/agent_traces/v1/<case_id>.json        严格 11 字段的 AgentResults（可直接进评测配对）
    data/agent_traces/v1/<case_id>.trace.json  运行元数据 + 每轮工具调用 + 证据 + 自检
    data/agent_traces/v1/SUMMARY.md            汇总（含与 truth 的对照，仅用于评测观察）

约定：
* ``<case_id>.json`` **只放 11 字段契约**，运行元数据一律进 ``.trace.json``，
  避免破坏 ``AgentResults`` 校验；
* 标准答案 ``*_truth.json`` **只在本脚本的评测段读取**，不参与调查、不进任何工具返回值；
* 结果不好也照实落盘，不手写答案。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATASET = REPO / "data" / "full_chain_logs"
OUT_DIR = REPO / "data" / "agent_traces" / "v1"

os.environ.setdefault("SECLOG_DATA_SOURCE", "dataset_replay")
# 检索若不可用不应中断调查：调查过程会记检索失败，最终在 unknown_items 里体现
os.environ.setdefault("SECLOG_SEARCH_MODE", "auto")

from ai_engine.redaction import redact_text
from ai_engine import attack_types  # noqa: E402
from ai_engine.investigation import InvestigationSession  # noqa: E402
from ai_engine.results_schema import validate_results  # noqa: E402
from ai_engine.verify import verify_triage  # noqa: E402
from api.evidence_check import registry  # noqa: E402


_ERROR_CODES = {"backend_unavailable", "invalid_params", "unknown_tool"}


#: 评测侧 truth 归一化规则（**不改 truth 文件本身**，只在算分时套用）。
#: 现有 truth 由队友按自己的口径编写，其中两份不属于七类取值；
#: 为了让"分类匹配"可计算，这里显式声明映射，并把它写进 trace 以便复核。
_TRUTH_RULES = {
    # 上传 webshell 后回连 C2 → 七类里的「恶意上传」+「可疑外连」
    "Webshell_Upload_And_C2_Callback": "C2_Exfiltration_After_Malicious_Upload",
    # 正常运维不属于任何攻击类
    "Normal_Maintenance_Operation": "none",
}


def _normalize_truth_type(raw: str) -> tuple[str, str | None]:
    """返回 (归一化后的类型, 命中的规则名)。规则名非空表示用了评测侧映射。"""
    if raw in _TRUTH_RULES:
        return _TRUTH_RULES[raw], f"truth_alias:{raw}"
    return attack_types.normalize(raw), None


def _code_version() -> dict:
    """记录本次运行的代码版本与工作区状态。

    实现尚未提交时必须如实标注 ``dirty_worktree=True``，
    不能让人误以为跑的就是某个提交的代码。
    """
    import subprocess

    def _run(args: list[str]) -> str:
        return subprocess.run(
            args, cwd=str(REPO), capture_output=True, text=True, timeout=20
        ).stdout.strip()

    try:
        commit = _run(["git", "rev-parse", "--short", "HEAD"]) or None
        branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"]) or None
        dirty = bool(_run(["git", "status", "--porcelain"]))
    except Exception as exc:  # git 不可用时如实记录，不猜
        return {"commit": None, "branch": None, "dirty_worktree": None, "error": type(exc).__name__}
    return {"commit": commit, "branch": branch, "dirty_worktree": dirty}


#: 判定依据字段：这些内容必须留下真实值，否则无法独立核验"为什么这么判"
_KEEP_KEYS = {
    "maintenance_windows",
    "weekdays",
    "start",
    "end",
    "timezone",
    "kind",
    "evaluated_at",
    "in_maintenance_window",
    "matched_window",
    "account_type",
    "common_src_ips",
    "allowed_src_ips",
    "allowed_assets",
    "observed_src_ips",
    "observed_assets",
    "per_log_in_window",
    "user",
    "asset_id",
    "importance",
    "role",
    "whitelisted",
    "whitelisted_ips",
    "authorized",
    "checks",
    "failed",
    "notes",
    "subjects",
    "reference_time",
    "window_start",
    "window_end",
}


def _redact(value, *, depth: int = 0, key: str | None = None):
    """按用途脱敏：判定依据保留原值，长文本截断并标注长度。

    早期版本用统一递归深度截断，结果把维护窗口截成
    ``{"weekdays":"…","start":"…"}``，无法核验窗口是否匹配。
    """
    import re
    if key and key.lower() in {"password", "passwd", "pwd", "authorization", "token"}:
        return "***"
    if isinstance(value, str):
        value = redact_text(value)
    keep = key in _KEEP_KEYS
    if isinstance(value, dict):
        if not keep and depth > 5:
            return {"_omitted": f"层级过深（>{5}），非判定依据字段"}
        return {k: _redact(v, depth=depth + 1, key=k) for k, v in value.items()}
    if isinstance(value, list):
        if not keep and depth > 5:
            return [f"…共 {len(value)} 项（层级过深）"]
        head = [_redact(v, depth=depth + 1, key=key) for v in value]
        return head
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + f"…(共 {len(value)} 字)"
    return value


def _step_result(tool: str, raw) -> dict:
    """把一次工具返回归类为 ok / empty / error，并保留可核验的响应摘要。"""
    if not isinstance(raw, dict):
        return {"status": "error", "error": {"code": "unexpected", "message": redact_text(str(raw))[:200]}}

    code = raw.get("code")
    if code in _ERROR_CODES or (code and "items" not in raw and "meta" not in raw):
        return {
            "status": "error",
            "error": {
                "code": code,
                "message": redact_text(str(raw.get("message") or ""))[:300],
                "details": _redact(raw.get("details") or {}),
            },
        }

    meta = raw.get("meta") or {}
    total = meta.get("total")
    status = "empty" if total == 0 else "ok"
    return {
        "status": status,
        "total": total,
        "response": _redact(raw),
    }


def list_scenarios() -> list[str]:
    from api.datasource import DatasetReplaySource
    return [item["trace_id"] for item in DatasetReplaySource(DATASET).scenarios_summary()]



def load_truth(case_id: str) -> dict | None:
    """仅用于评测对照。参与调查逻辑的部分永远不读这里。"""
    for path in DATASET.glob("*truth*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict) and payload.get("case_id") == case_id:
            return payload
    return None


def run_one(case_id: str) -> dict:
    registry.clear()
    started = datetime.now(timezone.utc)
    session = InvestigationSession(case_id=case_id, seed_trace_id=case_id, seed_asset_id=None)
    result = session.run()
    finished = datetime.now(timezone.utc)

    payload = result.to_results()
    # 严格契约校验（11 字段、无额外字段）
    validated = validate_results(payload)
    verify = verify_triage(payload)

    steps = []
    for idx, (call, raw) in enumerate(zip(session.calls, session.results), start=1):
        items = raw.get("items") if isinstance(raw, dict) else None
        detail = _step_result(call.tool, raw)
        steps.append(
            {
                "round": idx,
                "tool": call.tool,
                "args": _redact(call.args),
                "why": call.why,
                "data_source": (raw.get("meta") or {}).get("data_source")
                if isinstance(raw, dict)
                else None,
                "returned_log_ids": [i.get("log_id") for i in (items or []) if isinstance(i, dict)],
                **detail,
            }
        )

    registered = registry.known_log_ids(case_id=case_id)
    evidence = list(validated.evidence_log_ids)
    unregistered = [e for e in evidence if e not in registered]
    data_source = (session.results[0].get("meta") or {}).get("data_source") if session.results else None

    truth = load_truth(case_id)
    evaluation = None
    if truth:
        truth_evidence = set(truth.get("evidence_log_ids") or [])
        hit = len(set(evidence) & truth_evidence)
        truth_type, truth_rule = _normalize_truth_type(str(truth.get("attack_type") or ""))
        mine = set(attack_types.segments(validated.attack_type))
        evaluation = {
            "truth_case_id": truth.get("case_id"),
            "malicious_match": validated.is_malicious == truth.get("is_malicious"),
            "risk_match": validated.risk_level == truth.get("risk_level"),
            "truth_attack_type": truth.get("attack_type"),
            "normalized_truth_attack_type": truth_type,
            "truth_normalization_rule": truth_rule,
            "attack_type_exact_match": validated.attack_type == truth_type,
            # truth 常只记录关键阶段（不含 recon）；"覆盖"指 truth 的每一段都在本结论里
            "attack_type_covers_truth": all(seg in mine for seg in attack_types.segments(truth_type)),
            "attacker_ip_match": validated.attacker_ip == truth.get("attacker_ip"),
            "evidence_recall": round(hit / len(truth_evidence), 3) if truth_evidence else None,
            "evidence_hit": hit,
            "evidence_truth_total": len(truth_evidence),
            "note": "仅作独立评测对照，未参与调查过程",
        }

    trace = {
        "case_id": case_id,
        "run": {
            "run_id": started.strftime("%Y%m%dT%H%M%SZ"),
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_ms": int((finished - started).total_seconds() * 1000),
            "controller": "rule_based_v1_controller",
            "env": {
                "data_source_mode": os.environ.get("SECLOG_DATA_SOURCE", "auto"),
                "search_mode": os.environ.get("SECLOG_SEARCH_MODE", "auto"),
            },
            "code_version": _code_version(),
            "dataset": "data/full_chain_logs",
            "data_source": data_source,
            "rounds": session.round,
            "seed": {"case_id": case_id, "trace_id": case_id},
            "step_status_counts": {
                s: sum(1 for step in steps if step["status"] == s) for s in ("ok", "empty", "error")
            },
        },
        "trace": {"steps": steps},
        "result": payload,
        # 结论依据：分类/风险/攻击源/摘要分别依据哪些日志
        "conclusion_basis": _redact(session.findings.get("conclusion_basis") or {}),
        # 判定依据：为什么判正常/弃权，逐条可核验
        "context_decision": _redact(session.findings.get("authorization") or {}),
        "checks": {
            "schema_valid": True,
            "verify_ok": verify.ok,
            "verify_problems": verify.problems,
            "evidence_count": len(evidence),
            "evidence_all_registered": not unregistered,
            "unregistered_evidence": unregistered,
            "requires_human_approval": validated.requires_human_approval,
            "recommended_action": validated.recommended_action,
        },
        "evaluation": evaluation,
    }
    return {"result": payload, "trace": trace, "verify_ok": verify.ok, "unregistered": unregistered}


def main(argv: list[str]) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # 首次按新口径运行前，把上一版产物快照为旧基线：新旧结果口径不同，不能互相覆盖后无法区分
    baseline = REPO / "data" / "agent_traces" / "legacy" / "v1-before-context-and-seven-class"
    if not baseline.exists():
        existing = sorted(OUT_DIR.glob("*.json"))
        if existing:
            import shutil

            baseline.mkdir(parents=True, exist_ok=True)
            for path in existing:
                shutil.copy2(path, baseline / path.name)
            (baseline / "README.md").write_text(
                "# 旧基线（修复前产物）\n\n"
                "这是第二周修复前的 V1 运行结果，保留用于对比。\n\n"
                "- 攻击分类为合并口径（`XSS_RCE` / `File_Upload_Traversal`，共 6 类）\n"
                "- 上下文未参与正常判定\n"
                "- 轨迹只记录数量与 log_id，缺错误码与响应摘要\n\n"
                "**不要用于当前评测**，当前结果见 `data/agent_traces/v1/`。\n",
                encoding="utf-8",
            )
            print(f"[baseline] 已把旧产物快照到 {baseline}")
    targets = argv[1:] or list_scenarios()
    if not targets:
        print("数据集中没有任何场景，无法运行")
        return 2

    rows = []
    ok_all = True
    for case_id in targets:
        out = run_one(case_id)
        result_path = OUT_DIR / f"{case_id}.json"
        trace_path = OUT_DIR / f"{case_id}.trace.json"
        result_path.write_text(json.dumps(out["result"], ensure_ascii=False, indent=2), encoding="utf-8")
        trace_path.write_text(json.dumps(out["trace"], ensure_ascii=False, indent=2), encoding="utf-8")

        ev = out["trace"]["evaluation"] or {}
        rows.append(
            {
                "case_id": case_id,
                "attack_type": out["result"]["attack_type"],
                "risk": out["result"]["risk_level"],
                "malicious": out["result"]["is_malicious"],
                "evidence": len(out["result"]["evidence_log_ids"]),
                "rounds": out["trace"]["run"]["rounds"],
                "verify_ok": out["verify_ok"],
                "truth_match": ev.get("malicious_match"),
                "evidence_recall": ev.get("evidence_recall"),
            }
        )
        if not out["verify_ok"]:
            ok_all = False
        print(
            f"[{'OK ' if out['verify_ok'] else 'BAD'}] {case_id} "
            f"-> {out['result']['attack_type']} / {out['result']['risk_level']} "
            f"证据{len(out['result']['evidence_log_ids'])}条 轮次{out['trace']['run']['rounds']} "
            f"回放来源={out['trace']['run']['data_source']}"
        )

    # 实际运行信息（不硬编码"回放成功""检索不可用"，一律从 trace 读）
    traces = [__import__("json").loads((OUT_DIR / f"{r['case_id']}.trace.json").read_text(encoding="utf-8")) for r in rows]
    first = traces[0]["run"] if traces else {}
    ds_seen = sorted({t["run"]["data_source"] for t in traces if t["run"]["data_source"]})
    retrieval = [s for t in traces for s in t["trace"]["steps"] if s["tool"] == "search_knowledge"]
    retrieval_errors = [s["error"] for s in retrieval if s["status"] == "error"]
    code_version = first.get("code_version") or {}
    mode = first.get("env") or {}

    header = [
        "# V1 调查实跑汇总",
        "",
        f"- 运行时间：{first.get('started_at', '未知')}（run_id `{first.get('run_id', '-')}`）",
        f"- 数据源：{('、'.join(f'`{d}`' for d in ds_seen)) or '无'}"
        f"（时间基准 = 各场景最新日志；配置模式 `{mode.get('data_source_mode', '-')}`）",
        "- 控制器：`rule_based_v1_controller`（`src/ai_engine/investigation.py`）",
        f"- 代码版本：`{code_version.get('commit') or '未知'}`"
        f"（分支 `{code_version.get('branch') or '-'}`，工作区"
        f"{'**有未提交改动**' if code_version.get('dirty_worktree') else '干净'}）",
        "- 标准答案仅用于本表的评测对照，未参与任何调查步骤",
        "",
        "| 场景 | 结论 | 风险 | 恶意 | 证据数 | 轮次 | 契约校验 | 恶意判定一致 | 风险一致 | 覆盖 truth 分类 | 证据召回 | 工具状态 |",
        "| :--- | :--- | :--- | :--- | --: | --: | :--- | :--- | :--- | :--- | --: | :--- |",
    ]
    for r, t in zip(rows, traces):
        ev = t.get("evaluation") or {}
        counts = t["run"]["step_status_counts"]
        status_label = "、".join(f"{k}:{v}" for k, v in counts.items() if v) or "-"
        header.append(
            f"| {r['case_id']} | {r['attack_type']} | {r['risk']} | {r['malicious']} | "
            f"{r['evidence']} | {r['rounds']} | {'通过' if r['verify_ok'] else '**失败**'} | "
            f"{ev.get('malicious_match')} | {ev.get('risk_match')} | "
            f"{ev.get('attack_type_covers_truth')} | {ev.get('evidence_recall')} | {status_label} |"
        )

    header.append("")
    header.append("> 数据来源与结论均为本次实际运行所得，未经人工修饰。")
    if retrieval_errors:
        codes = sorted({(e.get("code") or "unknown") for e in retrieval_errors})
        header.append(
            f"> 检索步骤失败 {len(retrieval_errors)} 次（{', '.join(codes)}），"
            "错误码与原因见各 `.trace.json` 中 `search_knowledge` 步骤的 `error` 字段。"
        )
    elif retrieval:
        header.append(f"> 检索步骤 {len(retrieval)} 次全部成功返回。")
    else:
        header.append("> 本次运行未调用检索工具。")
    (OUT_DIR / "SUMMARY.md").write_text("\n".join(header) + "\n", encoding="utf-8")

    print(f"\n产物目录：{OUT_DIR}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
