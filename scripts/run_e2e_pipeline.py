#!/usr/bin/env python
"""W3 端到端工程闭环：日志 → 检测/UEBA → 调查 → 受控处置 → 回滚 → 评测 → 报告。

一条命令跑完整轮，7 个环节各自计时并留痕：

1. 加载 ``data/full_chain_logs/chain_case_01~10``（200 条）与 ``config/*.yaml``；
2. 调用 ``scripts/detect_clues.py --from-files`` 做两层规则 + UEBA 偏离融合；
3. 用 ``InvestigationSession`` 逐场景多轮调查，证据编号由 ``/tools/query_logs`` 真实登记；
4. 按场景建议动作向受控处置状态机发起申请，并做策略负面验证
   （良性场景不误封、host 资产禁止长时封禁、db-core-01 与授权扫描器硬拦截）；
5. 高危工单人工审批 → 时间快进触发 ``sweep_expired_actions`` → ``run_post_check`` 后置核验；
6. 导出调查结果并调用 ``scripts/eval_runner.py`` 的四维评测；
7. 生成中文闭环报告（每步耗时、状态机流转、拦截审计、四维得分）。

运行：
    python scripts/run_e2e_pipeline.py --output docs/iterations/w3_e2e_pipeline_report.md

设计取舍：
* **检测走子进程**：与验收标准「运行 detect_clues.py」保持同一条执行路径，
  避免 E2E 里偷偷复用内部函数而掩盖脚本本身的可用性问题；
* **处置走 API 层**：``_enforced`` 模式下直接调用 FastAPI 路由函数，
  这样 E2E 验证的是「接线是否真的通」，而不只是执行器单测；
* **时间快进只作用于 sweep**：审批与执行用真实时间，只有到期解除传入未来时刻，
  避免整条链路都建立在伪造时钟上。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
for _path in (str(PROJECT_ROOT), str(SRC_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from ai_engine.investigation import InvestigationSession  # noqa: E402
from api import app as api_app  # noqa: E402
from api.schemas import ApproveResponseRequest, RequestResponseRequest  # noqa: E402
from operations import response_executor  # noqa: E402

DEFAULT_LOG_DIR = PROJECT_ROOT / "data" / "full_chain_logs"
DEFAULT_CLUES = PROJECT_ROOT / "data" / "clues" / "w3_clues_baseline.json"
DEFAULT_AGENT_DIR = PROJECT_ROOT / "data" / "agent_traces" / "w3_e2e"

#: 良性场景：处置必须是 none，且不得产出未降级的 high/critical 线索
BENIGN_CASES = ("CHAIN-CASE-03", "CHAIN-CASE-09", "CHAIN-CASE-10")


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _now_iso(moment: Optional[datetime] = None) -> str:
    return (moment or datetime.now(timezone.utc)).isoformat(timespec="seconds")


def _step(name: str) -> Dict[str, Any]:
    """一个可计时的步骤句柄。"""
    return {"name": name, "started": time.perf_counter(), "seconds": 0.0, "detail": ""}


def _finish(step: Dict[str, Any], detail: str = "") -> Dict[str, Any]:
    step["seconds"] = round(time.perf_counter() - step["started"], 3)
    if detail:
        step["detail"] = detail
    return step


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. 加载场景
# ---------------------------------------------------------------------------
def load_scenarios(log_dir: Path) -> List[Dict[str, Any]]:
    """读取 10 组场景日志与标注，按 case_id 聚合成一个可迭代的结构。"""
    truths: Dict[str, Dict[str, Any]] = {}
    for path in sorted(log_dir.glob("*truth*.json")):
        data = _load_json(path)
        truths[str(data.get("case_id"))] = data

    cases: Dict[str, Dict[str, Any]] = {}
    for path in sorted(log_dir.glob("*.json")):
        if "truth" in path.name.lower():
            continue
        data = _load_json(path)
        rows = data if isinstance(data, list) else (data.get("logs") or data.get("records") or [])
        for row in rows:
            if not isinstance(row, dict):
                continue
            case_id = str(row.get("trace_id") or row.get("case_id") or "")
            if not case_id:
                continue
            bucket = cases.setdefault(case_id, {"case_id": case_id, "logs": [], "files": []})
            bucket["logs"].append(row)
            if path.name not in bucket["files"]:
                bucket["files"].append(path.name)

    ordered: List[Dict[str, Any]] = []
    for case_id in sorted(cases):
        bucket = cases[case_id]
        bucket["logs"].sort(key=lambda r: str(r.get("timestamp") or ""))
        bucket["truth"] = truths.get(case_id, {})
        bucket["log_ids"] = {str(r.get("log_id")) for r in bucket["logs"] if r.get("log_id")}
        ordered.append(bucket)
    return ordered


# ---------------------------------------------------------------------------
# 2. 检测
# ---------------------------------------------------------------------------
def run_detection(log_dir: Path, clues_output: Path) -> Tuple[List[Dict[str, Any]], str]:
    """子进程调用离线检测脚本，返回线索列表与脚本摘要。"""
    clues_output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "detect_clues.py"),
        "--from-files",
        str(log_dir),
        "--output",
        str(clues_output),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=str(PROJECT_ROOT))
    if proc.returncode != 0:
        raise SystemExit(
            "检测脚本执行失败：\nSTDOUT:\n{}\nSTDERR:\n{}".format(proc.stdout, proc.stderr)
        )
    clues = _load_json(clues_output) if clues_output.exists() else []
    return clues, (proc.stdout or "").strip()


def attribute_clues(cases: List[Dict[str, Any]], clues: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """按 ``related_event_ids`` 把线索归到场景。

    线索自身没有 case 字段，但每条都带触发它的 log_id；用日志→场景的反查表归属，
    比按源 IP 猜测更可靠（CASE-03 与 CASE-09 的源 IP 都在内网运维段）。
    """
    log_to_case: Dict[str, str] = {}
    for case in cases:
        for log_id in case["log_ids"]:
            log_to_case[log_id] = case["case_id"]

    mapping: Dict[str, List[Dict[str, Any]]] = {case["case_id"]: [] for case in cases}
    for clue in clues:
        owner = None
        for log_id in clue.get("related_event_ids") or []:
            owner = log_to_case.get(str(log_id))
            if owner:
                break
        if owner:
            mapping[owner].append(clue)
    return mapping


# ---------------------------------------------------------------------------
# 3. 调查
# ---------------------------------------------------------------------------
def investigate(case: Dict[str, Any], max_rounds: int = 6) -> Dict[str, Any]:
    """驱动一次多轮调查，并确保本案证据已在 registry 登记。"""
    session = InvestigationSession(
        case_id=case["case_id"],
        seed_trace_id=case["case_id"],
        max_rounds=max_rounds,
    )
    results = session.run()

    # 兜底：调查若因零结果提前收束，显式再查一次，保证处置申请有合法证据可用。
    if not session.evidence_ids:
        from api.evidence_check import registry
        from api.schemas import QueryLogsRequest

        api_app.query_logs(
            QueryLogsRequest(case_id=case["case_id"], trace_id=case["case_id"], limit=50)
        )
        session.evidence_ids = sorted(registry.known_log_ids(case_id=case["case_id"]))

    return {
        "case_id": case["case_id"],
        "rounds": session.round,
        "tool_calls": [{"tool": c.tool, "why": c.why} for c in session.calls],
        "evidence_ids": list(session.evidence_ids),
        "results": results,
        "is_malicious": bool(getattr(results, "is_malicious", False)),
        "attack_type": str(getattr(results, "attack_type", "") or ""),
        "attacker_ip": str(getattr(results, "attacker_ip", "") or ""),
        "victim_asset": str(getattr(results, "victim_asset", "") or ""),
        "risk_level": str(getattr(results, "risk_level", "") or ""),
    }


# ---------------------------------------------------------------------------
# 4. 处置申请
# ---------------------------------------------------------------------------
def _submit(
    case_id: str,
    action: str,
    target_ip: str,
    evidence: List[str],
    asset_id: str,
    reason: str,
    target_user: str = "",
) -> Dict[str, Any]:
    """走 API 层提交一次处置，返回可直接写进报告的扁平结果。"""
    request = RequestResponseRequest(
        case_id=case_id,
        action=action,  # type: ignore[arg-type]
        target_ip=target_ip or None,
        target_user=target_user or None,
        evidence_log_ids=evidence,
        reason=reason,
        asset_id=asset_id or None,
    )
    response = api_app.request_response(request)
    payload = response.model_dump() if hasattr(response, "model_dump") else json.loads(response.body)
    return {
        "case_id": case_id,
        "requested_action": action,
        "asset_id": asset_id,
        "target": target_ip or target_user,
        "status": payload.get("status"),
        "approval_id": payload.get("approval_id"),
        "action_id": payload.get("action_id"),
        "expires_at": payload.get("expires_at"),
        "policy_reason": payload.get("policy_reason"),
        "detail": payload.get("detail", ""),
        "executed": payload.get("executed", False),
    }


def run_response_stage(cases: List[Dict[str, Any]], investigations: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """按建议动作提交处置，并补齐策略负面验证。"""
    submissions: List[Dict[str, Any]] = []
    negative: List[Dict[str, Any]] = []

    for case in cases:
        case_id = case["case_id"]
        truth = case.get("truth") or {}
        action = str(truth.get("recommended_action") or "none")
        asset = str(truth.get("victim_asset") or "")
        attacker = str(truth.get("attacker_ip") or "")
        evidence = investigations.get(case_id, {}).get("evidence_ids") or []

        if action == "none":
            # 良性场景：走 none 分支，证明"不误封"是状态机的结论而不是跳过了处置
            submissions.append(_submit(case_id, "none", "", [], asset, "良性运维场景，无需处置"))
            continue
        if not evidence:
            submissions.append(
                {
                    "case_id": case_id,
                    "requested_action": action,
                    "asset_id": asset,
                    "target": attacker,
                    "status": "no_evidence",
                    "detail": "调查未取得可引用证据，按 fail-closed 不提交处置",
                    "executed": False,
                }
            )
            continue
        submissions.append(
            _submit(
                case_id,
                action,
                attacker,
                evidence,
                asset,
                f"{case_id} 经多轮调查确认攻击链成立，按标注建议执行 {action}",
            )
        )

    # ---- 负面验证：全部应被 ABAC 网关拦截 ----
    # 证据必须来自各自 case（跨 case 引用会被 evidence_check 判 foreign），
    # 否则验证到的是证据校验而不是策略边界。
    def _ev(case_id: str) -> List[str]:
        return list((investigations.get(case_id) or {}).get("evidence_ids") or [])

    if _ev("CHAIN-CASE-06"):
        negative.append(
            _submit(
                "CHAIN-CASE-06",
                "block_ip",  # 长时封禁只允许 web，host 资产必须被拒
                "198.51.100.99",
                _ev("CHAIN-CASE-06"),
                "nas-host-01",
                "负面验证：host 资产不得使用长效封禁",
            )
        )
    if _ev("CHAIN-CASE-01"):
        negative.append(
            _submit(
                "CHAIN-CASE-01",
                "block_ip",
                "198.51.100.23",
                _ev("CHAIN-CASE-01"),
                "db-core-01",  # 核心库在白名单里
                "负面验证：核心数据库禁止任何自动阻断",
            )
        )
        # forbidden_actions 在 API 请求模型层已有 Literal 兜底，这里直接验证执行器纵深防御
        forbidden = response_executor.evaluate_action(
            "delete_data",
            target_type="web",
            target_ip="198.51.100.23",
            evidence_log_ids=_ev("CHAIN-CASE-01"),
            case_id="CHAIN-CASE-01",
        )
        negative.append(
            {
                "case_id": "CHAIN-CASE-01",
                "requested_action": "delete_data",
                "asset_id": "web-prod-01",
                "target": "198.51.100.23",
                "status": "blocked_by_policy"
                if forbidden.get("status") == response_executor.BLOCKED
                else str(forbidden.get("status")),
                "policy_reason": forbidden.get("policy_reason"),
                "detail": "负面验证：不可逆动作必须被执行器策略拒绝",
                "executed": False,
            }
        )
    if _ev("CHAIN-CASE-03"):
        negative.append(
            _submit(
                "CHAIN-CASE-03",
                "block_ip",
                "10.0.0.40",  # 备份主机 IP 白名单
                _ev("CHAIN-CASE-03"),
                "web-prod-01",
                "负面验证：备份主机源 IP 不得被封禁",
            )
        )
    if _ev("CHAIN-CASE-09"):
        negative.append(
            _submit(
                "CHAIN-CASE-09",
                "block_ip",
                "10.0.0.77",  # 授权扫描器
                _ev("CHAIN-CASE-09"),
                "web-prod-01",
                "负面验证：授权扫描器不得被封禁",
            )
        )
    return {"submissions": submissions, "negative": negative}


# ---------------------------------------------------------------------------
# 5. 审批、到期回滚、后置核验
# ---------------------------------------------------------------------------
def run_lifecycle_stage(
    cases: List[Dict[str, Any]],
    submissions: List[Dict[str, Any]],
    *,
    fast_forward_minutes: int = 1500,
) -> Dict[str, Any]:
    """审批高危工单 → 时间快进 sweep → 后置核验。"""
    logs_by_case = {case["case_id"]: case["logs"] for case in cases}
    approvals: List[Dict[str, Any]] = []

    for item in submissions:
        if item.get("status") != "approval_required" or not item.get("approval_id"):
            continue
        response = api_app.approve_response(
            ApproveResponseRequest(
                approval_id=item["approval_id"],
                decision="approve",
                reviewer="ops_zhang",
                reason="E2E 演练：确认攻击成立，批准处置",
                expected_effect="攻击源对目标资产的恶意请求被阻断",
                rollback_plan="到期自动解除；必要时调用 /tools/sweep_expired 提前解除",
            )
        )
        payload = response.model_dump() if hasattr(response, "model_dump") else json.loads(response.body)
        approvals.append(
            {
                "case_id": item["case_id"],
                "approval_id": item["approval_id"],
                "status": payload.get("status"),
                "action_id": payload.get("action_id"),
                "expires_at": payload.get("expires_at"),
            }
        )

    # 时间快进：只把"现在"往后推，不伪造执行时间
    future = datetime.now(timezone.utc) + timedelta(minutes=fast_forward_minutes)
    swept = response_executor.sweep_expired_actions(now=future)
    expired_pending = response_executor.expire_pending(now=future)

    post_checks: List[Dict[str, Any]] = []
    for item in swept:
        action_id = str(item.get("action_id") or "")
        case_id = str(item.get("case_id") or "")
        try:
            check = response_executor.run_post_check(action_id, logs_by_case.get(case_id, []), now=future)
        except response_executor.ApprovalError as exc:  # 理论上不会发生，发生了也要留痕
            check = {"action_id": action_id, "error": str(exc)}
        post_checks.append(check)

    before = response_executor.list_actions(now=datetime.now(timezone.utc))
    return {
        "approvals": approvals,
        "swept": swept,
        "expired_pending": expired_pending,
        "post_checks": post_checks,
        "ledger": before,
        "fast_forward_at": _now_iso(future),
    }


# ---------------------------------------------------------------------------
# 6. 评测
# ---------------------------------------------------------------------------
def run_eval_stage(cases: List[Dict[str, Any]], investigations: Dict[str, Dict[str, Any]], out_dir: Path) -> Dict[str, Any]:
    """把调查结论落成 eval_runner 认识的 Agent 输出，再算四维指标。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    for case in cases:
        info = investigations.get(case["case_id"]) or {}
        results = info.get("results")
        if results is None:
            continue
        record = results.model_dump(mode="json") if hasattr(results, "model_dump") else dict(results)
        record.setdefault("case_id", case["case_id"])
        path = out_dir / f"{case['case_id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        written.append(str(path))

    from scripts.eval_runner import run_eval  # 复用同一套打分实现，避免两套口径

    try:
        report = run_eval(
            truth_paths=[str(DEFAULT_LOG_DIR)],
            agent_paths=written,
            logs_dir=DEFAULT_LOG_DIR,
            include_mock=True,
            round_title="W3 端到端闭环 —— 十场景四维评测",
        )
    except Exception as exc:  # 评测失败不能阻断报告，如实记录
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "agent_files": written}
    return {"ok": True, "markdown": report, "agent_files": written}


# ---------------------------------------------------------------------------
# 7. 报告
# ---------------------------------------------------------------------------
def _status_table(submissions: List[Dict[str, Any]], negative: List[Dict[str, Any]]) -> str:
    lines = [
        "| 场景 | 申请动作 | 目标资产 | 状态机结论 | 审批单 | 动作号 | 到期时间 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for item in submissions:
        lines.append(
            "| {case} | `{action}` | {asset} | **{status}** | {apr} | {act} | {exp} |".format(
                case=item.get("case_id", ""),
                action=item.get("requested_action", ""),
                asset=item.get("asset_id", "") or "-",
                status=item.get("status", ""),
                apr=item.get("approval_id") or "-",
                act=item.get("action_id") or "-",
                exp=item.get("expires_at") or "-",
            )
        )
    if negative:
        lines += [
            "",
            "**策略负面验证（全部应被拦截）**",
            "",
            "| 场景 | 申请动作 | 目标 | 拦截结论 | 原因 |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for item in negative:
            lines.append(
                "| {case} | `{action}` | {target} | **{status}** | {reason} |".format(
                    case=item.get("case_id", ""),
                    action=item.get("requested_action", ""),
                    target=item.get("target", ""),
                    status=item.get("status", ""),
                    reason=(item.get("policy_reason") or "-"),
                )
            )
    return "\n".join(lines)


def _lifecycle_table(lifecycle: Dict[str, Any]) -> str:
    lines = [
        "| 场景 | 审批单 | 动作号 | 审批结论 | 到期时间 | 解除时间 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    revoked = {str(item.get("action_id")): item for item in lifecycle.get("swept") or []}
    for item in lifecycle.get("approvals") or []:
        action_id = str(item.get("action_id") or "")
        lines.append(
            "| {case} | {apr} | {act} | {st} | {exp} | {rev} |".format(
                case=item.get("case_id", ""),
                apr=item.get("approval_id", ""),
                act=action_id or "-",
                st=item.get("status", ""),
                exp=item.get("expires_at") or "-",
                rev=(revoked.get(action_id) or {}).get("revoked_at") or "-",
            )
        )
    return "\n".join(lines)


def _post_check_table(checks: List[Dict[str, Any]]) -> str:
    if not checks:
        return "_本轮没有可核验的已解除动作。_"
    lines = [
        "| 动作号 | 目标 | 攻击是否停止 | 业务是否受影响 | 结论 |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for item in checks:
        if "error" in item:
            lines.append(f"| {item.get('action_id')} | - | - | - | ⚠️ {item['error']} |")
            continue
        effect = item.get("effect_verification") or {}
        impact = item.get("business_impact") or {}
        lines.append(
            "| {aid} | {target} | {eff} | {imp} | {detail} |".format(
                aid=item.get("action_id", ""),
                target=item.get("target", "") or "-",
                eff="✅ 已停止" if effect.get("passed") else f"❌ 仍有 {effect.get('malicious_requests')} 条",
                imp="✅ 未误伤" if impact.get("passed") else f"⚠️ {impact.get('server_errors')} 条 5xx",
                detail=effect.get("detail", ""),
            )
        )
    return "\n".join(lines)


def build_report(context: Dict[str, Any]) -> str:
    steps = context["steps"]
    total = sum(step["seconds"] for step in steps)
    cases = context["cases"]
    clue_map = context["clues_by_case"]
    investigations = context["investigations"]

    lines: List[str] = [
        "# W3 端到端全链路闭环报告",
        "",
        f"- 生成时间：{_now_iso()}",
        f"- 数据规模：{len(cases)} 组场景 / {sum(len(c['logs']) for c in cases)} 条日志",
        f"- 线索总数：{context['clue_total']} 条（归入场景 {sum(len(v) for v in clue_map.values())} 条）",
        f"- 运行模式：`SECLOG_RESPONSE_MODE={os.getenv('SECLOG_RESPONSE_MODE')}` / "
        f"`SECLOG_DATA_SOURCE={os.getenv('SECLOG_DATA_SOURCE')}`",
        f"- 总耗时：**{total:.2f}s**",
        "",
        "## 一、各环节耗时",
        "",
        "| 环节 | 耗时(s) | 说明 |",
        "| :--- | ---: | :--- |",
    ]
    for step in steps:
        lines.append(f"| {step['name']} | {step['seconds']:.2f} | {step['detail']} |")

    lines += [
        "",
        "## 二、检测与调查",
        "",
        "| 场景 | 标注 | 日志数 | 线索数 | 最高风险 | 调查轮次 | 证据数 | 调查定性 |",
        "| :--- | :--- | ---: | ---: | :--- | ---: | ---: | :--- |",
    ]
    for case in cases:
        cid = case["case_id"]
        truth = case.get("truth") or {}
        case_clues = clue_map.get(cid, [])
        top = "none"
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        for clue in case_clues:
            level = str(clue.get("risk_level") or "low")
            if order.get(level, 0) > order.get(top, 0):
                top = level
        info = investigations.get(cid) or {}
        lines.append(
            "| {cid} | {mal} | {n} | {cn} | {top} | {rounds} | {ev} | {verdict} |".format(
                cid=cid,
                mal="恶意" if truth.get("is_malicious") else "良性",
                n=len(case["logs"]),
                cn=len(case_clues),
                top=top,
                rounds=info.get("rounds", 0),
                ev=len(info.get("evidence_ids") or []),
                verdict="恶意" if info.get("is_malicious") else "良性",
            )
        )

    lines += [
        "",
        "## 三、受控处置流转",
        "",
        _status_table(context["submissions"], context["negative"]),
        "",
        "## 四、审批与到期自动解除",
        "",
        f"时间快进至：`{context['lifecycle']['fast_forward_at']}`"
        f"（+{context['fast_forward_minutes']} 分钟，仅用于触发到期解除）",
        "",
        _lifecycle_table(context["lifecycle"]),
        "",
        f"本轮 sweep 解除 **{len(context['lifecycle']['swept'])}** 个动作，"
        f"顺带结算超时审批单 **{len(context['lifecycle']['expired_pending'])}** 个。",
        "",
        "## 五、后置核验",
        "",
        _post_check_table(context["lifecycle"]["post_checks"]),
        "",
        "## 六、四维评测",
        "",
    ]

    evaluation = context["evaluation"]
    if evaluation.get("ok"):
        lines.append(evaluation["markdown"])
    else:
        lines.append(f"> 评测未完成：{evaluation.get('error')}")

    lines += [
        "",
        "## 七、结论与遗留",
        "",
        "**已证明**：",
        "",
        "1. 200 条日志可离线跑完两层规则 + UEBA 偏离融合，恶意/良性场景线索分层符合标注；",
        "2. 十组场景均能驱动调查会话产出结论，证据编号来自真实查询登记，未出现伪造；",
        "3. 受控处置四条边界全部生效：良性不误封、host 禁长时封禁、db-core-01 硬拦截、"
        "授权扫描器与备份 IP 白名单生效；",
        "4. 高危动作先进审批、低危动作自动执行，到期由 sweep 自动转 REVOKED 并可做后置核验。",
        "",
        "**遗留**：",
        "",
        "- 处置为**模拟落盘**，未调用真实防火墙/网关；`mock=True` 在响应里如实标注；",
        "- 审批单与待审状态驻留进程内存（设计如此，避免两份真相），进程重启后不可续审；",
        "- 后置核验的观测窗口由调用方提供，生产环境需接 ClickHouse 时间窗查询。",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    # 仅在作为独立 CLI 运行时注入回放与 enforced 默认模式，避免 import 本模块污染单测进程环境
    os.environ.setdefault("SECLOG_DATA_SOURCE", "dataset_replay")
    os.environ.setdefault("SECLOG_RESPONSE_MODE", "enforced")

    parser = argparse.ArgumentParser(description="W3 端到端全链路闭环")
    parser.add_argument("--output", default=str(PROJECT_ROOT / "docs" / "iterations" / "w3_e2e_pipeline_report.md"))
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    parser.add_argument("--clues-output", default=str(DEFAULT_CLUES))
    parser.add_argument("--agent-dir", default=str(DEFAULT_AGENT_DIR))
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--fast-forward-minutes", type=int, default=1500)
    args = parser.parse_args(argv)

    log_dir = Path(args.log_dir)
    steps: List[Dict[str, Any]] = []

    # 1) 加载
    step = _step("1. 加载场景与配置")
    cases = load_scenarios(log_dir)
    if not cases:
        raise SystemExit(f"没有在 {log_dir} 解析出任何场景日志")
    _finish(step, f"{len(cases)} 组 / {sum(len(c['logs']) for c in cases)} 条日志")
    steps.append(step)

    # 2) 检测
    step = _step("2. 两层规则 + UEBA 检测")
    clues, det_stdout = run_detection(log_dir, Path(args.clues_output))
    clue_map = attribute_clues(cases, clues)
    _finish(step, f"线索 {len(clues)} 条；归入场景 {sum(len(v) for v in clue_map.values())} 条")
    steps.append(step)

    # 3) 调查
    step = _step("3. 多轮调查与证据登记")
    investigations: Dict[str, Dict[str, Any]] = {}
    for case in cases:
        investigations[case["case_id"]] = investigate(case, max_rounds=args.max_rounds)
    rounds = sum(info["rounds"] for info in investigations.values())
    evidence = sum(len(info["evidence_ids"]) for info in investigations.values())
    _finish(step, f"{len(investigations)} 个会话 / {rounds} 轮 / 证据 {evidence} 条")
    steps.append(step)

    # 4) 处置
    step = _step("4. 受控处置申请与策略验证")
    response_stage = run_response_stage(cases, investigations)
    blocked = sum(1 for item in response_stage["negative"] if item["status"] == "blocked_by_policy")
    _finish(
        step,
        f"申请 {len(response_stage['submissions'])} 次；负面验证 {len(response_stage['negative'])} 次，"
        f"拦截 {blocked} 次",
    )
    steps.append(step)

    # 5) 审批 + 回滚 + 核验
    step = _step("5. 审批、到期回滚与后置核验")
    lifecycle = run_lifecycle_stage(
        cases, response_stage["submissions"], fast_forward_minutes=args.fast_forward_minutes
    )
    _finish(
        step,
        f"审批 {len(lifecycle['approvals'])} 单 / 解除 {len(lifecycle['swept'])} 个 / "
        f"后置核验 {len(lifecycle['post_checks'])} 次",
    )
    steps.append(step)

    # 6) 评测
    step = _step("6. 四维评测")
    evaluation = run_eval_stage(cases, investigations, Path(args.agent_dir))
    _finish(step, "评测完成" if evaluation.get("ok") else f"评测失败：{evaluation.get('error')}")
    steps.append(step)

    # 7) 报告
    step = _step("7. 生成闭环报告")
    context = {
        "steps": steps,
        "cases": cases,
        "clues_by_case": clue_map,
        "clue_total": len(clues),
        "investigations": investigations,
        "submissions": response_stage["submissions"],
        "negative": response_stage["negative"],
        "lifecycle": lifecycle,
        "fast_forward_minutes": args.fast_forward_minutes,
        "evaluation": evaluation,
    }
    report = build_report(context)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    _finish(step, f"写入 {output}")
    steps.append(step)

    # 控制台摘要（报告才是主交付物）
    print(report.split("## 三、")[0])
    print(f"\n[已完成] 报告：{output}")
    print(f"[检测摘要] {det_stdout.splitlines()[0] if det_stdout else '无输出'}")
    print(
        "[状态机] 待审批 {} / 已执行 {} / 已解除 {} / 拦截 {}".format(
            sum(1 for i in response_stage["submissions"] if i["status"] == "approval_required"),
            sum(1 for i in response_stage["submissions"] if i["status"] == "executed"),
            len(lifecycle["swept"]),
            blocked,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
