"""恒脑平台【受控处置步骤】代码节点（Week 3）。

位置：调查节点 → 校验节点 → 交互节点（人工审批）→ **本节点** → 报告节点

职责边界
--------
* **调查节点只读**：调查过程拿不到任何处置工具；处置只能在本节点发起。
* 本节点只做两件事：把审批结果翻译成一次 `/tools/request_response` 调用，
  并把服务端回执原样透出（`approval_required` / `EXECUTED` / `BLOCKED_BY_POLICY` /
  `REJECTED` / `no_action`）。不做策略判断、不做目标改写。
* 策略网关与状态机在服务端（`src/operations/response_executor.py`，PR #37/#38）；
  执行器未部署时服务端返回 `approval_required` 或 `backend_unavailable`，
  本节点**不得**把"没执行"写成"已处置"。

输入（平台引用）
----------------
``args.input.triage``   校验节点输出的 11 字段结论（Object 或 JSON 字符串）
``args.input.answer``   交互节点的单选结果（含 "A" 表示批准提交申请，其余表示拒绝）
``args.input.seed``     开始节点输入（含 case_id 与 service_url）

输出
----
``result_key``：``{"receipt": {...}, "results": {...}}``
回执字段：status / approval_id / executed / detail / action / target / evidence_log_ids。
"""

import json
import urllib.request


def _load(value):
    """平台字段可能是 JSON 字符串，也可能是已解析的 Object。"""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("```"):
            text = "\n".join(text.splitlines()[1:-1])
        return json.loads(text)
    return value


def _approved(answer) -> bool:
    """只认交互节点的明确批准（单选 A）；其余（B/空/超时）一律按拒绝处理。"""
    return isinstance(answer, str) and answer.strip() == "A"


def handler(args) -> dict:
    triage = _load(args.input.triage)
    seed = _load(args.input.seed)
    case_id = str(triage.get("case_id") or seed.get("case_id") or "")
    if not case_id:
        raise ValueError("缺少 case_id：不做任何处置")

    action = str(triage.get("recommended_action") or "none")
    evidence = [str(item) for item in (triage.get("evidence_log_ids") or [])]
    target_ip = str(triage.get("attacker_ip") or "")

    # 无需处置：直接给出回执，不调用工具、不产生副作用
    if action == "none":
        return {
            "result_key": {
                "receipt": {
                    "status": "no_action",
                    "case_id": case_id,
                    "action": "none",
                    "target": target_ip,
                    "executed": False,
                    "detail": "结论为无需处置，未提交任何动作",
                    "evidence_log_ids": evidence,
                },
                "results": triage,
            }
        }

    # 人工拒绝（或未批准）：只登记拒绝回执，绝不提交申请
    if not _approved(getattr(args.input, "answer", None)):
        return {
            "result_key": {
                "receipt": {
                    "status": "REJECTED",
                    "case_id": case_id,
                    "action": action,
                    "target": target_ip,
                    "executed": False,
                    "detail": "人工审批未批准，处置未提交、未执行",
                    "evidence_log_ids": evidence,
                },
                "results": triage,
            }
        }

    body = json.dumps(
        {
            "case_id": case_id,
            "action": action,
            "target_ip": target_ip or None,
            "evidence_log_ids": evidence,
            "reason": str(triage.get("attack_chain_summary") or "")[:500],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        seed["service_url"] + "/tools/request_response",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.load(response)

    status = payload.get("status")
    receipt = {
        # 服务端状态原样透出：approval_required / executed / rejected / 其它
        "status": status,
        "case_id": case_id,
        "action": action,
        "target": target_ip,
        "executed": (
            status in {"executed", "EXECUTED"}
            and payload.get("executed") is True
            and payload.get("mock") is not True
        ),
        "mock": payload.get("mock") is True,
        "approval_id": payload.get("approval_id"),
        "detail": payload.get("detail"),
        "evidence_log_ids": evidence,
        "raw_status": payload.get("status"),
    }
    if payload.get("status") == "approval_required" and not receipt["approval_id"]:
        raise ValueError("服务端未返回审批单号：视为处置未登记")
    return {"result_key": {"receipt": receipt, "results": triage}}
