"""HTTP boundary for the project's simulated ABAC approval flow."""

import hmac
import json
import os
import threading
from dataclasses import replace
from ipaddress import ip_address

from fastapi import HTTPException

from operations import response_step

from . import asset_context
from .evidence_check import registry
from .schemas import ApproveResponseRequest, RequestResponseRequest, RequestResponseResponse

_lock = threading.Lock()
_orders: dict[str, response_step.DispositionRequest] = {}


def mode() -> str:
    return os.getenv("SECLOG_RESPONSE_MODE", "legacy").strip().lower()


def _configured_tokens() -> tuple[str, dict[str, str]]:
    submit_token = os.getenv("SECLOG_RESPONSE_SUBMIT_TOKEN", "")
    try:
        reviewers = json.loads(os.getenv("SECLOG_RESPONSE_APPROVAL_TOKENS_JSON", "{}"))
        if not isinstance(reviewers, dict) or not reviewers or not all(
            name.strip() and isinstance(token, str) for name, token in reviewers.items()
        ):
            raise ValueError
        tokens = [submit_token, *reviewers.values()]
        if len(set(tokens)) != len(tokens) or not all(
            len(token) >= 24 and token.isascii() and not any(c.isspace() for c in token) for token in tokens
        ):
            raise ValueError
    except ValueError:
        raise HTTPException(503, "处置模拟入口未配置独立的提交与审批凭据") from None
    return submit_token, reviewers


def _matches(candidate: str, token: str) -> bool:
    return hmac.compare_digest(candidate.encode("utf-8"), token.encode("utf-8"))


def _receipt(status: str, detail: str, **fields) -> RequestResponseResponse:
    return RequestResponseResponse(status=status, detail=detail, executed=False,
                                   mock=True, simulation=True, **fields)


def _convert(result: response_step.DispositionReceipt) -> RequestResponseResponse:
    status = "no_action" if result.status == response_step.NO_ACTION else result.status
    detail = (
        "审批状态机已写入模拟执行审计，未执行真实网络处置。"
        if status == response_step.EXECUTED else result.detail
    )
    return _receipt(status, detail, approval_id=result.approval_id,
                    deadline=result.deadline, policy_reason=result.policy_reason)


def _expire_pending() -> None:
    for receipt in response_step.settle_timeouts():
        _orders.pop(receipt.approval_id, None)


def submit(req: RequestResponseRequest, bearer: str) -> RequestResponseResponse:
    submit_token, _ = _configured_tokens()
    if not _matches(bearer, submit_token):
        raise HTTPException(401, "处置提交凭据无效")
    if req.action == "none":
        return _receipt("no_action", "无需提交处置申请")

    records = {item.log_id: item for item in registry.snapshot(case_id=req.case_id)}
    rejected = [log_id for log_id in req.evidence_log_ids
                if log_id not in records or records[log_id].query_params.get("data_source") == "mock"]
    if rejected:
        return _receipt("BLOCKED_BY_POLICY", "证据不属于当前调查或来自 Mock",
                        policy_reason="unverified_evidence", rejected_evidence_ids=rejected)
    try:
        target_ip = str(ip_address(req.target_ip.strip())) if req.target_ip else ""
    except ValueError:
        return _receipt("BLOCKED_BY_POLICY", "处置目标 IP 无效", policy_reason="invalid_target")
    target_user = (req.target_user or "").strip()
    asset = asset_context.get_asset_context(req.asset_id) if req.asset_id else None
    if not asset or not any(
        record.asset_id == asset["asset_id"]
        and (target_ip in record.addresses if target_ip else target_user == record.user)
        for record in (records[log_id] for log_id in req.evidence_log_ids)
    ):
        return _receipt("BLOCKED_BY_POLICY", "目标与资产未同时出现在本案证据中",
                        policy_reason="unverified_asset_or_target")
    order = response_step.DispositionRequest(
        case_id=req.case_id, action=req.action, target_ip=target_ip, target_user=target_user,
        target_type=asset["role"] or "", evidence_log_ids=list(dict.fromkeys(req.evidence_log_ids)),
        reason=req.reason,
    )
    with _lock:
        _expire_pending()
        result = response_step.submit(order)
        if result.needs_human and result.approval_id:
            _orders[result.approval_id] = order
    return _convert(result)


def settle(req: ApproveResponseRequest, bearer: str) -> RequestResponseResponse:
    if mode() != "simulation":
        raise HTTPException(404, "审批状态机未启用")
    _, reviewers = _configured_tokens()
    reviewer = next((name for name, token in reviewers.items() if _matches(bearer, token)), None)
    if reviewer is None:
        raise HTTPException(401, "审批凭据无效")
    with _lock:
        order = _orders.get(req.approval_id)
        if order is None or order.case_id != req.case_id:
            raise HTTPException(404, "当前案件没有此待审工单")
        for expired in response_step.settle_timeouts():
            _orders.pop(expired.approval_id, None)
        if req.approval_id not in _orders:
            return _receipt("APPROVAL_TIMEOUT", "工单已超时拒批", approval_id=req.approval_id)
        if req.decision == "approve" and (not req.expected_effect.strip() or not req.rollback_plan.strip()):
            raise HTTPException(422, "批准时须提供预期效果及回滚方案")
        reviewed = replace(order, expected_effect=req.expected_effect.strip(), rollback_plan=req.rollback_plan.strip())
        approval_order = reviewed.approval_order(reviewer)
        approval_order["reason"] = req.reason
        result = response_step.resolve_approval(
            req.approval_id, decision=req.decision, reviewed_by=reviewer, order=approval_order,
        )
        if result.status in {response_step.EXECUTED, response_step.REJECTED}:
            _orders.pop(req.approval_id, None)
    return _convert(result)
