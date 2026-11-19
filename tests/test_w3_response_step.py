"""Week 3 受控处置步骤测试：待审 / 批准 / 拒批 / 超时 / 策略拦截。

纪律：
* **不产生任何真实副作用**——全部用契约测试替身（与 PR #37/#38 的
  ``response_executor`` 方法签名和返回结构逐字对齐）；
* 真实执行器未合入时，``resolve_executor()`` 返回 ``None``，本模块必须
  ``fail-closed``，返回 ``EXECUTOR_UNAVAILABLE`` 而不是"假装已执行"；
* 调查节点只读：调查结束后调用的处置步骤是**独立步骤**，不挂在调查循环里。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from operations import response_step as step

NOW = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)


class ContractDouble:
    """PR #37/#38 执行器的契约替身：状态流转与返回结构一一对应。"""

    def __init__(
        self,
        *,
        status: str = "PENDING_APPROVAL",
        policy_reason: str = "ALLOWED",
        timeout_minutes: float = 30,
    ) -> None:
        self.status = status
        self.policy_reason = policy_reason
        self.timeout_minutes = timeout_minutes
        self.calls: list[tuple] = []
        self.pending: dict[str, dict[str, Any]] = {}
        self.enforcements: list[dict[str, Any]] = []
        self._seq = 0

    # -- 契约方法 ---------------------------------------------------------
    def evaluate_action(
        self,
        action: str,
        target_type: str = "",
        target_ip: str = "",
        target_user: str = "",
        evidence_log_ids: Any = None,
        *,
        case_id: str = "",
        timeout_minutes: float = 30,
        now: Optional[datetime] = None,
    ) -> dict[str, Any]:
        self.calls.append(("evaluate_action", action, target_type, target_ip, tuple(evidence_log_ids or ())))
        base = {
            "action": action,
            "target_type": target_type,
            "target": target_ip or target_user,
            "evidence_log_ids": list(evidence_log_ids or ()),
            "policy_reason": self.policy_reason,
        }
        if self.status == "BLOCKED":
            return {"status": "BLOCKED", **base}
        if action == "none":
            return {"status": "NO_ACTION", **base}
        if self.status == "EXECUTED":
            record = {"ts": (now or NOW).isoformat(), "action": action, "target": base["target"]}
            self.enforcements.append(record)
            return {"status": "EXECUTED", **base, "record": record}
        self._seq += 1
        approval_id = f"APR-{self._seq:04d}"
        moment = now or NOW
        order = {
            "approval_id": approval_id,
            "status": "PENDING_APPROVAL",
            "action": action,
            "target_type": target_type,
            "target": base["target"],
            "target_ip": target_ip,
            "target_user": target_user,
            "evidence_log_ids": list(evidence_log_ids or ()),
            "policy_reason": self.policy_reason,
            "case_id": case_id,
            "deadline_at": moment + timedelta(minutes=timeout_minutes),
        }
        self.pending[approval_id] = order
        return {
            "status": "PENDING_APPROVAL",
            **base,
            "approval_id": approval_id,
            "deadline": order["deadline_at"].isoformat(),
        }

    def approve(
        self, approval_id: str, order: dict[str, Any], approved_by: str, *, now: Optional[datetime] = None
    ) -> dict[str, Any]:
        self.calls.append(("approve", approval_id, approved_by))
        pending = self.pending[approval_id]
        if pending["action"] != order["action"] or pending["target_ip"] != order["target_ip"]:
            raise ValueError("审批单动作/目标与待审批单不一致")
        record = {
            "ts": (now or NOW).isoformat(),
            "action": pending["action"],
            "target": pending["target"],
            "approved_by": approved_by,
        }
        self.enforcements.append(record)
        pending["status"] = "APPROVED"
        return {"status": "EXECUTED", "approval_id": approval_id, "record": record}

    def reject(
        self, approval_id: str, rejected_by: str, *, reason: str = "", now: Optional[datetime] = None
    ) -> dict[str, Any]:
        self.calls.append(("reject", approval_id, rejected_by))
        pending = self.pending[approval_id]
        pending["status"] = "REJECTED"
        return {"status": "REJECTED", "approval_id": approval_id, "rejected_by": rejected_by, "reason": reason}

    def expire_pending(self, now: Optional[datetime] = None) -> list[dict[str, Any]]:
        moment = now or NOW
        settled = []
        for order in self.pending.values():
            if order["status"] != "PENDING_APPROVAL" or moment < order["deadline_at"]:
                continue
            order["status"] = "REJECTED"
            order["reject_reason"] = "timeout: 审批超时，按 approval.on_timeout=reject 自动拒绝"
            settled.append(order)
        return settled


def _request(**overrides: Any) -> step.DispositionRequest:
    data = {
        "case_id": "CHAIN-CASE-01",
        "action": "block_ip",
        "target_ip": "198.51.100.23",
        "target_type": "web",
        "evidence_log_ids": ["LOG-20261027-0126", "LOG-20261027-0127"],
    }
    data.update(overrides)
    return step.DispositionRequest(**data)


# ---------------------------------------------------------------------------
# 1. 待审
# ---------------------------------------------------------------------------


def test_high_risk_action_is_registered_pending_approval():
    executor = ContractDouble()
    receipt = step.submit(_request(), executor=executor, now=NOW)

    assert receipt.status == step.APPROVAL_REQUIRED
    assert receipt.executed is False
    assert receipt.approval_id
    assert receipt.needs_human is True
    assert executor.enforcements == [], "待审状态下不得产生任何执行记录"
    assert receipt.evidence_log_ids


def test_low_risk_action_executes_with_audit_record():
    executor = ContractDouble(status="EXECUTED")
    receipt = step.submit(
        _request(action="rate_limit", target_ip="45.155.205.233"), executor=executor, now=NOW
    )

    assert receipt.status == step.EXECUTED
    assert receipt.executed is True
    assert len(executor.enforcements) == 1


# ---------------------------------------------------------------------------
# 2. 批准 / 拒批
# ---------------------------------------------------------------------------


def test_approve_executes_and_records_reviewer():
    executor = ContractDouble()
    pending = step.submit(_request(), executor=executor, now=NOW)
    order = _request().approval_order("ops_zhang")

    receipt = step.resolve_approval(
        pending.approval_id,
        decision="approve",
        reviewed_by="ops_zhang",
        order=order,
        executor=executor,
        now=NOW,
    )

    assert receipt.status == step.EXECUTED
    assert receipt.executed is True
    assert executor.enforcements[0]["approved_by"] == "ops_zhang"


def test_adapter_uses_merged_executor_to_record_pending_then_review(monkeypatch, tmp_path):
    from operations import response_executor

    monkeypatch.setenv("SECLOG_STATE_DIR", str(tmp_path))
    response_executor.reset_pending()
    try:
        request = _request(target_ip="192.0.2.10")
        pending = step.submit(request, now=NOW)
        assert pending.status == step.APPROVAL_REQUIRED
        assert not response_executor.enforcement_log_path().exists()
        receipt = step.resolve_approval(
            pending.approval_id, decision="approve", reviewed_by="test-reviewer",
            order=request.approval_order("test-reviewer"), now=NOW,
        )
        assert receipt.status == step.EXECUTED
        record = json.loads(response_executor.enforcement_log_path().read_text(encoding="utf-8").strip())
        assert record["approved_by"] == "test-reviewer"
        assert record["target"] == "192.0.2.10"
    finally:
        response_executor.reset_pending()


def test_reject_never_executes():
    executor = ContractDouble()
    pending = step.submit(_request(), executor=executor, now=NOW)

    receipt = step.resolve_approval(
        pending.approval_id,
        decision="reject",
        reviewed_by="ops_zhang",
        order=_request().approval_order("ops_zhang"),
        executor=executor,
        now=NOW,
    )

    assert receipt.status == step.REJECTED
    assert receipt.executed is False
    assert executor.enforcements == []


def test_approval_requires_named_reviewer():
    with pytest.raises(step.DispositionError):
        step.resolve_approval(
            "APR-0001",
            decision="approve",
            reviewed_by="  ",
            order=_request().approval_order(""),
            executor=ContractDouble(),
        )


def test_approval_for_other_target_is_rejected():
    """批 A 执行 B 必须被拦：审批单目标与待审批单不一致。"""
    executor = ContractDouble()
    pending = step.submit(_request(), executor=executor, now=NOW)
    wrong = _request(target_ip="203.0.113.9").approval_order("ops_zhang")

    receipt = step.resolve_approval(
        pending.approval_id,
        decision="approve",
        reviewed_by="ops_zhang",
        order=wrong,
        executor=executor,
        now=NOW,
    )

    assert receipt.status == step.INVALID_APPROVAL
    assert receipt.executed is False
    assert executor.enforcements == []


# ---------------------------------------------------------------------------
# 3. 超时
# ---------------------------------------------------------------------------


def test_timeout_settles_as_rejection_not_approval():
    executor = ContractDouble()
    pending = step.submit(_request(), executor=executor, now=NOW)

    early = step.settle_timeouts(executor=executor, now=NOW + timedelta(minutes=29))
    assert early == [], "未到期不得提前结算"

    settled = step.settle_timeouts(executor=executor, now=NOW + timedelta(minutes=31))
    assert len(settled) == 1
    assert settled[0].status == step.APPROVAL_TIMEOUT
    assert settled[0].executed is False
    assert settled[0].approval_id == pending.approval_id
    assert executor.enforcements == []


# ---------------------------------------------------------------------------
# 4. 策略拦截 / 执行器缺失
# ---------------------------------------------------------------------------


def test_policy_block_is_reported_with_reason_and_no_side_effect():
    executor = ContractDouble(status="BLOCKED", policy_reason="BLOCKED_BY_POLICY:target_type_not_allowed:block_ip 仅允许 web")
    receipt = step.submit(
        _request(target_type="database", target_ip="10.0.0.30"), executor=executor, now=NOW
    )

    assert receipt.status == step.BLOCKED_BY_POLICY
    assert receipt.executed is False
    assert "target_type_not_allowed" in (receipt.policy_reason or "")
    assert executor.enforcements == []


def test_missing_executor_fails_closed(monkeypatch):
    monkeypatch.setattr(step, "resolve_executor", lambda: None)
    receipt = step.submit(_request())

    assert receipt.status == step.EXECUTOR_UNAVAILABLE
    assert receipt.executed is False
    assert "未提交" in receipt.detail


def test_none_action_never_touches_executor():
    executor = ContractDouble()
    receipt = step.submit(_request(action="none", target_ip=""), executor=executor)

    assert receipt.status == step.NO_ACTION
    assert receipt.executed is False
    assert executor.calls == []


# ---------------------------------------------------------------------------
# 5. 从调查结论生成申请
# ---------------------------------------------------------------------------


def test_build_request_carries_action_target_and_evidence():
    result = {
        "case_id": "CHAIN-CASE-06",
        "recommended_action": "block_ip_short_term",
        "attacker_ip": "198.51.100.99",
        "evidence_log_ids": ["LOG-20261104-0613", "LOG-20261104-0617"],
        "attack_chain_summary": "SSH 爆破成功",
    }
    request = step.build_request(result, target_type="host")

    assert request.action == "block_ip_short_term"
    assert request.target_ip == "198.51.100.99"
    assert request.target_type == "host"
    assert request.evidence_log_ids == ["LOG-20261104-0613", "LOG-20261104-0617"]
    order = request.approval_order("ops_zhang")
    # 审批单必备字段（config/response-policy.yaml#approval.required_fields）
    for field in ("case_id", "action", "target_ip", "evidence_log_ids"):
        assert field in order


def test_approval_order_covers_all_executor_required_fields():
    """PR #38 的执行器要求 6 项必填；后两项留空会被直接拒批（真实联调时踩到过）。"""
    order = _request().approval_order("ops_zhang")
    for field in ("case_id", "action", "target_ip", "evidence_log_ids", "expected_effect", "rollback_plan"):
        assert order.get(field), f"审批单缺少 {field}"
    # 审批人可以改写，但默认文案必须与策略一致（到期自动解除）
    assert "自动解除" in order["rollback_plan"]


def test_isolate_account_needs_explicit_user():
    result = {
        "case_id": "CHAIN-CASE-06",
        "recommended_action": "isolate_account",
        "attacker_ip": "198.51.100.99",
        "evidence_log_ids": ["LOG-20261104-0613"],
    }
    request = step.build_request(result, target_type="host", target_user="ops")
    assert request.target_user == "ops"
    assert request.target_ip == ""

    unnamed = step.build_request(result, target_type="host")
    assert unnamed.target_user == "", "未显式给出账号时不猜隔离对象"


# ---------------------------------------------------------------------------
# 6. 恒脑平台【受控处置步骤】代码节点
# ---------------------------------------------------------------------------


def _load_platform_node():
    """按路径加载平台代码节点（不是可导入包，只能 run_path）。"""
    import runpy

    return runpy.run_path("design/hengnao_workflows/platform_nodes/code_response_step.py")


class _Input:
    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)


class _Args:
    def __init__(self, **kwargs: Any) -> None:
        self.input = _Input(**kwargs)


def _triage(**overrides: Any) -> dict[str, Any]:
    data = {
        "case_id": "CHAIN-CASE-01",
        "is_malicious": True,
        "attack_type": "SQL_Injection_After_Brute_Force",
        "risk_level": "HIGH",
        "attacker_ip": "198.51.100.23",
        "victim_asset": "web-prod-01",
        "evidence_log_ids": ["LOG-20261027-0126"],
        "attack_chain_summary": "注入绕过认证并导出数据",
        "recommended_action": "block_ip",
        "requires_human_approval": True,
        "unknown_items": "",
    }
    data.update(overrides)
    return data


def test_platform_node_does_not_submit_when_rejected():
    node = _load_platform_node()
    output = node["handler"](
        _Args(triage=_triage(), answer="B", seed=json.dumps({"case_id": "CHAIN-CASE-01", "service_url": "http://x"}))
    )
    receipt = output["result_key"]["receipt"]
    assert receipt["status"] == "REJECTED"
    assert receipt["executed"] is False


@pytest.mark.parametrize("answer", ["A/B", "NOT_APPROVED", ["B", "A"], "", None])
def test_platform_node_requires_an_unambiguous_approval(monkeypatch, answer):
    node = _load_platform_node()
    monkeypatch.setattr(node["urllib"].request, "urlopen", lambda *a, **k: pytest.fail("不应提交"))
    output = node["handler"](
        _Args(triage=_triage(), answer=answer, seed={"case_id": "CHAIN-CASE-01", "service_url": "http://x"})
    )
    assert output["result_key"]["receipt"]["status"] == "REJECTED"


def test_platform_node_none_action_skips_http():
    node = _load_platform_node()
    output = node["handler"](
        _Args(triage=_triage(recommended_action="none"), answer="A", seed=json.dumps({"case_id": "C", "service_url": "http://x"}))
    )
    assert output["result_key"]["receipt"]["status"] == "no_action"


def test_platform_report_includes_pending_receipt(monkeypatch):
    import runpy
    import sys
    from types import SimpleNamespace

    monkeypatch.setitem(sys.modules, "runtime", SimpleNamespace(Args=_Args))
    node = runpy.run_path("design/hengnao_workflows/platform_nodes/code_report.py")
    receipt = {"status": "approval_required", "approval_id": "APR-1", "mock": True}
    output = node["handler"](_Args(input=_triage(), receipt=json.dumps(receipt)))["result_key"]
    assert output["results"] == _triage()
    assert "approval_required（模拟回执）" in output["report"]
    assert "APR-1" in output["report"]


def test_platform_node_passes_server_receipt_through(monkeypatch):
    node = _load_platform_node()
    captured: dict[str, Any] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(
                {"status": "approval_required", "approval_id": "APR-1", "executed": False, "detail": "待审批"}
            ).encode()

    def _urlopen(request, timeout=0):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode())
        return _Response()

    monkeypatch.setattr(node["urllib"].request, "urlopen", _urlopen)
    output = node["handler"](
        _Args(triage=_triage(), answer="A", seed=json.dumps({"case_id": "CHAIN-CASE-01", "service_url": "https://seclog.example"}))
    )
    receipt = output["result_key"]["receipt"]
    assert captured["url"].endswith("/tools/request_response")
    assert captured["body"]["action"] == "block_ip"
    assert captured["body"]["evidence_log_ids"] == ["LOG-20261027-0126"]
    assert receipt["status"] == "approval_required"
    assert receipt["approval_id"] == "APR-1"
    assert receipt["executed"] is False
