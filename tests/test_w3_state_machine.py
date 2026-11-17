"""W3：受控处置状态机（NO_ACTION / EXECUTED / PENDING_APPROVAL）回归。

覆盖任务要求的六类断言：
    1. 决策 none → NO_ACTION，不落盘；
    2. 低危且 auto_execute → EXECUTED，并追加执行审计；
    3. 高危 → PENDING_APPROVAL，不落盘；
    4. 审批单 6 项必填字段校验（approve 缺字段直接拒绝）；
    5. on_timeout: reject 的超时自动拒批；
    6. 审计落盘字段完整性（ts / action / target_type / target / evidence_log_ids / policy_reason）。

状态机跑真实 ``config/response-policy.yaml``（唯一权威枚举，config/README.md 硬规则 1），
只把审计目录经 ``SECLOG_STATE_DIR`` 指向 tmp_path，避免污染 ``data/state/``。
审批单是进程内状态，用例之间用 ``reset_pending()`` 隔离。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from operations.response_executor import (
    BLOCKED,
    BLOCKED_BY_POLICY,
    EXECUTED,
    NO_ACTION,
    PENDING_APPROVAL,
    REJECTED,
    ApprovalError,
    approve,
    enforcement_log_path,
    evaluate_action,
    expire_pending,
    reject,
    reset_cache,
    reset_pending,
)

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = ["LOG-20261117-0001"]
ATTACKER_IP = "198.51.100.23"  # 台账外的攻击源，不命中任何白名单


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """审计目录隔离 + 策略缓存/待审批表复位。"""
    monkeypatch.setenv("SECLOG_STATE_DIR", str(tmp_path / "state"))
    reset_cache()
    reset_pending()
    yield
    reset_pending()
    reset_cache()


def _read_records() -> list:
    path = enforcement_log_path()
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _full_order(action: str, target_ip: str = ATTACKER_IP, case_id: str = "CASE-W3-0001") -> dict:
    """一份字段齐全的审批单（对应 approval.required_fields 的 6 项）。"""
    return {
        "case_id": case_id,
        "action": action,
        "target_ip": target_ip,
        "evidence_log_ids": list(EVIDENCE),
        "expected_effect": "同源 IP 请求归零，业务接口成功率不低于 99%",
        "rollback_plan": "封禁到期自动解除；异常时人工放行并回滚策略",
    }


# ---------------------------------------------------------------------------
# 1. 三条流转
# ---------------------------------------------------------------------------
def test_none_decision_is_no_action_and_writes_nothing():
    """决策 none：仅记录结论，不产生副作用，也不写执行审计。"""
    result = evaluate_action("none", case_id="CASE-W3-0001")

    assert result["status"] == NO_ACTION
    assert result["action"] == "none"
    assert _read_records() == []


def test_low_risk_auto_execute_lands_executed():
    """低危 + auto_execute=true：直接执行并落盘，别名归一化到权威键。"""
    result = evaluate_action(
        "rate_limit_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001"
    )

    assert result["status"] == EXECUTED
    assert result["action"] == "rate_limit"  # 别名受理前归一化
    records = _read_records()
    assert len(records) == 1
    assert records[0]["action"] == "rate_limit"
    assert records[0]["case_id"] == "CASE-W3-0001"
    assert result["record"] == records[0]


def test_high_risk_goes_pending_approval_without_execution_record():
    """高危动作即使网关放行也不能自动执行：转审批且不落盘。"""
    result = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")

    assert result["status"] == PENDING_APPROVAL
    assert result["action"] == "block_ip"
    assert result["approval_id"].startswith("APR-")
    assert _read_records() == []


def test_gate_blocked_action_is_fail_closed():
    """网关拦截（如缺证据）时不进入任何流转，也不落盘。"""
    result = evaluate_action("rate_limit", "web", ATTACKER_IP, "", [], case_id="CASE-W3-0001")

    assert result["status"] == BLOCKED
    assert result["policy_reason"].startswith(BLOCKED_BY_POLICY)
    assert "missing_evidence" in result["policy_reason"]
    assert _read_records() == []


# ---------------------------------------------------------------------------
# 2. 审批必填校验
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "missing_field",
    ["case_id", "action", "target_ip", "evidence_log_ids", "expected_effect", "rollback_plan"],
)
def test_approve_requires_all_six_fields(missing_field):
    """6 项必填字段缺任何一项都拒绝审批，且不产生执行记录。"""
    pending = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")
    order = _full_order("block_ip")
    order.pop(missing_field)

    with pytest.raises(ApprovalError) as excinfo:
        approve(pending["approval_id"], order, approved_by="ops_zhang")

    assert missing_field in str(excinfo.value)
    assert _read_records() == []


def test_approve_with_blank_field_is_rejected():
    """空白字符串等同于缺失，避免"填了空格"就过校验。"""
    pending = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")
    order = _full_order("block_ip")
    order["rollback_plan"] = "   "

    with pytest.raises(ApprovalError) as excinfo:
        approve(pending["approval_id"], order, approved_by="ops_zhang")

    assert "rollback_plan" in str(excinfo.value)
    assert _read_records() == []


def test_approve_without_approver_is_rejected():
    """谁批的必须可追溯：审批人为空直接拒绝，不落盘。"""
    pending = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")

    with pytest.raises(ApprovalError):
        approve(pending["approval_id"], _full_order("block_ip"), approved_by="  ")
    assert _read_records() == []


def test_approve_then_executed_with_approved_by():
    """字段齐全的审批放行：与 EXECUTED 同样落盘，并标注 approved_by 与 approval_id。"""
    pending = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")

    result = approve(pending["approval_id"], _full_order("block_ip"), approved_by="ops_zhang")

    assert result["status"] == EXECUTED
    records = _read_records()
    assert len(records) == 1
    assert records[0]["approved_by"] == "ops_zhang"
    assert records[0]["approval_id"] == pending["approval_id"]
    assert records[0]["policy_reason"] == "ALLOWED"


def test_approve_mismatched_action_is_rejected():
    """审批单动作必须与待审批单一致，防止"批 A 执行 B"。"""
    pending = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")

    with pytest.raises(ApprovalError):
        approve(
            pending["approval_id"],
            _full_order("block_ip_short_term"),
            approved_by="ops_zhang",
        )
    assert _read_records() == []


def test_approved_order_cannot_be_reused():
    """审批单只能结算一次：重复 approve / reject 都被拒绝。"""
    pending = evaluate_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001")
    approve(pending["approval_id"], _full_order("block_ip"), approved_by="ops_zhang")

    with pytest.raises(ApprovalError):
        approve(pending["approval_id"], _full_order("block_ip"), approved_by="ops_zhang")
    with pytest.raises(ApprovalError):
        reject(pending["approval_id"], rejected_by="ops_zhang")
    assert len(_read_records()) == 1


def test_reject_executes_nothing():
    """人工拒批：状态 REJECTED，不产生执行记录。"""
    pending = evaluate_action("isolate_account", "web", ATTACKER_IP, "bad_user", EVIDENCE)

    result = reject(pending["approval_id"], rejected_by="ops_zhang", reason="证据不足")

    assert result["status"] == REJECTED
    assert result["reason"] == "证据不足"
    assert _read_records() == []


# ---------------------------------------------------------------------------
# 3. 超时自动拒批（approval.on_timeout: reject）
# ---------------------------------------------------------------------------
def test_pending_expires_to_rejected_on_timeout():
    """超过有效期未审批：自动转为 REJECTED，不执行、不落盘。"""
    created = datetime(2026, 11, 17, 2, 0, tzinfo=timezone.utc)
    pending = evaluate_action(
        "block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001", now=created
    )

    settled = expire_pending(now=created + timedelta(minutes=31))

    assert [item["approval_id"] for item in settled] == [pending["approval_id"]]
    assert settled[0]["status"] == REJECTED
    assert settled[0]["rejected_by"] == "SYSTEM_TIMEOUT"
    assert settled[0]["reject_reason"].startswith("timeout")
    assert _read_records() == []


def test_expire_before_deadline_keeps_pending():
    """未到期不结算：审批窗口内仍可正常放行。"""
    created = datetime(2026, 11, 17, 2, 0, tzinfo=timezone.utc)
    pending = evaluate_action(
        "block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001", now=created
    )

    assert expire_pending(now=created + timedelta(minutes=5)) == []

    result = approve(
        pending["approval_id"],
        _full_order("block_ip"),
        approved_by="ops_zhang",
        now=created + timedelta(minutes=5),
    )
    assert result["status"] == EXECUTED


def test_late_approve_after_timeout_is_rejected():
    """超时后再审批：先结算为 REJECTED，本次 approve 直接失败且不落盘。"""
    created = datetime(2026, 11, 17, 2, 0, tzinfo=timezone.utc)
    pending = evaluate_action(
        "block_ip", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001", now=created
    )

    with pytest.raises(ApprovalError):
        approve(
            pending["approval_id"],
            _full_order("block_ip"),
            approved_by="ops_zhang",
            now=created + timedelta(minutes=45),
        )

    assert _read_records() == []


# ---------------------------------------------------------------------------
# 4. 审计落盘字段完整性
# ---------------------------------------------------------------------------
def test_executed_record_has_all_required_fields():
    """落盘记录必须含 ts / action / target_type / target / evidence_log_ids / policy_reason。"""
    result = evaluate_action(
        "rate_limit", "web", ATTACKER_IP, "", EVIDENCE, case_id="CASE-W3-0001"
    )
    record = result["record"]

    assert set(record) >= {
        "ts",
        "action",
        "target_type",
        "target",
        "evidence_log_ids",
        "policy_reason",
    }
    assert record["action"] == "rate_limit"
    assert record["target_type"] == "web"
    assert record["target"] == ATTACKER_IP
    assert record["evidence_log_ids"] == EVIDENCE
    assert record["policy_reason"] == "ALLOWED"
    datetime.fromisoformat(record["ts"])  # ts 必须是可解析的 ISO8601

    # 落盘内容与返回值一致，且是合法单行 JSON
    raw = enforcement_log_path().read_text(encoding="utf-8").splitlines()
    assert len(raw) == 1
    assert json.loads(raw[0]) == record


def test_enforcement_log_is_append_only_and_isolated():
    """多次执行按行追加，不覆盖历史；两次执行共享同一份审计文件。"""
    first = evaluate_action("rate_limit", "web", "198.51.100.31", "", ["LOG-1"])
    second = evaluate_action("rate_limit", "host", "198.51.100.32", "", ["LOG-2"])

    records = _read_records()
    assert [r["target"] for r in records] == ["198.51.100.31", "198.51.100.32"]
    assert records[0] == first["record"]
    assert records[1] == second["record"]
