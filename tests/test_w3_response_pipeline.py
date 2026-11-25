"""W3：受控处置全链路 + 端到端管线测试。

覆盖 Issue #30 要求的四类断言：

1. **生命周期**：low/auto_execute 动作自动执行并算出 ``expires_at``；
   到期由 ``sweep_expired_actions`` 转 ``REVOKED``；未到期不动；
2. **策略边界**：白名单 IP / 资产 / 用户、``target_types`` 越界、``forbidden_actions`` 全部拦截，
   且拦截不落执行审计；
3. **API 联调**：``/tools/request_response``（enforced）→ ``/tools/approve_response``
   → ``/tools/response_status`` → ``/tools/sweep_expired`` 一条链走通，
   legacy 模式保持 W2 的「只登记」语义不变；
4. **旁路能力**：无 SMTP 凭据时通知降级进 outbox，不阻断主流程；E2E 脚本主干可加载场景。

测试全部跑真实 ``config/*.yaml``（唯一权威策略源），只把审计目录指向 ``tmp_path``。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from operations import notify_bridge
from operations import response_executor as rx

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = ["LOG-20261125-9001", "LOG-20261125-9002"]
ATTACKER = "198.51.100.23"  # 台账之外的攻击源，不命中任何白名单
CASE = "CASE-W3-UT-01"


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """审计/通知目录隔离 + 策略缓存与待审批表复位 + 清掉 SMTP 凭据。"""
    monkeypatch.setenv("SECLOG_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASS", raising=False)
    rx.reset_cache()
    rx.reset_pending()
    yield
    rx.reset_pending()
    rx.reset_cache()


def _records() -> list[dict]:
    path = rx.enforcement_log_path()
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _full_order(action: str, target_ip: str = ATTACKER) -> dict:
    return {
        "case_id": CASE,
        "action": action,
        "target_ip": target_ip,
        "evidence_log_ids": list(EVIDENCE),
        "expected_effect": "同源恶意请求归零，业务接口成功率不低于 99%",
        "rollback_plan": "到期自动解除；异常时人工放行并回滚策略",
    }


# ---------------------------------------------------------------------------
# 1. 生命周期：执行 → 到期 → 解除
# ---------------------------------------------------------------------------
def test_rate_limit_auto_executes_with_expiry():
    """低危 rate_limit 自动执行，并写入 action_id / executed_at / expires_at。"""
    result = rx.evaluate_action(
        "rate_limit", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.EXECUTED
    assert result["action_id"].startswith("ACT-")
    assert result["expires_at"]

    record = result["record"]
    assert record["event"] == rx.EVENT_EXECUTED
    assert record["expires_at"] == result["expires_at"]
    assert record["max_duration_minutes"] == 30
    executed_at = datetime.fromisoformat(record["executed_at"])
    expires_at = datetime.fromisoformat(record["expires_at"])
    assert expires_at - executed_at == timedelta(minutes=30)


def test_sweep_revokes_expired_action():
    """到期后 sweep 把动作转 REVOKED，并追加一条 revoked 事件（append-only）。"""
    result = rx.evaluate_action(
        "rate_limit", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    action_id = result["action_id"]
    before = len(_records())

    future = datetime.now(timezone.utc) + timedelta(minutes=31)
    swept = rx.sweep_expired_actions(now=future)

    assert [item["action_id"] for item in swept] == [action_id]
    assert swept[0]["lifecycle"] == rx.REVOKED
    assert swept[0]["revoke_reason"] == "expired"

    after = _records()
    assert len(after) == before + 1  # 只追加撤销事件，不改写历史
    assert after[-1]["event"] == rx.EVENT_REVOKED
    assert after[-1]["action_id"] == action_id

    view = {item["action_id"]: item for item in rx.list_actions(now=future)}
    assert view[action_id]["lifecycle"] == rx.REVOKED


def test_sweep_leaves_unexpired_action_untouched():
    """未到期不解除；再 sweep 一次也不会重复写撤销事件。"""
    rx.evaluate_action(
        "rate_limit", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert rx.sweep_expired_actions(now=datetime.now(timezone.utc)) == []
    assert len(_records()) == 1

    future = datetime.now(timezone.utc) + timedelta(minutes=45)
    rx.sweep_expired_actions(now=future)
    assert rx.sweep_expired_actions(now=future) == []  # 幂等：已撤销的不再处理


def test_high_risk_requires_approval_and_writes_nothing():
    """高危动作只进待审批，不落执行审计。"""
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.PENDING_APPROVAL
    assert result["approval_id"].startswith("APR-")
    assert _records() == []


# ---------------------------------------------------------------------------
# 2. 审批单校验
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "missing",
    ["case_id", "action", "target_ip", "evidence_log_ids", "expected_effect", "rollback_plan"],
)
def test_approve_requires_all_six_fields(missing):
    """6 项必填字段缺任何一项都拒绝，且不产生执行记录。"""
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    approval_id = result["approval_id"]
    order = _full_order("block_ip")
    order[missing] = ""
    with pytest.raises(rx.ApprovalError):
        rx.approve(approval_id, order, "ops_zhang")
    assert _records() == []


def test_approve_without_reviewer_is_rejected():
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    with pytest.raises(rx.ApprovalError):
        rx.approve(result["approval_id"], _full_order("block_ip"), "  ")


def test_approve_executes_and_cannot_be_reused():
    """审批通过后落盘执行，同一审批单不能二次使用。"""
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    approval_id = result["approval_id"]
    approved = rx.approve(approval_id, _full_order("block_ip"), "ops_zhang")

    assert approved["status"] == rx.EXECUTED
    assert approved["action_id"].startswith("ACT-")
    record = _records()[-1]
    assert record["approved_by"] == "ops_zhang"
    assert record["approval_id"] == approval_id

    with pytest.raises(rx.ApprovalError):
        rx.approve(approval_id, _full_order("block_ip"), "ops_zhang")


def test_approve_rejects_mismatched_target():
    """审批单目标与待审批单不一致时拒绝（防止批 A 执行 B）。"""
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    with pytest.raises(rx.ApprovalError):
        rx.approve(result["approval_id"], _full_order("block_ip", "203.0.113.9"), "ops_zhang")


def test_reject_writes_no_enforcement_record():
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    rejected = rx.reject(result["approval_id"], "ops_zhang", reason="误报")
    assert rejected["status"] == rx.REJECTED
    assert _records() == []


def test_pending_expires_to_rejected_on_timeout():
    result = rx.evaluate_action(
        "block_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    future = datetime.now(timezone.utc) + timedelta(minutes=31)
    settled = rx.expire_pending(now=future)
    assert [item["approval_id"] for item in settled] == [result["approval_id"]]
    assert settled[0]["rejected_by"] == "SYSTEM_TIMEOUT"


# ---------------------------------------------------------------------------
# 3. 策略边界
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "target_ip,action",
    [
        ("10.0.0.40", "block_ip"),   # 备份主机
        ("10.0.0.40", "rate_limit"),
        ("10.0.0.77", "block_ip"),   # 授权扫描器
        ("127.0.0.1", "rate_limit"),  # 回环
    ],
)
def test_allowlist_ips_blocked(target_ip, action):
    result = rx.evaluate_action(
        action, target_type="web", target_ip=target_ip,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.BLOCKED
    assert result["policy_reason"].startswith(rx.BLOCKED_BY_POLICY)
    assert _records() == []


@pytest.mark.parametrize("action", ["block_ip", "block_ip_short_term"])
def test_allowlist_asset_db_core_blocked(action):
    """核心数据库在资产白名单里，任何封禁都拒绝。"""
    result = rx.evaluate_action(
        action, target_type="database", target_ip="10.0.0.30",
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.BLOCKED
    assert "db-core-01" in result["policy_reason"] or "allowlist" in result["policy_reason"]


@pytest.mark.parametrize("user", ["ops_zhang", "ops_li", "ops"])
def test_allowlist_users_cannot_be_isolated(user):
    """运维账号禁止自动隔离。"""
    result = rx.evaluate_action(
        "isolate_account", target_type="web", target_user=user,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.BLOCKED


def test_block_ip_target_type_host_blocked():
    """block_ip 只允许 web 资产，作用到 host 必须被拒。"""
    result = rx.evaluate_action(
        "block_ip", target_type="host", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.BLOCKED
    assert "target_type_not_allowed" in result["policy_reason"]


def test_block_ip_short_term_allows_host():
    """短时封禁允许 host（CASE-06 的实际诉求），与 block_ip 形成对照。"""
    result = rx.evaluate_action(
        "block_ip_short_term", target_type="host", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.PENDING_APPROVAL


@pytest.mark.parametrize("action", ["delete_data", "shutdown_host", "modify_firewall_rule"])
def test_forbidden_actions_blocked(action):
    result = rx.evaluate_action(
        action, target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["status"] == rx.BLOCKED
    assert "forbidden_action" in result["policy_reason"]


def test_action_alias_is_normalized():
    """知识卡里的 rate_limit_ip 必须归一化到 rate_limit 再判定。"""
    result = rx.evaluate_action(
        "rate_limit_ip", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    assert result["action"] == "rate_limit"
    assert result["status"] == rx.EXECUTED


def test_missing_evidence_is_blocked():
    result = rx.evaluate_action(
        "rate_limit", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=[], case_id=CASE,
    )
    assert result["status"] == rx.BLOCKED
    assert "missing_evidence" in result["policy_reason"]


# ---------------------------------------------------------------------------
# 4. 后置核验与通知旁路
# ---------------------------------------------------------------------------
def test_post_check_reports_effect_and_business_impact():
    """目标无异常 → 攻击已停止；非目标无 5xx → 未误伤。"""
    result = rx.evaluate_action(
        "rate_limit", target_type="web", target_ip=ATTACKER,
        evidence_log_ids=EVIDENCE, case_id=CASE,
    )
    logs = [
        {"src_ip": ATTACKER, "dest_ip": "10.0.0.15", "status_code": 200},
        {"src_ip": "10.0.0.66", "dest_ip": "10.0.0.15", "status_code": 200},
    ]
    check = rx.run_post_check(result["action_id"], logs)
    assert check["effect_verification"]["passed"] is True
    assert check["business_impact"]["passed"] is True

    bad = [
        {"src_ip": ATTACKER, "dest_ip": "10.0.0.15", "status_code": 500},
        {"src_ip": "10.0.0.66", "dest_ip": "10.0.0.15", "status_code": 502},
    ]
    check = rx.run_post_check(result["action_id"], bad)
    assert check["effect_verification"]["passed"] is False
    assert check["business_impact"]["passed"] is False


def test_post_check_unknown_action_raises():
    with pytest.raises(rx.ApprovalError):
        rx.run_post_check("ACT-NOT-EXIST", [])


def test_notify_falls_back_to_outbox_without_smtp():
    """没有 SMTP 凭据时不试探网络，直接进 outbox 队列。"""
    result = notify_bridge.notify_response_event("executed", {"case_id": CASE, "action": "rate_limit"})
    assert result["status"] == "queued"

    path = notify_bridge.outbox_path()
    assert path.exists()
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines[-1]["event"] == "executed"
    assert lines[-1]["reason"] == "smtp_not_configured"


# ---------------------------------------------------------------------------
# 5. API 联调（enforced / legacy 两种模式）
# ---------------------------------------------------------------------------
@pytest.fixture()
def enforced_api(monkeypatch):
    from api.evidence_check import registry

    monkeypatch.setenv("SECLOG_RESPONSE_MODE", "enforced")
    registry.register(EVIDENCE, case_id=CASE, query_params={"data_source": "dataset_replay"})
    yield
    monkeypatch.setenv("SECLOG_RESPONSE_MODE", "legacy")


def _client():
    from fastapi.testclient import TestClient

    from api.app import app

    return TestClient(app)


def test_api_request_response_enforced_returns_approval(enforced_api):
    with _client() as client:
        resp = client.post(
            "/tools/request_response",
            json={
                "case_id": CASE,
                "action": "block_ip",
                "target_ip": ATTACKER,
                "evidence_log_ids": EVIDENCE,
                "reason": "攻击链成立，申请长效封禁",
                "asset_id": "web-prod-01",
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approval_required"
    assert body["approval_id"].startswith("APR-")
    assert body["executed"] is False


def test_api_approve_status_and_sweep(enforced_api):
    with _client() as client:
        submitted = client.post(
            "/tools/request_response",
            json={
                "case_id": CASE,
                "action": "block_ip_short_term",
                "target_ip": ATTACKER,
                "evidence_log_ids": EVIDENCE,
                "reason": "短时封禁以阻断持续注入",
                "asset_id": "web-prod-01",
            },
        ).json()
        approval_id = submitted["approval_id"]

        approved = client.post(
            "/tools/approve_response",
            json={
                "approval_id": approval_id,
                "decision": "approve",
                "reviewer": "ops_zhang",
                "reason": "确认攻击成立",
                "expected_effect": "攻击源请求被阻断",
                "rollback_plan": "到期自动解除",
            },
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "executed"
        action_id = approved.json()["action_id"]

        status = client.get("/tools/response_status").json()
        assert status["mode"] == "enforced"
        assert any(item["action_id"] == action_id for item in status["active"])

        # 时间快进只能通过执行器做，API 的 sweep 按真实时间扫描
        future = datetime.now(timezone.utc) + timedelta(minutes=241)
        rx.sweep_expired_actions(now=future)

        status = client.get("/tools/response_status").json()
        assert any(item["action_id"] == action_id for item in status["revoked"])
        assert status["total_revoked"] >= 1

        swept = client.post("/tools/sweep_expired").json()
        assert swept["count"] == 0  # 已经撤过，幂等


def test_api_reject_flow(enforced_api):
    with _client() as client:
        submitted = client.post(
            "/tools/request_response",
            json={
                "case_id": CASE,
                "action": "block_ip",
                "target_ip": ATTACKER,
                "evidence_log_ids": EVIDENCE,
                "reason": "疑似注入，申请封禁待确认",
                "asset_id": "web-prod-01",
            },
        ).json()
        rejected = client.post(
            "/tools/approve_response",
            json={
                "approval_id": submitted["approval_id"],
                "decision": "reject",
                "reviewer": "ops_zhang",
                "reason": "证据不足，先观察",
            },
        )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


def test_api_approve_missing_effect_is_422(enforced_api):
    with _client() as client:
        submitted = client.post(
            "/tools/request_response",
            json={
                "case_id": CASE,
                "action": "block_ip",
                "target_ip": ATTACKER,
                "evidence_log_ids": EVIDENCE,
                "reason": "申请封禁以阻断注入",
                "asset_id": "web-prod-01",
            },
        ).json()
        resp = client.post(
            "/tools/approve_response",
            json={
                "approval_id": submitted["approval_id"],
                "decision": "approve",
                "reviewer": "ops_zhang",
            },
        )
    assert resp.status_code == 422


def test_api_unknown_approval_returns_404(enforced_api):
    with _client() as client:
        resp = client.post(
            "/tools/approve_response",
            json={"approval_id": "APR-NOT-EXIST", "decision": "approve", "reviewer": "ops_zhang"},
        )
    assert resp.status_code == 404


def test_api_legacy_mode_keeps_old_semantics(monkeypatch):
    """默认 legacy 模式：只登记待审批，executed 恒 false，既有 W2 行为不变。"""
    from api.evidence_check import registry

    monkeypatch.setenv("SECLOG_RESPONSE_MODE", "legacy")
    registry.register(EVIDENCE, case_id=CASE)
    with _client() as client:
        resp = client.post(
            "/tools/request_response",
            json={
                "case_id": CASE,
                "action": "block_ip",
                "target_ip": ATTACKER,
                "evidence_log_ids": EVIDENCE,
                "reason": "legacy 模式回归：只登记不执行",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "approval_required"
        assert body["executed"] is False
        assert body["mock"] is True

        # legacy 模式下台账接口应明确报"未启用"，而不是返回空列表
        status_resp = client.get("/tools/response_status")
    assert status_resp.status_code == 409


def test_api_enforced_mode_rejects_forged_evidence(enforced_api):
    with _client() as client:
        resp = client.post(
            "/tools/request_response",
            json={
                "case_id": CASE,
                "action": "block_ip",
                "target_ip": ATTACKER,
                "evidence_log_ids": ["LOG-FAKE-0001"],
                "reason": "使用伪造证据尝试绕过校验",
                "asset_id": "web-prod-01",
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert "LOG-FAKE-0001" in body["rejected_evidence_ids"]


# ---------------------------------------------------------------------------
# 6. E2E 主干烟雾
# ---------------------------------------------------------------------------
def test_e2e_pipeline_loads_ten_cases_and_attributes_clues():
    """主干函数冒烟：10 组 200 条日志可加载，线索能按 log_id 归属到场景。"""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_e2e_pipeline", REPO / "scripts" / "run_e2e_pipeline.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    cases = module.load_scenarios(REPO / "data" / "full_chain_logs")
    assert len(cases) == 10
    assert sum(len(case["logs"]) for case in cases) == 200
    assert all(case["truth"] for case in cases)

    clues_path = REPO / "data" / "clues" / "w3_clues_baseline.json"
    if clues_path.exists():
        clues = json.loads(clues_path.read_text(encoding="utf-8"))
        mapping = module.attribute_clues(cases, clues)
        assert set(mapping) == {case["case_id"] for case in cases}
        # 恶意场景必须有线索，良性场景不得出现未降级的 high/critical
        malicious = {"CHAIN-CASE-01", "CHAIN-CASE-02", "CHAIN-CASE-04", "CHAIN-CASE-05",
                     "CHAIN-CASE-06", "CHAIN-CASE-07", "CHAIN-CASE-08"}
        for case_id in malicious:
            assert mapping[case_id], f"{case_id} 应至少产出一条线索"
        for case_id in {"CHAIN-CASE-03", "CHAIN-CASE-09", "CHAIN-CASE-10"}:
            for clue in mapping[case_id]:
                assert clue["risk_level"] not in {"high", "critical"}, (
                    f"{case_id} 是良性场景，出现了未降级的 {clue['risk_level']} 线索"
                )
