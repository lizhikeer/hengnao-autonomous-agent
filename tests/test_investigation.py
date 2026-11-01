"""多轮自主调查骨架测试：验证"下一步动作取决于上一轮返回"，而不是固定串行。"""

from __future__ import annotations

from typing import Any

import pytest

from ai_engine.investigation import InvestigationSession


@pytest.mark.parametrize('stage,max_rounds', [
    ('brute_force', 1), ('brute_force', 8), ('benign', 1), (None, 8),
])
def test_partial_investigation_does_not_declare_safe(stage, max_rounds):
    row = _log('LOG-20261027-0001', stage=stage, user='admin')
    session = InvestigationSession(
        case_id='CASE-PARTIAL', seed_trace_id='CHAIN-ATTACK-01',
        max_rounds=max_rounds, tools=_fake_tools([[row]]),
    )
    final = session.run()
    assert final.attack_type == 'insufficient_evidence'
    assert final.requires_human_approval is True
    assert final.recommended_action == 'none'
    assert final.evidence_log_ids == [row['log_id']]
    assert final.unknown_items
    assert '判定为无恶意行为' not in final.attack_chain_summary
    assert 'request_response' not in [call.tool for call in session.calls]


def _log(log_id: str, *, stage: str, src: str = "198.51.100.23", asset: str = "web-prod-01", user=None):
    return {
        "log_id": log_id,
        "trace_id": "CHAIN-ATTACK-01",
        "timestamp": "2026-10-27T14:20:05Z",
        "log_source": "nginx_access",
        "src_ip": src,
        "dest_ip": "10.0.0.15",
        "asset_id": asset,
        "user": user,
        "action_or_method": "POST",
        "uri_or_target": "/admin/login.php",
        "payload_summary": "x",
        "status_code": 200,
        "user_agent": "sqlmap/1.7.2",
        "attack_stage_hint": stage,
    }


def _fake_tools(query_results: list[list[dict[str, Any]]]):
    """构造一个按调用顺序返回预设结果的 query_logs，其它工具返回固定值。"""
    state = {"i": 0}

    def query_logs(_args):
        idx = min(state["i"], len(query_results) - 1)
        state["i"] += 1
        items = query_results[idx]
        return {"meta": {"total": len(items), "mock": True}, "items": items}

    def get_context(_args):
        return {
            "meta": {"total": 2, "mock": True},
            "user_profile": {"user": "admin", "failed_logins_24h": 0},
            "asset_context": {"asset_id": "web-prod-01", "importance": "HIGH"},
        }

    def search_knowledge(_args):
        return {"meta": {"total": 1, "mock": True}, "items": [{"card_id": "KB-1"}]}

    def request_response(_args):
        return {"status": "approval_required", "approval_id": "APPR-TEST-0001", "executed": False}

    return {
        "query_logs": query_logs,
        "get_context": get_context,
        "search_knowledge": search_knowledge,
        "request_response": request_response,
    }


# ---------------------------------------------------------------------------
# 1. 正常攻击链：走完 日志 → 基线 → 知识 → 处置
# ---------------------------------------------------------------------------


def test_full_chain_produces_malicious_conclusion():
    chain = [
        _log("LOG-20261027-0001", stage="brute_force", user="admin"),
        _log("LOG-20261027-0008", stage="exploitation"),
        _log("LOG-20261027-0022", stage="c2_callback", src="10.0.0.15"),
    ]
    session = InvestigationSession(
        case_id="EVAL-CHAIN-001",
        seed_trace_id="CHAIN-ATTACK-01",
        seed_asset_id="web-prod-01",
        tools=_fake_tools([chain]),
    )
    final = session.run()

    tools_called = [c.tool for c in session.calls]
    assert tools_called == ["query_logs", "get_context", "search_knowledge"]
    assert final.is_malicious is True
    assert final.attack_type.startswith("C2_Callback_After_SQL_Injection_After_Brute_Force")
    assert final.risk_level in {"HIGH", "CRITICAL"}
    assert final.requires_human_approval is True
    assert final.recommended_action == "block_ip"
    assert "未提交处置申请" in final.unknown_items
    assert "request_response" not in tools_called  # 审批之前不能提交申请


# ---------------------------------------------------------------------------
# 2. 零结果：放宽一次，仍空则判"证据不足"，绝不判"安全"
# ---------------------------------------------------------------------------


def test_zero_result_broadens_then_declares_insufficient():
    session = InvestigationSession(
        case_id="CASE-EMPTY",
        seed_src_ip="203.0.113.99",
        tools=_fake_tools([[], []]),
    )
    final = session.run()

    q = [c for c in session.calls if c.tool == "query_logs"]
    assert len(q) == 2, "零结果应先放宽时间窗重查一次"
    assert q[1].args.get("time_window") == "24h"
    assert final.attack_type == "insufficient_evidence"
    assert final.is_malicious is False
    assert final.requires_human_approval is True
    assert final.evidence_log_ids == []
    assert "零结果" in final.unknown_items or "未取得" in final.unknown_items


# ---------------------------------------------------------------------------
# 3. 只有良性流量：不请求处置，判为无恶意
# ---------------------------------------------------------------------------


def test_benign_only_traffic_is_not_malicious_and_no_response():
    benign = [_log("LOG-20261027-0100", stage="benign", src="203.0.113.7", user="ops-wang")]
    session = InvestigationSession(
        case_id="CASE-BENIGN",
        seed_src_ip="203.0.113.7",
        tools=_fake_tools([benign]),
    )
    final = session.run()

    assert "request_response" not in [c.tool for c in session.calls]
    assert final.is_malicious is False
    assert final.attack_type == "none"
    assert final.recommended_action == "none"


# ---------------------------------------------------------------------------
# 4. 决策随返回变化：同一会话在有无"利用阶段"时走不同分支
# ---------------------------------------------------------------------------


def test_decision_depends_on_tool_result():
    brute_only = [_log("LOG-20261027-0001", stage="brute_force", user="admin")]
    s1 = InvestigationSession(
        case_id="CASE-BRUTE", seed_trace_id="CHAIN-ATTACK-01", tools=_fake_tools([brute_only])
    )
    s1.run()
    tools1 = [c.tool for c in s1.calls]

    with_exploit = [
        _log("LOG-20261027-0001", stage="brute_force", user="admin"),
        _log("LOG-20261027-0008", stage="exploitation"),
    ]
    s2 = InvestigationSession(
        case_id="CASE-EXPLOIT", seed_trace_id="CHAIN-ATTACK-01", tools=_fake_tools([with_exploit])
    )
    s2.run()
    tools2 = [c.tool for c in s2.calls]

    assert "search_knowledge" not in tools1, "只有爆破阶段时不应去检索利用类知识卡"
    assert "search_knowledge" in tools2, "出现利用阶段后才应检索处置知识"
    assert tools1 != tools2


# ---------------------------------------------------------------------------
# 5. 证据只能来自工具返回，不得凭空生成
# ---------------------------------------------------------------------------


def test_evidence_ids_are_subset_of_tool_output():
    chain = [
        _log("LOG-20261027-0001", stage="brute_force", user="admin"),
        _log("LOG-20261027-0008", stage="exploitation"),
    ]
    session = InvestigationSession(
        case_id="CASE-EVID", seed_trace_id="CHAIN-ATTACK-01", tools=_fake_tools([chain])
    )
    final = session.run()
    returned = {log["log_id"] for log in session.logs}
    assert set(final.evidence_log_ids) <= returned
    assert final.attacker_ip in {log["src_ip"] for log in session.logs}


# ---------------------------------------------------------------------------
# 6. 轮次上限与无新证据收敛
# ---------------------------------------------------------------------------


def test_round_cap_and_no_new_evidence_stop():
    session = InvestigationSession(
        case_id="CASE-CAP",
        seed_trace_id="CHAIN-ATTACK-01",
        tools=_fake_tools([[]]),
        max_rounds=2,
    )
    session.run()
    assert session.round <= 2


def test_no_seed_means_no_call():
    session = InvestigationSession(case_id="CASE-NOSEED", tools=_fake_tools([[]]))
    final = session.run()
    assert session.calls == []
    assert final.attack_type == "insufficient_evidence"
