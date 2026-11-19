"""Week 3 回归：V1 三类调查盲区、分类对齐与 RAG 驱动的调查步骤。

覆盖 Issue #32 的验收点：

* ``CHAIN-CASE-06``：同源多账号连续失败 + 后续登录成功 + 关联内网异常外连，不得弃权；
* ``CHAIN-CASE-08``：Zeek 无 HTTP payload 时，用目的地址/周期性/连接模式/字节量共同定性；
* ``CHAIN-CASE-10``：低频输错 + 同源登录成功 + 后续业务，判 ``none``；
* ``CASE-02/04/05/09``：分类与证据缺口对齐七类口径，CASE-09 正常判定不退化；
* 知识卡的 ``investigation_steps`` 驱动补查、``error_revision_note`` 触发复查；
* ``never_exempt`` 按窗口配置生效，禁止豁免行为照常告警并保留证据。

所有断言只看**行为事实与结论**，不读取 ``*_truth.json``；真值只用于评测脚本。
"""

from __future__ import annotations

from typing import Any

import pytest

from ai_engine.investigation import InvestigationSession

REPLAY_CASES = [
    "CHAIN-CASE-01",
    "CHAIN-CASE-02",
    "CHAIN-CASE-03",
    "CHAIN-CASE-04",
    "CHAIN-CASE-05",
    "CHAIN-CASE-06",
    "CHAIN-CASE-07",
    "CHAIN-CASE-08",
    "CHAIN-CASE-09",
    "CHAIN-CASE-10",
]


@pytest.fixture()
def replay(monkeypatch):
    """数据集回放 + 词面降级检索：本机没有 BGE/Qdrant 也能验证 RAG 流程。"""
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "dataset_replay")
    monkeypatch.setenv("SECLOG_SEARCH_MODE", "lexical_fallback")
    from api import app as api_app

    api_app.reset_source_cache()
    yield
    api_app.reset_source_cache()


def _run(case: str) -> tuple[InvestigationSession, Any]:
    session = InvestigationSession(case_id=case, seed_trace_id=case)
    result = session.run()
    return session, result


# ---------------------------------------------------------------------------
# 1. 三类盲区
# ---------------------------------------------------------------------------


def test_case06_multi_account_bruteforce_is_not_abstained(replay):
    """同源多账号连续失败不得因"账号不唯一"弃权。"""
    session, result = _run("CHAIN-CASE-06")

    assert result.attack_type != "insufficient_evidence"
    assert result.is_malicious is True
    assert "Brute_Force" in result.attack_type
    assert result.risk_level == "HIGH"

    facts = session._behavior_facts()
    reasons = [item["rule"] for item in facts["auth"].brute_reasons]
    assert "multi_account_sequential_failure" in reasons
    assert facts["auth"].distinct_users >= 3
    # 失败之后同源拿到会话 → 判定失陷
    assert facts["auth"].compromise is True
    # 失陷后的内网异常行为（跳板机对外非常规端口连接）必须进证据
    assert "LOG-20261104-0617" in result.evidence_log_ids
    assert "LOG-20261104-0613" in result.evidence_log_ids


def test_case06_host_asset_uses_short_term_block(replay):
    """host 资产不允许长效 block_ip（策略 target_types 仅 web）。"""
    _, result = _run("CHAIN-CASE-06")

    assert result.victim_asset == "nas-host-01"
    assert result.recommended_action == "block_ip_short_term"
    assert result.requires_human_approval is True


def test_case08_payloadless_c2_is_detected_by_corroborating_signals(replay):
    """无 HTTP payload 的外连：靠目的地址、周期性、连接状态与字节量共同定性。"""
    session, result = _run("CHAIN-CASE-08")

    assert result.is_malicious is True
    assert "C2_Exfiltration" in result.attack_type
    assert result.risk_level == "HIGH"
    # 攻击方是外连目的地址，而不是"未知"
    assert result.attacker_ip == "91.219.236.7"

    facts = session._behavior_facts()
    group = next(group for group in facts["outbound"] if group.dest_ip == "91.219.236.7")
    assert group.corroborated is True
    assert group.signals["periodic"] is True
    assert group.signals["long_lived"] is True
    assert group.signals["outbound_upload"] is True
    for log_id in ("LOG-20261105-0801", "LOG-20261105-0803", "LOG-20261105-0808", "LOG-20261105-0809"):
        assert log_id in result.evidence_log_ids


def test_case08_single_connection_is_not_enough(replay):
    """单次外连即使端口可疑也不能定性：CASE-06 的那次外连只有 1 条连接。"""
    session, _ = _run("CHAIN-CASE-06")
    group = next(
        group for group in session._behavior_facts()["outbound"] if group.dest_ip == "45.77.128.203"
    )

    assert group.signals["connections"] == 1
    assert group.corroborated is False
    assert "C2_Exfiltration" not in _run("CHAIN-CASE-06")[1].attack_type


def test_case10_low_frequency_retry_is_normal(replay):
    """低频输错 + 同源登录成功 + 后续业务 → none，而不是 insufficient_evidence。"""
    session, result = _run("CHAIN-CASE-10")

    assert result.attack_type == "none"
    assert result.is_malicious is False
    assert result.risk_level == "LOW"
    assert result.recommended_action == "none"
    assert result.requires_human_approval is False
    assert result.attacker_ip == "10.0.0.52"

    facts = session._behavior_facts()
    assert facts["auth"].attempts == 2
    assert facts["auth"].benign_retry is True
    assert facts["benign_pattern"]["established"] is True
    # 失败记录、成功登录与后续业务请求都在证据里
    for log_id in ("LOG-20261106-1001", "LOG-20261106-1002", "LOG-20261106-1005", "LOG-20261106-1007"):
        assert log_id in result.evidence_log_ids


def test_case10_slow_cadence_is_human_not_scripted(replay):
    """节奏是"人"还是"脚本"，由失败间隔决定，不看失败次数。"""
    session, _ = _run("CHAIN-CASE-10")
    auth = session._behavior_facts()["auth"]

    assert auth.median_interval is not None and auth.median_interval >= 20


# ---------------------------------------------------------------------------
# 2. 分类对齐与 CASE-09 不退化
# ---------------------------------------------------------------------------


def test_case02_upload_and_c2_without_false_traversal(replay):
    """cmd= 参数里的 /etc/passwd 是 webshell 命令，不应把上传混成目录遍历。"""
    _, result = _run("CHAIN-CASE-02")

    assert "Malicious_Upload" in result.attack_type
    assert "C2_Exfiltration" in result.attack_type
    assert "Path_Traversal_Privilege" not in result.attack_type
    assert result.attacker_ip == "203.0.113.45"


def test_case04_session_reuse_keeps_hijack_evidence(replay):
    """会话被异地复用属于影响迹象，必须进证据并抬高风险。"""
    session, result = _run("CHAIN-CASE-04")

    assert "XSS" in result.attack_type
    assert result.risk_level == "HIGH"
    sessions = session._behavior_facts()["sessions"]
    assert sessions and sessions[0]["reused_src"] == "198.51.100.61"
    # 被投毒页面的访问与被劫持后的操作都要在证据里
    assert "LOG-20261103-0407" in result.evidence_log_ids
    assert "LOG-20261103-0409" in result.evidence_log_ids


def test_case05_parameter_enumeration_counts_as_traversal(replay):
    """同一来源按递增编号批量读取他人订单 = 越权读取。"""
    session, result = _run("CHAIN-CASE-05")

    assert "Path_Traversal_Privilege" in result.attack_type
    enumerations = session._behavior_facts()["enumerations"]
    assert enumerations and enumerations[0]["parameter"] == "user_id"
    for log_id in ("LOG-20261103-0506", "LOG-20261103-0507"):
        assert log_id in result.evidence_log_ids


def test_case09_authorized_scan_still_normal(replay):
    """CASE-09 的授权扫描判定不能被本轮改动带偏。"""
    session, result = _run("CHAIN-CASE-09")

    assert result.is_malicious is False
    assert result.attack_type == "none"
    assert result.attacker_ip == "10.0.0.77"
    assert session.findings["authorization"]["authorized"] is True
    assert session.findings["authorization"]["evidence"]["never_exempt_hits"] == []


def test_never_exempt_blocks_window_exemption():
    """窗口内出现 never_exempt 行为时，窗口不能把整批行为洗成正常。"""
    logs = [
        {
            "log_id": "LOG-20261110-0001",
            "trace_id": "SCENE-NE",
            "timestamp": "2026-11-09T18:10:00Z",  # 周二 02:10 CST，落在维护窗口内
            "log_source": "nginx_access",
            "src_ip": "10.0.0.66",
            "dest_ip": "10.0.0.15",
            "asset_id": "web-prod-01",
            "user": None,
            "action_or_method": "GET",
            "uri_or_target": "/admin/login.php?username=admin&password=1'%20AND%20SLEEP(5)--",
            "payload_summary": "",
            "status_code": 200,
            "bytes_out": 512,
            "user_agent": "Mozilla/5.0",
            "attack_stage_hint": "benign",
        }
    ]
    asset = {
        "asset_id": "web-prod-01",
        "role": "web",
        "importance": "HIGH",
        "maintenance_windows": [
            {
                "asset_id": "web-prod-01",
                "days": ["tue"],
                "start": "02:00",
                "end": "03:30",
                "allowed_actions": ["deploy", "backup", "restart"],
                "never_exempt": ["sql_injection", "malicious_upload"],
            }
        ],
        "in_maintenance_window": True,
    }
    session = InvestigationSession(
        case_id="CASE-NE",
        seed_trace_id="SCENE-NE",
        tools={
            "query_logs": lambda _args: {"meta": {"total": len(logs), "data_source": "fake"}, "items": logs},
            "get_context": lambda _args: {"meta": {"total": 2}, "user_profile": None, "asset_context": asset},
            "search_knowledge": lambda _args: {"meta": {"total": 0}, "items": []},
            "request_response": lambda _args: {"status": "approval_required"},
        },
    )
    result = session.run()

    # 注入行为本身已经成立，窗口不参与定性
    assert result.is_malicious is True
    assert "SQL_Injection" in result.attack_type
    # 窗口内的这条日志仍保留在证据里，且授权核对记录下 never_exempt 命中
    assert logs[0]["log_id"] in result.evidence_log_ids
    decision = session.findings["authorization"]
    assert decision["authorized"] is False
    assert decision["evidence"]["never_exempt_hits"]


# ---------------------------------------------------------------------------
# 3. RAG：知识卡驱动补查与错题复查
# ---------------------------------------------------------------------------


def test_knowledge_is_queried_before_conclusion_with_case_isolation(replay):
    """所有案例在拿到初始日志、收到知识之后再补查，最后才形成结论。"""
    for case in REPLAY_CASES:
        session, _ = _run(case)
        calls = [call for call in session.calls if call.tool == "search_knowledge"]
        assert calls, f"{case} 未在结论前检索知识"
        assert calls[0].args.get("case_id") == case
        tools = [call.tool for call in session.calls]
        first_logs = tools.index("query_logs")
        knowledge_at = tools.index("search_knowledge")
        assert knowledge_at > first_logs, "必须先拿到日志再检索知识"
        # 知识卡驱动的补查必须发生在检索之后（否则就没有可依据的调查步骤）
        supplements = [index for index, call in enumerate(session.calls) if call.triggered_by]
        assert all(index > knowledge_at for index in supplements)


def test_card_investigation_steps_trigger_supplementary_queries(replay):
    """轨迹要能看出"哪张卡的第几步"触发了"补查哪个日志源"。"""
    session, _ = _run("CHAIN-CASE-06")
    supplements = session.card_triggered_queries

    assert supplements, "知识卡的调查步骤没有驱动任何补查"
    first = supplements[0]
    assert first["card_id"]
    assert first["step_index"] >= 1
    assert first["step"]
    assert first["log_source"] in {
        "nginx_access",
        "auth_log",
        "zeek_conn",
        "zeek_http",
        "zeek_dns",
    }
    # 补查必须真的发出了带 log_source 的查询
    matching = [
        call
        for call in session.calls
        if call.tool == "query_logs" and call.args.get("log_source") == first["log_source"]
    ]
    assert matching, "轨迹记录了补查，但没有对应的工具调用"
    assert matching[0].triggered_by["card_id"] == first["card_id"]


def test_card_steps_come_from_declared_log_sources(replay):
    """补查来源必须出现在卡片声明的范围内，不能凭空指定。"""
    session, _ = _run("CHAIN-CASE-08")
    for item in session.card_triggered_queries:
        declared = item.get("declared_log_sources") or []
        if declared:
            assert item["log_source"] in declared


def test_error_revision_note_is_applied_as_recheck(replay):
    """错题卡的 error_revision_note 要变成一次可核验的复查，而不是只展示文本。"""
    session, _ = _run("CHAIN-CASE-10")
    checks = session.findings.get("revision_checks") or []

    assert checks, "错题提示没有触发复查"
    login_checks = [item for item in checks if item["check"] == "login_retry_pattern"]
    assert login_checks, "低频输错场景应命中登录重试复查"
    assert login_checks[0]["outcome"] == "pattern_confirmed_benign"
    assert login_checks[0]["card_id"]


def test_retrieval_states_are_distinguishable(replay):
    """检索失败 / 零命中 / 降级三种状态必须能分开识别。"""
    from ai_engine.investigation import default_tools

    # 降级：lexical_fallback 返回结果且 meta.degraded=True
    session, _ = _run("CHAIN-CASE-06")
    assert session.retrieval_state == "degraded"
    assert session.retrieval_meta["degraded"] is True
    assert session.retrieval_meta["retrieval_mode"] == "lexical_fallback"

    # 零命中：检索成功但没有匹配卡片
    session = InvestigationSession(
        case_id="CHAIN-CASE-06",
        seed_trace_id="CHAIN-CASE-06",
        tools={
            **default_tools(),
            "search_knowledge": lambda _args: {
                "meta": {
                    "total": 0,
                    "data_source": "hybrid_search",
                    "mock": False,
                    "degraded": False,
                    "retrieval_mode": "hybrid",
                    "notes": ["检索未命中任何卡片"],
                },
                "items": [],
            },
        },
    )
    session.run()
    assert session.retrieval_state == "zero_hit"

    # 失败：检索调用报错，必须与"零命中"区分
    session = InvestigationSession(
        case_id="CHAIN-CASE-06",
        seed_trace_id="CHAIN-CASE-06",
        tools={
            **default_tools(),
            "search_knowledge": lambda _args: {"code": "backend_unavailable", "message": "BGE 模型缺失"},
        },
    )
    result = session.run()
    assert session.retrieval_state == "failed"
    assert "知识检索调用失败" in result.unknown_items
    assert "零命中" not in result.unknown_items


def test_investigation_never_submits_response(replay):
    """调查节点保持只读：任何案例都不得调用处置工具。"""
    for case in REPLAY_CASES:
        session, _ = _run(case)
        assert "request_response" not in [call.tool for call in session.calls]
        assert not session.findings.get("response")
