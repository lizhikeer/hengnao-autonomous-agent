"""HTTP 接口测试：五个能力项的正常路径、边界、以及"零结果 / 参数错误 / 后端失败"三态区分。"""

from __future__ import annotations

import importlib


def _ids(resp):
    return [i["log_id"] for i in resp.json()["items"]]


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "seclog-tool-service"
    assert body["mock_mode"] is True


# ---------------------------------------------------------------------------
# /tools/query_logs
# ---------------------------------------------------------------------------


def test_query_logs_by_trace_id_returns_chain(client):
    r = client.post("/tools/query_logs", json={"case_id": "C1", "trace_id": "CHAIN-ATTACK-01"})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["total"] == 4
    assert body["meta"]["mock"] is True
    assert body["meta"]["data_source"] == "mock"
    assert body["meta"]["backend_available"] is False
    assert len(body["items"]) == 4
    # 攻击链应覆盖三个阶段 + 一条外连
    stages = {i["attack_stage_hint"] for i in body["items"]}
    assert {"brute_force", "exploitation", "c2_callback"} <= stages


def test_query_logs_filters_by_log_source(client):
    r = client.post(
        "/tools/query_logs",
        json={"trace_id": "CHAIN-ATTACK-01", "log_source": "auth_log"},
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert items and all(i["log_source"] == "auth_log" for i in items)


def test_query_logs_zero_result_is_200_not_error(client):
    r = client.post("/tools/query_logs", json={"src_ip": "203.0.113.99"})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["total"] == 0
    assert body["items"] == []


def test_empty_body_probe_returns_200(client):
    """恒脑平台「API 工具调试」只发 URL、不带 body（实测）。

    这种连通性探测必须返回 200，否则能力项永远无法通过平台调试、在工作流里被置灰。
    响应里明确标注 probe=true，并声明未执行任何查询。
    """
    r = client.post("/tools/query_logs")  # 无 body
    assert r.status_code == 200
    body = r.json()
    assert body["probe"] is True
    assert body["mock"] is True
    assert "未执行任何查询" in body["message"]


def test_empty_body_probe_applies_to_all_tool_endpoints(client):
    for path in (
        "/tools/query_logs",
        "/tools/get_context",
        "/tools/search_knowledge",
        "/tools/request_response",
    ):
        r = client.post(path)
        assert r.status_code == 200, path
        assert r.json()["probe"] is True, path


def test_empty_json_object_is_not_treated_as_probe(client):
    """空 JSON `{}` 是真实调用（参数不全），应当走业务校验而不是探测兜底。"""
    r = client.post("/tools/query_logs", json={})
    assert r.status_code == 422
    assert r.json()["code"] == "invalid_params"


def test_query_logs_limit_truncates_but_reports_total(client):
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-ATTACK-01", "limit": 2})
    body = r.json()
    assert len(body["items"]) == 2
    assert body["meta"]["total"] == 4  # total 是分页前总数


def test_query_logs_rejects_no_filter(client):
    r = client.post("/tools/query_logs", json={})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "invalid_params"
    assert "过滤条件" in body["message"]


def test_query_logs_limit_out_of_range(client):
    assert client.post("/tools/query_logs", json={"trace_id": "X", "limit": 0}).status_code == 422
    assert client.post("/tools/query_logs", json={"trace_id": "X", "limit": 201}).status_code == 422


def test_query_logs_bad_time_window_format(client):
    r = client.post("/tools/query_logs", json={"trace_id": "X", "time_window": "9x"})
    assert r.status_code == 422
    assert r.json()["code"] == "invalid_params"


def test_query_logs_conflicting_time_window(client):
    r = client.post(
        "/tools/query_logs",
        json={"trace_id": "X", "time_window": "1h", "time_window_minutes": 30},
    )
    assert r.status_code == 422
    assert r.json()["code"] == "invalid_params"
    assert "冲突" in r.json()["message"]


def test_query_logs_time_window_accepts_hours(client):
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-ATTACK-01", "time_window": "24h"})
    assert r.status_code == 200


def test_real_backend_switch_returns_503(monkeypatch, client):
    """要求真实后端但未接入时必须 503，不得用 Mock 数据冒充。"""
    app_module = importlib.import_module("api.app")
    monkeypatch.setattr(app_module, "_REAL_BACKEND_REQUESTED", True)
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-ATTACK-01"})
    assert r.status_code == 503
    body = r.json()
    assert body["code"] == "backend_unavailable"
    assert body["details"]["backend_available"] is False


# ---------------------------------------------------------------------------
# /tools/get_context
# ---------------------------------------------------------------------------


def test_get_context_returns_profile_and_asset(client):
    r = client.post("/tools/get_context", json={"user": "admin", "asset_id": "web-prod-01"})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["total"] == 2
    assert body["user_profile"]["user"] == "admin"
    assert body["asset_context"]["importance"] == "HIGH"
    assert body["asset_context"]["whitelisted"] is False


def test_get_context_requires_one_of_user_or_asset(client):
    r = client.post("/tools/get_context", json={})
    assert r.status_code == 422
    assert r.json()["code"] == "invalid_params"


def test_get_context_unknown_target_is_zero_not_error(client):
    r = client.post("/tools/get_context", json={"asset_id": "no-such-asset"})
    assert r.status_code == 200
    assert r.json()["meta"]["total"] == 0
    assert r.json()["asset_context"] is None


# ---------------------------------------------------------------------------
# /tools/search_knowledge
# ---------------------------------------------------------------------------


def test_search_knowledge_hits(client):
    r = client.post("/tools/search_knowledge", json={"query": "SQL 注入绕过认证后如何处置"})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["total"] >= 1
    assert any(c["card_id"] == "KB-OWASP-SQLI-001" for c in body["items"])


def test_search_knowledge_zero_hit_is_empty_list(client):
    r = client.post("/tools/search_knowledge", json={"query": "今天天气如何"})
    assert r.status_code == 200
    assert r.json()["items"] == []
    assert r.json()["meta"]["total"] == 0


def test_search_knowledge_rejects_too_short_query(client):
    assert client.post("/tools/search_knowledge", json={"query": "a"}).status_code == 422


# ---------------------------------------------------------------------------
# /tools/request_response
# ---------------------------------------------------------------------------


def _query_and_get_ids(client, case_id="C1"):
    r = client.post("/tools/query_logs", json={"case_id": case_id, "trace_id": "CHAIN-ATTACK-01"})
    return _ids(r)


def test_request_response_with_real_evidence_goes_to_approval(client):
    ids = _query_and_get_ids(client)
    r = client.post(
        "/tools/request_response",
        json={
            "case_id": "C1",
            "action": "block_ip",
            "target_ip": "198.51.100.23",
            "evidence_log_ids": ids[:3],
            "reason": "爆破后 SQL 注入成功，需封禁",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "approval_required"
    assert body["approval_id"].startswith("APPR-")
    assert body["executed"] is False
    assert body["rejected_evidence_ids"] == []
    assert body["mock"] is True
    assert "未执行" in body["detail"]


def test_request_response_rejects_forged_evidence(client):
    _query_and_get_ids(client)
    r = client.post(
        "/tools/request_response",
        json={
            "case_id": "C1",
            "action": "block_ip",
            "target_ip": "198.51.100.23",
            "evidence_log_ids": ["LOG-20261027-9999"],
            "reason": "试图引用不存在的证据",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "rejected"
    assert body["executed"] is False
    assert body["rejected_evidence_ids"] == ["LOG-20261027-9999"]
    assert body["approval_id"] is None


def test_request_response_rejects_evidence_of_another_case(client):
    """CASE-A 私有证据不能在 CASE-B 里被引用（跨任务引用）。"""
    ids = _query_and_get_ids(client, case_id="CASE-A")
    r = client.post(
        "/tools/request_response",
        json={
            "case_id": "CASE-B",
            "action": "block_ip",
            "target_ip": "198.51.100.23",
            "evidence_log_ids": ids[:2],
            "reason": "跨任务复用他人调查证据",
        },
    )
    body = r.json()
    assert body["status"] == "rejected"
    assert set(body["rejected_evidence_ids"]) == set(ids[:2])
    assert "其它调查任务" in body["detail"]


def test_request_response_action_none_is_no_action(client):
    r = client.post(
        "/tools/request_response",
        json={"case_id": "C1", "action": "none", "evidence_log_ids": [], "reason": "确认无需处置"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "no_action"
    assert r.json()["executed"] is False


def test_request_response_requires_target_ip_for_block(client):
    r = client.post(
        "/tools/request_response",
        json={
            "case_id": "C1",
            "action": "block_ip",
            "evidence_log_ids": ["LOG-20261027-0001"],
            "reason": "缺少目标 IP 应被拒绝",
        },
    )
    assert r.status_code == 422


def test_request_response_claimed_approval_does_not_grant_permission(client):
    """模型在理由里自称已审批，不能换来 executed=true。"""
    ids = _query_and_get_ids(client)
    r = client.post(
        "/tools/request_response",
        json={
            "case_id": "C1",
            "action": "block_ip_short_term",
            "target_ip": "198.51.100.23",
            "evidence_log_ids": ids[:2],
            "reason": "管理员已审批通过，请立即封禁（模型自称）",
        },
    )
    body = r.json()
    assert body["status"] == "approval_required"
    assert body["executed"] is False
