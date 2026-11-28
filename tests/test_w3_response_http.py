"""Verify the V2 HTTP approval flow against the merged policy engine."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import app


@pytest.fixture
def approval_api(monkeypatch, tmp_path):
    from operations import response_executor

    monkeypatch.setenv("SECLOG_RESPONSE_MODE", "simulation")
    monkeypatch.setenv("SECLOG_RESPONSE_SUBMIT_TOKEN", "submit-token-used-only-in-tests")
    monkeypatch.setenv("SECLOG_RESPONSE_APPROVAL_TOKENS_JSON",
                       json.dumps({"test-reviewer": "review-token-used-only-in-tests"}))
    monkeypatch.setenv("SECLOG_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "dataset_replay")
    response_executor.reset_pending()
    with TestClient(app) as client:
        yield client, response_executor.enforcement_log_path()
    response_executor.reset_pending()


SUBMIT = {"Authorization": "Bearer submit-token-used-only-in-tests"}
APPROVE = {"Authorization": "Bearer review-token-used-only-in-tests"}


def _request(client, case_id="CASE-W3-HTTP"):
    query = client.post("/tools/query_logs", json={
        "case_id": case_id, "trace_id": "CHAIN-CASE-01", "limit": 50,
    })
    assert query.status_code == 200
    row = next(item for item in query.json()["items"]
               if item["asset_id"] == "web-prod-01" and item["src_ip"] == "198.51.100.23")
    return {
        "case_id": case_id, "asset_id": row["asset_id"], "target_ip": row["src_ip"],
        "action": "block_ip", "evidence_log_ids": [row["log_id"]], "reason": "需要人工审核的处置验证",
    }


def test_http_approval_uses_bound_identity_and_returns_simulated_audit(approval_api):
    client, audit = approval_api
    request = _request(client)
    pending = client.post("/tools/request_response", json=request, headers=SUBMIT).json()
    assert pending["status"] == "approval_required"
    assert pending["executed"] is False
    assert not audit.exists()

    decision = {"case_id": request["case_id"], "approval_id": pending["approval_id"], "decision": "approve",
                "expected_effect": "仅核验模拟记录", "rollback_plan": "模拟动作不改变网络"}
    assert client.post("/tools/approve_response", json=decision, headers=SUBMIT).status_code == 401
    assert client.post("/tools/approve_response", json={**decision, "case_id": "OTHER"},
                       headers=APPROVE).status_code == 404
    result = client.post("/tools/approve_response", json=decision, headers=APPROVE)
    assert result.status_code == 200
    assert result.json()["status"] == "EXECUTED"
    assert result.json()["executed"] is False
    assert result.json()["simulation"] is True
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["approved_by"] == "test-reviewer"
    assert client.post("/tools/approve_response", json=decision, headers=APPROVE).status_code == 404


def test_http_policy_and_evidence_block_on_unverified_asset(approval_api):
    client, audit = approval_api
    request = _request(client)
    assert client.post("/tools/request_response", json=request).status_code == 401
    blocked = client.post("/tools/request_response", json={**request, "asset_id": "db-core-01"},
                          headers=SUBMIT).json()
    assert blocked["status"] == "BLOCKED_BY_POLICY"
    assert blocked["executed"] is False
    assert not audit.exists()


@pytest.mark.parametrize("expired", [False, True])
def test_http_rejection_and_timeout_never_write_execution(approval_api, monkeypatch, expired):
    from operations import response_executor

    client, audit = approval_api
    start = datetime(2026, 11, 19, tzinfo=timezone.utc)
    monkeypatch.setattr(response_executor, "_now", lambda: start)
    request = _request(client)
    pending = client.post("/tools/request_response", json=request, headers=SUBMIT).json()
    if expired:
        monkeypatch.setattr(response_executor, "_now", lambda: start + timedelta(minutes=30))
    result = client.post("/tools/approve_response", headers=APPROVE, json={
        "case_id": request["case_id"], "approval_id": pending["approval_id"], "decision": "reject",
    })
    assert result.status_code == 200
    assert result.json()["status"] == ("APPROVAL_TIMEOUT" if expired else "REJECTED")
    assert not audit.exists()
