from datetime import timedelta

import pytest

from api.evidence_check import EvidenceRegistry
from api.mock_data import MOCK_LOGS, MOCK_REFERENCE_TIME


@pytest.mark.parametrize('blank', ['', '   '])
@pytest.mark.parametrize('with_valid', [False, True])
def test_blank_evidence_cannot_create_approval(client, blank, with_valid):
    from mcp_server.server import seclog_request_response

    ids = [blank]
    if with_valid:
        rows = client.post('/tools/query_logs', json={
            'case_id': 'BLANK', 'trace_id': 'CHAIN-ATTACK-01',
        }).json()['items']
        ids.insert(0, rows[0]['log_id'])
    request = dict(case_id='BLANK', action='block_ip', target_ip='198.51.100.23',
                   evidence_log_ids=ids, reason='空编号不得授权处置')
    for body in (client.post('/tools/request_response', json=request).json(),
                 seclog_request_response(**request)):
        assert body['status'] == 'rejected'
        assert body['executed'] is False
        assert body['approval_id'] is None
        assert blank in body['rejected_evidence_ids']


def test_time_window_filters_before_limit_and_evidence_registration(client):
    short = client.post('/tools/query_logs', json={
        'case_id': 'SHORT', 'trace_id': 'CHAIN-ATTACK-01', 'time_window': '1m',
    }).json()
    wide = client.post('/tools/query_logs', json={
        'case_id': 'WIDE', 'trace_id': 'CHAIN-ATTACK-01', 'time_window': '1h',
    }).json()
    assert len(short['items']) == 1
    assert len(wide['items']) == 4
    assert short['meta']['reference_time'] == MOCK_REFERENCE_TIME.isoformat()
    old_id = next(row['log_id'] for row in wide['items'] if row not in short['items'])
    response = client.post('/tools/request_response', json={
        'case_id': 'SHORT', 'action': 'block_ip', 'target_ip': '198.51.100.23',
        'evidence_log_ids': [old_id], 'reason': '验证时间范围外的证据不能引用',
    }).json()
    assert response['status'] == 'rejected'


def test_time_window_includes_lower_boundary_excludes_future(client, monkeypatch):
    row = MOCK_LOGS[0]
    samples = [{**row, 'timestamp': stamp.isoformat(), 'log_id': log_id}
               for stamp, log_id in [
                   (MOCK_REFERENCE_TIME - timedelta(minutes=1), 'BOUNDARY'),
                   (MOCK_REFERENCE_TIME - timedelta(minutes=1, seconds=1), 'OLD'),
                   (MOCK_REFERENCE_TIME + timedelta(seconds=1), 'FUTURE'),
               ]]
    monkeypatch.setattr('api.mock_data.MOCK_LOGS', samples)
    body = client.post('/tools/query_logs', json={
        'trace_id': row['trace_id'], 'time_window': '1m',
    }).json()
    assert [r['log_id'] for r in body['items']] == ['BOUNDARY']


def test_unscoped_query_cannot_authorize_another_case(client):
    rows = client.post('/tools/query_logs', json={'trace_id': 'CHAIN-ATTACK-01'}).json()['items']
    body = client.post('/tools/request_response', json={
        'case_id': 'NEVER-QUERIED', 'action': 'block_ip', 'target_ip': '198.51.100.23',
        'evidence_log_ids': [rows[0]['log_id']], 'reason': '验证无案例查询不可授权处置',
    }).json()
    assert body['status'] == 'rejected'
    assert body['executed'] is False


def test_same_log_must_be_queried_independently_in_each_case():
    registry = EvidenceRegistry()
    registry.register(['LOG-A'], case_id='A')
    assert not registry.check(['LOG-A'], case_id='B').ok
    registry.register(['LOG-A'], case_id='B')
    assert registry.check(['LOG-A'], case_id='A').ok
    assert registry.check(['LOG-A'], case_id='B').ok
    assert not registry.check(['LOG-A'], case_id='C').ok


def test_platform_verifier_checks_actual_query_output_and_case():
    import json
    from pathlib import Path
    from ai_engine.verify import main
    data = json.loads(Path("src/ai_engine/schemas/agent_results.example.json").read_text(encoding="utf-8"))
    args = {"triage": data, "case_id": data["case_id"],
            "query_results": [{"log_id": i} for i in data["evidence_log_ids"]]}
    assert main(args)["verified"] is True
    assert main({**args, "query_results": []})["verified"] is False
    assert main({**args, "case_id": "OTHER"})["verified"] is False
    assert main({"triage": data})["verified"] is False


def test_backend_verifies_model_results_against_case_registry(client):
    import json
    from pathlib import Path
    data = json.loads(Path("src/ai_engine/schemas/agent_results.example.json").read_text(encoding="utf-8"))
    request = {"case_id": data["case_id"], "results": data}
    assert client.post("/tools/verify_results", json=request).json()["verified"] is False
    client.post("/tools/query_logs", json={"case_id": data["case_id"], "trace_id": "CHAIN-ATTACK-01"})
    assert client.post("/tools/verify_results", json=request).json()["verified"] is True
    assert client.post("/tools/verify_results", json={**request, "case_id": "OTHER"}).json()["verified"] is False
