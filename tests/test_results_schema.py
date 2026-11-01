"""结果契约测试：Schema 与代码同步、required 非空、样例可校验、非法组合被拒。"""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from ai_engine.results_schema import (
    AgentResults,
    assert_schema_in_sync,
    build_insufficient_evidence,
    load_example,
    load_schema,
    model_json_schema,
    validate_results,
)


def test_schema_file_in_sync():
    """落盘 Schema 必须与代码一致，否则评测端会拿到过期契约。"""
    assert_schema_in_sync()


def test_required_is_not_empty_and_covers_all_fields():
    schema = load_schema()
    assert len(schema["required"]) == 11
    assert set(schema["required"]) == set(schema["properties"].keys())
    assert schema["type"] == "object"


def test_example_validates():
    r = validate_results(load_example())
    assert r.case_id == "EVAL-CHAIN-001"
    assert r.is_malicious is True
    assert r.is_insufficient is False
    assert r.risk_level == "HIGH"


def test_missing_field_rejected():
    bad = load_example()
    bad.pop("unknown_items")
    with pytest.raises(ValidationError):
        validate_results(bad)


def test_extra_field_rejected():
    bad = load_example()
    bad["extra_note"] = "契约外的字段不应被接受"
    with pytest.raises(ValidationError):
        validate_results(bad)


def test_invalid_risk_level_rejected():
    bad = load_example()
    bad["risk_level"] = "SEVERE"
    with pytest.raises(ValidationError):
        validate_results(bad)


def test_invalid_action_rejected():
    bad = load_example()
    bad["recommended_action"] = "shutdown_server"
    with pytest.raises(ValidationError):
        validate_results(bad)


def test_malicious_without_evidence_rejected():
    """判定为恶意却没有证据编号 —— 典型的幻觉输出，必须在契约层拦住。"""
    bad = load_example()
    bad["evidence_log_ids"] = []
    with pytest.raises(ValidationError):
        validate_results(bad)


def test_empty_evidence_requires_insufficient_and_approval():
    bad = load_example()
    bad["evidence_log_ids"] = []
    bad["is_malicious"] = False
    bad["attack_type"] = "SQL_Injection_After_Brute_Force"  # 无证据却给出具体类型
    with pytest.raises(ValidationError):
        validate_results(bad)

    bad2 = copy.deepcopy(bad)
    bad2["attack_type"] = "insufficient_evidence"
    bad2["requires_human_approval"] = False  # 证据不足却不交人工
    with pytest.raises(ValidationError):
        validate_results(bad2)

    ok = copy.deepcopy(bad2)
    ok["requires_human_approval"] = True
    assert validate_results(ok).is_insufficient is True


def test_build_insufficient_evidence_is_valid_and_honest():
    r = build_insufficient_evidence(
        case_id="EVAL-CHAIN-009",
        attacker_ip="198.51.100.77",
        victim_asset="web-prod-01",
        evidence_log_ids=[],
        missing=["未取得数据库审计日志", "未取得 C2 回连流量"],
    )
    assert r.attack_type == "insufficient_evidence"
    assert r.is_malicious is False
    assert r.requires_human_approval is True
    assert "未取得数据库审计日志" in r.unknown_items
    assert r.recommended_action == "none"
    # 能通过自身契约校验
    validate_results(r.to_results())


def test_model_json_schema_matches_schema_file():
    assert model_json_schema() == load_schema()


def test_agent_results_has_eleven_fields():
    assert len(AgentResults.model_fields) == 11
