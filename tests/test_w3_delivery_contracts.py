"""Regression checks for scoring and V2 replay provenance."""

import pytest

import run_v2_traces


def test_attack_type_tokenizer_preserves_abbreviations_and_camel_case():
    scorer = run_v2_traces._load_eval_runner()
    assert scorer._split_type_tokens("StoredXSS_SSH_And_IDOR") == {
        "stored", "xss", "ssh", "and", "idor",
    }


def test_benign_truth_label_matches_none_without_waiving_other_fields():
    scorer = run_v2_traces._load_eval_runner()
    truth = {
        "is_malicious": False, "attack_type": "Authorized_Security_Scan",
        "attacker_ip": "192.0.2.10", "victim_asset": "web-01", "recommended_action": "none",
    }
    result = {**truth, "attack_type": "none"}
    assert scorer.score_case(truth, result)["diagnosis_ok"]
    assert not scorer.score_case(truth, {**result, "attacker_ip": "192.0.2.11"})["diagnosis_ok"]
    assert not scorer.score_case({**truth, "is_malicious": True}, result)["type_hit"]
    assert not scorer.score_case(truth, {**result, "attack_type": "Scan"})["type_hit"]


@pytest.mark.parametrize("platform_flag", [True, False])
def test_local_runner_rejects_platform_provenance(monkeypatch, tmp_path, platform_flag):
    monkeypatch.setattr(run_v2_traces, "OUT_DIR", tmp_path)
    argv = ["run_v2_traces.py"]
    if platform_flag:
        argv += ["--from-platform", str(tmp_path)]
    else:
        monkeypatch.setenv("SECLOG_RUN_ORIGIN", "platform")
    monkeypatch.setattr(run_v2_traces, "run", lambda *_: pytest.fail("不应回放"))
    with pytest.raises(SystemExit) as exc:
        run_v2_traces.main(argv)
    assert exc.value.code == 2
    assert not list(tmp_path.iterdir())


def test_lexical_fallback_enforces_same_tenant_as_hybrid(monkeypatch):
    from api import knowledge_adapter

    monkeypatch.setenv("KNOWLEDGE_TENANT_ID", "default")
    with pytest.raises(knowledge_adapter.KnowledgeUnavailable, match="租户"):
        knowledge_adapter.search("认证失败", filters={"tenant_id": "other"}, mode="lexical_fallback")
