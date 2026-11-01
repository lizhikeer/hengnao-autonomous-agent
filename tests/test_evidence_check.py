"""证据登记与程序校验测试：伪造证据、跨任务引用、无案例查询、审计快照。"""

from __future__ import annotations

from api.evidence_check import EvidenceRegistry, UNSCOPED_BUCKET


def test_register_then_check_ok():
    reg = EvidenceRegistry()
    n = reg.register(["LOG-20261027-0001", "LOG-20261027-0008"], case_id="CASE-A")
    assert n == 2
    result = reg.check(["LOG-20261027-0001"], case_id="CASE-A")
    assert result.ok is True
    assert result.accepted == ["LOG-20261027-0001"]


def test_forged_id_is_rejected_as_unknown():
    reg = EvidenceRegistry()
    reg.register(["LOG-20261027-0001"], case_id="CASE-A")
    result = reg.check(["LOG-20261027-0001", "LOG-FAKE-9999"], case_id="CASE-A")
    assert result.ok is False
    assert result.unknown == ["LOG-FAKE-9999"]
    assert result.foreign == []


def test_other_case_evidence_is_foreign_not_unknown():
    """跨任务引用要和"凭空编造"区分开：前者是权限问题，后者是幻觉问题。"""
    reg = EvidenceRegistry()
    reg.register(["LOG-20261027-0001"], case_id="CASE-A")
    result = reg.check(["LOG-20261027-0001"], case_id="CASE-B")
    assert result.ok is False
    assert result.foreign == ["LOG-20261027-0001"]
    assert result.unknown == []


def test_unscoped_query_does_not_register():
    """未带 case_id 的查询不生成可引用证据。"""
    reg = EvidenceRegistry()
    reg.register(["LOG-20261027-0100"], case_id=None)
    assert reg.stats() == {}
    assert reg.check(["LOG-20261027-0100"], case_id="ANY-CASE").ok is False


def test_private_evidence_still_rejected_when_shared_pool_exists():
    reg = EvidenceRegistry()
    reg.register(["LOG-20261027-0001"], case_id="CASE-A")
    reg.register(["LOG-20261027-0100"], case_id=None)
    result = reg.check(["LOG-20261027-0001"], case_id="CASE-B")
    assert result.ok is False
    assert result.foreign == ["LOG-20261027-0001"]


def test_repeated_register_is_idempotent():
    reg = EvidenceRegistry()
    assert reg.register(["LOG-1"], case_id="C") == 1
    assert reg.register(["LOG-1"], case_id="C") == 0


def test_snapshot_includes_only_own_with_audit_info():
    reg = EvidenceRegistry()
    reg.register(["LOG-20261027-0001"], case_id="CASE-A", query_params={"trace_id": "CHAIN-ATTACK-01"})
    reg.register(["LOG-20261027-0100"], case_id=None)
    records = reg.snapshot(case_id="CASE-A")
    ids = [r.log_id for r in records]
    assert ids == ["LOG-20261027-0001"]
    own = next(r for r in records if r.log_id == "LOG-20261027-0001")
    assert own.case_id == "CASE-A"
    assert own.query_params["trace_id"] == "CHAIN-ATTACK-01"
    assert own.registered_at > 0


def test_known_log_ids_for_case():
    reg = EvidenceRegistry()
    reg.register(["LOG-A", "LOG-B"], case_id="CASE-X")
    assert reg.known_log_ids(case_id="CASE-X") == {"LOG-A", "LOG-B"}
    assert reg.known_log_ids(case_id="CASE-Y") == set()


def test_clear_resets_everything():
    reg = EvidenceRegistry()
    reg.register(["LOG-A"], case_id="CASE-X")
    reg.clear()
    assert reg.stats() == {}
    assert reg.check(["LOG-A"], case_id="CASE-X").ok is False


def test_empty_input_passes_vacuously():
    reg = EvidenceRegistry()
    assert reg.check([], case_id="CASE-X").ok is True
