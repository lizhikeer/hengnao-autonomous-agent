"""集成测试：实际使用 Qdrant Local 与 SQLite，验证审核、版本、过滤及故障边界。"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from qdrant_client import QdrantClient, models

from src.knowledge.config import PROJECT_ROOT, KnowledgeConfig
from src.knowledge.embedding import check_vectors
from src.knowledge.loader import parse_cards
from src.knowledge.qdrant_client import VectorStore
from src.knowledge.schema import CardValidator, normalize_card
from src.knowledge.search import reciprocal_rank_fusion
from src.knowledge.text import match_query, terms

from .conftest import source_files


def import_cards(service, tmp_path, cards, *, approve=True, split="knowledge"):
    paths, manifest = source_files(tmp_path, cards, split=split)
    return service.ingest_files(
        paths, manifest=manifest, reviewed_by="test-reviewer" if approve else None
    )


def test_pending_is_sqlite_only(service, card, tmp_path):
    result = import_cards(service, tmp_path, [card], approve=False)
    assert result[0]["status"] == "pending"
    assert service.store.get("default", card["card_id"], 1)["review_status"] == "pending"
    for collection in ("security_knowledge", "verified_cases"):
        assert service.vectors.client.count(collection).count == 0
    assert service.search("密码爆破") == []


def test_publish_reimport_and_restore_full_text(service, card, tmp_path):
    import_cards(service, tmp_path, [card])
    count = service.vectors.client.count("security_knowledge").count
    import_cards(service, tmp_path, [card])
    assert service.vectors.client.count("security_knowledge").count == count
    result = service.search("Web后台口令爆破", top_k=1)
    assert result[0]["card_id"] == card["card_id"]
    assert result[0]["investigation_steps"] == card["investigation_steps"]
    assert result[0]["source_reference"] == card["source_reference"]
    assert result[0]["review_status"] == "approved"


def test_new_pending_keeps_old_published_version(service, card, tmp_path):
    import_cards(service, tmp_path, [card])
    card.update(version=2, title="新版：登录失败后成功的调查")
    import_cards(service, tmp_path, [card], approve=False)
    assert {item["version"] for item in service.search("登录爆破")} == {1}
    import_cards(service, tmp_path, [card])
    assert {item["version"] for item in service.search("登录爆破")} == {2}
    card["version"] = 1
    with pytest.raises(ValueError, match="同版本内容冲突"):
        import_cards(service, tmp_path, [card])


def test_incompatible_collection_is_preserved(tmp_path):
    client = QdrantClient(path=str(tmp_path / "bad-qdrant"))
    client.create_collection(
        "security_knowledge",
        vectors_config={"dense": models.VectorParams(size=768, distance=models.Distance.COSINE)},
    )
    vectors = VectorStore(KnowledgeConfig(qdrant_path="local"), client=client)
    with pytest.raises(ValueError, match="不兼容"):
        vectors.initialize()
    assert client.get_collection("security_knowledge").config.params.vectors["dense"].size == 768
    client.close()


def test_index_failure_retains_old_version_and_retry_is_safe(service, card, tmp_path, monkeypatch):
    import_cards(service, tmp_path, [card])
    card.update(version=2, title="新版认证调查")
    original = service.vectors.upsert
    with monkeypatch.context() as patch:
        patch.setattr(
            service.vectors, "upsert", lambda *args: (_ for _ in ()).throw(OSError("test"))
        )
        with pytest.raises(OSError):
            import_cards(service, tmp_path, [card])
    assert {item["version"] for item in service.search("密码爆破")} == {1}
    assert (
        service.store.db.execute(
            "SELECT count(*) FROM kb_index_jobs WHERE status='failed'"
        ).fetchone()[0]
        == 1
    )
    assert service.vectors.upsert == original
    import_cards(service, tmp_path, [card])
    assert {item["version"] for item in service.search("密码爆破")} == {2}


def test_withdrawal_is_effective_even_when_qdrant_delete_fails(
    service, card, tmp_path, monkeypatch
):
    import_cards(service, tmp_path, [card])
    with monkeypatch.context() as patch:
        patch.setattr(
            service.vectors, "delete_points", lambda *args: (_ for _ in ()).throw(OSError("test"))
        )
        with pytest.raises(OSError):
            service.withdraw(card["card_id"], reviewed_by="reviewer", reason="证据已失效")
    assert service.vectors.client.count("security_knowledge").count > 0
    assert service.search("密码爆破") == []
    with pytest.raises(ValueError, match="恢复下架"):
        import_cards(service, tmp_path, [card])
    card["version"] = 2
    import_cards(service, tmp_path, [card])
    assert service.search("密码爆破")[0]["version"] == 2


def test_tenant_category_log_source_and_dates(service, card, tmp_path):
    expired = copy.deepcopy(card)
    expired.update(
        card_id="expired",
        valid_from="2000-01-01T00:00:00.000Z",
        valid_until="2001-01-01T00:00:00.000Z",
    )
    assert import_cards(service, tmp_path, [expired])[0]["status"] == "outside_validity"
    import_cards(service, tmp_path, [card])
    assert service.search("密码爆破", filters={"attack_category": "XSS"}) == []
    assert service.search("密码爆破", filters={"log_sources": ["unknown"]}) == []
    with pytest.raises(ValueError, match="租户"):
        service.search("密码爆破", filters={"tenant_id": "other"})
    service.vectors.client.set_payload(
        "security_knowledge",
        {"tenant_id": "other"},
        points=models.Filter(
            must=[
                models.FieldCondition(key="card_id", match=models.MatchValue(value=card["card_id"]))
            ]
        ),
    )
    # BM25 仍只能返回本地可信租户的已发布版本。
    assert service.search("密码爆破")[0]["tenant_id"] == "default"


def test_candidate_case_and_approved_revision_are_isolated(service, tmp_path):
    case = json.loads(
        (PROJECT_ROOT / "design/knowledge/examples.json").read_text(encoding="utf-8")
    )[2]
    case["tenant_id"] = "default"
    import_cards(service, tmp_path, [case], approve=False, split="development")
    assert service.vectors.client.count("verified_cases").count == 0
    with pytest.raises(ValueError):
        import_cards(service, tmp_path, [case], split="development")
    case["case_details"]["verification"] = {
        "method": "human_evidence_review",
        "reference": "urn:test:review",
        "notes": "仅用于结构测试的模拟审核记录。",
    }
    # 内容变化使用新版本；测试记录不会导入仓库的真实检索库。
    case["version"] = 2
    import_cards(service, tmp_path, [case], split="development")
    assert service.vectors.client.count("security_knowledge").count == 0
    assert service.vectors.client.count("verified_cases").count > 0
    assert service.search("UNION SELECT")[0]["case_details"]["corrected_steps"]
    assert (
        service.search(
            "UNION SELECT", filters={"exclude_investigation_id": case["origin"]["investigation_id"]}
        )
        == []
    )
    assert (
        service.search(
            "UNION SELECT", filters={"exclude_scenario_ids": case["origin"]["scenario_ids"]}
        )
        == []
    )


def test_untrusted_changed_or_holdout_sources_rejected_before_write(service, card, tmp_path):
    paths, manifest = source_files(tmp_path, [card], split="independent_eval")
    with pytest.raises(ValueError, match="白名单"):
        service.ingest_files(paths, manifest=manifest)
    paths, manifest = source_files(tmp_path, [card])
    paths[0].write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="内容发生变化"):
        service.ingest_files(paths, manifest=manifest)
    assert service.store.db.execute("SELECT count(*) FROM kb_card_versions").fetchone()[0] == 0


def test_source_outside_root_and_duplicate_ids_are_rejected(tmp_path, card):
    paths, manifest = source_files(tmp_path, [card])
    with pytest.raises(ValueError, match="根目录"):
        manifest.read(tmp_path.parent / "outside.json", "default")
    cards = [card, card]
    paths, manifest = source_files(tmp_path, cards)
    with pytest.raises(ValueError, match="重复"):
        manifest.read(paths[0], "default")


def test_all_twenty_existing_cards_validate():
    validator = CardValidator()
    count = 0
    for path in sorted((PROJECT_ROOT / "data/knowledge_cards").glob("*.json")):
        if path.name == "manifest.json":
            continue
        for card in json.loads(path.read_text(encoding="utf-8")):
            validator.validate(normalize_card(card, tenant_id="default"))
            count += 1
    assert count == 20


def test_markdown_front_matter_and_json_block(card):
    document = "说明\n```json\n" + json.dumps(card, ensure_ascii=False) + "\n```"
    assert parse_cards(document, ".md") == [card]
    assert parse_cards("---\r\ntitle: demo\r\n---\r\n正文", ".md")[0]["summary"] == "正文"


def test_reference_validation_and_snapshot_hash():
    card = json.loads(
        (PROJECT_ROOT / "design/knowledge/examples.json").read_text(encoding="utf-8")
    )[2]
    validator = CardValidator()
    validator.validate(card)
    card["case_details"]["investigation_trace"][0]["rule_ids"] = ["missing"]
    with pytest.raises(ValueError, match="不存在"):
        validator.validate(card)
    card["evidence_refs"][0]["snapshot_summary"] = "changed"
    with pytest.raises(ValueError, match="sha256"):
        validator.validate(card)


def test_match_query_is_literal_and_aliases_are_shared(service, card, tmp_path):
    import_cards(service, tmp_path, [card])
    assert "brute_force" in terms("密码爆破")
    assert '"' in match_query('登录 " OR * NOT')
    # 用户输入的引号、括号、保留词不能成为 FTS 表达式或 SQL。
    service.search('登录 " OR * NOT (')
    assert service.store.db.execute("SELECT count(*) FROM kb_cards").fetchone()[0] == 1


def test_rrf_keeps_both_branches_and_deduplicates():
    ranking = reciprocal_rank_fusion([["A", "B", "B"], ["B", "C"]])
    assert ranking[0][0] == "B"
    assert {key for key, _ in ranking} == {"A", "B", "C"}


def test_keyword_only_retrieves_exact_mitre_identifier(service, card, tmp_path, monkeypatch):
    import_cards(service, tmp_path, [card])
    monkeypatch.setattr(service.vectors, "search", lambda *args, **kwargs: [])
    assert service.search("T1110.001")[0]["card_id"] == card["card_id"]


def test_same_content_under_another_id_reuses_existing_entry(service, card, tmp_path):
    import_cards(service, tmp_path, [card], approve=False)
    original_id = card["card_id"]
    card["card_id"] = "copy-card"
    report = import_cards(service, tmp_path, [card])
    assert report[0]["status"] == "duplicate"
    assert report[0]["duplicate_of"] == original_id
    assert report[0]["existing_review_status"] == "pending"
    assert service.store.db.execute("SELECT count(*) FROM kb_cards").fetchone()[0] == 1
    assert service.vectors.client.count("security_knowledge").count == 0


def test_expiration_after_publication_excludes_both_branches(service, card, tmp_path, monkeypatch):
    import src.knowledge.search as search_module

    card.update(valid_from="2000-01-01T00:00:00.000Z", valid_until="2001-01-01T00:00:00.000Z")
    monkeypatch.setattr(search_module, "utc_now", lambda: "2000-06-01T00:00:00.000Z")
    import_cards(service, tmp_path, [card])
    assert service.search("密码爆破")
    monkeypatch.setattr(search_module, "utc_now", lambda: "2002-01-01T00:00:00.000Z")
    assert service.search("密码爆破") == []


def test_remote_payload_indexes_cover_issue_fields_and_are_idempotent():
    client = MagicMock(spec=QdrantClient)
    client.collection_exists.return_value = True
    info = SimpleNamespace(
        config=SimpleNamespace(
            params=SimpleNamespace(
                vectors={"dense": models.VectorParams(size=512, distance=models.Distance.COSINE)}
            )
        ),
        payload_schema={},
    )
    client.get_collection.return_value = info
    vector_store = VectorStore(KnowledgeConfig(), client=client)
    vector_store.initialize()
    calls = client.create_payload_index.call_args_list
    fields = {call.args[1] for call in calls}
    assert {
        "card_id",
        "card_type",
        "attack_category",
        "mitre_id",
        "applicable_log_sources",
        "review_status",
        "valid_until",
    } <= fields
    assert {call.args[0] for call in calls} == {"security_knowledge", "verified_cases"}
    info.payload_schema = {
        call.args[1]: SimpleNamespace(data_type=call.kwargs["field_schema"]) for call in calls
    }
    count = len(calls)
    vector_store.initialize()
    assert client.create_payload_index.call_count == count


def test_generation_change_cancels_publication(service, card, tmp_path, monkeypatch):
    original = service.vectors.upsert

    def superseded(*args):
        original(*args)
        with service.store.db:
            service.store.db.execute("UPDATE kb_cards SET generation=generation+1")

    monkeypatch.setattr(service.vectors, "upsert", superseded)
    with pytest.raises(ValueError, match="发布意图"):
        import_cards(service, tmp_path, [card])
    assert service.search("密码爆破") == []


@pytest.mark.parametrize("vector", [[0.0] * 512, [1.0] * 768, [float("nan")] * 512])
def test_invalid_vectors_rejected(vector):
    with pytest.raises(ValueError):
        check_vectors([vector], 1)


@pytest.mark.parametrize("top_k", [0, 21, True, 1.5])
def test_invalid_limits(service, top_k):
    with pytest.raises(ValueError):
        service.search("SQL 注入", top_k=top_k)
