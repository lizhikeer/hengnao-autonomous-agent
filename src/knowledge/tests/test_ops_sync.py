"""验证运维同步不会把候选当作已发布，以及异常是否体现在报告和退出码。"""

import json

from scripts.ops import sync_knowledge_index as sync
from src.knowledge.search import KnowledgeService

from .conftest import FakeEncoder, source_files


def test_sync_reports_staged_unchanged_and_content_conflict(service, card, tmp_path, monkeypatch):
    paths, source = source_files(tmp_path, [card])
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.json"
    args = ["--manifest", str(manifest_path), "--output", str(report_path)]
    monkeypatch.setattr(sync, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("KNOWLEDGE_SQLITE_PATH", service.config.sqlite_path)

    assert sync.main(args) == 0
    report = json.loads(report_path.read_text("utf-8"))
    assert report["verdict"] == "staged" and report["qdrant"]["status"] == "skipped"
    service.ingest_files(paths, manifest=source, reviewed_by="test-reviewer")
    assert sync.main(args) == 0
    assert json.loads(report_path.read_text("utf-8"))["verdict"] == "unchanged"

    source_files(tmp_path, [{**card, "title": "同版本正文冲突"}])
    assert sync.main(args) == 1
    assert json.loads(report_path.read_text("utf-8"))["verdict"] == "failed"
    assert service.store.get("default", card["card_id"], card["version"])["title"] == card["title"]


def test_sync_reports_vector_failure_and_dry_run_is_read_only(card, tmp_path, monkeypatch):
    source_files(tmp_path, [card])
    report = tmp_path / "report.json"
    sqlite = tmp_path / "db.sqlite3"
    args = [
        "--manifest",
        str(tmp_path / "manifest.json"),
        "--output",
        str(report),
        "--sqlite-path",
        str(sqlite),
        "--qdrant-path",
        str(tmp_path / "vectors"),
    ]
    monkeypatch.setattr(sync, "PROJECT_ROOT", tmp_path)
    assert sync.main([*args, "--dry-run"]) == 0
    assert not sqlite.exists()

    def missing_model(_service):
        raise RuntimeError("本地权重不可用")

    monkeypatch.setattr(KnowledgeService, "encoder", property(missing_model))
    assert sync.main([*args, "--approve-by", "test-reviewer"]) == 1
    result = json.loads(report.read_text("utf-8"))
    assert result["verdict"] == "failed"
    assert result["qdrant"]["status"] == "unverified"
    assert result["failures"][0]["stage"] == "sync"


def test_partly_published_batch_reports_every_card(card, tmp_path, monkeypatch):
    future = {**card, "card_id": "KB-FUTURE", "valid_from": "2099-01-01T00:00:00.000Z"}
    duplicate = {**card, "card_id": "KB-DUPLICATE"}
    source_files(tmp_path, [card, future, duplicate])
    monkeypatch.setattr(sync, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(KnowledgeService, "encoder", property(lambda _: FakeEncoder()))
    report = tmp_path / "report.json"
    code = sync.main(
        [
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--approve-by",
            "test",
            "--sqlite-path",
            str(tmp_path / "store.sqlite3"),
            "--qdrant-path",
            str(tmp_path / "qdrant"),
            "--output",
            str(report),
        ]
    )
    result = json.loads(report.read_text("utf-8"))
    assert code != 0 and result["verdict"] == "partial"
    assert result["smoke_test"]["ok"] and result["qdrant"]["published"] == 1
    rows = {r["card_id"]: r for r in result["qdrant"]["cards"]}
    assert rows[card["card_id"]]["status"] == "published"
    assert rows["KB-FUTURE"]["status"] == "outside_validity"
    assert rows["KB-FUTURE"]["reason"] == "not_yet_valid"
    assert rows["KB-DUPLICATE"]["duplicate_of"] == card["card_id"]
