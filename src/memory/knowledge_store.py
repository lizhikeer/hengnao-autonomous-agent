"""SQLite 卡片存储：版本原文、候选隔离、发布指针和 FTS5 关键词索引的一致性。"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.knowledge.config import PROJECT_ROOT
from src.knowledge.schema import canonical_hash, utc_now

SCALARS = (
    "tenant_id",
    "card_id",
    "version",
    "schema_version",
    "card_type",
    "title",
    "attack_category",
    "mitre_id",
    "source_reference",
    "dataset_split",
    "review_status",
    "reviewed_by",
    "reviewed_at",
    "valid_from",
    "valid_until",
    "created_at",
    "updated_at",
)
JSON_COLUMNS = {
    "applicable_log_sources": "applicable_log_sources_json",
    "keywords": "keywords_json",
    "sources": "sources_json",
}


class KnowledgeStore:
    """每个服务实例持有一个连接；调用者需串行使用同一实例，不共享给多个线程。"""

    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        ddl = PROJECT_ROOT / "design" / "knowledge" / "sqlite_schema.sql"
        self.db.executescript(ddl.read_text(encoding="utf-8"))

    def duplicate(self, card: dict[str, Any]) -> sqlite3.Row | None:
        """同租户、同类型、同正文的其他编号返回已有条目，避免相同内容重复建索引。"""
        return self.db.execute(
            "SELECT card_id,version,review_status FROM kb_card_versions WHERE tenant_id=? AND card_type=? AND content_hash=? AND card_id<>? ORDER BY version DESC LIMIT 1",
            (card["tenant_id"], card["card_type"], canonical_hash(card), card["card_id"]),
        ).fetchone()

    def save(self, card: dict[str, Any]) -> None:
        """保存候选或批准版本；已批准正文不可原地改写，旧发布版本持续可用。"""
        identity = (card["tenant_id"], card["card_id"], card["version"])
        existing = self.db.execute(
            "SELECT content_hash,review_status FROM kb_card_versions WHERE tenant_id=? AND card_id=? AND version=?",
            identity,
        ).fetchone()
        content_hash = canonical_hash(card)
        if existing and existing["content_hash"] != content_hash:
            raise ValueError("同一版本内容发生变化，请增加 version")
        if existing and existing["review_status"] == "approved":
            if card["review_status"] != "approved":
                raise ValueError("已批准版本不能降回候选；请提交新版本")
            return

        def encoded(value: Any) -> str:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)

        excluded = set(SCALARS) | set(JSON_COLUMNS) | {"origin", "evidence_refs"}
        row = {key: card[key] for key in SCALARS}
        row.update({column: encoded(card.get(key, [])) for key, column in JSON_COLUMNS.items()})
        row.update(
            content_hash=content_hash,
            origin_json=encoded(card.get("origin", {})),
            content_json=encoded(
                {key: value for key, value in card.items() if key not in excluded}
            ),
        )
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO kb_cards(tenant_id,card_id,created_at,updated_at) VALUES(?,?,?,?)",
                (card["tenant_id"], card["card_id"], card["created_at"], card["updated_at"]),
            )
            if existing:
                self.db.execute(
                    "DELETE FROM kb_evidence_refs WHERE tenant_id=? AND card_id=? AND version=?",
                    identity,
                )
                self.db.execute(
                    "UPDATE kb_card_versions SET review_status=?,reviewed_by=?,reviewed_at=? WHERE tenant_id=? AND card_id=? AND version=?",
                    (card["review_status"], card["reviewed_by"], card["reviewed_at"], *identity),
                )
            else:
                columns = ",".join(row)
                self.db.execute(
                    f"INSERT INTO kb_card_versions({columns}) VALUES({','.join('?' for _ in row)})",
                    tuple(row.values()),
                )
            for evidence in card.get("evidence_refs", []):
                values = {
                    "tenant_id": identity[0],
                    "card_id": identity[1],
                    "version": identity[2],
                    **evidence,
                }
                self.db.execute(
                    f"INSERT INTO kb_evidence_refs({','.join(values)}) VALUES({','.join('?' for _ in values)})",
                    tuple(values.values()),
                )
            if card["review_status"] != "pending":
                self.db.execute(
                    "INSERT INTO kb_reviews VALUES(?,?,?,?,?,?,?,?)",
                    (
                        str(uuid4()),
                        *identity,
                        card["review_status"],
                        "管理入口明确批准导入",
                        card["reviewed_by"],
                        card["reviewed_at"],
                    ),
                )

    def get(self, tenant_id: str, card_id: str, version: int) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT * FROM kb_card_versions WHERE tenant_id=? AND card_id=? AND version=?",
            (tenant_id, card_id, version),
        ).fetchone()
        if row is None:
            return None
        card = {key: row[key] for key in SCALARS}
        card.update(json.loads(row["content_json"]))
        for key, column in JSON_COLUMNS.items():
            card[key] = json.loads(row[column])
        if card["schema_version"] == "1.0":
            card.pop("sources", None)
        if card["card_type"] != "security_knowledge":
            card["origin"] = json.loads(row["origin_json"])
            evidence = self.db.execute(
                "SELECT * FROM kb_evidence_refs WHERE tenant_id=? AND card_id=? AND version=?",
                (tenant_id, card_id, version),
            ).fetchall()
            card["evidence_refs"] = [
                {
                    key: item[key]
                    for key in item.keys()
                    if key not in {"tenant_id", "card_id", "version"}
                }
                for item in evidence
            ]
        return card

    def visible(self, tenant_id: str, card_id: str, version: int, now: str) -> bool:
        return (
            self.db.execute(
                """SELECT 1 FROM kb_card_versions v JOIN kb_cards c
            ON c.tenant_id=v.tenant_id AND c.card_id=v.card_id AND c.published_version=v.version
            WHERE v.tenant_id=? AND v.card_id=? AND v.version=? AND c.status='active'
            AND v.review_status='approved' AND v.valid_from<=? AND (v.valid_until IS NULL OR v.valid_until>?)""",
                (tenant_id, card_id, version, now, now),
            ).fetchone()
            is not None
        )

    def begin_publish(self, card: dict[str, Any], profile: str) -> tuple[int, str]:
        """先记录发布意图，再操作 Qdrant；generation 防止旧任务覆盖撤回决定。"""
        key = (card["tenant_id"], card["card_id"])
        with self.db:
            row = self.db.execute(
                "SELECT generation,published_version,status FROM kb_cards WHERE tenant_id=? AND card_id=?",
                key,
            ).fetchone()
            if row["published_version"] and row["published_version"] > card["version"]:
                raise ValueError("禁止使用旧版本覆盖已发布的新版本")
            if row["status"] == "withdrawn":
                maximum = self.db.execute(
                    "SELECT max(version) FROM kb_reviews WHERE tenant_id=? AND card_id=? AND decision='withdrawn'",
                    key,
                ).fetchone()[0]
                if maximum is not None and card["version"] <= maximum:
                    raise ValueError("恢复下架卡片需创建并审核新版本")
            generation, job = row["generation"] + 1, str(uuid4())
            self.db.execute(
                "UPDATE kb_cards SET generation=?,updated_at=? WHERE tenant_id=? AND card_id=?",
                (generation, utc_now(), *key),
            )
            self.db.execute(
                "INSERT INTO kb_index_jobs(job_id,tenant_id,card_id,version,index_profile,generation,operation,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'publish','running',?,?)",
                (job, *key, card["version"], profile, generation, utc_now(), utc_now()),
            )
        return generation, job

    def publish(
        self,
        card: dict[str, Any],
        chunks: list[dict[str, Any]],
        profile: str,
        generation: int,
        job: str,
    ) -> None:
        with self.db:
            # 条件更新决定能否发布。即使 Qdrant 留有旧点，最终查询也会按此指针排除。
            cursor = self.db.execute(
                "UPDATE kb_cards SET published_version=?,status='active',updated_at=? WHERE tenant_id=? AND card_id=? AND generation=?",
                (card["version"], utc_now(), card["tenant_id"], card["card_id"], generation),
            )
            if cursor.rowcount != 1:
                raise ValueError("发布意图已被更新或撤回，请重新核对任务")
            self.db.execute(
                "DELETE FROM kb_chunks WHERE tenant_id=? AND card_id=? AND version=? AND index_profile=?",
                (card["tenant_id"], card["card_id"], card["version"], profile),
            )
            for chunk in chunks:
                self.db.execute(
                    "INSERT INTO kb_chunks(tenant_id,card_id,version,index_profile,chunk_index,point_id,collection_name,section_path,text,search_text,token_count,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        card["tenant_id"],
                        card["card_id"],
                        card["version"],
                        profile,
                        chunk["chunk_index"],
                        chunk["point_id"],
                        chunk["collection_name"],
                        chunk["section_path"],
                        chunk["text"],
                        chunk["search_text"],
                        chunk["token_count"],
                        utc_now(),
                    ),
                )
            self.db.execute(
                "UPDATE kb_index_jobs SET status='succeeded',updated_at=? WHERE job_id=?",
                (utc_now(), job),
            )

    def fail_job(self, job: str, exc: Exception) -> None:
        with self.db:
            self.db.execute(
                "UPDATE kb_index_jobs SET status='failed',last_error=?,attempts=attempts+1,updated_at=? WHERE job_id=?",
                (type(exc).__name__, utc_now(), job),
            )

    def obsolete_chunks(self, card: dict[str, Any], profile: str) -> list[sqlite3.Row]:
        """只返回旧版本/旧配置的确切点编号，清理时不会误删刚发布的新版本。"""
        return self.db.execute(
            "SELECT * FROM kb_chunks WHERE tenant_id=? AND card_id=? AND (version<? OR (version=? AND index_profile<>?))",
            (card["tenant_id"], card["card_id"], card["version"], card["version"], profile),
        ).fetchall()

    def remove_chunks(self, point_ids: list[str]) -> None:
        with self.db:
            self.db.executemany(
                "DELETE FROM kb_chunks WHERE point_id=?", [(point_id,) for point_id in point_ids]
            )

    def keyword_search(
        self,
        query: str,
        *,
        tenant_id: str,
        profile: str,
        now: str,
        limit: int,
        category: str | None = None,
    ) -> list[sqlite3.Row]:
        if not query:
            return []
        sql = """SELECT ch.*,bm25(kb_chunk_fts) AS score FROM kb_chunk_fts
            JOIN kb_chunks ch ON ch.chunk_pk=kb_chunk_fts.rowid
            JOIN kb_cards c ON c.tenant_id=ch.tenant_id AND c.card_id=ch.card_id AND c.published_version=ch.version
            JOIN kb_card_versions v ON v.tenant_id=ch.tenant_id AND v.card_id=ch.card_id AND v.version=ch.version
            WHERE kb_chunk_fts MATCH ? AND ch.tenant_id=? AND ch.index_profile=?
            AND c.status='active' AND v.review_status='approved' AND v.valid_from<=?
            AND (v.valid_until IS NULL OR v.valid_until>?)"""
        args: list[Any] = [query, tenant_id, profile, now, now]
        if category:
            sql += " AND v.attack_category=?"
            args.append(category)
        sql += " ORDER BY score,ch.point_id LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    def withdraw(
        self, tenant_id: str, card_id: str, *, reviewed_by: str, reason: str
    ) -> list[sqlite3.Row]:
        """先停止可见，再返回需要清理的点；Qdrant 清理失败也不会放行已下架卡片。"""
        if not reviewed_by.strip() or not reason.strip():
            raise ValueError("下架需要审核人与原因")
        rows = self.db.execute(
            "SELECT * FROM kb_chunks WHERE tenant_id=? AND card_id=?", (tenant_id, card_id)
        ).fetchall()
        with self.db:
            header = self.db.execute(
                "SELECT published_version FROM kb_cards WHERE tenant_id=? AND card_id=?",
                (tenant_id, card_id),
            ).fetchone()
            if header is None:
                raise ValueError("卡片不存在")
            version = self.db.execute(
                "SELECT max(version) FROM kb_card_versions WHERE tenant_id=? AND card_id=?",
                (tenant_id, card_id),
            ).fetchone()[0]
            if version:
                self.db.execute(
                    "INSERT INTO kb_reviews VALUES(?,?,?,?,?,?,?,?)",
                    (
                        str(uuid4()),
                        tenant_id,
                        card_id,
                        version,
                        "withdrawn",
                        reason,
                        reviewed_by,
                        utc_now(),
                    ),
                )
            self.db.execute(
                "UPDATE kb_cards SET status='withdrawn',published_version=NULL,generation=generation+1,updated_at=? WHERE tenant_id=? AND card_id=?",
                (utc_now(), tenant_id, card_id),
            )
            self.db.execute(
                "DELETE FROM kb_chunks WHERE tenant_id=? AND card_id=?", (tenant_id, card_id)
            )
        return rows

    def close(self) -> None:
        self.db.close()
