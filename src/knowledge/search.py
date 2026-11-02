"""知识服务：受控入库、候选隔离、语义/BM25 召回、RRF 合并和原文恢复。"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from src.memory.knowledge_store import KnowledgeStore

from .config import KnowledgeConfig
from .embedding import BGEEncoder, Encoder
from .loader import SourceManifest
from .qdrant_client import VectorStore
from .schema import CardValidator, canonical_hash, normalize_card, utc_now
from .text import match_query, sections, terms


def reciprocal_rank_fusion(rankings: list[list[str]]) -> list[tuple[str, float]]:
    """按名次融合，避免直接相加含义不同的余弦距离与 BM25 原始分数。"""
    scores: dict[str, float] = defaultdict(float)
    for ranking in rankings:
        for rank, key in enumerate(dict.fromkeys(ranking), start=1):
            scores[key] += 1 / (60 + rank)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


class KnowledgeService:
    """由后端为每个可信租户创建实例；写操作只给管理员脚本，不注册给普通 Agent。"""

    def __init__(
        self,
        config: KnowledgeConfig,
        *,
        encoder: Encoder | None = None,
        vectors: VectorStore | None = None,
    ) -> None:
        self.config = config
        self.store = KnowledgeStore(config.sqlite_path)
        self.vectors = vectors or VectorStore(config)
        self.validator = CardValidator()
        self._encoder = encoder

    @property
    def encoder(self) -> Encoder:
        # 校验、候选存储、集合初始化不需要加载模型，减少启动开销。
        if self._encoder is None:
            self._encoder = BGEEncoder(self.config.model_path)
        return self._encoder

    def ingest_files(
        self, paths: list[Path], *, manifest: SourceManifest, reviewed_by: str | None = None
    ) -> list[dict[str, Any]]:
        """所有来源和卡片先预检；显式 reviewed_by 表示维护者批准此次导入。"""
        cards = []
        for path in paths:
            for raw in manifest.read(path, self.config.tenant_id):
                card = normalize_card(raw, tenant_id=self.config.tenant_id, reviewed_by=reviewed_by)
                self.validator.validate(card)
                cards.append(card)
        identities = {(card["tenant_id"], card["card_id"], card["version"]) for card in cards}
        if len(identities) != len(cards):
            raise ValueError("同一次导入包含重复卡片版本")
        # 版本冲突也在写入前检查，避免格式错误使整批只导入一半。
        for card in cards:
            previous = self.store.get(card["tenant_id"], card["card_id"], card["version"])
            if previous and canonical_hash(previous) != canonical_hash(card):
                raise ValueError(f"{card['card_id']} 同版本内容冲突，请增加 version")
            if (
                previous
                and previous["review_status"] == "approved"
                and card["review_status"] != "approved"
            ):
                raise ValueError("已批准版本不能降回候选；请提交新版本")
        self.vectors.initialize()
        return [self._ingest(card) for card in cards]

    def _ingest(self, card: dict[str, Any]) -> dict[str, Any]:
        duplicate = self.store.duplicate(card)
        if duplicate is not None:
            # 新文件的批准操作不改变另一编号的审核状态，重复内容交由管理员沿用已有条目。
            return {
                "card_id": card["card_id"],
                "status": "duplicate",
                "points": 0,
                "duplicate_of": duplicate["card_id"],
                "existing_review_status": duplicate["review_status"],
            }
        self.store.save(card)
        result = {
            "card_id": card["card_id"],
            "version": card["version"],
            "status": "pending",
            "points": 0,
        }
        if card["review_status"] != "approved":
            return result
        now = utc_now()
        if card["valid_from"] > now or (
            card["valid_until"] is not None and card["valid_until"] <= now
        ):
            return {**result, "status": "outside_validity"}
        profile = self.encoder.profile
        generation, job = self.store.begin_publish(card, profile)
        try:
            chunks = []
            for section_path, text in sections(card):
                for part in self.encoder.split(text):
                    number = len(chunks)
                    # JSON 序列化身份避免拼接字符串的分隔符碰撞。
                    identity = json.dumps(
                        [card["tenant_id"], card["card_id"], card["version"], profile, number]
                    )
                    chunks.append(
                        {
                            "point_id": str(uuid5(NAMESPACE_URL, identity)),
                            "chunk_index": number,
                            "collection_name": self.vectors.collection(card["card_type"]),
                            "section_path": section_path,
                            "text": part,
                            "search_text": " ".join(
                                terms(
                                    " ".join(
                                        [
                                            part,
                                            card["attack_category"],
                                            card.get("mitre_id") or "",
                                            card["source_reference"],
                                            *card.get("keywords", []),
                                        ]
                                    )
                                )
                            ),
                            "token_count": self.encoder.count_tokens(part),
                        }
                    )
            encoded = self.encoder.encode_documents([chunk["text"] for chunk in chunks])
            self.vectors.upsert(card, chunks, encoded, profile)
            self.store.publish(card, chunks, profile, generation, job)
        except Exception as exc:
            self.store.fail_job(job, exc)
            raise
        result.update(status="published", points=len(chunks))
        obsolete = self.store.obsolete_chunks(card, profile)
        try:
            for collection in {row["collection_name"] for row in obsolete}:
                ids = [row["point_id"] for row in obsolete if row["collection_name"] == collection]
                self.vectors.delete_points(ids, collection)
                self.store.remove_chunks(ids)
        except Exception as exc:
            # 发布已经成功；清理失败保留旧分块，重复导入时继续清理，不误报发布失败。
            result["cleanup_pending"] = type(exc).__name__
        return result

    def search(
        self, query: str, *, top_k: int = 5, filters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """最终返回前复查 SQLite 发布版本；旧 Qdrant 点不会越过审核、下架和租户边界。"""
        if not isinstance(query, str) or not 2 <= len(query.strip()) <= 500:
            raise ValueError("query 长度必须在 2~500 之间")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 20:
            raise ValueError("top_k 必须为 1~20 的整数")
        if filters is not None and not isinstance(filters, dict):
            raise ValueError("filters 必须是对象")
        filters = filters or {}
        allowed = {
            "tenant_id",
            "attack_category",
            "log_sources",
            "exclude_investigation_id",
            "exclude_scenario_ids",
        }
        if set(filters) - allowed:
            raise ValueError("不支持的检索过滤参数")
        if filters.get("tenant_id", self.config.tenant_id) != self.config.tenant_id:
            raise ValueError("调用者不能扩大后台租户范围")
        category = filters.get("attack_category")
        if category is not None and not isinstance(category, str):
            raise ValueError("attack_category 必须是字符串")
        if filters.get("exclude_investigation_id") is not None and not isinstance(
            filters["exclude_investigation_id"], str
        ):
            raise ValueError("exclude_investigation_id 必须是字符串")
        for name in ("log_sources", "exclude_scenario_ids"):
            if name in filters and (
                not isinstance(filters[name], list)
                or any(not isinstance(value, str) for value in filters[name])
            ):
                raise ValueError(f"{name} 必须是字符串数组")
        vector, now, profile = self.encoder.encode_query(query), utc_now(), self.encoder.profile
        # 旧点清理可能滞后；有限扩大候选池，补足被最终复核排除的结果。
        depth = max(20, top_k * 2)
        while True:
            dense = self.vectors.search(
                vector,
                tenant_id=self.config.tenant_id,
                profile=profile,
                now=now,
                limit=depth,
                category=category,
            )
            lexical = self.store.keyword_search(
                match_query(query),
                tenant_id=self.config.tenant_id,
                profile=profile,
                now=now,
                limit=depth * 2,
                category=category,
            )
            dense_ids, lexical_ids, candidates = [], [], {}
            for hit in dense:
                key = str(hit.id)
                dense_ids.append(key)
                candidates[key] = hit.payload
            for hit in lexical:
                key = hit["point_id"]
                lexical_ids.append(key)
                candidates[key] = dict(hit)
            results = []
            seen = set()
            for key, score in reciprocal_rank_fusion([dense_ids, lexical_ids]):
                item = candidates[key]
                identity = (item["card_id"], item["version"])
                if identity in seen or not self.store.visible(
                    self.config.tenant_id, *identity, now
                ):
                    continue
                card = self.store.get(self.config.tenant_id, *identity)
                if card is None or not self._in_scope(card, filters):
                    continue
                seen.add(identity)
                # 原文恢复包括完整条件、步骤、来源与错误修订，避免返回 tokenizer 截断片段。
                results.append(
                    {
                        **card,
                        "score": min(score / (2 / 61), 1.0),
                        "rrf_score": score,
                        "matched_section": item["section_path"],
                    }
                )
                if len(results) == top_k:
                    break
            if len(results) >= top_k or depth >= 200:
                return results
            depth = min(depth * 2, 200)

    @staticmethod
    def _in_scope(card: dict[str, Any], filters: dict[str, Any]) -> bool:
        sources = set(card["applicable_log_sources"])
        requested = set(filters.get("log_sources", []))
        if sources and requested and not sources & requested:
            return False
        origin = card.get("origin", {})
        if (
            filters.get("exclude_investigation_id")
            and origin.get("investigation_id") == filters["exclude_investigation_id"]
        ):
            return False
        return not set(origin.get("scenario_ids", [])) & set(
            filters.get("exclude_scenario_ids", [])
        )

    def withdraw(self, card_id: str, *, reviewed_by: str, reason: str) -> None:
        rows = self.store.withdraw(
            self.config.tenant_id, card_id, reviewed_by=reviewed_by, reason=reason
        )
        for collection in {row["collection_name"] for row in rows}:
            self.vectors.delete_points(
                [row["point_id"] for row in rows if row["collection_name"] == collection],
                collection,
            )

    def close(self) -> None:
        self.store.close()
        self.vectors.close()


def hybrid_search(query: str, *, top_k: int = 5, filters: dict | None = None) -> list[dict]:
    """保留基础设施约定的函数签名，供接口负责人封装到 FastAPI/MCP。"""
    service = KnowledgeService(KnowledgeConfig.from_env())
    try:
        service.vectors.initialize()
        return service.search(query, top_k=top_k, filters=filters)
    finally:
        service.close()
