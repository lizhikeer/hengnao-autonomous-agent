"""Qdrant 适配层：管理两个隔离集合、Payload 索引、幂等写入和受限语义查询。"""

from __future__ import annotations

from typing import Any

from qdrant_client import QdrantClient, models

from .config import VECTOR_SIZE, KnowledgeConfig
from .embedding import check_vectors


class VectorStore:
    """只封装本模块使用的操作；不删除或重建已存在的集合。"""

    def __init__(self, config: KnowledgeConfig, client: QdrantClient | None = None) -> None:
        self.config = config
        self.client = client or (
            QdrantClient(path=config.qdrant_path)
            if config.qdrant_path
            else QdrantClient(url=config.qdrant_url, api_key=config.qdrant_api_key, timeout=15)
        )

    def initialize(self) -> None:
        """连接已有集合时核对维度与距离；不兼容时明确失败，保护已有数据。"""
        for name in (self.config.knowledge_collection, self.config.case_collection):
            if not self.client.collection_exists(name):
                self.client.create_collection(
                    name,
                    vectors_config={
                        "dense": models.VectorParams(
                            size=VECTOR_SIZE, distance=models.Distance.COSINE
                        )
                    },
                )
            info = self.client.get_collection(name)
            vectors = info.config.params.vectors
            if not isinstance(vectors, dict) or "dense" not in vectors:
                raise ValueError(f"{name} 缺少 dense 命名向量")
            if (
                vectors["dense"].size != VECTOR_SIZE
                or vectors["dense"].distance != models.Distance.COSINE
            ):
                raise ValueError(f"{name} 与 small 的 512 维 Cosine 配置不兼容")
            fields = {
                "tenant_id": "keyword",
                "card_id": "keyword",
                "card_type": "keyword",
                "attack_category": "keyword",
                "mitre_id": "keyword",
                "applicable_log_sources": "keyword",
                "review_status": "keyword",
                "status": "keyword",
                "dataset_split": "keyword",
                "index_profile": "keyword",
                "version": "integer",
                "valid_from": "datetime",
                "valid_until": "datetime",
            }
            # 本地模式不构建 Payload 索引；部署服务模式时使用同一份正式索引定义。
            if not self.config.qdrant_path:
                for field, field_type in fields.items():
                    existing = info.payload_schema.get(field)
                    if existing is not None and existing.data_type != field_type:
                        raise ValueError(f"{name}.{field} 的 Payload 索引类型不兼容")
                    if existing is None:
                        self.client.create_payload_index(
                            name, field, field_schema=field_type, wait=True
                        )

    def collection(self, card_type: str) -> str:
        return (
            self.config.knowledge_collection
            if card_type == "security_knowledge"
            else self.config.case_collection
        )

    def upsert(
        self,
        card: dict[str, Any],
        chunks: list[dict[str, Any]],
        vectors: list[list[float]],
        profile: str,
    ) -> None:
        """只有 approved 版本可进入 Qdrant；发布可见性还由 SQLite 指针二次校验。"""
        if card["review_status"] != "approved":
            raise ValueError("未审核卡片禁止写入 Qdrant")
        vectors = check_vectors(vectors, len(chunks))
        metadata = {
            key: card[key]
            for key in (
                "tenant_id",
                "card_id",
                "version",
                "card_type",
                "attack_category",
                "mitre_id",
                "applicable_log_sources",
                "review_status",
                "valid_from",
                "valid_until",
                "dataset_split",
                "title",
                "source_reference",
            )
        }
        points = [
            models.PointStruct(
                id=chunk["point_id"],
                vector={"dense": vector},
                payload={
                    **metadata,
                    "status": "active",
                    "index_profile": profile,
                    "chunk_index": chunk["chunk_index"],
                    "section_path": chunk["section_path"],
                    "text": chunk["text"],
                },
            )
            for chunk, vector in zip(chunks, vectors, strict=True)
        ]
        # 批次受控，避免把整库载荷放进一次 HTTP 请求。
        for start in range(0, len(points), 64):
            self.client.upsert(
                self.collection(card["card_type"]), points=points[start : start + 64], wait=True
            )

    def search(
        self,
        vector: list[float],
        *,
        tenant_id: str,
        profile: str,
        now: str,
        limit: int,
        category: str | None = None,
    ) -> list[Any]:
        """两集合分别召回；有效期、租户与审核过滤由后台固定添加。"""
        check_vectors([vector], 1)
        conditions: list[Any] = [
            models.FieldCondition(key=key, match=models.MatchValue(value=value))
            for key, value in {
                "tenant_id": tenant_id,
                "review_status": "approved",
                "status": "active",
                "index_profile": profile,
            }.items()
        ]
        conditions.append(
            models.FieldCondition(
                key="dataset_split",
                match=models.MatchAny(any=["knowledge", "development", "production"]),
            )
        )
        conditions.append(
            models.FieldCondition(key="valid_from", range=models.DatetimeRange(lte=now))
        )
        conditions.append(
            models.Filter(
                should=[
                    models.IsNullCondition(is_null=models.PayloadField(key="valid_until")),
                    models.FieldCondition(key="valid_until", range=models.DatetimeRange(gt=now)),
                ]
            )
        )
        if category:
            conditions.append(
                models.FieldCondition(
                    key="attack_category", match=models.MatchValue(value=category)
                )
            )
        hits = []
        for name in (self.config.knowledge_collection, self.config.case_collection):
            hits.extend(
                self.client.query_points(
                    name,
                    query=vector,
                    using="dense",
                    query_filter=models.Filter(must=conditions),
                    limit=limit,
                    with_payload=True,
                    with_vectors=False,
                ).points
            )
        return sorted(hits, key=lambda hit: (-hit.score, str(hit.id)))

    def delete_points(self, point_ids: list[str], collection: str) -> None:
        if point_ids:
            self.client.delete(
                collection, points_selector=models.PointIdsList(points=point_ids), wait=True
            )

    def close(self) -> None:
        self.client.close()
