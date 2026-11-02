"""读取知识库独立配置；与服务器共用 QDRANT_* 名称，避免改变其他模块。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MODEL_ID = "BAAI/bge-small-zh-v1.5"
VECTOR_SIZE = 512
COLLECTIONS = ("security_knowledge", "verified_cases")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class KnowledgeConfig:
    """本地路径与远端地址二选一；local 路径供离线开发，URL 供容器部署。"""

    sqlite_path: str = "work/knowledge.sqlite3"
    qdrant_path: str | None = None
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str | None = None
    model_path: str = MODEL_ID
    tenant_id: str = "default"
    knowledge_collection: str = COLLECTIONS[0]
    case_collection: str = COLLECTIONS[1]

    def __post_init__(self) -> None:
        if not self.tenant_id.strip():
            raise ValueError("tenant_id 不能为空")
        if self.knowledge_collection == self.case_collection:
            raise ValueError("知识与案例必须使用不同的 Qdrant 集合")

    @classmethod
    def from_env(cls) -> KnowledgeConfig:
        """配置名沿用底座约定；模型默认只读取本地 Hugging Face 缓存。"""
        return cls(
            sqlite_path=os.getenv("KNOWLEDGE_SQLITE_PATH", "work/knowledge.sqlite3"),
            qdrant_path=os.getenv("QDRANT_LOCAL_PATH") or None,
            qdrant_url=os.getenv("QDRANT_URL", "http://localhost:6333"),
            qdrant_api_key=os.getenv("QDRANT_API_KEY") or None,
            model_path=os.getenv("BGE_MODEL_PATH", MODEL_ID),
            tenant_id=os.getenv("KNOWLEDGE_TENANT_ID", "default"),
            knowledge_collection=os.getenv("QDRANT_KNOWLEDGE_COLLECTION", COLLECTIONS[0]),
            case_collection=os.getenv("QDRANT_CASE_COLLECTION", COLLECTIONS[1]),
        )
