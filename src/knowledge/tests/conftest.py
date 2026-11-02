"""知识库独立夹具：使用临时数据库与明确标记的测试编码器，不依赖其他模块的 API。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.knowledge.config import PROJECT_ROOT, KnowledgeConfig
from src.knowledge.loader import SourceManifest
from src.knowledge.search import KnowledgeService


class FakeEncoder:
    """仅验证流程的人工向量，不用于报告 BGE 语义精度。"""

    profile = "test-only:512:v1"

    def split(self, text: str) -> list[str]:
        return [text]

    def count_tokens(self, text: str) -> int:
        return len(text)

    def encode_documents(self, texts: list[str]) -> list[list[float]]:
        return [self.encode_query(text) for text in texts]

    def encode_query(self, text: str) -> list[float]:
        index = 0 if "注入" in text or "UNION" in text else 1
        return [float(i == index) for i in range(512)]


@pytest.fixture
def service(tmp_path):
    instance = KnowledgeService(
        KnowledgeConfig(
            sqlite_path=str(tmp_path / "cards.sqlite3"), qdrant_path=str(tmp_path / "qdrant")
        ),
        encoder=FakeEncoder(),
    )
    yield instance
    instance.close()


@pytest.fixture
def card():
    return json.loads(
        (PROJECT_ROOT / "data/knowledge_cards/Brute_Force.json").read_text(encoding="utf-8")
    )[0]


def source_files(
    tmp_path: Path, cards: list[dict], *, split: str = "knowledge", tenant: str = "default"
):
    """测试来源清单也绑定真实文件哈希，走与命令行相同的入口。"""
    path = tmp_path / "cards.json"
    path.write_text(json.dumps(cards, ensure_ascii=False), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": {
                    "cards.json": {
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "tenant_id": tenant,
                        "dataset_split": split,
                        "card_ids": [card["card_id"] for card in cards],
                        "scenario_ids": cards[0].get("origin", {}).get("scenario_ids", []),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return [path], SourceManifest(manifest, tmp_path)
