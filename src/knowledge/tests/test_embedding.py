"""编码测试：验证 small 查询前缀、归一化、分块长度及可选真实模型端到端检索。"""

from __future__ import annotations

import os
from types import SimpleNamespace

import numpy as np
import pytest

from src.knowledge.config import PROJECT_ROOT, KnowledgeConfig
from src.knowledge.embedding import QUERY_PREFIX, BGEEncoder
from src.knowledge.loader import SourceManifest
from src.knowledge.search import KnowledgeService


class TokenizerStub:
    """字符级假 tokenizer 只用于长度/前缀断言，不用于真实语义检索。"""

    def encode(self, text, add_special_tokens=True):
        return [ord(char) for char in text] + ([0, 0] if add_special_tokens else [])

    def decode(self, ids, skip_special_tokens=True):
        return "".join(chr(item) for item in ids)

    def num_special_tokens_to_add(self, pair=False):
        return 2


class ModelStub:
    max_seq_length = 512
    tokenizer = TokenizerStub()

    def __init__(self):
        self.inputs = []

    def __getitem__(self, key):
        return SimpleNamespace(
            auto_model=SimpleNamespace(
                config=SimpleNamespace(hidden_size=512, num_hidden_layers=4, _commit_hash="test")
            )
        )

    def get_sentence_embedding_dimension(self):
        return 512

    def encode(self, texts, **kwargs):
        self.inputs.extend(texts)
        return np.ones((len(texts), 512))


def test_encoder_prefix_length_and_normalization():
    model = ModelStub()
    encoder = BGEEncoder(model=model)
    query = encoder.encode_query("登录失败后成功")
    encoder.encode_documents(["登录知识正文"])
    assert model.inputs == [QUERY_PREFIX + "登录失败后成功", "登录知识正文"]
    assert np.linalg.norm(query) == pytest.approx(1)
    assert encoder.count_tokens("abc") == 5
    assert all(encoder.count_tokens(text) <= 512 for text in encoder.split("中文调查" * 400))
    with pytest.raises(ValueError, match="超过"):
        encoder.encode_documents(["中" * 511])
    with pytest.raises(ValueError):
        encoder.encode_query("中" * 500)


@pytest.mark.skipif(
    not os.getenv("BGE_MODEL_PATH"), reason="设置 BGE_MODEL_PATH 后执行真实 small 联调"
)
def test_real_small_ingest_and_hybrid_search(tmp_path):
    """实际编码至少三张现有卡，验证集合持久化与重启后的真实查询。"""
    config = KnowledgeConfig(
        sqlite_path=str(tmp_path / "cards.sqlite3"),
        qdrant_path=str(tmp_path / "qdrant"),
        model_path=os.environ["BGE_MODEL_PATH"],
    )
    manifest = SourceManifest(PROJECT_ROOT / "data/knowledge_cards/manifest.json", PROJECT_ROOT)
    paths = [
        PROJECT_ROOT / "data/knowledge_cards" / name
        for name in ("SQL_Injection.json", "Brute_Force.json", "File_Upload_Traversal.json")
    ]
    service = KnowledgeService(config)
    try:
        # 仅批准临时测试库的副本，源文件及来源清单保持原样。
        report = service.ingest_files(paths, manifest=manifest, reviewed_by="integration-test")
        assert len(report) >= 3
        assert all(item["status"] == "published" and item["points"] > 0 for item in report)
        sql = service.search("UNION SELECT 请求返回 200，怎样确认数据库数据是否被读出", top_k=3)
        assert any(item["attack_category"] == "SQL_Injection" for item in sql)
        login = service.search("有人反复猜测密码，后来成功登入，应继续核查哪些线索", top_k=3)
        assert any(item["attack_category"] == "Brute_Force" for item in login)
        assert all(item["source_reference"] and item["investigation_steps"] for item in sql + login)
        assert service.vectors.client.count("verified_cases").count == 0
    finally:
        service.close()
    reopened = KnowledgeService(config)
    try:
        assert reopened.search("目录遍历读取文件", top_k=3)
    finally:
        reopened.close()
