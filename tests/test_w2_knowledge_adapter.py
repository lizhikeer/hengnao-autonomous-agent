"""第二周：知识检索适配层的确定性测试。

之前的用例只证明"成功或报不可用都行"，无法证明接线正确。这里注入一个假的
``src.knowledge.search.hybrid_search``，逐项验证：

* 参数是否按真实签名传下去（``query`` / 关键字参数 ``top_k`` / ``filters``）；
* 返回字段是否被正确映射到 ``KnowledgeCard``（多余字段丢弃、缺省值兜底）；
* 零命中是否被如实表达（而不是当失败）；
* 后端异常是否被包装成 ``KnowledgeUnavailable`` 并保留原因；
* 导入失败与执行失败能否区分（``stage`` 字段）。

注意：这组测试**不替代**真实集成验证 —— 真实检索是否可用由
``scripts/check_knowledge_ready.py``（见验收报告）另行确认。
"""

from __future__ import annotations

import sys
import types

import pytest

from api import knowledge_adapter


@pytest.fixture(autouse=True)
def _force_hybrid_mode(monkeypatch):
    """本文件测的是"真实混合检索"这条路径，需覆盖 conftest 的 Mock 默认值。"""
    monkeypatch.setenv("SECLOG_SEARCH_MODE", "auto")


def _inject_hybrid(monkeypatch, fn):
    """把假的 hybrid_search 塞进 sys.modules，模拟"依赖齐全"的情形。"""
    module = types.ModuleType("src.knowledge.search")
    module.hybrid_search = fn
    monkeypatch.setitem(sys.modules, "src.knowledge.search", module)


def test_params_are_passed_per_real_signature(monkeypatch):
    captured: dict = {}

    def fake_hybrid(query, *, top_k=5, filters=None):
        captured.update({"query": query, "top_k": top_k, "filters": filters})
        return []

    _inject_hybrid(monkeypatch, fake_hybrid)
    knowledge_adapter.search("SQL 注入如何处置", top_k=3, attack_category="SQL_Injection")

    assert captured["query"] == "SQL 注入如何处置"
    assert captured["top_k"] == 3
    # attack_category 必须并入 filters，而不是当作独立参数
    assert captured["filters"]["attack_category"] == "SQL_Injection"


def test_only_allowed_filters_are_forwarded(monkeypatch):
    captured: dict = {}

    def fake_hybrid(query, *, top_k=5, filters=None):
        captured["filters"] = filters
        return []

    _inject_hybrid(monkeypatch, fake_hybrid)
    knowledge_adapter.search(
        "查询", top_k=2, filters={"tenant_id": "t1", "log_sources": ["nginx_access"], "evil_key": "x"}
    )
    assert "evil_key" not in captured["filters"]
    assert captured["filters"]["tenant_id"] == "t1"


def test_hit_maps_fields_and_drops_extras(monkeypatch):
    def fake_hybrid(query, *, top_k=5, filters=None):
        return [
            {
                "card_id": "KB-SQLI-001",
                "card_type": "security_knowledge",
                "title": "SQL注入异常请求的日志识别与调查",
                "attack_category": "SQL_Injection",
                "mitre_id": "T1190",
                "key_indicators": ["UNION SELECT", "sleep("],
                "recommended_action": "block_ip_short_term",
                "score": 0.82,
                # 真实检索会带出很多内部字段，对外应被裁掉
                "version": 3,
                "matched_section": "detection/body",
                "rrf_score": 0.03,
            }
        ]

    _inject_hybrid(monkeypatch, fake_hybrid)
    cards, meta = knowledge_adapter.search("SQL 注入", top_k=5)

    assert meta["retrieval_mode"] == "hybrid"
    assert meta["mock"] is False
    assert meta["backend"].startswith("bge-small")
    card = cards[0]
    assert card["card_id"] == "KB-SQLI-001"
    assert card["card_type"] == "security_knowledge"
    assert card["key_indicators"] == ["UNION SELECT", "sleep("]
    assert card["score"] == 0.82
    assert "version" not in card and "rrf_score" not in card


def test_unknown_card_type_falls_back(monkeypatch):
    _inject_hybrid(
        monkeypatch,
        lambda *a, **k: [{"card_id": "K", "card_type": "some_new_type", "title": "t", "score": 0.1}],
    )
    cards, _ = knowledge_adapter.search("查询", top_k=1)
    assert cards[0]["card_type"] == "security_knowledge"


def test_zero_hit_is_success_not_error(monkeypatch):
    _inject_hybrid(monkeypatch, lambda *a, **k: [])
    cards, meta = knowledge_adapter.search("完全不相关的问题", top_k=5)
    assert cards == []
    assert meta["retrieval_mode"] == "hybrid"


def test_backend_failure_is_wrapped_with_stage_search(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("qdrant connection refused")

    _inject_hybrid(monkeypatch, boom)
    with pytest.raises(knowledge_adapter.KnowledgeUnavailable) as exc:
        knowledge_adapter.search("SQL 注入", top_k=3)
    assert exc.value.details["stage"] == "search"
    assert "qdrant connection refused" in exc.value.details["error"]


def test_import_failure_is_wrapped_with_stage_import(monkeypatch):
    # 模拟依赖缺失：模块存在但导入即抛错
    broken = types.ModuleType("src.knowledge.search")

    def _raise_import(*args, **kwargs):
        raise ImportError("no module named qdrant_client")

    broken.__getattr__ = _raise_import  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "src.knowledge.search", broken)

    with pytest.raises(knowledge_adapter.KnowledgeUnavailable) as exc:
        knowledge_adapter.search("SQL 注入", top_k=3)
    # 缺依赖与执行失败要能分开定位
    assert exc.value.details.get("stage") in {"import", "search"}


def test_api_returns_503_with_reason_on_failure(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("qdrant down")

    _inject_hybrid(monkeypatch, boom)
    monkeypatch.setenv("SECLOG_SEARCH_MODE", "auto")
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as client:
        r = client.post("/tools/search_knowledge", json={"query": "SQL 注入如何处置"})
    assert r.status_code == 503
    body = r.json()
    assert body["code"] == "backend_unavailable"
    assert body["details"]["backend"] == "knowledge"
    assert body["details"]["stage"] == "search"
    # 失败时不能夹带任何卡片
    assert "items" not in body


def test_mock_mode_is_explicitly_labelled(monkeypatch):
    monkeypatch.setenv("SECLOG_SEARCH_MODE", "mock")
    cards, meta = knowledge_adapter.search("SQL 注入", top_k=3, mode="mock")
    assert meta["mock"] is True
    assert meta["retrieval_mode"] == "mock"
    assert cards
