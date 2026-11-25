"""知识检索适配层：把 ``src/knowledge`` 的混合检索接到 HTTP/MCP 工具上。

原则（Issue #18 / #31 / Week 3 RAG 接入）：

* **不另写检索系统**：真实模式直接调用 ``src.knowledge.search.hybrid_search``
  （BGE-small-zh-v1.5 dense + SQLite FTS5 BM25 + RRF），只做参数与字段映射；
* **不用固定答案冒充检索**：缺模型、缺 Qdrant、缺 SQLite 时抛
  :class:`KnowledgeUnavailable`，由 API 层转 503 并说明缺什么；
* **降级必须显式**：``SECLOG_SEARCH_MODE=lexical_fallback`` 时，用**源清单校验过的
  同一批知识卡**做词面检索（CJK 二元组 + 拉丁词），响应里标
  ``meta.degraded=true`` 与 ``retrieval_mode=lexical_fallback``，
  绝不冒充混合检索，也绝不静默从失败切换过来；
* Mock 只在显式 ``SECLOG_SEARCH_MODE=mock`` 时启用，且响应里必须标 ``mock=true``。

环境变量：

* ``SECLOG_SEARCH_MODE``：``auto``（默认，走真实混合检索） | ``lexical_fallback`` | ``mock``
* ``SECLOG_KNOWLEDGE_MANIFEST``：降级检索使用的来源清单，默认
  ``data/knowledge_cards/manifest.json``
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "knowledge_cards" / "manifest.json"

#: 允许透传给 hybrid_search 的过滤键（与 KnowledgeService.search 白名单一致）
_ALLOWED_FILTERS = {"attack_category", "log_sources", "tenant_id", "exclude_investigation_id", "exclude_scenario_ids", "knowledge_only"}

#: 知识卡 card_type 到对外枚举的兜底映射
_CARD_TYPES = {"security_knowledge", "verified_correct_case", "verified_error_revision"}


class KnowledgeUnavailable(RuntimeError):
    """混合检索不可用。``reason`` 直接透给调用方，便于定位是缺模型还是缺服务。"""

    def __init__(self, reason: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"知识检索不可用：{reason}")
        self.reason = reason
        self.details = details or {}


def resolve_mode(mode: str | None = None) -> str:
    return (mode or os.getenv("SECLOG_SEARCH_MODE", "auto")).strip().lower()


def _ensure_project_root_on_path() -> None:
    """``src.knowledge`` 用的是 ``src.xxx`` 绝对导入，需要项目根在 sys.path 上。"""
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def map_card(raw: dict[str, Any]) -> dict[str, Any]:
    """保留完整命中规则和对应来源，避免把整张历史案例带入调查。"""
    card_type = raw.get("card_type")
    if card_type not in _CARD_TYPES:
        card_type = "security_knowledge"
    indicators = raw.get("key_indicators") or []
    if isinstance(indicators, str):
        indicators = [indicators]
    rules = raw.get("analysis_rules") or []
    section = raw.get("matched_section")
    matched = [rule for rule in rules if section == f"analysis_rules.{rule['rule_id']}"]
    selected = (matched or rules)[:1]
    data_ids = {item for rule in selected for item in rule["data_ids"]}
    source_ids = {item for rule in selected for item in rule["source_ids"]}
    case = raw.get("case_details") or {}
    return {
        "card_id": str(raw.get("card_id") or ""),
        "version": raw.get("version"),
        "card_type": card_type,
        "title": str(raw.get("title") or ""),
        "attack_category": raw.get("attack_category"),
        "mitre_id": raw.get("mitre_id"),
        "key_indicators": [str(x) for x in indicators],
        "recommended_action": raw.get("recommended_action"),
        "score": float(raw.get("score") or 0.0),
        "investigation_steps": (raw.get("investigation_steps") or [])[:5],
        "analysis_rules": selected,
        "required_data": [
            item for item in raw.get("required_data", []) if item["data_id"] in data_ids
        ],
        "source_reference": raw.get("source_reference"),
        "sources": [item for item in raw.get("sources", []) if item["source_id"] in source_ids],
        "applicability_limits": (raw.get("applicability_limits") or [])[:3],
        "error_revision_note": raw.get("error_revision_note") or None,
        "corrected_steps": (case.get("corrected_steps") or [])[:5],
    }


# ---------------------------------------------------------------------------
# 词面降级检索（显式开启；用同一批源清单校验过的知识卡，不伪造结果）
# ---------------------------------------------------------------------------

#: 字段权重：标题与判别特征最能代表卡片主题，调查步骤次之
_FIELD_WEIGHTS: dict[str, float] = {
    "title": 3.0,
    "key_indicators": 2.0,
    "keywords": 2.0,
    "investigation_steps": 1.5,
    "error_revision_note": 1.0,
    "summary": 0.5,
}

_card_cache: dict[str, Any] = {"key": None, "cards": []}

_LATIN_TOKEN = re.compile(r"[a-z0-9_.+/#-]{2,}")


def _tokens(text: str) -> set[str]:
    """CJK 二元组 + 拉丁词。

    不引入分词依赖（降级场景本来就缺 sentence-transformers/jieba），
    二元组对中文安全术语足够区分，且完全确定、可复现。
    """
    lowered = (text or "").lower()
    latin = set(_LATIN_TOKEN.findall(lowered))
    chars = [ch for ch in lowered if "\u4e00" <= ch <= "\u9fff"]
    grams = {"".join(chars[index:index + 2]) for index in range(len(chars) - 1)}
    return latin | grams


def _load_manifest_cards(tenant_id: str) -> list[dict[str, Any]]:
    """按来源清单（SHA-256 白名单）加载全部知识卡；文件损坏即报错，不返回半套。"""
    manifest = Path(os.getenv("SECLOG_KNOWLEDGE_MANIFEST", DEFAULT_MANIFEST))
    if not manifest.is_file():
        raise KnowledgeUnavailable(
            f"知识卡来源清单不存在：{manifest}",
            details={"stage": "manifest", "path": str(manifest)},
        )
    key = (str(manifest), manifest.stat().st_mtime, tenant_id)
    if _card_cache["key"] == key:
        return _card_cache["cards"]

    _ensure_project_root_on_path()
    try:
        from src.knowledge.loader import SourceManifest  # noqa: PLC0415
    except Exception as exc:
        raise KnowledgeUnavailable(
            "导入来源清单加载器失败",
            details={"error": f"{type(exc).__name__}: {exc}", "stage": "import_loader"},
        ) from exc

    doc = json.loads(manifest.read_text(encoding="utf-8"))
    source = SourceManifest(manifest, PROJECT_ROOT)
    cards: list[dict[str, Any]] = []
    for relative in doc.get("files", {}):
        if doc["files"][relative].get("tenant_id") != tenant_id:
            continue
        path = PROJECT_ROOT / relative
        try:
            # 文件清单证明来源，案例审批和下架状态由 SQLite 管理。
            # 此降级后端仅读知识卡，案例只经正式索引返回。
            cards.extend(
                card for card in source.read(path, tenant_id)
                if card.get("card_type") == "security_knowledge"
                and card.get("dataset_split", "knowledge") == "knowledge"
            )
        except Exception as exc:
            raise KnowledgeUnavailable(
                f"知识卡 {relative} 未通过来源清单校验",
                details={"error": f"{type(exc).__name__}: {exc}", "stage": "load_card", "path": relative},
            ) from exc
    _card_cache.update({"key": key, "cards": cards})
    return cards


def _lexical_score(card: dict[str, Any], query_tokens: set[str]) -> float:
    if not query_tokens:
        return 0.0
    total = 0.0
    for field, weight in _FIELD_WEIGHTS.items():
        value = card.get(field)
        if isinstance(value, list):
            text = " ".join(str(item) for item in value)
        elif isinstance(value, dict):
            text = json.dumps(value, ensure_ascii=False)
        else:
            text = str(value or "")
        if not text:
            continue
        overlap = len(query_tokens & _tokens(text))
        total += weight * overlap / len(query_tokens)
    return min(total / sum(_FIELD_WEIGHTS.values()), 1.0)


def _lexical_search(
    query: str, *, top_k: int, filters: dict[str, Any]
) -> list[dict[str, Any]]:
    """在已校验的知识卡上做词面检索；只为"缺向量依赖时仍能跑通调查"而存在。"""
    _ensure_project_root_on_path()
    from src.knowledge.categories import categories_for  # noqa: PLC0415
    from src.knowledge.config import KnowledgeConfig  # noqa: PLC0415

    tenant_id = KnowledgeConfig.from_env().tenant_id
    if filters.get("tenant_id", tenant_id) != tenant_id:
        raise KnowledgeUnavailable("调用者不能扩大后台租户范围", details={"stage": "filters"})
    cards = _load_manifest_cards(tenant_id)
    wanted = set(categories_for(filters.get("attack_category")))
    excluded_scenarios = set(filters.get("exclude_scenario_ids") or [])
    excluded_investigation = filters.get("exclude_investigation_id")
    log_sources = set(filters.get("log_sources") or [])
    query_tokens = _tokens(query)

    scored: list[tuple[float, dict[str, Any]]] = []
    for card in cards:
        if filters.get("knowledge_only") and card.get("card_type") != "security_knowledge":
            continue
        origin = card.get("origin") or {}
        if excluded_investigation and origin.get("investigation_id") == excluded_investigation:
            continue
        if excluded_scenarios & set(origin.get("scenario_ids") or []):
            continue
        if wanted and card.get("attack_category") not in wanted:
            continue
        if log_sources and not (set(card.get("applicable_log_sources") or []) & log_sources):
            continue
        score = _lexical_score(card, query_tokens)
        if score <= 0:
            continue
        scored.append((score, card))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("card_id"))))
    picked: list[dict[str, Any]] = []
    for score, card in scored[:top_k]:
        enriched = dict(card)
        enriched["score"] = round(score, 4)
        picked.append(enriched)
    return picked


def search(
    query: str,
    *,
    top_k: int = 5,
    attack_category: str | None = None,
    filters: dict[str, Any] | None = None,
    mode: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """执行检索，返回 ``(cards, meta)``。

    ``meta`` 里带 ``retrieval_mode`` / ``degraded`` / ``backend`` 等标识，
    供调用方写进响应和审计：调用方必须能区分"检索失败""零命中""降级返回"。
    """
    selected = resolve_mode(mode)
    if selected == "mock":
        from .mock_data import search_mock_knowledge  # 延迟导入，避免循环依赖

        cards = search_mock_knowledge(query, attack_category)[:top_k]
        return cards, {
            "retrieval_mode": "mock",
            "mock": True,
            "degraded": False,
            "backend": "src/api/mock_data.py",
        }
    if selected == "lexical_fallback":
        merged_filters: dict[str, Any] = {
            k: v for k, v in (filters or {}).items() if k in _ALLOWED_FILTERS and v is not None
        }
        if attack_category:
            merged_filters.setdefault("attack_category", attack_category)
        cards = [map_card(card) for card in _lexical_search(query, top_k=top_k, filters=merged_filters)]
        return cards, {
            "retrieval_mode": "lexical_fallback",
            "mock": False,
            "degraded": True,
            "degraded_reason": "lexical_fallback explicitly configured",
            "backend": "data/knowledge_cards(manifest-verified)+lexical",
            "filters": merged_filters,
        }
    if selected != "auto":
        raise KnowledgeUnavailable(
            f"SECLOG_SEARCH_MODE 取值非法：{selected}（auto/lexical_fallback/mock）",
            details={"mode": selected},
        )

    merged: dict[str, Any] = {
        k: v for k, v in (filters or {}).items() if k in _ALLOWED_FILTERS and v is not None
    }
    if attack_category:
        merged.setdefault("attack_category", attack_category)

    _ensure_project_root_on_path()
    try:
        from src.knowledge.search import hybrid_search  # noqa: PLC0415
    except Exception as exc:  # 缺 sentence_transformers / qdrant_client 等
        raise KnowledgeUnavailable(
            "导入 src.knowledge.search 失败（通常缺 sentence-transformers / qdrant-client 依赖）",
            details={"error": f"{type(exc).__name__}: {exc}", "stage": "import"},
        ) from exc

    try:
        raw_cards = hybrid_search(query, top_k=top_k, filters=merged)
    except Exception as exc:
        raise KnowledgeUnavailable(
            "混合检索执行失败（检查 BGE 模型缓存、Qdrant 服务与 SQLite 知识库是否就绪）",
            details={
                "error": f"{type(exc).__name__}: {exc}",
                "stage": "search",
                "filters": merged,
                "hint": "BGE_MODEL_PATH / QDRANT_URL / KNOWLEDGE_SQLITE_PATH",
            },
        ) from exc

    cards = [map_card(c) for c in raw_cards]
    return cards, {
        "retrieval_mode": "hybrid",
        "mock": False,
        "degraded": False,
        "backend": "bge-small-zh-v1.5+qdrant+fts5+rrf",
        "filters": merged,
    }


def health() -> dict[str, Any]:
    """诊断用：报告检索链路各部分是否就绪（不实际执行检索）。"""
    status: dict[str, Any] = {"mode": resolve_mode()}
    _ensure_project_root_on_path()
    try:
        import src.knowledge.search as _search  # noqa: F401, PLC0415

        status["import"] = "ok"
    except Exception as exc:
        status["import"] = f"fail: {type(exc).__name__}: {exc}"
        return status
    try:
        from src.knowledge.config import KnowledgeConfig  # noqa: PLC0415

        cfg = KnowledgeConfig.from_env()
        status["config"] = {
            "model_path": cfg.model_path,
            "qdrant_url": cfg.qdrant_url,
            "qdrant_path": cfg.qdrant_path,
            "sqlite_path": cfg.sqlite_path,
            "tenant_id": cfg.tenant_id,
        }
        sqlite_file = PROJECT_ROOT / cfg.sqlite_path
        status["sqlite_exists"] = sqlite_file.exists()
    except Exception as exc:
        status["config"] = f"fail: {type(exc).__name__}: {exc}"
    return status
