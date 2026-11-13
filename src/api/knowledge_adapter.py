"""知识检索适配层：把 ``src/knowledge`` 的混合检索接到 HTTP/MCP 工具上。

原则（Issue #18）：

* **不另写检索系统**：真实模式直接调用 ``src.knowledge.search.hybrid_search``
  （BGE-small-zh-v1.5 dense + SQLite FTS5 BM25 + RRF），只做参数与字段映射；
* **不用固定答案冒充检索**：缺模型、缺 Qdrant、缺 SQLite 时抛
  :class:`KnowledgeUnavailable`，由 API 层转 503 并说明缺什么；
* Mock 只在显式 ``SECLOG_SEARCH_MODE=mock`` 时启用，且响应里必须标 ``mock=true``。

环境变量：

* ``SECLOG_SEARCH_MODE``：``auto``（默认，走真实混合检索） | ``mock``
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]

#: 允许透传给 hybrid_search 的过滤键（与 KnowledgeService.search 白名单一致）
_ALLOWED_FILTERS = {"attack_category", "log_sources", "tenant_id", "exclude_investigation_id", "exclude_scenario_ids"}

#: 知识卡 card_type 到对外枚举的兜底映射
_CARD_TYPES = {"security_knowledge", "verified_correct_case", "verified_error_revision"}


class KnowledgeUnavailable(RuntimeError):
    """混合检索不可用。``reason`` 直接透给调用方，便于定位是缺模型还是缺服务。"""

    def __init__(self, reason: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"知识检索不可用：{reason}")
        self.reason = reason
        self.details = details or {}


def resolve_mode(mode: Optional[str] = None) -> str:
    return (mode or os.getenv("SECLOG_SEARCH_MODE", "auto")).strip().lower()


def _ensure_project_root_on_path() -> None:
    """``src.knowledge`` 用的是 ``src.xxx`` 绝对导入，需要项目根在 sys.path 上。"""
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def map_card(raw: dict[str, Any]) -> dict[str, Any]:
    """把检索返回的原始卡片收敛到 ``KnowledgeCard`` 的字段。

    只做字段映射与类型兜底，不改写内容——检索到什么就返回什么。
    """
    card_type = raw.get("card_type")
    if card_type not in _CARD_TYPES:
        card_type = "security_knowledge"
    indicators = raw.get("key_indicators") or []
    if isinstance(indicators, str):
        indicators = [indicators]
    return {
        "card_id": str(raw.get("card_id") or ""),
        "card_type": card_type,
        "title": str(raw.get("title") or ""),
        "attack_category": raw.get("attack_category"),
        "mitre_id": raw.get("mitre_id"),
        "key_indicators": [str(x) for x in indicators],
        "recommended_action": raw.get("recommended_action"),
        "score": float(raw.get("score") or 0.0),
    }


def search(
    query: str,
    *,
    top_k: int = 5,
    attack_category: Optional[str] = None,
    filters: Optional[dict[str, Any]] = None,
    mode: Optional[str] = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """执行检索，返回 ``(cards, meta)``。

    ``meta`` 里带 ``retrieval_mode`` / ``backend`` 等标识，供调用方写进响应和审计。
    """
    selected = resolve_mode(mode)
    if selected == "mock":
        from .mock_data import search_mock_knowledge  # 延迟导入，避免循环依赖

        cards = search_mock_knowledge(query, attack_category)[:top_k]
        return cards, {"retrieval_mode": "mock", "mock": True, "backend": "src/api/mock_data.py"}
    if selected != "auto":
        raise KnowledgeUnavailable(
            f"SECLOG_SEARCH_MODE 取值非法：{selected}（auto/mock）",
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
