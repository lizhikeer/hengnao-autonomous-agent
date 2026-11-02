"""卡片契约：兼容首周现有知识卡，严格校验 1.1 卡片、来源及证据引用。"""

from __future__ import annotations

import copy
import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .config import PROJECT_ROOT


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_hash(card: dict[str, Any]) -> str:
    """内容哈希不包含审批元数据，允许同一候选版本被人工审核后发布。"""
    ignored = {
        "tenant_id",
        "card_id",
        "version",
        "created_at",
        "updated_at",
        "review_status",
        "reviewed_by",
        "reviewed_at",
    }
    body = {key: value for key, value in card.items() if key not in ignored}
    # 引用集合的顺序不代表调查顺序；SQLite 读取顺序不能使同一案例被误判为内容变化。
    if "evidence_refs" in body:
        body["evidence_refs"] = sorted(body["evidence_refs"], key=lambda item: item["evidence_id"])
    text = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = unicodedata.normalize("NFC", text.replace("\r\n", "\n"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_card(
    raw: dict[str, Any], *, tenant_id: str, reviewed_by: str | None = None
) -> dict[str, Any]:
    """旧卡只补存储元数据，不编造调查规则；默认导入为候选，审批由管理入口明确授权。"""
    card = copy.deepcopy(raw)
    if not isinstance(card, dict):
        raise ValueError("每张卡片必须是 JSON 对象")
    if card.get("tenant_id", tenant_id) != tenant_id:
        raise ValueError("卡片 tenant_id 与导入范围不符")
    if card.get("review_status", "pending") not in {"pending", "approved", "rejected"}:
        raise ValueError("不支持的审核状态")
    if "schema_version" not in card:
        card.update(schema_version="1.0", tenant_id=tenant_id)
        card.setdefault("version", 1)
        card.setdefault("valid_from", "1970-01-01T00:00:00.000Z")
        card.setdefault("valid_until", None)
        card.setdefault("created_at", utc_now())
        card.setdefault("updated_at", card["created_at"])
        card.setdefault("dataset_split", "knowledge")
        card.setdefault("keywords", [])
    if reviewed_by:
        if not reviewed_by.strip():
            raise ValueError("审核人不能为空")
        card.update(review_status="approved", reviewed_by=reviewed_by, reviewed_at=utc_now())
    else:
        # 文件内的 approved 声明不能替代发布权限；普通导入和 Agent 提交均保持隔离。
        card.update(review_status="pending", reviewed_by=None, reviewed_at=None)
    return card


class CardValidator:
    """JSON Schema 校验结构；额外检查唯一 ID、跨字段引用、有效期及证据摘录哈希。"""

    def __init__(self, schema_dir: Path | None = None) -> None:
        schema_dir = schema_dir or PROJECT_ROOT / "design" / "knowledge"
        full = json.loads((schema_dir / "card.schema.json").read_text(encoding="utf-8"))
        legacy = json.loads((schema_dir / "legacy-card.schema.json").read_text(encoding="utf-8"))
        self.validators = {}
        for version, schema in (("1.0", legacy), ("1.1", full)):
            Draft202012Validator.check_schema(schema)
            self.validators[version] = Draft202012Validator(schema, format_checker=FormatChecker())

    def validate(self, card: dict[str, Any]) -> None:
        version = card.get("schema_version")
        if version not in self.validators:
            raise ValueError("不支持的 schema_version")
        errors = sorted(
            self.validators[version].iter_errors(card), key=lambda error: str(error.path)
        )
        if errors:
            error = errors[0]
            path = ".".join(str(part) for part in error.path) or "card"
            raise ValueError(f"{path}: {error.message}")
        if card["valid_until"] is not None and card["valid_until"] <= card["valid_from"]:
            raise ValueError("valid_until 必须晚于 valid_from")
        if card["dataset_split"] not in {"knowledge", "development", "production"}:
            raise ValueError("独立评测内容禁止进入知识存储")
        data_ids = self._ids(card.get("required_data", []), "data_id")
        source_ids = self._ids(card.get("sources", []), "source_id")
        rules = card.get("analysis_rules", [])
        rule_ids = self._ids(rules, "rule_id")
        for rule in rules:
            if not set(rule["data_ids"]) <= data_ids or not set(rule["source_ids"]) <= source_ids:
                raise ValueError("规则包含不存在的数据或来源引用")
        evidence = card.get("evidence_refs", [])
        evidence_ids = self._ids(evidence, "evidence_id")
        for item in evidence:
            expected = hashlib.sha256(item["snapshot_summary"].encode("utf-8")).hexdigest()
            if expected != item["snapshot_sha256"]:
                raise ValueError("证据摘要与 snapshot_sha256 不匹配")
        steps = card.get("case_details", {}).get("investigation_trace", [])
        self._ids(steps, "step_id")
        for step in steps:
            if (
                not set(step["rule_ids"]) <= rule_ids
                or not set(step["evidence_ids"]) <= evidence_ids
            ):
                raise ValueError("调查步骤包含不存在的规则或证据引用")

    @staticmethod
    def _ids(items: list[dict[str, Any]], key: str) -> set[str]:
        values = {item[key] for item in items}
        if len(values) != len(items):
            raise ValueError(f"{key} 重复")
        return values
