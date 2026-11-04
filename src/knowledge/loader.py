"""受控文件导入：读取 JSON/Markdown，通过可信来源清单隔离评测内容与未知来源。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml


class SourceManifest:
    """清单由维护者管理，采用文件 SHA-256 白名单，Agent 不能自行指定数据划分。"""

    def __init__(self, path: Path, root: Path) -> None:
        self.root = root.resolve()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        self.files = manifest["files"]
        self.excluded_scenarios = set(manifest.get("excluded_scenario_ids", []))

    def read(self, path: Path, tenant_id: str) -> list[dict[str, Any]]:
        """先验证文件路径、摘要与可信来源，再解析卡片，整个文件有误时不做部分导入。"""
        resolved = path.resolve()
        if not resolved.is_relative_to(self.root):
            raise ValueError("文件超出允许的导入根目录")
        relative = resolved.relative_to(self.root).as_posix()
        record = self.files.get(relative)
        if not record or record.get("dataset_split") not in {
            "knowledge",
            "development",
            "production",
        }:
            raise ValueError("来源不在知识/开发/生产白名单中，禁止导入")
        if record.get("tenant_id") != tenant_id:
            raise ValueError("来源清单中的租户不匹配")
        content = resolved.read_bytes()
        if hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise ValueError("文件内容发生变化，请维护者重新核对来源清单")
        cards = parse_cards(content.decode("utf-8-sig"), resolved.suffix)
        expected = set(record.get("card_ids", []))
        if {card.get("card_id") for card in cards} != expected or len(cards) != len(expected):
            raise ValueError("文件卡片编号与来源清单不一致或包含重复卡片")
        for card in cards:
            split = card.get("dataset_split", "knowledge")
            if split != record["dataset_split"]:
                raise ValueError("卡片数据划分与可信来源不符")
            scenarios = set(card.get("origin", {}).get("scenario_ids", []))
            if (
                scenarios != set(record.get("scenario_ids", []))
                or scenarios & self.excluded_scenarios
            ):
                raise ValueError("案例场景未获来源清单授权或属于独立评测")
        return cards


def parse_cards(text: str, suffix: str) -> list[dict[str, Any]]:
    """Markdown 接受 JSON 代码块，或 YAML 元数据加正文；正文作为旧卡的 summary。"""
    text = text.replace("\r\n", "\n")
    if suffix.lower() == ".json":
        value = json.loads(text)
    elif suffix.lower() == ".md":
        block = re.search(r"```json\s*\n(.*?)\n```", text, re.DOTALL)
        if block:
            value = json.loads(block.group(1))
        elif text.startswith("---\n"):
            parts = text.split("\n---", 1)
            if len(parts) != 2:
                raise ValueError("Markdown 缺少 YAML 元数据结束标记")
            value = yaml.safe_load(parts[0][4:])
            if isinstance(value, dict) and parts[1].strip():
                value["summary"] = parts[1].strip()
        else:
            raise ValueError("Markdown 需要 JSON 代码块或 YAML 元数据")
    else:
        raise ValueError("仅支持 .json 与 .md 卡片")
    cards = value if isinstance(value, list) else [value]
    if not cards or any(not isinstance(card, dict) for card in cards):
        raise ValueError("卡片文件需要对象或非空对象数组")
    return cards
