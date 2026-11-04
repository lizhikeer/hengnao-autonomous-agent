"""检索文本组织：恢复完整规则所需定位，并统一中文分词、术语别名及 MATCH 转义。"""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from typing import Any

import jieba

# 可在这里扩展本站术语；索引 profile 中的 lex 版本应随分词规则一起升级。
ALIASES = {
    "sqli": ("sql injection", "sql注入", "sql 注入"),
    "xss": ("跨站脚本",),
    "brute_force": ("brute force", "密码爆破", "暴力破解"),
    "path_traversal": ("路径遍历", "目录遍历"),
    "webshell": ("恶意上传", "网页后门"),
}


@lru_cache(maxsize=1)
def _tokenizer() -> jieba.Tokenizer:
    tokenizer = jieba.Tokenizer()
    for words in ALIASES.values():
        for word in words:
            tokenizer.add_word(word)
    return tokenizer


def terms(text: str) -> list[str]:
    """同样的入库/查询分词逻辑；编号原值以短语保留，不丢掉中间的连接符。"""
    normalized = unicodedata.normalize("NFC", text).casefold()
    words = [word.strip() for word in _tokenizer().cut(normalized) if re.search(r"\w", word)]
    words.extend(re.findall(r"[a-z0-9]+(?:[-_./:][a-z0-9]+)+", normalized))
    for canonical, aliases in ALIASES.items():
        if canonical in normalized or any(alias in normalized for alias in aliases):
            words.extend((canonical, *aliases))
    return list(dict.fromkeys(words))


def match_query(text: str) -> str:
    """仅从词项构造 OR 表达式，用户引号和运算符只能作为文字参与匹配。"""
    return " OR ".join('"' + term.replace('"', '""') + '"' for term in terms(text)[:64])


def sections(card: dict[str, Any]) -> list[tuple[str, str]]:
    """每条规则包含标题与调查目标；定位标识用于命中后恢复未截断的原文。"""
    header = card["title"] + "\n" + card.get("investigation_goal", "")
    result = []
    for rule in card.get("analysis_rules", []):
        result.append(
            (
                "analysis_rules." + rule["rule_id"],
                header + "\n" + json.dumps(rule, ensure_ascii=False),
            )
        )
    if not result:
        body = "\n".join(card["key_indicators"] + card["investigation_steps"])
        result.append(("investigation_steps", header + "\n" + body))
    if card["card_type"] == "verified_error_revision":
        details = card.get("case_details", {})
        result.append(
            (
                "error_revision",
                header
                + "\n"
                + card["error_revision_note"]
                + "\n"
                + "\n".join(details.get("corrected_steps", [])),
            )
        )
    return result
