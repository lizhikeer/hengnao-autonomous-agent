"""调查分类 → 知识卡类别的关联表（唯一来源）。

``src/knowledge/search.py`` 的混合检索与 ``src/api/knowledge_adapter.py`` 的
词面降级检索必须按同一张表扩展类别，否则同一问题在两种模式下召回范围不同，
"降级"就会悄悄改变结论依据。

本模块**只依赖标准库**：降级路径无法导入 qdrant/sentence-transformers 时仍可使用。
表内容与 PR #29 落盘的 ``_RELATED_CATEGORIES`` 保持一致，本次不改检索权重。
"""

from __future__ import annotations

#: 首期七类 → 知识卡 attack_category（与 PR #29 的映射逐项一致）
RELATED_CATEGORIES: dict[str, tuple[str, ...]] = {
    "Scan": ("Information_Gathering", "Discovery"),
    "Brute_Force": ("Credential_Access",),
    "XSS": ("XSS_RCE",),
    "Path_Traversal_Privilege": (
        "File_Upload_Traversal",
        "Authorization_Failure",
        "Privilege_Escalation",
    ),
    "Malicious_Upload": ("File_Upload_Traversal",),
    "C2_Exfiltration": ("Command_and_Control", "Exfiltration"),
}


def categories_for(category: str | None) -> tuple[str, ...]:
    """返回该调查分类应检索的全部知识卡类别（含自身）。"""
    if not category:
        return ()
    return (category, *RELATED_CATEGORIES.get(category, ()))
