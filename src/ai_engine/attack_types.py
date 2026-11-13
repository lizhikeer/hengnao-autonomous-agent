"""攻击分类口径（首期七类）。

依据：``docs/project design/database/知识库总体设计.md`` §36
——「首批建议覆盖扫描、密码爆破、SQL 注入、XSS、遍历与越权、恶意上传、可疑外连」，
分类基准为 OWASP WSTG v4.2（4.1~4.11）+ MITRE ATT&CK 网络侧三类。

**重要：这不是"团队已冻结契约"。** 与 Issue #17 的正式枚举对齐前，
本模块的取值属于我方实现口径，集中在此便于一处修改、全员同步。

设计取舍：
* 七类中「恶意上传」与「遍历与越权」现有知识卡合并为 ``File_Upload_Traversal``，
  因此对外取值沿用知识卡口径，便于检索时按 ``attack_category`` 直接过滤；
* 「扫描」暂无知识卡（待 @Snowed-night 补充），但枚举先占位，避免模型自造词；
* ``attack_type`` 允许组合，格式 ``<后阶段>_After_<前阶段>``，逐段校验，
  例如 ``SQL_Injection_After_Brute_Force``；
* 证据不足用 ``insufficient_evidence``，无恶意用 ``none``，两者都不属于七类。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

INSUFFICIENT = "insufficient_evidence"
NONE = "none"
_AFTER = "_After_"


@dataclass(frozen=True)
class AttackType:
    """一类攻击的规范定义。"""

    code: str
    zh: str
    mitre: tuple[str, ...] = ()
    #: 知识卡里的 attack_category（用于检索过滤；None 表示暂无对应知识卡）
    knowledge_category: Optional[str] = None
    #: 判定时关注的日志关键词，供调查逻辑与回归测试参考
    indicators: tuple[str, ...] = field(default_factory=tuple)


ATTACK_TYPES: tuple[AttackType, ...] = (
    AttackType(
        code="Scan",
        zh="扫描探测",
        mitre=("T1046",),
        knowledge_category=None,
        indicators=("dirsearch", "nikto", "nmap", "masscan", "robots.txt", ".git/", "敏感路径探测"),
    ),
    AttackType(
        code="Brute_Force",
        zh="密码爆破",
        mitre=("T1110",),
        knowledge_category="Brute_Force",
        indicators=("hydra", "medusa", "auth_fail", "登录失败", "多次口令尝试"),
    ),
    AttackType(
        code="SQL_Injection",
        zh="SQL 注入",
        mitre=("T1190",),
        knowledge_category="SQL_Injection",
        indicators=("union select", "sleep(", "information_schema", "sqlmap", "' or ", "into outfile"),
    ),
    AttackType(
        code="XSS",
        zh="跨站脚本",
        mitre=("T1059.007",),
        # 知识卡侧 XSS 与 RCE 合并在 XSS_RCE.json，但结果分类不合并
        knowledge_category="XSS_RCE",
        indicators=("<script", "onerror=", "javascript:", "alert(", "document.cookie"),
    ),
    AttackType(
        code="Path_Traversal_Privilege",
        zh="目录遍历与越权",
        mitre=("T1083", "T1548"),
        knowledge_category="File_Upload_Traversal",
        indicators=("../", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow", "未授权访问", "越权"),
    ),
    AttackType(
        code="Malicious_Upload",
        zh="恶意上传",
        mitre=("T1105",),
        knowledge_category="File_Upload_Traversal",
        indicators=("upload", "filename=", "multipart/form-data", "webshell", "shell.php", "cmd="),
    ),
    AttackType(
        code="C2_Exfiltration",
        zh="可疑外连与数据外传",
        mitre=("TA0011", "TA0010"),
        knowledge_category="C2_Exfiltration",
        indicators=("c2", "beacon", "4444", "外连", "dns 隧道", "大流量外传"),
    ),
)

BY_CODE: dict[str, AttackType] = {t.code: t for t in ATTACK_TYPES}
VALID_CODES = frozenset(BY_CODE) | {INSUFFICIENT, NONE}

#: 历史兼容段：第二周初版把「恶意上传+遍历越权」「XSS+RCE」合并过，
#: 早期产物里可能留有这些取值。校验放行，但不作为新产出的目标。
COMPAT_SEGMENTS = frozenset({"XSS_RCE", "File_Upload_Traversal", "C2_Callback", "Unknown_Attack"})

#: 中文名 → 代码，便于把自然语言结论收敛
_ZH_TO_CODE = {t.zh: t.code for t in ATTACK_TYPES} | {
    "扫描": "Scan",
    "密码爆破": "Brute_Force",
    "暴力破解": "Brute_Force",
    "SQL 注入": "SQL_Injection",
    "SQL注入": "SQL_Injection",
    "XSS": "XSS",
    "跨站脚本": "XSS",
    "跨站脚本攻击": "XSS",
    "遍历与越权": "Path_Traversal_Privilege",
    "目录遍历": "Path_Traversal_Privilege",
    "越权访问": "Path_Traversal_Privilege",
    "恶意上传": "Malicious_Upload",
    "文件上传": "Malicious_Upload",
    "可疑外连": "C2_Exfiltration",
    "数据外传": "C2_Exfiltration",
}

#: 常见别名（含历史合并类到七类的映射）
#: 注意 ``File_Upload_Traversal`` 是复合旧值，无法唯一还原：默认落到「恶意上传」，
#: 若需区分遍历语义，应按日志内容重新判定，而不是照抄别名。
_ALIASES = {
    "BruteForce": "Brute_Force",
    "Bruteforce": "Brute_Force",
    "SQLi": "SQL_Injection",
    "C2_Callback": "C2_Exfiltration",
    "C2": "C2_Exfiltration",
    "Exfiltration": "C2_Exfiltration",
    "Path_Traversal": "Path_Traversal_Privilege",
    "Privilege_Escalation": "Path_Traversal_Privilege",
    "Webshell": "Malicious_Upload",
    "Upload": "Malicious_Upload",
    "XSS_RCE": "XSS",
    "File_Upload_Traversal": "Malicious_Upload",
    "Recon": "Scan",
    "Scanning": "Scan",
}


def segments(attack_type: str) -> list[str]:
    """把 ``A_After_B`` 拆成 ``[B, A]``（按发生顺序）；单值返回 ``[x]``。"""
    if not isinstance(attack_type, str) or not attack_type.strip():
        return []
    parts = [p for p in attack_type.strip().split(_AFTER) if p]
    return list(reversed(parts))


def normalize(attack_type: str) -> str:
    """规范化为本模块口径；无法识别的段原样保留（不猜）。"""
    if not isinstance(attack_type, str):
        return NONE
    text = attack_type.strip()
    if not text:
        return NONE
    if text in {INSUFFICIENT, NONE}:
        return text
    mapped: list[str] = []
    for seg in segments(text):
        code = BY_CODE.get(seg)
        if code is not None:
            mapped.append(code.code)
            continue
        code = _ZH_TO_CODE.get(seg) or _ALIASES.get(seg)
        mapped.append(code or seg)
    return _AFTER.join(reversed(mapped))


def invalid_segments(attack_type: str) -> list[str]:
    """返回不属于任何合法取值的段（用于契约校验）。"""
    return [seg for seg in segments(attack_type) if seg not in VALID_CODES]


def is_valid(attack_type: str) -> bool:
    return bool(attack_type) and not invalid_segments(attack_type)


def zh_name(attack_type: str) -> str:
    parts = [BY_CODE[s].zh if s in BY_CODE else s for s in segments(attack_type)]
    if attack_type == INSUFFICIENT:
        return "证据不足"
    if attack_type == NONE:
        return "无恶意行为"
    return " → ".join(parts) if parts else attack_type


def knowledge_category(attack_type: str) -> Optional[str]:
    """取最末阶段对应的知识卡分类，用于检索过滤。"""
    parts = segments(attack_type)
    for seg in reversed(parts):
        item = BY_CODE.get(seg)
        if item and item.knowledge_category:
            return item.knowledge_category
    return None


def infer_from_text(text: str) -> Optional[str]:
    """从日志文本（URI / payload / UA）推断最可能的攻击类别，供调查逻辑使用。

    只做关键词打分，命中不到返回 ``None``——不强行归类。
    """
    if not text:
        return None
    lowered = text.lower()
    best: tuple[int, str] | None = None
    for item in ATTACK_TYPES:
        hits = sum(1 for kw in item.indicators if kw.lower() in lowered)
        if hits and (best is None or hits > best[0]):
            best = (hits, item.code)
    return best[1] if best else None


def catalog() -> list[dict[str, object]]:
    """对外暴露的分类清单（写进文档与验收报告）。"""
    return [
        {
            "code": t.code,
            "zh": t.zh,
            "mitre": list(t.mitre),
            "knowledge_category": t.knowledge_category,
            "knowledge_card_ready": t.knowledge_category is not None,
        }
        for t in ATTACK_TYPES
    ]


# ---------------------------------------------------------------------------
# 强 / 弱特征分级
# ---------------------------------------------------------------------------

#: **强特征**：这些字符串在正常业务里基本不会出现，可作为攻击成立的支撑。
STRONG_INDICATORS: dict[str, tuple[str, ...]] = {
    "Scan": ("dirsearch", "nikto", "nmap", "masscan", "/.git/config", "/phpmyadmin/"),
    "Brute_Force": (
        "hydra",
        "medusa",
        "auth_fail",
        "登录失败",
        "invalid user",
        "invalid_password",
        "failed password",
        "authentication failure",
    ),
    "SQL_Injection": (
        "union select",
        "sleep(",
        "benchmark(",
        "information_schema",
        "into outfile",
        "' or ",
        "sqlmap",
    ),
    "XSS": ("<script", "onerror=", "javascript:", "alert(", "document.cookie"),
    "Path_Traversal_Privilege": ("../", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow"),
    "Malicious_Upload": ("shell.php", "webshell", "c99.php", "<?php", "cmd=cat"),
    "C2_Exfiltration": ("beacon", "c2_callback"),
}

#: **弱特征**：正常业务也会出现，单独不构成攻击，只能作为线索。
WEAK_INDICATORS: dict[str, tuple[str, ...]] = {
    "Scan": ("robots.txt", ".git/", "/admin/", "/backup", "sitemap.xml"),
    "Malicious_Upload": ("upload", "filename=", "multipart/form-data", ".php", "/uploads/"),
    "Path_Traversal_Privilege": ("..",),
    "Brute_Force": ("login", "登录", "password"),
}


def classify_signals(text: str) -> dict[str, list[str]]:
    """把日志文本分成强特征与弱特征两类命中。

    强特征可用于支撑"攻击成立"；弱特征只说明"值得再看一眼"，
    必须结合账号、来源、时间与其它日志事实才能定性。
    """
    lowered = (text or "").lower()
    strong = [code for code, kws in STRONG_INDICATORS.items() if any(k.lower() in lowered for k in kws)]
    weak = [
        code
        for code, kws in WEAK_INDICATORS.items()
        if code not in strong and any(k.lower() in lowered for k in kws)
    ]
    return {"strong": strong, "weak": weak}
