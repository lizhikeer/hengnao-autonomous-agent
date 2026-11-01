"""输入预处理（与工作流「代码节点 code_clean」同源的可执行实现）。

平台上的代码节点 `code_clean` 见 `design/hengnao_workflows/week1_workflow_design.md` §3.2，
本模块是同一套规则的本地可执行版本，用途：

1. 端到端链路模拟（`tests/e2e_workflow_sim.py`）需要在本地跑通"清洗 → 分支"这一段；
2. 让平台侧粘贴的代码有对照实现，改动时两边一起改，避免"文档一套、本地一套"。

不做任何网络或数据库访问，纯函数。
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Literal

HEALTH_PATHS = ("/healthz", "/health", "/ping", "/readyz")
PROBE_UA = ("kube-probe", "elb-healthchecker", "googlehc")

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_IP_RE = re.compile(r"\b(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\b")
_REQ_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[\d.]+"')
_ST_RE = re.compile(r'"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)')
_UA_RE = re.compile(r'"([^"]*)"\s*$')

Branch = Literal["whitelist", "ask", "investigate"]


@dataclass
class CleanResult:
    clean: dict[str, object] = field(default_factory=dict)
    is_complete: bool = False
    is_whitelist: bool = False
    missing_fields: list[str] = field(default_factory=list)

    @property
    def branch(self) -> Branch:
        """工作流的边条件判定结果。"""
        if self.is_whitelist:
            return "whitelist"
        if not self.is_complete:
            return "ask"
        return "investigate"


def clean_log(raw: str) -> CleanResult:
    """把一行原始日志清洗成结构化字段，并给出分支结论。"""
    text = _CTRL_RE.sub("", raw or "")

    m_ip = _IP_RE.search(text)
    m_req = _REQ_RE.search(text)
    m_st = _ST_RE.search(text)
    m_ua = _UA_RE.search(text)

    src_ip = m_ip.group("src_ip") if m_ip else ""
    method = m_req.group("method") if m_req else ""
    uri = m_req.group("uri") if m_req else ""
    status = int(m_st.group("status")) if m_st else 0
    nbytes = int(m_st.group("bytes")) if m_st else 0
    ua = (m_ua.group(1) if m_ua else "") or ""

    decoded = urllib.parse.unquote(uri)
    double_encoded = "%" in decoded
    if double_encoded:
        decoded = urllib.parse.unquote(decoded)

    missing = [k for k, v in (("src_ip", src_ip), ("uri", uri), ("status", status)) if not v]
    is_complete = not missing

    ua_l = ua.lower()
    is_whitelist = (
        is_complete
        and uri.split("?")[0] in HEALTH_PATHS
        and any(p in ua_l for p in PROBE_UA)
    )

    clean = {
        "src_ip": src_ip,
        "method": method,
        "uri": uri,
        "status": status,
        "bytes": nbytes,
        "decoded_uri": decoded,
        "double_encoded": double_encoded,
        "user_agent": ua,
        "is_complete": is_complete,
    }
    return CleanResult(
        clean=clean,
        is_complete=is_complete,
        is_whitelist=is_whitelist,
        missing_fields=missing,
    )


def ask_back_message(result: CleanResult) -> str:
    """字段残缺时给用户的反问文案（对应工作流 code_ask 节点）。"""
    fields = "、".join(result.missing_fields) or "未知字段"
    return (
        f"这条日志缺少关键字段：{fields}，无法定位攻击源或请求目标。"
        "请补充完整日志行（建议包含源 IP、请求方法与 URI、响应状态码），或说明该日志的采集来源。"
    )
