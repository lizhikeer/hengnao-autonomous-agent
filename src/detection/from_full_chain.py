"""把统一 Schema 的全链路日志适配成老项目 `NormalizedLog`，让既有规则引擎可直接复用。

## 为什么需要这层

老项目的 `RuleEngine.evaluate_log()` 是按 **业务动作语义** 判断的：

    if log.action == "login" and log.result == "fail":  → 爆破规则
    if log.action == "api_call":                        → 高频调用规则
    if _is_download_or_export(log):                     → 数据外带规则

而统一 Schema 存的是 **协议事实**：`action_or_method` 是 `GET`/`POST`/`ssh`/`tcp`，
`status_code` 是 HTTP 码。两者之间必须有一层语义映射，否则所有规则都命中不了。

## 映射原则

不做「聪明」的推断，只做可解释的映射，且把所有推断依据写进 `attrs`，方便回溯：

| 统一 Schema | NormalizedLog | 依据 |
| :--- | :--- | :--- |
| `log_id` | `event_id` | 日志唯一编号，证据引用锚点 |
| `timestamp` | `event_time` | UTC |
| `log_source` | `source_type` | 见 `LOG_SOURCE_MAP` |
| `user_name` | `user_id` | 契约字段 `user` 的落库名 |
| `dest_ip` | `dst_ip` | 命名差异 |
| `action_or_method` | `action` | 见 `_infer_action` |
| `uri_or_target` | `resource` | 用于敏感资源判断 |
| `status_code` | `result` | 见 `_infer_result` |
| `attack_stage_hint` | `attrs.attack_stage_hint` | 额外字段，`extra="allow"` 可保留 |

## 边界

本模块**只做映射，不做判定**。是否构成异常由 `RuleEngine` 决定；
统一 Schema 里已有的 `attack_stage_hint` 只作为提示写进 attrs，不参与规则计算，
避免「标注数据反向污染检测结果」。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.schemas import NormalizedLog
from src.schemas.models import LogResult, SourceType

# log_source → source_type。老枚举没有 Web/Zeek 这两类，按语义就近归并：
#   nginx_access → oa     （面向用户的 Web 应用）
#   auth_log     → vpn    （远程/身份认证）
#   zeek_*       → security_device（网络侧设备日志）
LOG_SOURCE_MAP: dict[str, SourceType] = {
    "nginx_access": "oa",
    "auth_log": "vpn",
    "zeek_conn": "security_device",
    "zeek_http": "security_device",
    "zeek_dns": "security_device",
}

# URI 关键词 → 业务动作。顺序敏感：login 必须先于通用 api_call 判断
_ACTION_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("login", "signin", "auth"), "login"),
    (("logout", "signout"), "logout"),
    (("export", "download", "dump"), "export"),
    (("upload",), "upload"),
    (("admin",), "admin_access"),
)


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    text = str(raw).replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _infer_result(status_code: Any) -> LogResult:
    """HTTP 状态码 → 老枚举。

    401/403 归 fail（认证/授权未通过，爆破规则依赖这个值）；
    2xx 归 success；其余归 error。
    """
    if status_code in (None, ""):
        return "success"
    code = int(status_code)
    if 200 <= code < 300:
        return "success"
    if code in (401, 403):
        return "fail"
    return "error"


def _infer_action(log_source: str, uri: str, method: str) -> str:
    """推断业务动作。

    认证日志直接视为 login（它的语义就是一次登录尝试）；
    Web 日志先按 URI 关键词匹配，匹配不到再退化为 api_call。
    """
    if log_source == "auth_log":
        return "login"
    if log_source == "zeek_conn":
        return "connect"

    lowered = (uri or "").lower()
    for keywords, action in _ACTION_KEYWORDS:
        if any(k in lowered for k in keywords):
            return action
    return "api_call" if method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"} else "connect"


def to_normalized(row: dict[str, Any]) -> NormalizedLog:
    """把一行 `full_chain_logs` 记录转成 `NormalizedLog`。

    `row` 的键可以是 ClickHouse 列名（`user_name` / `dest_ip`），
    也可以是契约名（`user` / `timestamp` 带 Z），两种都兼容。
    """
    log_source = str(row.get("log_source") or "")
    uri = str(row.get("uri_or_target") or "")
    method = str(row.get("action_or_method") or "")
    event_time = _parse_ts(row.get("timestamp") or row.get("event_time"))

    user = row.get("user_name") if row.get("user_name") not in (None, "") else row.get("user")
    action = _infer_action(log_source, uri, method)
    result = _infer_result(row.get("status_code"))

    return NormalizedLog(
        event_id=str(row.get("log_id") or row.get("event_id") or ""),
        event_time=event_time,
        ingest_time=_parse_ts(row.get("ingest_time") or event_time),
        tenant_id="default",
        source_type=LOG_SOURCE_MAP.get(log_source, "system"),
        log_type=log_source,
        user_id=str(user) if user else None,
        host=str(row.get("asset_id") or "") or None,
        src_ip=str(row.get("src_ip") or "") or None,
        src_port=row.get("src_port") or None,
        dst_ip=str(row.get("dest_ip") or row.get("dst_ip") or "") or None,
        dst_port=row.get("dest_port") or row.get("dst_port") or None,
        action=action,
        object_type="uri" if log_source in ("nginx_access", "zeek_http") else "session",
        object_id=uri or None,
        resource=uri or None,
        result=result,
        user_agent=str(row.get("user_agent") or "") or None,
        protocol="tcp" if log_source.startswith("zeek") else "http",
        session_id=str(row.get("session_id") or "") or None,
        trace_id=str(row.get("trace_id") or "") or None,
        # extra="allow" 允许带过去，供审计与下游展示，但不参与规则判定
        attack_stage_hint=str(row.get("attack_stage_hint") or "") or None,
        log_source=log_source or None,
        asset_id=str(row.get("asset_id") or "") or None,
        payload_summary=str(row.get("payload_summary") or "") or None,
        # 补充规则（扫描探测）需要状态码，NormalizedLog 无此字段，走 extra 透传
        status_code=row.get("status_code"),
        # 老模型的两个必填字段：message 供人读，raw_log 供取证回溯
        message=f"{log_source} {method} {uri}".strip(),
        raw_log=str(row.get("raw_log") or "") or f"{log_source} {method} {uri}".strip(),
    )
