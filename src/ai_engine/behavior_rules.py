"""行为事实抽取（V2）：只用日志字段特征，不读场景编号、不读标准答案。

为什么单独成模块
----------------
V1 的判定散落在 ``investigation.py`` 里，规则与"下结论"耦合，导致三类盲区：

* 认证失败按"同源同账号 5 次"聚合，多账号试探（每个账号只失败一次的撞库/爆破）
  永远聚不起来，只能弃权；
* C2 只认 ``payload_summary`` 里写明的 beacon 字样，Zeek 连接日志没有 payload 时
  整段外连证据作废；
* 失败重试只看次数，不看节奏与后续登录结果，把人工输错与脚本爆破混为一谈。

本模块只回答"日志里到底发生了什么"，输出结构化事实；是否恶意、如何分类、
给出什么处置，仍由 ``investigation.py`` 决定。所有规则只用以下通用日志特征：

* 认证：来源、账号、服务、结果、时间间隔、账号数量；
* 外连：目的地址是否外网、目的端口、连接次数、间隔、持续时长、字节量、方法；
* Web：请求路径、参数个数与取值序列、状态码、响应字节、会话标识与来源变化。

**禁止**在这里出现任何 ``case_id`` / 场景编号判断——场景编号只用于回放与回归测试。
"""

from __future__ import annotations

import ipaddress
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

#: 内网/保留地址段：命中即视为"本方资产侧"
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

#: 常规出网端口：出现在这些端口上的连接本身不构成异常
_COMMON_EGRESS_PORTS = frozenset(
    {21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080}
)

#: 认证失败特征（大小写无关）。既覆盖 auth_log 的 reason=/action，也覆盖 Web 侧 401。
_FAILURE_MARKERS = (
    "invalid_password",
    "invalid user",
    "failed password",
    "authentication failure",
    "auth_fail",
    "login_failure",
    "登录失败",
    "认证失败",
)

#: 自动化口令工具 UA：出现即视为脚本爆破，不再要求次数门槛
_AUTOMATION_UA = ("hydra", "medusa", "ncrack", "patator", "crackmapexec")

#: 登录成功特征
_SUCCESS_MARKERS = ("login_success", "session_opened", "login success", "accepted password", "登录成功")

#: 登录接口路径特征（用于识别 Web 登录请求）
_LOGIN_PATH_HINTS = ("login", "signin", "sign_in", "auth", "session", "logon")


_MAX_FAILURE_SPAN_SECONDS = 300     # 同账号口令猜测的短窗口
_MAX_MULTI_ACCOUNT_SPAN = 900       # 多账号试探的观察窗
_MULTI_ACCOUNT_MIN_USERS = 3
_MULTI_ACCOUNT_MIN_ATTEMPTS = 5
_HUMAN_RETRY_MIN_INTERVAL = 20      # 人工输入口令的合理间隔下限
_MAX_HUMAN_RETRY_ATTEMPTS = 4
_LOGIN_SUCCESS_LOOKAHEAD = 900      # 失败后多久内成功登录仍算"同一串行为"


def parse_ts(value: Any) -> Optional[datetime]:
    """解析时间戳为 UTC aware；无法解析返回 ``None``（不猜）。"""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_external_ip(value: Any) -> bool:
    """是否为公网地址；无法解析的一律按"非外网"处理，避免拿坏数据当攻击源。"""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local:
        return False
    return not any(address in network for network in _PRIVATE_NETWORKS)


def _text(log: dict[str, Any], *keys: str) -> str:
    return " ".join(str(log.get(key) or "") for key in keys)


def _seconds_between(later: dict[str, Any], earlier: dict[str, Any]) -> Optional[float]:
    a, b = parse_ts(later.get("timestamp")), parse_ts(earlier.get("timestamp"))
    if a is None or b is None:
        return None
    return (a - b).total_seconds()


def _median(values: Iterable[float]) -> Optional[float]:
    rows = [v for v in values if v is not None]
    return statistics.median(rows) if rows else None


# ---------------------------------------------------------------------------
# 认证行为
# ---------------------------------------------------------------------------


@dataclass
class AuthAssessment:
    """一次调查窗口内的认证行为事实。"""

    failure_logs: list[dict[str, Any]] = field(default_factory=list)
    attempts: int = 0
    distinct_users: int = 0
    distinct_sources: int = 0
    median_interval: Optional[float] = None
    brute_force: bool = False
    brute_reasons: list[dict[str, Any]] = field(default_factory=list)
    success_logs: list[dict[str, Any]] = field(default_factory=list)
    compromise: bool = False
    benign_retry: bool = False
    benign_reasons: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)

    @property
    def brute_sources(self) -> set[str]:
        return {reason["src_ip"] for reason in self.brute_reasons if reason.get("src_ip")}

    def as_finding(self) -> dict[str, Any]:
        return {
            "attempts": self.attempts,
            "distinct_users": self.distinct_users,
            "distinct_sources": self.distinct_sources,
            "median_interval_seconds": self.median_interval,
            "brute_force": self.brute_force,
            "brute_reasons": self.brute_reasons,
            "success_after_failure": bool(self.success_logs),
            "compromise": self.compromise,
            "benign_retry": self.benign_retry,
            "benign_reasons": self.benign_reasons,
        }


def _is_failure_log(log: dict[str, Any]) -> bool:
    """是否为认证失败记录。

    认证结论只认认证侧证据：``auth_log`` 的失败原因，或 Web 侧明确返回 401 的登录请求。
    不能对任意日志正文做关键词匹配——帮助页里的 "failed password recovery" 之类的
    文案会被读成"密码失败"，把正常浏览算成爆破（独立验收反例）。
    """
    source = log.get("log_source")
    if source == "auth_log":
        text = _text(log, "payload_summary", "action_or_method").lower()
        return any(marker in text for marker in _FAILURE_MARKERS)
    if source == "nginx_access":
        return log.get("status_code") == 401
    return False


#: Web 侧"带攻击语法的登录请求"不能当作登录成功（注入绕过 ≠ 正常登录）
_ATTACK_SYNTAX = ("union select", "sleep(", "benchmark(", "<script", "../", "..%2f", "cmd=", "or 1=1", "' or ")


def _is_login_success(log: dict[str, Any], failure_seconds: Optional[set[int]] = None) -> bool:
    """是否为成功的登录。

    nginx 200 不能单独当成功：不少应用把认证失败也返回 200，正常请求里也可能
    带着注入语法。因此只有"显式成功标记"，或"登录路径 200 且同一秒没有认证失败记录、
    请求不带攻击语法"才算成功。
    """
    text = _text(log, "payload_summary", "action_or_method").lower()
    if any(marker in text for marker in _SUCCESS_MARKERS):
        return True
    if log.get("log_source") != "nginx_access" or log.get("status_code") != 200:
        return False
    uri = str(log.get("uri_or_target") or "")
    if not any(hint in uri.lower() for hint in _LOGIN_PATH_HINTS):
        return False
    joined = _text(log, "uri_or_target", "payload_summary").lower()
    if any(token in joined for token in _ATTACK_SYNTAX):
        return False
    stamp = parse_ts(log.get("timestamp"))
    if stamp is not None and failure_seconds and int(stamp.timestamp()) in failure_seconds:
        return False
    return True


def _is_automated_credential_tool(log: dict[str, Any]) -> bool:
    ua = str(log.get("user_agent") or "").lower()
    return any(tool in ua for tool in _AUTOMATION_UA)


def assess_authentication(logs: list[dict[str, Any]]) -> AuthAssessment:
    """抽取认证事实：失败簇、账号发散度、节奏、失败后是否成功登录。

    失败记录先按 ``(来源, 账号, 秒级时间)`` 合并：同一次尝试在 nginx 与 auth_log
    两侧各留一条记录，直接计数会把"3 次输错"读成"6 次爆破"。
    """
    assessment = AuthAssessment()
    failures = [log for log in logs if _is_failure_log(log)]
    if not failures:
        return assessment

    # 1) 同一次尝试双侧留痕合并：同一秒、同源、同账号的 nginx 记录与 auth_log 记录
    #    是同一次尝试的两侧。按**秒**分桶而不是按滑动窗口，否则同一秒内的多次脚本
    #    尝试会被合并成一次，把爆破读成"手滑"（V1 曾因此漏判）。
    buckets: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for log in failures:
        stamp = parse_ts(log.get("timestamp"))
        if stamp is None:
            continue
        key = (str(log.get("src_ip") or ""), str(log.get("user") or ""), int(stamp.timestamp()))
        buckets.setdefault(key, []).append(log)

    attempts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for (src, user, _second), rows in buckets.items():
        per_source: dict[str, int] = {}
        for row in rows:
            source = str(row.get("log_source") or "")
            per_source[source] = per_source.get(source, 0) + 1
        stamp = min(
            (parse_ts(row.get("timestamp")) for row in rows),
            key=lambda item: item or datetime.min.replace(tzinfo=timezone.utc),
        )
        attempts.setdefault((src, user), []).append(
            {
                "stamp": stamp,
                "logs": rows,
                # 同一次尝试在两侧各留一条 → 计 1 次；同一侧多条 → 按条数计
                "count": max(per_source.values()) if per_source else 1,
            }
        )

    for entries in attempts.values():
        entries.sort(key=lambda item: item["stamp"])
        for entry in entries:
            assessment.failure_logs.extend(entry["logs"])

    assessment.attempts = sum(entry["count"] for entries in attempts.values() for entry in entries)
    assessment.distinct_users = len({user for _, user in attempts if user})
    assessment.distinct_sources = len({src for src, _ in attempts if src})

    intervals: list[float] = []
    for entries in attempts.values():
        for earlier, later in zip(entries, entries[1:]):
            gap = (later["stamp"] - earlier["stamp"]).total_seconds()
            if gap >= 0:
                intervals.append(gap)
    assessment.median_interval = _median(intervals)

    # 2) 同账号短窗口重复失败 —— 经典口令爆破
    for (src, user), entries in attempts.items():
        for start in entries:
            window = [
                entry
                for entry in entries
                if 0 <= (entry["stamp"] - start["stamp"]).total_seconds() <= _MAX_FAILURE_SPAN_SECONDS
            ]
            failures_in_window = sum(entry["count"] for entry in window)
            if failures_in_window >= 5:
                assessment.brute_force = True
                assessment.brute_reasons.append(
                    {
                        "rule": "same_account_repeated_failure",
                        "src_ip": src,
                        "user": user,
                        "attempts": failures_in_window,
                        "window_seconds": int(
                            (window[-1]["stamp"] - window[0]["stamp"]).total_seconds()
                        ),
                    }
                )
                break
    # 3) 同源多账号连续失败 —— 只看账号唯一性会漏掉这一整类（V1 CASE-06 盲区）
    by_source: dict[str, list[dict[str, Any]]] = {}
    for (src, _user), entries in attempts.items():
        if src:
            by_source.setdefault(src, []).extend(entries)
    for src, entries in by_source.items():
        entries.sort(key=lambda item: item["stamp"])
        span = (entries[-1]["stamp"] - entries[0]["stamp"]).total_seconds()
        attempts_count = sum(entry["count"] for entry in entries)
        users = {
            str(log.get("user"))
            for entry in entries
            for log in entry["logs"]
            if log.get("user")
        }
        if (
            attempts_count >= _MULTI_ACCOUNT_MIN_ATTEMPTS
            and len(users) >= _MULTI_ACCOUNT_MIN_USERS
            and span <= _MAX_MULTI_ACCOUNT_SPAN
        ):
            assessment.brute_force = True
            assessment.brute_reasons.append(
                {
                    "rule": "multi_account_sequential_failure",
                    "src_ip": src,
                    "users": sorted(users),
                    "attempts": attempts_count,
                    "window_seconds": int(span),
                }
            )

    # 4) 自动化口令工具 UA
    for log in failures:
        if _is_automated_credential_tool(log):
            assessment.brute_force = True
            assessment.brute_reasons.append(
                {"rule": "automation_user_agent", "src_ip": log.get("src_ip"), "user_agent": log.get("user_agent")}
            )
    if assessment.brute_force:
        # 只关联触发爆破规则的来源，避免把同案正常用户重试后的成功算作失陷。
        attacker_sources = assessment.brute_sources
        for log in logs:
            src = log.get("src_ip")
            if src not in attacker_sources:
                continue
            matching_failures = [
                row for row in assessment.failure_logs
                if row.get("src_ip") == src
                and not any(
                    log.get(field) and row.get(field) and log[field] != row[field]
                    for field in ("asset_id", "dest_ip", "user")
                )
            ]
            times = [stamp for row in matching_failures if (stamp := parse_ts(row.get("timestamp")))]
            if not times or not _is_login_success(log, {int(stamp.timestamp()) for stamp in times}):
                continue
            last_failure = max(times)
            stamp = parse_ts(log.get("timestamp"))
            if stamp and 0 <= (stamp - last_failure).total_seconds() <= _LOGIN_SUCCESS_LOOKAHEAD:
                assessment.success_logs.append(log)
        assessment.compromise = bool(assessment.success_logs)
        return assessment

    # 5) 低频人工输错：次数少、同源同账号、节奏像人、随后正常登录成功
    if (
        1 <= assessment.attempts <= _MAX_HUMAN_RETRY_ATTEMPTS
        and len(attempts) == 1
        and (assessment.median_interval is None or assessment.median_interval >= _HUMAN_RETRY_MIN_INTERVAL)
    ):
        src, user = next(iter(attempts))
        last_failure = max(
            (parse_ts(row.get("timestamp")) for row in assessment.failure_logs if parse_ts(row.get("timestamp"))),
            default=None,
        )
        failure_seconds = {
            int(stamp.timestamp())
            for stamp in (parse_ts(row.get("timestamp")) for row in assessment.failure_logs)
            if stamp is not None
        }
        for log in logs:
            if not _is_login_success(log, failure_seconds):
                continue
            if str(log.get("src_ip") or "") != src or str(log.get("user") or "") not in {"", user}:
                continue
            stamp = parse_ts(log.get("timestamp"))
            if last_failure and stamp and 0 <= (stamp - last_failure).total_seconds() <= _LOGIN_SUCCESS_LOOKAHEAD:
                assessment.success_logs.append(log)
        if assessment.success_logs:
            assessment.benign_retry = True
            assessment.benign_reasons.append(
                f"同源 {src} 账号 {user} 失败 {assessment.attempts} 次"
                f"（中位间隔 {assessment.median_interval or 0:.0f}s），随后同源登录成功"
            )
    return assessment


# ---------------------------------------------------------------------------
# 对外连接（C2 / 数据外传）
# ---------------------------------------------------------------------------


@dataclass
class OutboundGroup:
    """同一 (目的地址, 目的端口) 上的一组对外连接。"""

    dest_ip: str
    dest_port: Optional[int]
    logs: list[dict[str, Any]] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    corroborated: bool = False
    reasons: list[str] = field(default_factory=list)

    def as_finding(self) -> dict[str, Any]:
        return {
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "connections": len(self.logs),
            "signals": self.signals,
            "corroborated": self.corroborated,
            "reasons": self.reasons,
            "log_ids": [log.get("log_id") for log in self.logs if log.get("log_id")],
        }


def _dest_port(log: dict[str, Any]) -> Optional[int]:
    try:
        value = log.get("dest_port")
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def dest_port(log: dict[str, Any]) -> Optional[int]:
    """对外暴露的端口读取（供证据相关性判断复用）。"""
    return _dest_port(log)


def is_unusual_egress_port(log: dict[str, Any]) -> bool:
    """目的端口是否属于非常规出网端口。"""
    port = _dest_port(log)
    return port is not None and port not in _COMMON_EGRESS_PORTS


def connection_duration(log: dict[str, Any]) -> Optional[float]:
    """从 ``payload_summary`` 读取连接持续秒数。"""
    return _duration(log)


def is_auth_failure(log: dict[str, Any]) -> bool:
    """是否为认证失败记录（供调查层核对授权豁免时复用）。"""
    return _is_failure_log(log)


def _duration(log: dict[str, Any]) -> Optional[float]:
    payload = str(log.get("payload_summary") or "")
    match = re.search(r"duration=([0-9.]+)", payload)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _conn_state(log: dict[str, Any]) -> Optional[str]:
    payload = str(log.get("payload_summary") or "")
    match = re.search(r"conn_state=([A-Za-z0-9_]+)", payload)
    return match.group(1) if match else None


def _periodic(events: list[dict[str, Any]]) -> tuple[bool, Optional[float]]:
    """连接是否呈固定周期：多数间隔集中在同一个中位值附近。

    用"落在中位数 ±25% 内的间隔占比"而不是最大/最小比值：真实心跳会被重试、
    补发打乱，要求每次都严格等距会把真正的周期性信标判掉（V1 CASE-08 的成因之一）。
    """
    stamps = sorted(parse_ts(log.get("timestamp")) for log in events if parse_ts(log.get("timestamp")))
    if len(stamps) < 3:
        return False, None
    gaps = [(later - earlier).total_seconds() for earlier, later in zip(stamps, stamps[1:])]
    gaps = [gap for gap in gaps if gap > 0]
    if len(gaps) < 2:
        return False, None
    median = statistics.median(gaps)
    if median < 30:
        return False, None
    steady = sum(1 for gap in gaps if median * 0.75 <= gap <= median * 1.25)
    return steady / len(gaps) >= 0.6, median


def assess_outbound(logs: list[dict[str, Any]]) -> list[OutboundGroup]:
    """按目的地址聚合对外连接，并用多信号共同确认可疑外连。

    单一信号不足以定性（V1 的教训）：

    * 只有端口可疑 —— 正常业务也可能用高位端口；
    * 只有字节量大 —— 备份、CDN 回源、软件更新都会产生大流量；
    * 只有一次长连接 —— 流媒体/长轮询同样如此。

    因此要求"重复出现（>=3 次）"并且"周期性 / 长时保持"中至少一条，
    再叠加"非常规端口 / 服务端主动外发上传 / 定长心跳"中至少一条。
    """
    candidates = [
        log
        for log in logs
        if log.get("log_source") in {"zeek_conn", "zeek_http"}
        and not is_external_ip(log.get("src_ip"))
        and is_external_ip(log.get("dest_ip"))
    ]
    groups: dict[tuple[str, Optional[int]], OutboundGroup] = {}
    for log in candidates:
        key = (str(log.get("dest_ip")), _dest_port(log))
        groups.setdefault(key, OutboundGroup(dest_ip=key[0], dest_port=key[1])).logs.append(log)

    # 该主机全部对外连接的字节基线，用于判断"相对自身基线是否突增"
    baseline_bytes = [log.get("bytes_out") for log in candidates if isinstance(log.get("bytes_out"), (int, float))]
    baseline_median = statistics.median(baseline_bytes) if baseline_bytes else 0

    result: list[OutboundGroup] = []
    for group in groups.values():
        group.logs.sort(key=lambda log: parse_ts(log.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
        events = group.logs
        count = len(events)
        # 心跳周期性按应用层请求计算；连接层日志常与技术请求交错，会把间隔打散
        http_events = [log for log in events if log.get("log_source") == "zeek_http"]
        periodic, median_gap = _periodic(http_events if len(http_events) >= 3 else events)
        durations = [value for value in (_duration(log) for log in events) if value is not None]
        long_lived = bool(durations) and statistics.median(durations) >= 120
        long_lived_count = sum(1 for value in durations if value >= 240)
        outbound_upload = any(
            str(log.get("action_or_method") or "").upper() == "POST"
            and 200 <= int(log.get("status_code") or 0) < 300
            for log in events
        )
        # 定长心跳：同一路径反复请求且响应体恒定且很小（指令通道的典型形态）
        by_path: dict[str, list[dict[str, Any]]] = {}
        for log in http_events:
            by_path.setdefault(str(log.get("uri_or_target") or ""), []).append(log)
        beacon_paths: list[dict[str, Any]] = []
        for path, rows in by_path.items():
            if len(rows) < 3:
                continue
            sizes = {row.get("bytes_out") for row in rows}
            if len(sizes) > 2 or not all(isinstance(size, (int, float)) and size <= 512 for size in sizes):
                continue
            if not all(200 <= int(row.get("status_code") or 0) < 300 for row in rows):
                continue
            beacon_paths.append({"path": path, "requests": len(rows), "sizes": sorted(sizes)})
        fixed_beacon = bool(beacon_paths)
        unusual_port = group.dest_port is not None and group.dest_port not in _COMMON_EGRESS_PORTS
        total_bytes = sum(log.get("bytes_out") or 0 for log in events)
        volume_spike = (
            baseline_median > 0
            and total_bytes >= 5 * baseline_median
            and total_bytes >= 1_000_000
        )
        established = any((_conn_state(log) or "").lower() == "sf" for log in events)

        group.signals = {
            "connections": count,
            "periodic": periodic,
            "median_interval_seconds": median_gap,
            "long_lived": long_lived,
            "long_lived_connections": long_lived_count,
            "fixed_beacon": fixed_beacon,
            "beacon_paths": beacon_paths,
            "outbound_upload": outbound_upload,
            "unusual_port": unusual_port,
            "established": established,
            "total_bytes_out": total_bytes,
            "volume_spike": volume_spike,
        }

        # 证据门槛：重复出现 + (周期性 或 长时保持) + 至少一条方向性信号
        directional = unusual_port or outbound_upload or fixed_beacon or (long_lived and long_lived_count >= 2)
        if count >= 3 and (periodic or long_lived) and directional:
            group.corroborated = True
            if periodic:
                group.reasons.append(f"{count} 次连接间隔中位 {median_gap:.0f}s，呈固定周期")
            if long_lived:
                group.reasons.append(f"{long_lived_count or 1} 次连接持续 ≥240s（中位 {statistics.median(durations):.0f}s）")
            if fixed_beacon:
                group.reasons.append("同一路径、定长响应、全部 2xx，符合心跳指令通道")
            if outbound_upload:
                group.reasons.append("由资产侧主动向外部地址 POST 上传")
            if unusual_port:
                group.reasons.append(f"目的端口 {group.dest_port} 非常规出网端口")
            if volume_spike:
                group.reasons.append(f"外发合计 {int(total_bytes)} 字节，超过该主机对外连接基线 5 倍")
        result.append(group)

    # 同一目的地址上的不同端口属于同一条外连通道：主通道已被多信号确认时，
    # 附属端口（例如指令通道 :4444 + 心跳页 :8080）并入同一结论，
    # 但它们自身仍不足以独立定性（不改变"单次连接不算 C2"的下限）。
    confirmed_destinations = {group.dest_ip for group in result if group.corroborated}
    for group in result:
        if group.corroborated or group.dest_ip not in confirmed_destinations:
            continue
        group.corroborated = True
        group.signals["corroborated_via"] = "same_destination"
        group.reasons.append(
            f"与同一目的地址 {group.dest_ip} 的已确认连接同属一条外连通道"
        )

    result.sort(key=lambda group: (-len(group.logs), group.dest_ip))
    return result


# ---------------------------------------------------------------------------
# 会话与 Web 行为
# ---------------------------------------------------------------------------


def detect_session_reuse(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """同一会话标识被不同来源复用 —— 会话劫持的通用特征。

    返回 ``{session_id, original_src, reused_src, logs, pivot_logs}``；
    ``pivot_logs`` 是劫持前原来源在同一会话上的最后若干请求（被投毒页面的访问通常在这里）。
    """
    by_session: dict[str, list[dict[str, Any]]] = {}
    for log in logs:
        session = str(log.get("session_id") or "").strip()
        if session:
            by_session.setdefault(session, []).append(log)

    findings: list[dict[str, Any]] = []
    for session, rows in by_session.items():
        rows.sort(key=lambda log: parse_ts(log.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
        sources: list[str] = []
        for log in rows:
            src = str(log.get("src_ip") or "")
            if src and src not in sources:
                sources.append(src)
        if len(sources) < 2:
            continue
        original, reused = sources[0], sources[1]
        reused_logs = [log for log in rows if str(log.get("src_ip") or "") == reused]
        first_reuse = parse_ts(reused_logs[0].get("timestamp")) if reused_logs else None
        original_logs = [log for log in rows if str(log.get("src_ip") or "") == original]
        pivot = [
            log
            for log in original_logs
            if first_reuse
            and (stamp := parse_ts(log.get("timestamp"))) is not None
            and 0 <= (first_reuse - stamp).total_seconds() <= 900
        ]
        findings.append(
            {
                "session_id": session,
                "original_src": original,
                "reused_src": reused,
                "logs": reused_logs,
                "pivot_logs": pivot,
                "external_reuse": is_external_ip(reused) and not is_external_ip(original),
            }
        )
    return findings


_SEQUENTIAL_PARAM = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(\d{2,})")


def detect_parameter_enumeration(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """同一来源对同一路径按递增编号批量请求 —— 越权/遍历读取的通用特征。"""
    groups: dict[tuple[str, str, str], list[tuple[int, dict[str, Any]]]] = {}
    for log in logs:
        if log.get("log_source") != "nginx_access":
            continue
        if not (200 <= int(log.get("status_code") or 0) < 300):
            continue
        uri = str(log.get("uri_or_target") or "")
        path, _, query = uri.partition("?")
        for name, value in _SEQUENTIAL_PARAM.findall(query):
            groups.setdefault((str(log.get("src_ip") or ""), path, name), []).append((int(value), log))

    findings: list[dict[str, Any]] = []
    for (src, path, name), rows in groups.items():
        if len({value for value, _ in rows}) < 3:
            continue
        rows.sort(key=lambda item: item[0])
        stamps = sorted(
            (parse_ts(log.get("timestamp")) for _, log in rows if parse_ts(log.get("timestamp"))),
        )
        if not stamps or (stamps[-1] - stamps[0]).total_seconds() > 900:
            continue
        values = [value for value, _ in rows]
        if max(values) - min(values) > 50:  # 编号跳跃过大更像正常分页/筛选
            continue
        findings.append(
            {
                "src_ip": src,
                "path": path,
                "parameter": name,
                "values": values,
                "logs": [log for _, log in rows],
            }
        )
    return findings


def detect_bulk_export(
    logs: list[dict[str, Any]], attackers: set[str]
) -> list[dict[str, Any]]:
    """攻击源在利用之后拉取导出/下载接口且响应体明显偏大 —— 数据外泄迹象。

    只对**已经确认有攻击行为**的来源生效，避免把正常报表导出算成攻击。
    """
    hits: list[dict[str, Any]] = []
    for log in logs:
        if log.get("log_source") != "nginx_access":
            continue
        if str(log.get("src_ip") or "") not in attackers:
            continue
        uri = str(log.get("uri_or_target") or "").lower()
        if not any(word in uri for word in ("/export", "download", "dump", "backup")):
            continue
        if not (200 <= int(log.get("status_code") or 0) < 300):
            continue
        size = log.get("bytes_out")
        if isinstance(size, (int, float)) and size >= 50_000:
            hits.append(log)
    return hits


def window_matches(window: dict[str, Any], timestamp: Any) -> bool:
    """日志时间是否落在单个维护窗口内（配置时区固定为 UTC+8）。"""
    moment = parse_ts(timestamp)
    if moment is None:
        return False
    local = moment.astimezone(timezone(timedelta(hours=8)))
    weekday = local.strftime("%a").lower()[:3]
    days = [str(day).lower()[:3] for day in (window.get("days") or window.get("weekdays") or [])]
    if days and weekday not in days:
        return False
    try:
        start_h, start_m = (int(part) for part in str(window.get("start", "00:00")).split(":"))
        end_h, end_m = (int(part) for part in str(window.get("end", "00:00")).split(":"))
    except ValueError:
        return False
    start = local.replace(hour=start_h, minute=start_m, second=0, microsecond=0)
    end = local.replace(hour=end_h, minute=end_m, second=0, microsecond=0)
    if end <= start:
        end += timedelta(days=1)
    return start <= local <= end
