"""针对统一 Schema 的补充检测规则（Issue #16 任务 3）。

## 为什么要在老规则之外再写一层

老项目 `src/detection/rules.py` 面向的是「账号 + 资源 + 结果」这类 OA/VPN 日志，
它覆盖的是爆破、敏感资源、API 高频、下载外带、权限变更、横向移动。
但本项目接入的是 **Web 访问 + 认证 + Zeek 网络日志**，首期要求的 7 类场景里，
扫描探测、SQL 注入、XSS、路径遍历、恶意上传、可疑外连这 6 类它都不判。

所以这层的职责是：**只补老规则不覆盖的场景，不改老规则本身**。
两层结果由 `scripts/detect_clues.py` 合并输出，事件结构完全一致（都用 `AnomalyEventBuilder`）。

## 设计约束

1. 只读 `NormalizedLog`，不查库、不依赖网络，方便单测与离线回放。
2. 每条规则给出**可解释的证据**（命中的字段与片段），Agent 后续要用它做多轮调查。
3. 风险定级用 `risk_component_overrides`，不改共享的 `config/risk-scoring-v1.json`——
   配置是团队共享资产，加码要评审。
4. `attack_stage_hint` 只作为参考写进证据，不参与判定，避免标注数据反向污染检测。
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

from src.detection.anomaly_builder import AnomalyEventBuilder
from src.schemas import AnomalyEvent, NormalizedLog

# --- 特征（大小写不敏感，%XX 已解码前的原文也要覆盖）---------------------------

SQLI_PATTERN = re.compile(
    r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|sleep\s*\(|benchmark\s*\("
    r"|information_schema|into\s+outfile|load_file\s*\(|;\s*drop\s+table)",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"(<script|onerror\s*=|onload\s*=|javascript:|alert\s*\(|document\.cookie)",
    re.IGNORECASE,
)

TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
    re.IGNORECASE,
)

WEBSHELL_NS = re.compile(r"(shell|cmd|backdoor|webshell|behinder|godzilla)", re.IGNORECASE)
UPLOAD_EXT = re.compile(r"\.(php\d?|jspx?|asp|aspx|exe|sh|py)$", re.IGNORECASE)
PHP_OR_JSP_PAYLOAD = re.compile(r"(<\?php|<%|eval\s*\(|base64_decode\s*\()", re.IGNORECASE)

# 常见 C2 / 反弹 shell 端口，命中即提高可疑度
C2_PORTS = {4444, 4445, 1337, 31337, 6667, 6666, 8888, 9001, 12345}

PRIVATE_PREFIX = ("10.", "192.168.", "127.")


def _is_private(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(PRIVATE_PREFIX):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def _text_of(log: NormalizedLog) -> tuple[str, str]:
    """返回 (URI, payload) 的小写文本，供特征匹配。"""
    uri = str(getattr(log, "resource", "") or "")
    payload = str(getattr(log, "payload_summary", "") or "")
    extra = getattr(log, "object_id", "") or ""
    return f"{uri} {extra}".strip(), payload


#: 周期性外连判定：同一 (src,dst,uri) 至少这么多次才可能是心跳
BEACON_MIN_BEATS = 3
#: 心跳间隔的变异系数上限（标准差/均值）。真实业务请求不会这么规整。
BEACON_MAX_CV = 0.25
#: 单次出向字节达到该值视为大流量外传
EXFIL_BYTES_THRESHOLD = 100_000


def _outbound_signals(logs: list[NormalizedLog]) -> dict[str, tuple[str, dict[str, object]]]:
    """批量识别两类出向异常，返回 ``{event_id: (kind, evidence)}``。

    * ``beacon``：内网 → 外网、同一 URI 的等间隔重复请求（C2 心跳）；
    * ``exfil`` ：内网 → 外网单次出向字节超过阈值（数据外传）。

    为什么必须批量算：单条日志看不出"每 5 分钟一次"这种节律，只有把同一
    (源, 目的, URI) 的整串请求放在一起比较间隔才能识别。CASE-08 的 C2
    走 443 端口伪装成正常 HTTPS，端口规则永远抓不到，只能靠行为特征。

    只在**命中的那几条日志**上出线索，而不是整段流量都报，
    否则一次心跳会把几十条正常日志全变成告警。
    """
    buckets: dict[tuple[str, str, str], list[NormalizedLog]] = defaultdict(list)
    for log in logs:
        if not str(getattr(log, "log_source", "") or "").startswith("zeek"):
            continue
        src = log.src_ip or ""
        dst = log.dst_ip or ""
        if not (_is_private(src) and dst and not _is_private(dst)):
            continue
        uri = str(getattr(log, "resource", "") or "")
        buckets[(src, dst, uri)].append(log)

    signals: dict[str, tuple[str, dict[str, object]]] = {}
    for (src, dst, uri), items in buckets.items():
        # exfil：任意一条出向字节超过阈值即成立（不要求周期性，一次性拖库也算）
        for log in items:
            try:
                nbytes = int(getattr(log, "bytes_out", 0) or 0)
            except (TypeError, ValueError):
                nbytes = 0
            if nbytes >= EXFIL_BYTES_THRESHOLD:
                signals[log.event_id] = (
                    "exfil",
                    {"internal_ip": src, "external_ip": dst, "bytes_out": nbytes},
                )

        # beacon：URI 非空、次数足够、且间隔足够规整
        if not uri or len(items) < BEACON_MIN_BEATS:
            continue
        times = sorted(log.event_time for log in items)
        gaps = [
            (later - earlier).total_seconds()
            for earlier, later in zip(times, times[1:])
        ]
        gaps = [gap for gap in gaps if gap > 0]
        if len(gaps) < BEACON_MIN_BEATS - 1:
            continue
        mean = sum(gaps) / len(gaps)
        if mean <= 0:
            continue
        variance = sum((gap - mean) ** 2 for gap in gaps) / len(gaps)
        if (variance ** 0.5) / mean > BEACON_MAX_CV:
            continue
        for log in items:
            signals.setdefault(
                log.event_id,
                (
                    "beacon",
                    {
                        "internal_ip": src,
                        "external_ip": dst,
                        "uri": uri,
                        "beats": len(items),
                        "interval_seconds": round(mean, 1),
                    },
                ),
            )
    return signals


def detect_supplementary(
    logs: list[NormalizedLog],
    *,
    builder: AnomalyEventBuilder | None = None,
    scan_window_minutes: int = 5,
    scan_error_threshold: int = 5,
) -> list[AnomalyEvent]:
    """跑全部补充规则，返回异常事件列表。

    `logs` 需要按时间升序传入，扫描规则的滑动窗口依赖顺序。
    """
    builder = builder or AnomalyEventBuilder()
    events: list[AnomalyEvent] = []
    outbound = _outbound_signals(logs)

    # 扫描探测的滑动窗口：src_ip -> 最近 N 分钟的 404/403 时间戳
    error_window: dict[str, deque[datetime]] = defaultdict(deque)
    window = timedelta(minutes=scan_window_minutes)

    for log in logs:
        uri, payload = _text_of(log)
        haystack = f"{uri} {payload}"
        status = getattr(log, "status_code", None)
        try:
            status_int = int(status) if status not in (None, "") else None
        except (TypeError, ValueError):
            status_int = None

        # ---- 1. 扫描探测：同源 IP 在窗口内大量 404/403 ----
        if log.src_ip and status_int in (403, 404):
            q = error_window[log.src_ip]
            q.append(log.event_time)
            while q and log.event_time - q[0] > window:
                q.popleft()
            if len(q) == scan_error_threshold:  # 只在跨过阈值的那一次报，避免刷屏
                events.append(builder.build(
                    log=log,
                    rule_hits=["同源IP短时间大量敏感路径探测"],
                    reason_codes=["scanning_probe"],
                    evidence={
                        "src_ip": log.src_ip,
                        "error_count_in_window": len(q),
                        "window_minutes": scan_window_minutes,
                        "sample_uri": uri,
                    },
                    attack_type="Scanning_Probe",
                    risk_component_overrides={"rule_strength": 20},
                ))

        # ---- 2. SQL 注入 ----
        if SQLI_PATTERN.search(haystack):
            events.append(builder.build(
                log=log,
                rule_hits=["URI/载荷包含SQL注入特征"],
                reason_codes=["sql_injection"],
                evidence={
                    "src_ip": log.src_ip,
                    "uri": uri,
                    "payload": payload[:200],
                    "matched": SQLI_PATTERN.search(haystack).group(0),
                    "status_code": status_int,
                },
                attack_type="SQL_Injection",
                risk_component_overrides={"rule_strength": 35, "behavior_sensitivity": 20},
            ))

        # ---- 3. XSS ----
        if XSS_PATTERN.search(haystack):
            events.append(builder.build(
                log=log,
                rule_hits=["URI/载荷包含XSS特征"],
                reason_codes=["xss_attempt"],
                evidence={
                    "src_ip": log.src_ip,
                    "uri": uri,
                    "payload": payload[:200],
                    "matched": XSS_PATTERN.search(haystack).group(0),
                },
                attack_type="XSS",
                risk_component_overrides={"rule_strength": 30, "behavior_sensitivity": 15},
            ))

        # ---- 4. 路径遍历 ----
        if TRAVERSAL_PATTERN.search(haystack):
            events.append(builder.build(
                log=log,
                rule_hits=["URI包含路径遍历特征"],
                reason_codes=["path_traversal"],
                evidence={
                    "src_ip": log.src_ip,
                    "uri": uri,
                    "matched": TRAVERSAL_PATTERN.search(haystack).group(0),
                },
                attack_type="Path_Traversal",
                risk_component_overrides={"rule_strength": 30, "behavior_sensitivity": 20},
            ))

        # ---- 5. 恶意文件上传 / webshell ----
        upload_hit = False
        if PHP_OR_JSP_PAYLOAD.search(payload) and (log.action or "").lower() in {"upload", "api_call", "post"}:
            upload_hit = True
        if UPLOAD_EXT.search(uri) and (log.action or "").lower() in {"upload", "post"}:
            upload_hit = True
        if upload_hit:
            events.append(builder.build(
                log=log,
                rule_hits=["检测到可执行脚本上传特征"],
                reason_codes=["malicious_upload"],
                evidence={
                    "src_ip": log.src_ip,
                    "uri": uri,
                    "payload": payload[:200],
                    "status_code": status_int,
                },
                attack_type="Malicious_Upload",
                risk_component_overrides={"rule_strength": 35, "behavior_sensitivity": 20},
            ))

        # webshell 访问：URI 像 shell 且带执行参数
        if WEBSHELL_NS.search(uri) and UPLOAD_EXT.search(uri):
            events.append(builder.build(
                log=log,
                rule_hits=["访问疑似webshell脚本"],
                reason_codes=["webshell_access"],
                evidence={
                    "src_ip": log.src_ip,
                    "uri": uri,
                    "status_code": status_int,
                    "user_agent": getattr(log, "user_agent", None),
                },
                attack_type="Webshell_Access",
                risk_component_overrides={"rule_strength": 35, "event_correlation": 10},
            ))

        # ---- 6. 可疑外连：内网资产 → 外部 IP 的异常端口 ----
        if (
            str(getattr(log, "log_source", "") or "").startswith("zeek")
            and _is_private(log.src_ip or "")
            and log.dst_ip
            and not _is_private(log.dst_ip)
            and log.dst_port in C2_PORTS
        ):
            events.append(builder.build(
                log=log,
                rule_hits=["内网资产向外部非常用端口发起连接"],
                reason_codes=["suspicious_outbound"],
                evidence={
                    "internal_ip": log.src_ip,
                    "external_ip": log.dst_ip,
                    "external_port": log.dst_port,
                    "conn_state": payload[:80],
                },
                attack_type="Suspicious_Outbound",
                risk_component_overrides={"rule_strength": 30, "event_correlation": 10},
            ))

        # ---- 7. 行为型出向异常：C2 心跳 / 大流量外传 ----
        # 与第 6 条互补：第 6 条看端口，这一条看节律与字节数，
        # 专门覆盖"伪装成 443 正常 HTTPS"的 C2（CASE-08）。
        signal = outbound.get(log.event_id)
        if signal:
            kind, detail = signal
            if kind == "beacon":
                events.append(builder.build(
                    log=log,
                    rule_hits=["内网资产对外部地址呈现等间隔心跳"],
                    reason_codes=["beacon_pattern"],
                    evidence=dict(detail),
                    attack_type="Suspicious_Outbound",
                    risk_component_overrides={"rule_strength": 30, "event_correlation": 20},
                ))
            else:
                events.append(builder.build(
                    log=log,
                    rule_hits=["内网资产向外部地址单次传输大流量"],
                    reason_codes=["outbound_volume_spike"],
                    evidence=dict(detail),
                    attack_type="Data_Exfiltration",
                    risk_component_overrides={"rule_strength": 30, "behavior_sensitivity": 20},
                ))

    return events
