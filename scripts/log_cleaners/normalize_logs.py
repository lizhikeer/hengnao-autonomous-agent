#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecLog-Agent 多源日志清洗与字段标准化脚本。

把三类原始日志统一转换为《全链路日志统一 Schema》（18 字段）：

    1. Nginx 访问日志      -> log_source = nginx_access
       - 支持默认 combined / main 文本格式
       - 支持 log_format json_escape 输出的 JSON 行
    2. 登录认证日志        -> log_source = auth_log
       - 支持 OpenSSH 标准 auth.log（Failed/Accepted password 等）
       - 支持应用侧 key=value 结构化认证日志（auth_event=... user=... result=...）
    3. Zeek 网络日志       -> log_source = zeek_conn / zeek_http
       - 支持 Zeek 默认 TSV 输出（#fields 表头驱动）
       - 支持 LogAscii::use_json=T 的 JSON 输出

统一 Schema 的 18 个字段（顺序固定，缺失值为 null）：

    log_id, trace_id, timestamp, log_source, src_ip, src_port, dest_ip,
    dest_port, asset_id, user, session_id, action_or_method, uri_or_target,
    payload_summary, status_code, bytes_out, user_agent, attack_stage_hint

字段口径约定（详见 data/full_chain_logs/README.md）：
    * log_id       格式 LOG-<YYYYMMDD>-<NNNN>；后端用该编号做全局唯一证据校验。
                   多个 Case 会合进同一张 ClickHouse 表，因此用 --id-segment N 按 Case 分号段
                   （Case01 -> 01xx、Case02 -> 02xx…），避免不同 Case 撞号
    * timestamp    统一转成 UTC 的 ISO8601（形如 2026-10-27T14:20:05Z）
    * bytes_out    该条日志中"响应/回传方向"的字节数：
                   nginx 取 $body_bytes_sent，zeek_http 取 response_body_len，
                   zeek_conn 取 resp_bytes，auth_log 为 null
    * src_port     Nginx 默认格式不含源端口（需 $remote_port 自定义格式），故为 null
    * attack_stage_hint  仅由弱特征规则给出提示，不构成定性结论；未知时为 null

用法：
    python normalize_logs.py --selftest
    python normalize_logs.py --source nginx_access --input raw.log \
        --trace-id CHAIN-CASE-01 --asset-id web-prod-01 --asset-ip 10.0.0.15 \
        --id-segment 1 --out normalized.jsonl
    python normalize_logs.py --source auto --input ./raw_logs --out all.json --format json

无参数直接运行等价于 --selftest。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

__all__ = [
    "FIELD_ORDER",
    "LOG_SOURCES",
    "STAGE_HINTS",
    "new_record",
    "parse_nginx_line",
    "parse_auth_line",
    "parse_zeek_conn_line",
    "parse_zeek_http_line",
    "infer_stage_hint",
    "validate_record",
]

FIELD_ORDER = (
    "log_id", "trace_id", "timestamp", "log_source",
    "src_ip", "src_port", "dest_ip", "dest_port", "asset_id",
    "user", "session_id", "action_or_method", "uri_or_target",
    "payload_summary", "status_code", "bytes_out", "user_agent",
    "attack_stage_hint",
)

LOG_SOURCES = ("nginx_access", "auth_log", "zeek_conn", "zeek_http")
STAGE_HINTS = ("recon", "brute_force", "exploitation", "c2_callback", "benign")

ISO_Z = "%Y-%m-%dT%H:%M:%SZ"

# ---------------------------------------------------------------- 基础工具


def _clean(value):
    """Zeek 的 '-' / nginx 的 '-' 均表示空值，统一转 None。"""
    if value is None:
        return None
    value = str(value).strip()
    if value in ("", "-", "(empty)"):
        return None
    return value


def _to_int(value):
    try:
        if value is None:
            return None
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_utc_iso(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO_Z)


_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_nginx_time(text):
    """27/Oct/2026:22:02:18 +0800 -> datetime(UTC aware)"""
    m = re.match(
        r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$",
        text.strip(),
    )
    if not m:
        raise ValueError("unrecognized nginx time: %r" % text)
    day, mon, year, hour, minute, second, sign, off_h, off_m = m.groups()
    offset = timedelta(hours=int(off_h), minutes=int(off_m))
    if sign == "-":
        offset = -offset
    tz = timezone(offset)
    return datetime(int(year), _MONTHS[mon], int(day), int(hour), int(minute),
                    int(second), tzinfo=tz)


def _parse_iso_time(text, default_year=None):
    """解析 ISO8601 / syslog 风格时间，返回 UTC aware datetime。"""
    text = text.strip()
    normalised = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalised)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass
    # syslog: Oct 27 22:05:09（无年份，用 default_year 或当前年份补齐）
    m = re.match(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", text)
    if m:
        mon, day, hour, minute, second = m.groups()
        year = default_year or datetime.now(timezone.utc).year
        return datetime(year, _MONTHS[mon], int(day), int(hour), int(minute),
                        int(second), tzinfo=timezone.utc)
    raise ValueError("unrecognized time: %r" % text)


_LEADING_ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_LEADING_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def _split_leading_time(line):
    """拆出行首时间戳，返回 (时间字符串, 余下内容)。"""
    m = _LEADING_ISO_RE.match(line) or _LEADING_SYSLOG_RE.match(line)
    if not m:
        return None, line
    return m.group(1), line[m.end():].lstrip()


def _from_epoch(value):
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def new_record(**kwargs):
    """按固定字段顺序构造一条标准日志记录，拒绝未定义字段。"""
    unknown = set(kwargs) - set(FIELD_ORDER)
    if unknown:
        raise ValueError("unknown field(s): %s" % ", ".join(sorted(unknown)))
    record = {name: None for name in FIELD_ORDER}
    record.update(kwargs)
    for name in ("src_port", "dest_port", "status_code", "bytes_out"):
        record[name] = _to_int(record[name])
    for name in FIELD_ORDER:
        if name in ("src_port", "dest_port", "status_code", "bytes_out"):
            continue
        if record[name] is not None:
            record[name] = str(record[name]).strip()
    return record


# ---------------------------------------------------------------- 阶段提示规则

_PRIVATE_RE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")
_SCANNER_RE = re.compile(
    r"(sqlmap|nikto|dirsearch|gobuster|ffuf|nmap|masscan|zgrab|whatweb|wpscan|hydra|wfuzz)",
    re.I)
_INJECTION_RE = re.compile(
    r"(union\s+select|sleep\s*\(\s*\d|benchmark\s*\(|into\s+outfile|into\s+dumpfile"
    r"|information_schema|'\s*or\s*'?1'?\s*=\s*'?1|<script|\.\./|%2e%2e|/etc/passwd"
    r"|cmd=|/bin/(?:ba)?sh|base64_decode|eval\s*\()",
    re.I)
_WEBSHELL_RE = re.compile(r"/[^\s/]*?(?:shell|webshell|c99|r57|cmd)\.(?:php|jsp|jspx|asp|aspx)\b", re.I)
_SENSITIVE_PATH_RE = re.compile(
    r"(/\.git|/\.svn|/\.env|/\.DS_Store|/backup|\.zip$|\.tar\.gz$|\.bak$|\.sql$"
    r"|/phpmyadmin|/wp-admin|/config\.|/server-status|/actuator)", re.I)
_LOGIN_RE = re.compile(r"/(?:[\w./-]*/)?(?:login|signin|auth|logon)\b", re.I)


def _is_private(ip):
    return bool(ip and _PRIVATE_RE.match(ip))


def infer_stage_hint(log_source, method=None, uri=None, payload=None,
                     user_agent=None, src_ip=None, dest_ip=None, status_code=None):
    """基于单条日志的弱特征给出攻击阶段提示。

    注意：这里只做"提示"，不是定性结论。真实数据集该字段由人工标注，
    Agent 侧不应把它当作唯一线索（否则会造成标签泄漏）。
    """
    target = " ".join(x for x in (uri, payload) if x)
    ua = user_agent or ""

    if log_source in ("zeek_conn", "zeek_http"):
        if _is_private(src_ip) and not _is_private(dest_ip):
            return "c2_callback"
        if _is_private(src_ip) and _is_private(dest_ip):
            return "benign"

    if _INJECTION_RE.search(target):
        return "exploitation"
    if _WEBSHELL_RE.search(uri or ""):
        return "exploitation"
    if _SCANNER_RE.search(ua):
        return "exploitation" if "sqlmap" in ua.lower() else "recon"
    if _SENSITIVE_PATH_RE.search(uri or "") and status_code in (401, 403, 404):
        return "recon"
    if (method or "").upper() == "POST" and _LOGIN_RE.search(uri or ""):
        return "brute_force"
    if log_source == "auth_log" and method and "fail" in method:
        return "brute_force"
    if _is_private(src_ip):
        return "benign"
    return None


# ---------------------------------------------------------------- Nginx

_NGINX_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _split_request(request):
    """'GET /a?b=1 HTTP/1.1' -> ('GET', '/a?b=1')"""
    request = (request or "").strip()
    if not request or request == "-":
        return None, None
    parts = request.split(" ")
    method = parts[0] if parts else None
    target = parts[1] if len(parts) > 1 else None
    return method, target


def parse_nginx_line(line, trace_id, asset_id, dest_ip=None, dest_port=None):
    """解析一行 Nginx 访问日志（combined 文本或 JSON 行），返回 18 字段字典。"""
    line = (line or "").strip()
    if not line:
        return None

    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        time_text = obj.get("time_iso8601") or obj.get("time_local") or obj.get("time")
        src_ip = obj.get("remote_addr") or obj.get("src_ip")
        method, target = _split_request(obj.get("request"))
        if not method:
            method = obj.get("request_method")
            target = obj.get("request_uri") or obj.get("uri")
        try:
            timestamp = _to_utc_iso(_parse_iso_time(time_text))
        except (ValueError, TypeError):
            return None
        user = _clean(obj.get("remote_user"))
        payload = _clean(obj.get("request_body") or obj.get("http_request_body"))
        status_code = _to_int(obj.get("status"))
        bytes_out = _to_int(obj.get("body_bytes_sent"))
        user_agent = _clean(obj.get("http_user_agent"))
        src_port = _to_int(obj.get("remote_port"))
    else:
        m = _NGINX_RE.match(line)
        if not m:
            return None
        try:
            timestamp = _to_utc_iso(_parse_nginx_time(m.group("time")))
        except ValueError:
            return None
        src_ip = m.group("src_ip")
        method, target = _split_request(m.group("request"))
        user = _clean(m.group("user"))
        status_code = _to_int(m.group("status"))
        bytes_out = _to_int(m.group("bytes"))
        user_agent = _clean(m.group("ua"))
        payload = None
        src_port = None

    uri = (target or "").split("?", 1)[0] if target else None
    return new_record(
        trace_id=trace_id,
        timestamp=timestamp,
        log_source="nginx_access",
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        asset_id=asset_id,
        user=user,
        session_id=None,
        action_or_method=method,
        uri_or_target=uri,
        payload_summary=payload,
        status_code=status_code,
        bytes_out=bytes_out,
        user_agent=user_agent,
        attack_stage_hint=infer_stage_hint(
            "nginx_access", method, uri, payload, user_agent, src_ip, dest_ip, status_code),
    )


# ---------------------------------------------------------------- 认证日志

_SSHD_RE = re.compile(
    r"(?P<event>Failed password|Accepted password|Failed publickey|Accepted publickey"
    r"|Invalid user|session opened|session closed|Connection closed)"
    r"(?:\s+for\s+(?:(?:invalid user)\s+)?(?P<user>\S+))?"
    r"(?:\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+))?"
)
_KV_RE = re.compile(r"(\w+)=(\S+)")


def _auth_action_from_sshd(event):
    event = event.lower()
    if event.startswith("failed") or event.startswith("invalid"):
        return "login_failure"
    if event.startswith("accepted"):
        return "login_success"
    if "session opened" in event:
        return "session_opened"
    if "session closed" in event or "connection closed" in event:
        return "session_closed"
    return "auth_event"


def parse_auth_line(line, trace_id, asset_id, dest_ip=None, dest_port=None, year=None):
    """解析一行登录认证日志（sshd 标准格式或 key=value 应用认证格式）。"""
    line = (line or "").strip()
    if not line:
        return None

    user = src_ip = src_port = session_id = target_uri = None
    payload = None
    status_code = bytes_out = user_agent = None

    time_text, rest = _split_leading_time(line)
    if time_text is None:
        return None
    try:
        timestamp = _to_utc_iso(_parse_iso_time(time_text, default_year=year))
    except ValueError:
        return None

    if re.search(r"\b(?:user|src_ip|auth_event)=", rest):
        # 应用侧结构化认证日志：<ts> <host> <proc>[pid]: k=v k=v ...
        kv = dict(_KV_RE.findall(rest))
        event = (kv.get("auth_event") or kv.get("event") or "auth_event").lower()
        user = _clean(kv.get("user"))
        src_ip = _clean(kv.get("src_ip"))
        src_port = _to_int(kv.get("src_port"))
        session_id = _clean(kv.get("session_id"))
        target_uri = _clean(kv.get("uri"))
        result = (kv.get("result") or "").lower()
        if "fail" in event or result in ("fail", "failed", "failure"):
            action = "login_failure"
        elif "success" in event or result in ("success", "ok"):
            action = "login_success"
        elif "closed" in event:
            action = "session_closed"
        elif "opened" in event:
            action = "session_opened"
        else:
            action = event
        reason = _clean(kv.get("reason"))
        if reason:
            payload = "reason=%s" % reason
    else:
        m = _SSHD_RE.search(rest)
        if not m:
            return None
        action = _auth_action_from_sshd(m.group("event"))
        user = _clean(m.group("user"))
        src_ip = _clean(m.group("src_ip"))
        src_port = _to_int(m.group("src_port"))
        target_uri = "sshd"

    return new_record(
        trace_id=trace_id,
        timestamp=timestamp,
        log_source="auth_log",
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        asset_id=asset_id,
        user=user,
        session_id=session_id,
        action_or_method=action,
        uri_or_target=target_uri,
        payload_summary=payload,
        status_code=status_code,
        bytes_out=bytes_out,
        user_agent=user_agent,
        attack_stage_hint=infer_stage_hint(
            "auth_log", action, target_uri, payload, user_agent, src_ip, dest_ip, status_code),
    )


# ---------------------------------------------------------------- Zeek

def _zeek_row(line, fields):
    if not fields:
        raise ValueError(
            "Zeek TSV line requires the '#fields' header (or use JSON output). "
            "Pass fields=... or run with --input on a full Zeek log file.")
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) < len(fields):
        parts += [""] * (len(fields) - len(parts))
    return dict(zip(fields, parts))


def _zeek_dict(line, fields):
    """返回 Zeek 记录字典：既支持 JSON 行，也支持 TSV（需 fields 表头）。"""
    line = (line or "").strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            return json.loads(line)
        except ValueError:
            return None
    return _zeek_row(line, fields)


def parse_zeek_conn_line(line, trace_id, asset_id, fields=None, dest_ip=None, dest_port=None):
    """解析一行 Zeek conn 日志（TSV 需传入 #fields 表头，JSON 行可省略）。"""
    obj = _zeek_dict(line, fields)
    if not obj:
        return None
    try:
        timestamp = _to_utc_iso(_from_epoch(obj["ts"]))
    except (KeyError, TypeError, ValueError):
        return None

    src_ip = _clean(obj.get("id.orig_h"))
    dest = _clean(obj.get("id.resp_h"))
    sport = _to_int(obj.get("id.orig_p"))
    dport = _to_int(obj.get("id.resp_p"))
    service = _clean(obj.get("service"))
    duration = _clean(obj.get("duration"))
    conn_state = _clean(obj.get("conn_state"))
    payload = None
    if conn_state or duration:
        payload = "conn_state=%s;duration=%s" % (conn_state or "-", duration or "-")

    return new_record(
        trace_id=trace_id,
        timestamp=timestamp,
        log_source="zeek_conn",
        src_ip=src_ip,
        src_port=sport,
        dest_ip=dest or dest_ip,
        dest_port=dport or dest_port,
        asset_id=asset_id,
        user=None,
        session_id=_clean(obj.get("uid")),
        action_or_method=_clean(obj.get("proto")),
        uri_or_target="%s:%s" % (dest, dport) if dest else None,
        payload_summary=payload,
        status_code=None,
        bytes_out=_to_int(obj.get("resp_bytes")),
        user_agent=None,
        attack_stage_hint=infer_stage_hint(
            "zeek_conn", _clean(obj.get("proto")), None, payload, None, src_ip, dest),
    )


def parse_zeek_http_line(line, trace_id, asset_id, fields=None, dest_ip=None, dest_port=None):
    """解析一行 Zeek http 日志（TSV 需传入 #fields 表头，JSON 行可省略）。"""
    obj = _zeek_dict(line, fields)
    if not obj:
        return None
    try:
        timestamp = _to_utc_iso(_from_epoch(obj["ts"]))
    except (KeyError, TypeError, ValueError):
        return None

    src_ip = _clean(obj.get("id.orig_h"))
    dest = _clean(obj.get("id.resp_h"))
    sport = _to_int(obj.get("id.orig_p"))
    dport = _to_int(obj.get("id.resp_p"))
    method = _clean(obj.get("method"))
    uri = _clean(obj.get("uri"))
    status_code = _to_int(obj.get("status_code"))
    user_agent = _clean(obj.get("user_agent"))
    request_body_len = _to_int(obj.get("request_body_len"))
    payload = None
    if request_body_len:
        payload = "request_body_len=%s" % request_body_len

    return new_record(
        trace_id=trace_id,
        timestamp=timestamp,
        log_source="zeek_http",
        src_ip=src_ip,
        src_port=sport,
        dest_ip=dest or dest_ip,
        dest_port=dport or dest_port,
        asset_id=asset_id,
        user=_clean(obj.get("username")),
        session_id=_clean(obj.get("uid")),
        action_or_method=method,
        uri_or_target=(uri or "").split("?", 1)[0] if uri else None,
        payload_summary=payload,
        status_code=status_code,
        bytes_out=_to_int(obj.get("response_body_len")),
        user_agent=user_agent,
        attack_stage_hint=infer_stage_hint(
            "zeek_http", method, uri, payload, user_agent, src_ip, dest, status_code),
    )


PARSERS = {
    "nginx_access": parse_nginx_line,
    "auth_log": parse_auth_line,
    "zeek_conn": parse_zeek_conn_line,
    "zeek_http": parse_zeek_http_line,
}


# ---------------------------------------------------------------- 校验

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$")
_LOG_ID_RE = re.compile(r"^LOG-\d{8}-\d{4,}$")


def validate_record(record):
    """校验一条记录是否符合统一 Schema，返回错误字符串列表（空列表即通过）。"""
    errors = []
    if not isinstance(record, dict):
        return ["record is not a dict"]
    if list(record.keys()) != list(FIELD_ORDER):
        missing = [k for k in FIELD_ORDER if k not in record]
        extra = [k for k in record if k not in FIELD_ORDER]
        if missing:
            errors.append("missing fields: %s" % ",".join(missing))
        if extra:
            errors.append("unexpected fields: %s" % ",".join(extra))
    if record.get("log_source") not in LOG_SOURCES:
        errors.append("bad log_source: %r" % record.get("log_source"))
    ts = record.get("timestamp")
    if ts is None or not _ISO_RE.match(str(ts)):
        errors.append("bad timestamp: %r" % ts)
    hint = record.get("attack_stage_hint")
    if hint is not None and hint not in STAGE_HINTS:
        errors.append("bad attack_stage_hint: %r" % hint)
    log_id = record.get("log_id")
    if log_id is not None and not _LOG_ID_RE.match(str(log_id)):
        errors.append("bad log_id: %r" % log_id)
    for name in ("src_port", "dest_port", "status_code", "bytes_out"):
        value = record.get(name)
        if value is not None and not isinstance(value, int):
            errors.append("%s must be int or null, got %r" % (name, value))
    return errors


# ---------------------------------------------------------------- 文件处理

def _read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def _zeek_fields(lines):
    fields = None
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            break
    return fields


def guess_source(path, lines):
    name = Path(path).name.lower()
    if "zeek" in name and "http" in name:
        return "zeek_http"
    if "zeek" in name and "conn" in name:
        return "zeek_conn"
    if "auth" in name or "secure" in name:
        return "auth_log"
    if "nginx" in name or "access" in name:
        return "nginx_access"
    sample = "\n".join(lines[:40])
    if "#fields" in sample:
        return "zeek_http" if re.search(r"\bmethod\b", sample) else "zeek_conn"
    if "sshd[" in sample or "auth_event=" in sample:
        return "auth_log"
    return "nginx_access"


def normalize_file(path, source, trace_id, asset_id, asset_ip=None, asset_port=None,
                   year=None, log_id_prefix=None, id_segment=None):
    lines = _read_lines(path)
    if source == "auto":
        source = guess_source(path, lines)
    parser = PARSERS[source]
    fields = _zeek_fields(lines) if source.startswith("zeek") else None

    records = []
    skipped = 0
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        if source.startswith("zeek"):
            record = parser(line, trace_id, asset_id, fields=fields,
                            dest_ip=asset_ip, dest_port=asset_port)
        else:
            kwargs = {"dest_ip": asset_ip, "dest_port": asset_port}
            if source == "auth_log":
                kwargs["year"] = year
            record = parser(line, trace_id, asset_id, **kwargs)
        if record is None:
            skipped += 1
            continue
        records.append(record)

    tag = log_id_prefix or datetime.now(timezone.utc).strftime("%Y%m%d")
    for index, record in enumerate(records, start=1):
        if id_segment:
            # 按 Case 分号段：Case01 -> 01xx、Case02 -> 02xx（合进同一张表后仍全局唯一）
            record["log_id"] = "LOG-%s-%04d" % (tag, int(id_segment) * 100 + index)
        else:
            record["log_id"] = "LOG-%s-%04d" % (tag, index)
    return records, skipped


def write_records(records, out_path, fmt="jsonl", indent=2):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="\n") as handle:
        if fmt == "json":
            json.dump(records, handle, ensure_ascii=False, indent=indent)
            handle.write("\n")
        else:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- 自检

_SAMPLE_NGINX = (
    '198.51.100.23 - - [27/Oct/2026:22:02:18 +0800] "GET /.git/config HTTP/1.1" '
    '404 162 "-" "dirsearch/0.4.3"'
)
_SAMPLE_NGINX_JSON = json.dumps({
    "time_iso8601": "2026-10-27T22:05:09+08:00",
    "remote_addr": "198.51.100.23",
    "remote_user": "-",
    "request": "POST /admin/login.php HTTP/1.1",
    "status": 200,
    "body_bytes_sent": 3980,
    "http_user_agent": "python-requests/2.31.0",
    "request_body": "username=admin&password=Admin@123",
}, ensure_ascii=False)

_SAMPLE_AUTH_APP = (
    "2026-10-27T22:05:09+08:00 web-prod-01 webadmin[1188]: auth_event=login_failure "
    "user=admin src_ip=198.51.100.23 src_port=54321 app=web_admin uri=/admin/login.php "
    "session_id=- result=fail reason=invalid_password"
)
_SAMPLE_AUTH_SSHD = (
    "2026-10-30T02:30:00+08:00 web-prod-01 sshd[20431]: Accepted password for ops_zhang "
    "from 10.0.0.66 port 61234 ssh2"
)
_ZEEK_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                "proto", "service", "duration", "orig_bytes", "resp_bytes",
                "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
                "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"]
_SAMPLE_ZEEK_CONN_TSV = (
    "1793182053.000000\tC9a1c4e77b0d3f28\t10.0.0.15\t49712\t45.77.128.203\t4444\t"
    "TCP\t-\t512.3\t1240\t880\tSF\tT\tF\t0\tShADadFf\t8\t1560\t8\t1200\t-"
)
_SAMPLE_ZEEK_HTTP_JSON = json.dumps({
    "ts": 1793181980.0, "uid": "C1d8e7a3409b2f61",
    "id.orig_h": "203.0.113.45", "id.orig_p": 51244,
    "id.resp_h": "10.0.0.15", "id.resp_p": 80,
    "method": "POST", "host": "shop.anheng-lab.cn", "uri": "/uploads/shell.php",
    "user_agent": "Mozilla/5.0", "request_body_len": 96,
    "response_body_len": 120, "status_code": 200,
})


def _selftest():
    cases = []

    def expect(label, record, trace_id="CHAIN-CASE-01", **fields):
        base = new_record(trace_id=trace_id, asset_id="web-prod-01")
        base.update(fields)
        cases.append((label, record, base))

    expect(
        "nginx combined",
        parse_nginx_line(_SAMPLE_NGINX, "CHAIN-CASE-01", "web-prod-01",
                         dest_ip="10.0.0.15", dest_port=443),
        timestamp="2026-10-27T14:02:18Z", log_source="nginx_access",
        src_ip="198.51.100.23", dest_ip="10.0.0.15", dest_port=443,
        action_or_method="GET", uri_or_target="/.git/config",
        status_code=404, bytes_out=162, user_agent="dirsearch/0.4.3",
        attack_stage_hint="recon",
    )
    expect(
        "nginx json",
        parse_nginx_line(_SAMPLE_NGINX_JSON, "CHAIN-CASE-01", "web-prod-01",
                         dest_ip="10.0.0.15", dest_port=443),
        timestamp="2026-10-27T14:05:09Z", log_source="nginx_access",
        src_ip="198.51.100.23", dest_ip="10.0.0.15", dest_port=443,
        action_or_method="POST", uri_or_target="/admin/login.php",
        payload_summary="username=admin&password=Admin@123",
        status_code=200, bytes_out=3980, user_agent="python-requests/2.31.0",
        attack_stage_hint="brute_force",
    )
    expect(
        "auth app kv",
        parse_auth_line(_SAMPLE_AUTH_APP, "CHAIN-CASE-01", "web-prod-01", dest_ip="10.0.0.15"),
        timestamp="2026-10-27T14:05:09Z", log_source="auth_log",
        src_ip="198.51.100.23", src_port=54321, dest_ip="10.0.0.15",
        user="admin", action_or_method="login_failure", uri_or_target="/admin/login.php",
        payload_summary="reason=invalid_password", attack_stage_hint="brute_force",
    )
    expect(
        "auth sshd",
        parse_auth_line(_SAMPLE_AUTH_SSHD, "CHAIN-CASE-03", "web-prod-01", dest_ip="10.0.0.15"),
        trace_id="CHAIN-CASE-03",
        timestamp="2026-10-29T18:30:00Z", log_source="auth_log",
        src_ip="10.0.0.66", src_port=61234, dest_ip="10.0.0.15",
        user="ops_zhang", action_or_method="login_success", uri_or_target="sshd",
        attack_stage_hint="benign",
    )
    expect(
        "zeek conn tsv",
        parse_zeek_conn_line(_SAMPLE_ZEEK_CONN_TSV, "CHAIN-CASE-02", "web-prod-01",
                             fields=_ZEEK_FIELDS),
        trace_id="CHAIN-CASE-02",
        timestamp="2026-10-28T10:07:33Z", log_source="zeek_conn",
        src_ip="10.0.0.15", src_port=49712, dest_ip="45.77.128.203", dest_port=4444,
        session_id="C9a1c4e77b0d3f28", action_or_method="TCP",
        uri_or_target="45.77.128.203:4444",
        payload_summary="conn_state=SF;duration=512.3",
        bytes_out=880, attack_stage_hint="c2_callback",
    )
    expect(
        "zeek http json",
        parse_zeek_http_line(_SAMPLE_ZEEK_HTTP_JSON, "CHAIN-CASE-02", "web-prod-01"),
        trace_id="CHAIN-CASE-02",
        timestamp="2026-10-28T10:06:20Z", log_source="zeek_http",
        src_ip="203.0.113.45", src_port=51244, dest_ip="10.0.0.15", dest_port=80,
        session_id="C1d8e7a3409b2f61", action_or_method="POST",
        uri_or_target="/uploads/shell.php", payload_summary="request_body_len=96",
        status_code=200, bytes_out=120, user_agent="Mozilla/5.0",
        attack_stage_hint="exploitation",
    )

    failures = 0
    for label, record, expected in cases:
        if record is None:
            print("  [FAIL] %-16s -> parser returned None" % label)
            failures += 1
            continue
        diff = {k: (expected[k], record.get(k)) for k in FIELD_ORDER
                if expected[k] != record.get(k)}
        if diff:
            failures += 1
            print("  [FAIL] %-16s" % label)
            for key, (want, got) in diff.items():
                print("         %-18s expected=%r got=%r" % (key, want, got))
        else:
            errors = validate_record(record)
            if errors:
                failures += 1
                print("  [FAIL] %-16s schema: %s" % (label, "; ".join(errors)))
            else:
                print("  [ OK ] %-16s -> %s %s" % (label, record["log_source"],
                                                   record["timestamp"]))

    if parse_nginx_line("this is not a log line", "T", "A") is not None:
        failures += 1
        print("  [FAIL] malformed line should be skipped, not parsed")

    if failures:
        print("SELFTEST FAILED: %d case(s)" % failures)
        return 1
    print("SELFTEST PASSED: %d cases, 18 fields aligned" % len(cases))
    return 0


# ---------------------------------------------------------------- CLI

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="多源日志清洗：nginx / auth / zeek -> 全链路日志统一 Schema")
    parser.add_argument("--input", help="原始日志文件或目录")
    parser.add_argument("--source", default="auto", choices=("auto",) + LOG_SOURCES)
    parser.add_argument("--out", help="输出文件路径（.jsonl 或 .json）")
    parser.add_argument("--format", default="jsonl", choices=("jsonl", "json"))
    parser.add_argument("--trace-id", default="TRACE-UNSPECIFIED")
    parser.add_argument("--asset-id", default="unknown-asset")
    parser.add_argument("--asset-ip", default=None, help="目标资产 IP，回填 dest_ip")
    parser.add_argument("--asset-port", type=int, default=None, help="目标资产端口")
    parser.add_argument("--year", type=int, default=None, help="syslog 无年份时补齐")
    parser.add_argument("--log-id-prefix", default=None, help="log_id 日期段，默认当天 YYYYMMDD")
    parser.add_argument("--id-segment", type=int, default=None, metavar="N",
                        help="按 Case 分号段：Case01 传 1 -> LOG-YYYYMMDD-01xx（保证合表后全局唯一）")
    parser.add_argument("--strict", action="store_true", help="Schema 校验不通过则退出码 1")
    parser.add_argument("--selftest", action="store_true", help="运行内置自检用例")
    args = parser.parse_args(argv)

    if args.selftest or not args.input:
        return _selftest()

    input_path = Path(args.input)
    if not input_path.exists():
        print("ERROR: input not found: %s" % input_path, file=sys.stderr)
        return 2

    files = sorted(input_path.glob("*.log")) if input_path.is_dir() else [input_path]
    if not files:
        print("ERROR: no *.log file under %s" % input_path, file=sys.stderr)
        return 2

    all_records = []
    total_skipped = 0
    for file_path in files:
        records, skipped = normalize_file(
            file_path, args.source, args.trace_id, args.asset_id,
            asset_ip=args.asset_ip, asset_port=args.asset_port,
            year=args.year, log_id_prefix=args.log_id_prefix,
            id_segment=args.id_segment)
        all_records.extend(records)
        total_skipped += skipped
        print("parsed %-40s %4d records, %d skipped" % (file_path.name, len(records), skipped))

    invalid = 0
    for record in all_records:
        errors = validate_record(record)
        if errors:
            invalid += 1
            print("SCHEMA ERROR %s: %s" % (record.get("log_id"), "; ".join(errors)),
                  file=sys.stderr)

    if args.out:
        write_records(all_records, args.out, args.format)
        print("wrote %s (%d records, format=%s)" % (args.out, len(all_records), args.format))
    else:
        for record in all_records:
            print(json.dumps(record, ensure_ascii=False))

    print("total=%d skipped=%d schema_invalid=%d" % (len(all_records), total_skipped, invalid))
    if args.strict and (invalid or total_skipped):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
