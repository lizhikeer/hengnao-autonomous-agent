#!/usr/bin/env python3
"""把 `data/full_chain_logs/raw/` 下的三源原始日志转成统一 Schema JSONL。

## 定位（重要）

这是**验证用的样本转换器，不是正式清洗管线**。
正式的清洗脚本由 `@ribbonfish-jun` 在 `scripts/log_cleaners/` 下按
《全链路日志统一字段规范》实现，会处理更多边界、脱敏与幂等。
本脚本只服务于「把已有样本灌进 ClickHouse 端到端验证链路」这一个目的，
输出文件放在 `data/full_chain_logs/normalized/`，可直接喂给
`scripts/ingest_clickhouse.py`。

## 用法

```bash
python3 scripts/sample_env/sample_to_schema.py \
    --raw data/full_chain_logs/raw \
    --out data/full_chain_logs/normalized/CHAIN-sample.jsonl
```
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# 攻击者指纹：样本里的攻击流量都带这些 UA / 特征
ATTACK_UA = re.compile(r"sqlmap|python-requests|nikto|nmap|masscan", re.I)
EXPLOIT_URI = re.compile(r"(OR\+?1%3D1|OR 1=1|UNION\+?SELECT|shell\.php|<script)", re.I)

NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) "[^"]*" "(?P<ua>[^"]*)"'
)

AUTH_RE = re.compile(
    r"^(?P<ts>\S+) (?P<host>\S+) sshd\[\d+\]: "
    r"(?:Accepted|session opened for user|Disconnected from user|pam_unix)\(?.*?"
    r"(?:user (?P<user>\w+)|for user (?P<user2>\w+))?",
)


def parse_nginx_time(raw: str) -> str:
    """`01/Nov/2026:16:29:04 +0000` → UTC ISO8601 带 Z。"""
    dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def classify(uri: str, ua: str, status: int) -> tuple[str, str]:
    """返回 (trace_id, attack_stage_hint)。"""
    is_attack = bool(ATTACK_UA.search(ua)) or bool(EXPLOIT_URI.search(uri))
    if not is_attack:
        return "", "benign"
    if EXPLOIT_URI.search(uri):
        return "CHAIN-001", "exploitation"
    if status == 401:
        return "CHAIN-001", "brute_force"
    if status in (403, 404):
        return "CHAIN-001", "recon"
    return "CHAIN-001", "recon"


def convert_nginx(path: Path, start_seq: int) -> list[dict]:
    rows = []
    seq = start_seq
    for line in path.read_text(encoding="utf-8").splitlines():
        m = NGINX_RE.match(line)
        if not m:
            continue
        seq += 1
        ts = parse_nginx_time(m["ts"])
        trace_id, stage = classify(m["uri"], m["ua"], int(m["status"]))
        day = ts[:10].replace("-", "")
        rows.append({
            "log_id": f"LOG-{day}-{seq:04d}",
            "trace_id": trace_id,
            "timestamp": ts,
            "log_source": "nginx_access",
            "src_ip": m["ip"],
            "src_port": None,
            "dest_ip": "10.0.0.15",
            "dest_port": 18081,
            "asset_id": "web-prod-01",
            "user": "",
            "session_id": "sess-sample-01",
            "action_or_method": m["method"],
            "uri_or_target": m["uri"],
            "payload_summary": "",
            "status_code": int(m["status"]),
            "bytes_out": int(m["bytes"]),
            "user_agent": m["ua"],
            "attack_stage_hint": stage,
        })
    return rows


def convert_auth(path: Path, start_seq: int) -> list[dict]:
    rows = []
    seq = start_seq
    for line in path.read_text(encoding="utf-8").splitlines():
        if "sshd" not in line:
            continue
        seq += 1
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        ts_raw, host, rest = parts
        try:
            ts = datetime.fromisoformat(ts_raw).astimezone(timezone.utc)
            ts_str = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            ts = datetime.now(timezone.utc)
            ts_str = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        # sshd 的 IP 出现在 "from <ip>" / "IP":"<ip>" 等多种上下文，
        # 统一用「行内第一个 IP 字面量」兜底，避免被 "from user xxx" 干扰
        ip_m = re.search(
            r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b",
            rest,
        )
        user_m = re.search(r"user (\w+)", rest)
        failed = "Failed" in rest or "Invalid" in rest
        day = ts.strftime("%Y%m%d")
        rows.append({
            "log_id": f"LOG-{day}-{seq:04d}",
            "trace_id": "",
            "timestamp": ts_str,
            "log_source": "auth_log",
            "src_ip": ip_m.group(1) if ip_m else "",
            "src_port": None,
            "dest_ip": "10.0.0.20",
            "dest_port": 22,
            "asset_id": "nas-host-01",
            "user": user_m.group(1) if user_m else "",
            "session_id": "",
            "action_or_method": "ssh",
            "uri_or_target": "sshd",
            "payload_summary": "",
            "status_code": 401 if failed else 0,
            "bytes_out": None,
            "user_agent": "",
            "attack_stage_hint": "brute_force" if failed else "benign",
        })
    return rows


def read_zeek(path: Path) -> tuple[list[str], list[list[str]]]:
    """按 #fields 表头解析 Zeek TSV，返回 (fields, rows)。"""
    fields: list[str] = []
    rows: list[list[str]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#") or not line.strip():
            continue
        else:
            rows.append(line.split("\t"))
    return fields, rows


def convert_zeek_conn(path: Path, start_seq: int) -> list[dict]:
    fields, rows = read_zeek(path)
    if not fields:
        return []
    out = []
    for i, r in enumerate(rows, start=start_seq):
        rec = dict(zip(fields, r))
        ts = datetime.fromtimestamp(float(rec["ts"]), tz=timezone.utc)
        day = ts.strftime("%Y%m%d")
        out.append({
            "log_id": f"LOG-{day}-{i:04d}",
            "trace_id": "CHAIN-001",
            "timestamp": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "log_source": "zeek_conn",
            "src_ip": rec.get("id.orig_h", ""),
            "src_port": int(float(rec["id.orig_p"])) if rec.get("id.orig_p") else None,
            "dest_ip": rec.get("id.resp_h", ""),
            "dest_port": int(float(rec["id.resp_p"])) if rec.get("id.resp_p") else None,
            "asset_id": "web-prod-01",
            "user": "",
            "session_id": "",
            "action_or_method": rec.get("proto", "tcp"),
            "uri_or_target": f"{rec.get('id.resp_h','')}:{rec.get('id.resp_p','')}",
            "payload_summary": f"{rec.get('conn_state','')}/{rec.get('history','')}",
            "status_code": 200 if rec.get("conn_state") == "SF" else None,
            "bytes_out": int(rec["resp_bytes"]) if rec.get("resp_bytes", "").isdigit() else None,
            "user_agent": "",
            "attack_stage_hint": "benign",
        })
    return out


def convert_zeek_http(path: Path, start_seq: int) -> list[dict]:
    fields, rows = read_zeek(path)
    if not fields:
        return []
    out = []
    for i, r in enumerate(rows, start=start_seq):
        rec = dict(zip(fields, r))
        ts = datetime.fromtimestamp(float(rec["ts"]), tz=timezone.utc)
        day = ts.strftime("%Y%m%d")
        uri = rec.get("uri", "")
        ua = rec.get("user_agent", "")
        trace_id, stage = classify(uri, ua, 200)
        out.append({
            "log_id": f"LOG-{day}-{i:04d}",
            "trace_id": trace_id,
            "timestamp": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "log_source": "zeek_http",
            "src_ip": rec.get("id.orig_h", ""),
            "src_port": int(float(rec["id.orig_p"])) if rec.get("id.orig_p") else None,
            "dest_ip": rec.get("id.resp_h", ""),
            "dest_port": int(float(rec["id.resp_p"])) if rec.get("id.resp_p") else None,
            "asset_id": "web-prod-01",
            "user": "",
            "session_id": "",
            "action_or_method": rec.get("method", ""),
            "uri_or_target": f"{rec.get('host','')}{uri}",
            "payload_summary": "",
            "status_code": None,
            "bytes_out": None,
            "user_agent": "" if ua == "-" else ua,
            "attack_stage_hint": stage,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="data/full_chain_logs/raw")
    ap.add_argument("--out", default="data/full_chain_logs/normalized/CHAIN-sample.jsonl")
    args = ap.parse_args()

    raw = Path(args.raw)
    jobs = [
        (raw / "nginx_access" / "access.log", convert_nginx),
        (raw / "auth" / "auth_sample.log", convert_auth),
        (raw / "zeek" / "conn.log", convert_zeek_conn),
        (raw / "zeek" / "http.log", convert_zeek_http),
    ]

    all_rows: list[dict] = []
    seq = 0
    for path, fn in jobs:
        if not path.exists():
            print(f"[skip] 不存在: {path}")
            continue
        rows = fn(path, seq)
        seq += len(rows)
        print(f"{path.name}: {len(rows)} 条")
        all_rows.extend(rows)

    # log_id 去重（nginx 与 zeek 可能撞日序号）
    seen: set[str] = set()
    unique: list[dict] = []
    for r in all_rows:
        base = r["log_id"]
        lid = base
        n = 1
        while lid in seen:
            n += 1
            lid = f"{base}-{n}"
        seen.add(lid)
        r["log_id"] = lid
        unique.append(r)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fp:
        for r in unique:
            fp.write(json.dumps(r, ensure_ascii=False) + "\n")

    stages: dict[str, int] = {}
    for r in unique:
        stages[r["attack_stage_hint"]] = stages.get(r["attack_stage_hint"], 0) + 1
    print(f"\n合计 {len(unique)} 条 → {out}")
    print("阶段分布:", ", ".join(f"{k}={v}" for k, v in sorted(stages.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
