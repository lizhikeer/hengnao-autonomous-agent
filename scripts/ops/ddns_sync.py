#!/usr/bin/env python3
"""让固定域名跟随 DDNS 域名，解决「中转机是家宽动态 IP」导致链路随时失效的问题。

## 背景

恒脑平台只认 `https://seclog.91666.icu:18443`，证书也签在这个域名上，不能换成中转机自带的
DDNS 域名 `9188888.cn`。但中转机是家宽动态 IP，`9188888.cn` 的 A 记录会跟着变，
`seclog.91666.icu` 的 A 记录是写死的——IP 一变，平台侧立刻失联，而且现象和"隧道挂了"一样，很难排查。

## 方案

每 5 分钟对比一次：

    源：9188888.cn 的 A 记录（由中转机的 DDNS 客户端维护）
    目标：seclog.91666.icu 的 A 记录（DNSPod 上手工建的）

不一致就调 DNSPod API 把目标改成源的值。

## 为什么不用 CNAME

把 `seclog` 改成 CNAME 指向 `9188888.cn` 看似更省事，但证书续期走的是
`acme.sh` 的 `dns_dp`（DNS-01），需要在 `_acme-challenge.seclog.91666.icu`
建 TXT 记录。父节点是 CNAME 时，部分递归解析器会拒绝解析其子域，
等于拿「IP 跟随」换「续期可能失败」。A 记录同步没有这个副作用。

## 凭据

复用 acme.sh 已保存的 DNSPod 凭据（`~/.acme.sh/account.conf` 里的
`SAVED_DP_Id` / `SAVED_DP_Key`），不单独存一份，也不写入仓库。

## 用法

    python3 scripts/ops/ddns_sync.py            # 正常同步
    python3 scripts/ops/ddns_sync.py --dry-run  # 只比较不写
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from pathlib import Path

DNSPOD_API = "https://dnsapi.cn"
ACCOUNT_CONF = Path.home() / ".acme.sh" / "account.conf"


def load_dnspod_token() -> str:
    """从 acme.sh 的 account.conf 读取 DNSPod 凭据，返回 `id,key` 形式。"""
    if not ACCOUNT_CONF.exists():
        raise SystemExit(f"[ERR] 找不到 {ACCOUNT_CONF}")
    text = ACCOUNT_CONF.read_text(encoding="utf-8", errors="ignore")
    id_m = re.search(r"^SAVED_DP_Id=['\"]?([^'\"\n]+)", text, re.M)
    key_m = re.search(r"^SAVED_DP_Key=['\"]?([^'\"\n]+)", text, re.M)
    if not id_m or not key_m:
        raise SystemExit("[ERR] account.conf 里没有 SAVED_DP_Id / SAVED_DP_Key")
    return f"{id_m.group(1).strip()},{key_m.group(1).strip()}"


def resolve_a(host: str) -> str | None:
    """只取 IPv4。中转机同时有 AAAA，但平台走 IPv4。"""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except socket.gaierror:
        return None


def dnspod_post(token: str, path: str, payload: dict) -> dict:
    data = urllib.parse.urlencode(
        {"login_token": token, "format": "json", "lang": "cn", **payload}
    ).encode()
    req = urllib.request.Request(f"{DNSPOD_API}/{path}", data=data, method="POST")
    req.add_header("User-Agent", "seclog-ddns/1.0 (python-urllib)")
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if str(body.get("status", {}).get("code")) != "1":
        raise RuntimeError(f"DNSPod {path} 失败: {body.get('status')}")
    return body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="9188888.cn", help="跟随的 DDNS 域名")
    ap.add_argument("--domain", default="91666.icu")
    ap.add_argument("--sub", default="seclog")
    ap.add_argument("--ttl", type=int, default=600)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    desired = resolve_a(args.source)
    if not desired:
        print(f"[ERR] 解析不到 {args.source} 的 A 记录", file=sys.stderr)
        return 2

    token = load_dnspod_token()
    listing = dnspod_post(token, "Record.List", {"domain": args.domain, "sub_domain": args.sub})
    records = [
        r for r in listing.get("records", [])
        if r.get("type") == "A" and r.get("name") == args.sub
    ]
    if not records:
        print(f"[ERR] DNSPod 上找不到 {args.sub}.{args.domain} 的 A 记录", file=sys.stderr)
        return 2

    current = records[0]
    current_ip = current.get("value", "")
    record_id = current.get("id")
    line = current.get("line") or "默认"

    if current_ip == desired:
        print(f"[OK] 无需变更：{args.sub}.{args.domain} = {current_ip}")
        return 0

    print(f"[DIFF] {args.sub}.{args.domain}: {current_ip} → {desired}（源 {args.source}）")
    if args.dry_run:
        print("--dry-run：未写入")
        return 0

    dnspod_post(token, "Record.Modify", {
        "domain": args.domain,
        "record_id": record_id,
        "sub_domain": args.sub,
        "record_type": "A",
        "record_line": line,
        "value": desired,
        "ttl": str(args.ttl),
    })
    print(f"[OK] 已更新为 {desired}（TTL {args.ttl}s）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
