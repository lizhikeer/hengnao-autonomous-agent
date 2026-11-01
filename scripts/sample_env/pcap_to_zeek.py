#!/usr/bin/env python3
"""PCAP → Zeek 格式日志（conn.log / http.log）转换器。

## 定位

**备用方案**。正式样本由真实 Zeek（`zeek/zeek:lts`）产出，见 `data/full_chain_logs/raw/README.md`。

保留本脚本是因为部署机拉取 `zeek/zeek` 镜像曾连续失败 30 分钟（Docker Hub 直连 EOF，
国内加速源反复中断在 25MB），离线或网络受限环境需要一个不依赖镜像的兜底。
它输出的**字段与 Zeek 完全对齐**：

- 输出 TSV，表头 `#separator \\x09` / `#fields` / `#types` 与 Zeek 6.x 一致；
- `conn.log`、`http.log` 的字段名、顺序、类型与 Zeek 原生输出一致；
- 下游清洗脚本（`scripts/log_cleaners/clean_zeek.py`）按 `#fields` 解析，
  换成真 Zeek 产物后**无需改一行代码**。

## 局限（务必知悉）

- 不做 TCP 重组，只解析单包内可见的 HTTP 请求行；
- `conn_state` 用简化判定（见 `_conn_state`），不是 Zeek 的完整状态机；
- 不产出 dns.log / ssl.log 等其它日志。

因此本脚本定位为「Zeek 不在场时的等价样本生成器」，正式环境仍应使用真 Zeek。

用法：
    python3 pcap_to_zeek.py --pcap seclog-sample.pcap --outdir ./zeek
"""

from __future__ import annotations

import argparse
import struct
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

# --- Zeek 日志表头（与 Zeek 6.x 原生输出一致） ---------------------------------

CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
    "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]
CONN_TYPES = [
    "time", "string", "addr", "port", "addr", "port", "enum",
    "string", "interval", "count", "count", "string", "bool",
    "bool", "count", "string", "count", "count",
    "count", "count", "set[string]",
]

HTTP_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth",
    "method", "host", "uri", "referrer", "version", "user_agent", "request_body_len",
    "response_body_len", "status_code", "status_msg", "info_code", "info_msg", "tags",
    "username", "password", "proxied", "orig_fuids", "orig_filenames",
    "orig_mime_types", "resp_fuids", "resp_filenames", "resp_mime_types",
]
HTTP_TYPES = [
    "time", "string", "addr", "port", "addr", "port", "count",
    "string", "string", "string", "string", "string", "string", "count",
    "count", "count", "string", "count", "string", "set[enum]",
    "string", "string", "set[string]", "vector[string]", "vector[string]",
    "vector[string]", "vector[string]", "vector[string]", "vector[string]",
]


def _ts(value: float) -> str:
    """Zeek 输出 6 位小数的时间戳。"""
    return f"{value:.6f}"


def _uid(counter: int) -> str:
    """Zeek 的 uid 形如 C1x2y3，这里用确定性派生，保证重复解析结果一致。"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    n = counter
    out = []
    for _ in range(6):
        out.append(alphabet[n % len(alphabet)])
        n //= len(alphabet)
    return "C" + "".join(out)


def write_log(path: Path, path_name: str, fields: list[str], types: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fp:
        fp.write("#separator \\x09\n")
        fp.write("#set_separator\t,\n")
        fp.write("#empty_field\t(empty)\n")
        fp.write("#unset_field\t-\n")
        fp.write(f"#path\t{path_name}\n")
        fp.write("#open\t" + datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S") + "\n")
        fp.write("#fields\t" + "\t".join(fields) + "\n")
        fp.write("#types\t" + "\t".join(types) + "\n")
        for row in rows:
            fp.write("\t".join(row) + "\n")
        fp.write("#close\t" + datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S") + "\n")


def _conn_state(flags_seen: set[str]) -> str:
    """简化版连接状态判定，覆盖样本里会出现的几种情况。

    SF  = 正常建立并双向传输后结束
    S1  = 只建连、无数据后结束
    RSTO= 发起方发了 SYN 但被重置
    S0  = 只发 SYN，无响应
    """
    if "SYN" in flags_seen and "FIN" in flags_seen:
        return "SF"
    if "RST" in flags_seen:
        return "RSTO"
    if "SYN" in flags_seen and ("PSH" in flags_seen or "ACK" in flags_seen):
        return "SF"
    return "S1"


class Flow:
    __slots__ = (
        "orig_h", "orig_p", "resp_h", "resp_p", "start", "last",
        "orig_pkts", "resp_pkts", "orig_bytes", "resp_bytes",
        "flags", "http_request",
    )

    def __init__(self, orig_h: str, orig_p: int, resp_h: str, resp_p: int, ts: float):
        self.orig_h = orig_h
        self.orig_p = orig_p
        self.resp_h = resp_h
        self.resp_p = resp_p
        self.start = ts
        self.last = ts
        self.orig_pkts = 0
        self.resp_pkts = 0
        self.orig_bytes = 0
        self.resp_bytes = 0
        self.flags: set[str] = set()
        self.http_request: dict[str, str] | None = None


def parse_pcap(path: Path):
    """逐包产出 (ts, eth_payload)。只处理 Ethernet + IPv4。"""
    data = path.read_bytes()
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xA1B2C3D4:
        raise SystemExit(f"不支持的 pcap 魔数: {magic:#x}（仅支持小端经典 pcap）")
    offset = 24  # 全局头 24 字节
    total = len(data)
    while offset + 16 <= total:
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack_from("<IIII", data, offset)
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        yield ts_sec + ts_usec / 1_000_000, frame


def parse_frame(frame: bytes):
    """解析 Ethernet + IPv4 + TCP，返回 (src_ip, src_port, dst_ip, dst_port, flags, payload) 或 None。"""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if len(frame) < 14 + ihl + 20:
        return None
    if frame[14 + 9] != 6:  # TCP
        return None

    src_ip = ".".join(str(b) for b in frame[26:30])
    dst_ip = ".".join(str(b) for b in frame[30:34])

    tcp_off = 14 + ihl
    src_port, dst_port = struct.unpack_from("!HH", frame, tcp_off)
    doff = (frame[tcp_off + 12] >> 4) * 4
    flags_byte = frame[tcp_off + 13]

    flags = set()
    if flags_byte & 0x02:
        flags.add("SYN")
    if flags_byte & 0x10:
        flags.add("ACK")
    if flags_byte & 0x08:
        flags.add("PSH")
    if flags_byte & 0x01:
        flags.add("FIN")
    if flags_byte & 0x04:
        flags.add("RST")

    payload = frame[tcp_off + doff :]
    return src_ip, src_port, dst_ip, dst_port, flags, payload


def parse_http(payload: bytes) -> dict[str, str] | None:
    """从 TCP payload 里提取 HTTP 请求头。只处理请求（方法开头），不处理响应。"""
    if not payload:
        return None
    try:
        head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except Exception:  # noqa: BLE001 - 二进制断片直接放弃
        return None
    lines = head.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 3 or parts[0] not in {"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}:
        return None

    method, uri, version = parts[0], parts[1], parts[2]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return {
        "method": method,
        "uri": uri,
        "version": version,
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
        "referrer": headers.get("referer", ""),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    pcap = Path(args.pcap)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    flows: "OrderedDict[tuple, Flow]" = OrderedDict()

    for ts, frame in parse_pcap(pcap):
        parsed = parse_frame(frame)
        if parsed is None:
            continue
        s_ip, s_port, d_ip, d_port, flags, payload = parsed

        # 以「客户端 → 服务端」为正向：知名端口（<1024 或 8080/18080/18081）作为服务端
        if d_port < s_port:
            key = (s_ip, s_port, d_ip, d_port)
            forward = True
        else:
            key = (d_ip, d_port, s_ip, s_port)
            forward = False

        flow = flows.get(key)
        if flow is None:
            flow = Flow(key[0], key[1], key[2], key[3], ts)
            flows[key] = flow

        flow.last = ts
        flow.flags |= flags
        if forward:
            flow.orig_pkts += 1
            flow.orig_bytes += len(payload)
        else:
            flow.resp_pkts += 1
            flow.resp_bytes += len(payload)

        if flow.http_request is None:
            req = parse_http(payload)
            if req is not None:
                flow.http_request = req
                flow.http_request["_ts"] = _ts(ts)

    conn_rows: list[list[str]] = []
    http_rows: list[list[str]] = []

    for idx, flow in enumerate(flows.values(), start=1):
        uid = _uid(idx)
        service = "http" if flow.http_request else "-"
        duration = max(flow.last - flow.start, 0.0)
        conn_rows.append([
            _ts(flow.start), uid, flow.orig_h, str(flow.orig_p),
            flow.resp_h, str(flow.resp_p), "tcp", service,
            f"{duration:.6f}", str(flow.orig_bytes), str(flow.resp_bytes),
            _conn_state(flow.flags), "T", "T", "0",
            "ShADadFf", str(flow.orig_pkts), str(flow.orig_bytes + 40 * flow.orig_pkts),
            str(flow.resp_pkts), str(flow.resp_bytes + 40 * flow.resp_pkts), "(empty)",
        ])

        if flow.http_request:
            req = flow.http_request
            http_rows.append([
                req["_ts"], uid, flow.orig_h, str(flow.orig_p),
                flow.resp_h, str(flow.resp_p), "1",
                req["method"], req["host"] or flow.resp_h, req["uri"],
                req["referrer"] or "-", req["version"],
                req["user_agent"] or "-", "0", "0",
                "-", "-", "-", "-", "(empty)",
                "-", "-", "(empty)",
                "(empty)", "(empty)", "(empty)",
                "(empty)", "(empty)", "(empty)",
            ])

    write_log(outdir / "conn.log", "conn", CONN_FIELDS, CONN_TYPES, conn_rows)
    write_log(outdir / "http.log", "http", HTTP_FIELDS, HTTP_TYPES, http_rows)

    print(f"conn.log: {len(conn_rows)} 条连接")
    print(f"http.log: {len(http_rows)} 条 HTTP 请求")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
