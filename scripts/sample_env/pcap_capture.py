#!/usr/bin/env python3
"""零依赖 PCAP 抓包器（仅用标准库 + AF_PACKET）。

为什么不用 tcpdump/netshoot：
    本项目的部署机是定制 NAS 系统，宿主 tcpdump 动态库与 Debian 容器不兼容，
    而容器内 apk/apt 装包的出口带宽又不稳定。AF_PACKET 是内核能力，标准库即可，
    对「抓一段样本流量」这个需求足够，且不会给生产机引入任何常驻进程。

用法：
    python3 pcap_capture.py --iface lo --port 18080 --output out.pcap --duration 40

限制：
    - 过滤只做到 TCP 端口粒度，不做完整 BPF；
    - 固定 linktype=1 (Ethernet)，回环网卡在 Linux 上同样是 Ethernet 帧，Zeek 可直接解析。
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
ETH_P_ALL = 0x0003


def _tcp_ports(frame: bytes) -> tuple[int, int] | None:
    """从 Ethernet 帧里取出 (src_port, dst_port)，非 IPv4/TCP 返回 None。"""
    if len(frame) < 34:
        return None
    # Ethernet: 12 字节 MAC + 2 字节 EtherType
    if frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[14 + 9] != 6:  # protocol == TCP
        return None
    tcp_off = 14 + ihl
    if len(frame) < tcp_off + 4:
        return None
    return struct.unpack("!HH", frame[tcp_off : tcp_off + 4])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--port", type=int, required=True, help="只保留该 TCP 端口的流量")
    ap.add_argument("--output", required=True)
    ap.add_argument("--duration", type=float, default=40.0)
    ap.add_argument("--snap", type=int, default=65535)
    args = ap.parse_args()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError:
        print("[ERR] 需要 NET_RAW 权限（容器加 --cap-add=NET_RAW）", file=sys.stderr)
        return 2

    sock.bind((args.iface, 0))
    sock.settimeout(1.0)

    deadline = time.time() + args.duration
    written = 0
    # 缓冲写，减少小 IO
    with open(args.output, "wb") as fp:
        fp.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC, 2, 4, 0, 0, args.snap, LINKTYPE_ETHERNET,
            )
        )
        while time.time() < deadline:
            try:
                frame, _addr = sock.recvfrom(args.snap)
            except socket.timeout:
                continue
            ports = _tcp_ports(frame)
            if ports is None or args.port not in ports:
                continue
            ts = time.time()
            fp.write(
                struct.pack("<IIII", int(ts), int(round((ts % 1) * 1_000_000)), len(frame), len(frame))
            )
            fp.write(frame)
            written += 1

    print(f"captured {written} packets -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
