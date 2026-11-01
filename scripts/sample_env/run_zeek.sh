#!/usr/bin/env bash
# 用 Zeek 容器解析 PCAP，产出 conn.log / http.log / dns.log 等结构化网络日志。
#
# 用法（服务器 ~/seclog 目录下）：
#   ./scripts/sample_env/run_zeek.sh
#
# 产出：/vol4/seclog/samples/zeek/*.log  （Zeek TSV 格式，带 #fields 表头）
set -euo pipefail

ROOT="${SECLOG_SAMPLE_ROOT:-/vol4/seclog/samples}"
PCAP="${ROOT}/pcap/seclog-sample.pcap"
OUT="${ROOT}/zeek"
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:6.0.4}"

if [[ ! -f "${PCAP}" ]]; then
    echo "[ERR] 未找到 ${PCAP}，请先执行 capture_traffic.sh" >&2
    exit 1
fi

mkdir -p "${OUT}"
chmod 777 "${OUT}"

echo "解析 ${PCAP} ..."
docker run --rm \
    -v "${ROOT}/pcap:/pcap:ro" \
    -v "${OUT}:/out" \
    "${ZEEK_IMAGE}" \
    zeek -C -r /pcap/seclog-sample.pcap Log::default_logdir=/out

echo
echo "Zeek 产物："
ls -lh "${OUT}"/*.log 2>/dev/null | awk '{printf "  %-40s %s\n", $9, $5}'
echo
echo "说明：-C 关闭校验和检查，因为抓包在容器虚拟网卡上可能带有未卸载的 checksum offload。"
