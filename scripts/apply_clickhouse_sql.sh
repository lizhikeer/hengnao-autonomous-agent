#!/usr/bin/env bash
# 按文件名顺序执行 sql/clickhouse/ 下的全部建表脚本（幂等，可重复执行）。
#
# 用法：
#   ./scripts/apply_clickhouse_sql.sh
#   CLICKHOUSE_CONTAINER=seclog-clickhouse ./scripts/apply_clickhouse_sql.sh
#
# 说明：docker compose 首次启动时，ClickHouse 官方镜像会自动执行挂载到
# /docker-entrypoint-initdb.d 的脚本；但数据目录非空后该机制不再触发，
# 因此新增脚本或重建表结构时用本脚本显式执行。
set -euo pipefail

CONTAINER="${CLICKHOUSE_CONTAINER:-seclog-clickhouse}"
DB_USER="${CLICKHOUSE_USER:-seclog}"
SQL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../sql/clickhouse" && pwd)"

if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER}"; then
    echo "[ERR] 容器 ${CONTAINER} 未运行" >&2
    exit 1
fi

if [[ -z "${CLICKHOUSE_PASSWORD:-}" ]]; then
    # 允许从项目根目录的 .env 读取，避免密码出现在命令行历史里
    if [[ -f "$(dirname "${BASH_SOURCE[0]}")/../.env" ]]; then
        # shellcheck disable=SC1091
        set -a && source "$(dirname "${BASH_SOURCE[0]}")/../.env" && set +a
    fi
fi

for f in "${SQL_DIR}"/*.sql; do
    name="$(basename "$f")"
    printf '>>> %-32s' "${name}"
    if docker exec -i "${CONTAINER}" clickhouse-client \
        --user "${DB_USER}" --password "${CLICKHOUSE_PASSWORD}" \
        --multiquery < "$f" 2>/tmp/seclog_sql_err; then
        echo " OK"
    else
        echo " FAILED"
        sed 's/^/    /' /tmp/seclog_sql_err >&2
        exit 1
    fi
done

echo
echo "全部脚本执行完毕。当前库表："
docker exec -i "${CONTAINER}" clickhouse-client \
    --user "${DB_USER}" --password "${CLICKHOUSE_PASSWORD}" \
    --query "SELECT database, name, engine FROM system.tables WHERE database NOT IN ('system','INFORMATION_SCHEMA','information_schema') ORDER BY database, name FORMAT PrettyCompact"
