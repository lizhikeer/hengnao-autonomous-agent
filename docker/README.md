# SecLog-Agent 部署手册（W1 基础设施）

> 目标机器：`kekeshenla`（Debian 12 x86_64，7.7G 内存，数据盘 `/vol4` 余量 75G）
> 部署目录：代码 `~/seclog`，数据 `/vol4/seclog`
> 对外入口：`https://seclog.91666.icu`（natfrp HTTP 隧道 → 本机 `127.0.0.1:18000`）

---

## 一、架构

```
                    恒脑 SaaS 云端（仅 IPv4）
                              │ HTTPS
                              ▼
              natfrp HTTP 隧道  seclog.91666.icu
                 （节点 frp-fly.com）
                              │
                              ▼  frpc 容器（--net=host）
┌──────────────────────── 部署机 kekeshenla ────────────────────────┐
│                                                                    │
│   127.0.0.1:18000 ──► seclog-api（FastAPI / MCP）                 │
│                              │                                     │
│              ┌───────────────┼───────────────┐                     │
│              ▼               ▼               ▼                     │
│        ClickHouse        Qdrant          （后续 SQLite）           │
│        127.0.0.1:8123    127.0.0.1:6333                            │
│        数据 /vol4/seclog/clickhouse                                │
└────────────────────────────────────────────────────────────────────┘
```

**所有容器端口只绑 `127.0.0.1`**，外网唯一入口是 natfrp 隧道。数据库不直接暴露公网。

---

## 二、首次部署

```bash
# 1. 同步代码（本地执行）
tar czf - --exclude=.git --exclude=.venv --exclude=__pycache__ . | ssh nas "tar xzf - -C ~/seclog"

# 2. 生成环境变量（服务器执行，一次即可）
cd ~/seclog
CH=$(openssl rand -hex 16); API=$(openssl rand -hex 16)
sed -e "s|^CLICKHOUSE_PASSWORD=.*|CLICKHOUSE_PASSWORD=${CH}|" \
    -e "s|^API_INTERNAL_TOKEN=.*|API_INTERNAL_TOKEN=${API}|" .env.example > .env
chmod 600 .env

# 3. 建数据目录
mkdir -p /vol4/seclog/{clickhouse,qdrant}

# 4. 起容器
cd docker && docker compose --env-file ../.env up -d

# 5. 建表（首次必做，见下方「为什么不能只靠 initdb」）
cd .. && ./scripts/apply_clickhouse_sql.sh
```

---

## 三、为什么不能只靠 initdb

ClickHouse 官方镜像只会在 `/var/lib/clickhouse` **为空**时执行 `/docker-entrypoint-initdb.d` 里的脚本。
本项目第一次启动曾因配置错误反复重启，数据目录被写入了一半，之后即使配置修好也不会再执行建表。
因此：

- 新增或修改 `sql/clickhouse/*.sql` 后，**显式执行** `./scripts/apply_clickhouse_sql.sh`；
- 脚本本身幂等（全部 `IF NOT EXISTS` / 可重复 ALTER），重复执行安全；
- 脚本会为 `03`、`05` 这类不带库名的 SQL 自动补 `--database log_ai`，否则会报 `UNKNOWN_TABLE`。

---

## 四、公网隧道（natfrp）

| 项 | 值 |
| :--- | :--- |
| 隧道 ID | `29740457` |
| 隧道名 | `seclog_api`（HTTP 类型） |
| 节点 | `72`（日本1，`frp-fly.com`，免费节点） |
| 本地端口 | `127.0.0.1:18000` |
| 绑定域名 | `seclog.91666.icu` |
| 客户端 | 容器 `seclog-frpc`，二进制 `/vol4/seclog/bin/frpc`（0.51.0-sakura-15.1） |

**为什么不用国内节点**：国内节点强制备案校验（`下列域名未通过备案检查`），
`91666.icu` 未在 natfrp 侧完成备案验证；海外免费节点不校验备案。

**为什么单独跑 frpc 容器**：机器上原有的 `natfrp-service` 是「远程管理」模式的启动器，
隧道要在网页上手动点启动。这里用独立容器托管 SecLog 这一条隧道，与用户既有面板隧道解耦，
互不影响，重启后自动恢复（`--restart unless-stopped`）。

常用命令：

```bash
docker logs -f seclog-frpc          # 看隧道状态
docker restart seclog-frpc          # 隧道重连
```

### DNS 要求

需要在 DNSPod 为 `91666.icu` 增加：

```
seclog    CNAME    frp-fly.com
```

**注意**：`91666.icu` 当前只有 AAAA 记录（IPv6），而恒脑云端无 IPv6 路由，
所以这条 CNAME 是链路成立的前提。改完后用 `dig +short A seclog.91666.icu` 应能拿到 `202.182.125.24`。

---

## 五、踩过的坑（配置变更前请先读）

| 现象 | 原因 | 处理 |
| :--- | :--- | :--- |
| 容器无限重启，日志 `users.d/default-user.xml: Read-only file system` | 把 `users.d` 只读挂载了，而 entrypoint 需要写入该文件来创建 `CLICKHOUSE_USER` | **不要挂载 `users.d`**，只挂 `config.d` |
| 启动即退出，`number_of_free_entries_in_pool_to_execute_mutation` | `background_pool_size × 默认 ratio(2)` 小于 20 | 见 `config.d/limits.xml`：pool 设 8，并显式把两个阈值降到 4 |
| `COMMENT ON TABLE ...` 语法错误 | 那是 PostgreSQL 语法 | ClickHouse 用 `ALTER TABLE ... MODIFY COMMENT` / `COMMENT COLUMN` |
| `finished_at cannot be used as version column` | 版本列不能是 `Nullable` | `ingest_batches` 改用 `started_at` 作版本列 |
| 宿主机 tcpdump 放进容器报 `stack smashing` / `libdbus` 缺失 | 定制 NAS 的 glibc 与 Debian 容器不兼容 | 用 `scripts/sample_env/pcap_capture.py`（标准库 AF_PACKET）替代 |
| `docker pull` 拉 ClickHouse 极慢或超时 | 国际链路 | 用 `crane` 走国内镜像源拉成 tar 再 `docker load`，见下 |

```bash
# 镜像拉取（crane 方式，实测 171M / 1min）
cd /vol4/seclog/bin
./crane pull --platform linux/amd64 docker.m.daocloud.io/clickhouse/clickhouse-server:24.8 /vol4/seclog/ch.tar
docker load -i /vol4/seclog/ch.tar
```

镜像源可用性实测：`docker.m.daocloud.io` ✅、`docker.1ms.run` ✅（zeek 只有 `lts` 标签）、
`docker.nju.edu.cn` ⚠️ 不稳定、`dockerpull.org` ❌。

---

## 六、日常运维

```bash
cd ~/seclog/docker

docker compose --env-file ../.env ps                    # 状态
docker compose --env-file ../.env logs -f api           # API 日志
docker compose --env-file ../.env restart api           # 重启 API
docker compose --env-file ../.env up -d --build api     # 改代码后重建

# 资源占用（机器只有 7.7G 内存，务必盯着）
docker stats --no-stream seclog-clickhouse seclog-qdrant seclog-api

# 数据量
docker exec seclog-clickhouse clickhouse-client --user seclog --password "$PW" \
  --query "SELECT table, formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE database='log_ai' AND active GROUP BY table"
```

---

## 七、端口占用

| 端口 | 用途 | 绑定 |
| :--- | :--- | :--- |
| 18000 | SecLog API（隧道入口） | 127.0.0.1 |
| 8123 / 9000 | ClickHouse HTTP / Native | 127.0.0.1 |
| 6333 / 6334 | Qdrant HTTP / gRPC | 127.0.0.1 |
| 18080 | **已被宿主机其他服务占用**，样本站点改用 18081 | — |
