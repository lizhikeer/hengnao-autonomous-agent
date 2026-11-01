# scripts/log_cleaners/ —— 多源日志清洗脚本

**归属：`@ribbonfish-jun`**

## 契约

```
输入：data/full_chain_logs/raw/<源类型>/*.log|*.pcap
输出：data/full_chain_logs/normalized/*.jsonl   （每行一条，严格遵循统一 Schema）
```

每个脚本必须：

1. 以 `--input` / `--output` 显式传参，**不写死路径**；
2. 以 `--dry-run` 支持只解析不入库，输出统计；
3. 解析失败的行写入 `*.dropped.jsonl` 并保留原始行，禁止静默丢弃；
4. 幂等：同一输入重复执行，输出一致（`log_id` 由「源文件 + 行号 + 时间戳」确定性派生）；
5. 不连接 ClickHouse，入库由 `scripts/ingest_clickhouse.py` 统一负责。

## 计划的脚本

| 脚本 | 输入 | 说明 |
| :--- | :--- | :--- |
| `clean_nginx_access.py` | Nginx `combined` 格式 | 解析 `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"` |
| `clean_auth_log.py` | `/var/log/auth.log` 或 Web 登录日志 | 提取成功/失败登录、来源 IP、账号 |
| `clean_zeek.py` | Zeek `conn.log` / `http.log` / `dns.log` | TSV + `#fields` 表头解析 |
| `run_zeek.sh` | `.pcap` | 调用 Zeek 容器解析 PCAP，产出 `data/full_chain_logs/zeek/` |

## 参考

- 字段定义：`docs/project design/全链路日志统一字段规范.md`
- 样本：`data/full_chain_logs/raw/`（W1 由 `@lizhikeer` 提供三种源各一份）
