# data/full_chain_logs/ —— 全链路攻击故事日志包

**归属：`@ribbonfish-jun`**（清洗脚本与日志包构造）；目录结构与本文件由 `@lizhikeer` 在 W1 冻结。

## 目录约定

```
data/full_chain_logs/
├── raw/                       # 原始日志，保持采集时的原样，不做任何改写
│   ├── nginx_access/          # Nginx 访问日志（combined 格式）
│   ├── auth/                  # SSH / Web 登录认证日志
│   └── pcap/                  # PCAP 抓包文件（.pcap），体积大，只保留样本
├── zeek/                      # Zeek 解析产物（conn.log / http.log / dns.log）
├── normalized/                # 清洗后的 JSONL，字段严格遵循 §5.1 统一 Schema
└── ground_truth/              # 每个场景的标准证据链答案卡（**不得进入 Qdrant**）
```

## 命名规范

```
<场景编号>_<阶段>_<源类型>_<序号>.<扩展名>

场景编号：CHAIN-<三位序号>      例：CHAIN-001
阶段：recon | brute | exploit | c2 | benign
源类型：nginx | auth | zeek | pcap

示例：
  CHAIN-001_recon_nginx_01.log
  CHAIN-001_brute_auth_01.log
  CHAIN-001_exploit_zeek_01.log
  CHAIN-001.json                     # 该场景的 ground_truth 答案卡
```

## 统一 Schema（W1 冻结，详见 `docs/project design/全链路日志统一字段规范.md`）

清洗产物为 **JSON Lines**，每行一条日志，字段如下：

```json
{
  "log_id": "LOG-20261027-0001",
  "trace_id": "CHAIN-001",
  "timestamp": "2026-10-27T14:20:05Z",
  "log_source": "nginx_access",
  "src_ip": "198.51.100.23",
  "src_port": 54321,
  "dest_ip": "10.0.0.15",
  "dest_port": 443,
  "asset_id": "web-prod-01",
  "user": "admin",
  "session_id": "sess-9f8a7b",
  "action_or_method": "POST",
  "uri_or_target": "/admin/login.php",
  "payload_summary": "username=admin&password=***",
  "status_code": 200,
  "bytes_out": 4520,
  "user_agent": "sqlmap/1.7.2",
  "attack_stage_hint": "recon"
}
```

## 硬性要求

1. `timestamp` 一律 **UTC**，ISO 8601 带 `Z` 后缀。
2. `log_id` 全局唯一，格式 `LOG-YYYYMMDD-NNNN`，同日递增。
3. 同一攻击故事链的所有日志共享同一个 `trace_id`。
4. `payload_summary` 必须脱敏：口令、Cookie、Token、身份证、手机号一律以 `***` 替代。
5. `raw/` 与 `ground_truth/` 不得被任何清洗脚本改写。
6. `ground_truth/` 内容禁止导入 Qdrant，也禁止作为 Agent 上下文。
