# 平台调试等价预检报告（Platform Preflight）

> 生成脚本：`tests/platform_preflight.py`。
> 作用：在没有恒脑平台账号/公网隧道的情况下，按平台调试的行为方式把五个能力项各发一次请求，
> 逐项检查状态码、Content-Type、编码、体积、时延与参数文档完整性，
> 从而把「调试能否通过」提前算出来。**本报告不能替代平台上的实际调试**，
> 但隧道与账号到位后，照下面「调试配方」逐条点一遍即可，无需现场试错。

## 一、结论

| 能力项 | 方法 | 路径 | 状态码 | 时延 | 体积 | 结果 |
| :--- | :--- | :--- | ---: | ---: | ---: | :--- |
| 服务健康检查 | GET | `/health` | 200 | 47ms | 0.1KB | 通过 |
| 全链路关联日志查询 | POST | `/tools/query_logs` | 200 | 5ms | 1.6KB | 通过 |
| 账号行为基线与资产上下文查询 | POST | `/tools/get_context` | 200 | 4ms | 0.3KB | 通过 |
| 安全知识卡与案例卡检索 | POST | `/tools/search_knowledge` | 200 | 4ms | 1.7KB | 通过 |
| 处置动作提交（封禁/限速，需审批） | POST | `/tools/request_response` | 200 | 3ms | 0.2KB | 通过 |

全局检查：全部通过

## 二、逐项检查明细

### 服务健康检查（`GET /health`）

| 检查项 | 结果 | 说明 |
| :--- | :--- | :--- |
| HTTP 200 | 通过 | 实际 200 |
| Content-Type 为 application/json | 通过 | application/json |
| UTF-8 无 BOM | 通过 | 无 BOM |
| 可按 UTF-8 解码 | 通过 | ok |
| 响应体为可解析 JSON | 通过 | ok |
| 响应体积 ≤ 256KB | 通过 | 0.1KB |
| 时延 ≤ 5.0s | 通过 | 47ms |

实测响应（截断）：

```json
{"status": "ok", "service": "seclog-tool-service", "version": "0.1.0", "mock_mode": true}
```

### 全链路关联日志查询（`POST /tools/query_logs`）

调试样例值（平台调试页照填）：

```json
{
  "case_id": "EVAL-CHAIN-001",
  "trace_id": "CHAIN-ATTACK-01",
  "limit": 50
}
```

| 检查项 | 结果 | 说明 |
| :--- | :--- | :--- |
| HTTP 200 | 通过 | 实际 200 |
| Content-Type 为 application/json | 通过 | application/json |
| UTF-8 无 BOM | 通过 | 无 BOM |
| 可按 UTF-8 解码 | 通过 | ok |
| 响应体为可解析 JSON | 通过 | ok |
| 响应体积 ≤ 256KB | 通过 | 1.6KB |
| 时延 ≤ 5.0s | 通过 | 5ms |

实测响应（截断）：

```json
{"meta": {"total": 4, "data_source": "mock", "mock": true, "backend_available": false}, "items": [{"log_id": "LOG-20261027-0001", "trace_id": "CHAIN-ATTACK-01", "timestamp": "2026-10-27T14:18:02Z", "log_source": "auth_log", "src_ip": "198.51.100.23", "dest_ip": "10.0.0.15", "asset_id": "web-prod-01", "user": "admin", "action_or_method": "auth_fail", "uri_or_target": "/admin", "payload_summary": "password attempt #1 (wrong)", "status_code": 401, "user_agent": "hydra/9.1", "attack_stage_hint": "brute_force"}, {"log_id": "LOG-20261027-0008", "trace_id": "CHAIN-ATTACK-01", "timestamp": "2026-10-27 ...（截断）
```

### 账号行为基线与资产上下文查询（`POST /tools/get_context`）

调试样例值（平台调试页照填）：

```json
{
  "user": "admin",
  "asset_id": "web-prod-01"
}
```

| 检查项 | 结果 | 说明 |
| :--- | :--- | :--- |
| HTTP 200 | 通过 | 实际 200 |
| Content-Type 为 application/json | 通过 | application/json |
| UTF-8 无 BOM | 通过 | 无 BOM |
| 可按 UTF-8 解码 | 通过 | ok |
| 响应体为可解析 JSON | 通过 | ok |
| 响应体积 ≤ 256KB | 通过 | 0.3KB |
| 时延 ≤ 5.0s | 通过 | 4ms |

实测响应（截断）：

```json
{"meta": {"total": 2, "data_source": "mock", "mock": true, "backend_available": false}, "user_profile": {"user": "admin", "active_hours": "09:00-19:00 CST", "common_src_ips": ["203.0.113.7"], "failed_logins_24h": 0, "mock": true}, "asset_context": {"asset_id": "web-prod-01", "importance": "HIGH", "maintenance_window": null, "whitelisted": false, "mock": true}}
```

### 安全知识卡与案例卡检索（`POST /tools/search_knowledge`）

调试样例值（平台调试页照填）：

```json
{
  "query": "SQL 注入绕过认证后如何处置",
  "limit": 5
}
```

| 检查项 | 结果 | 说明 |
| :--- | :--- | :--- |
| HTTP 200 | 通过 | 实际 200 |
| Content-Type 为 application/json | 通过 | application/json |
| UTF-8 无 BOM | 通过 | 无 BOM |
| 可按 UTF-8 解码 | 通过 | ok |
| 响应体为可解析 JSON | 通过 | ok |
| 响应体积 ≤ 256KB | 通过 | 1.7KB |
| 时延 ≤ 5.0s | 通过 | 4ms |

实测响应（截断）：

```json
{"meta": {"total": 4, "data_source": "mock", "mock": true, "backend_available": false}, "items": [{"card_id": "KB-OWASP-SQLI-001", "card_type": "security_knowledge", "title": "SQL 注入攻击（联合查询与写文件 Webshell）调查与处置指南", "attack_category": "SQL_Injection", "mitre_id": "T1190", "key_indicators": ["URI 或请求体包含 UNION SELECT、INTO OUTFILE、sleep()、information_schema", "同一源 IP 短时间内触发大量 500/403 后突然出现 200 且响应包体异常增大"], "recommended_action": "block_ip_short_term", "score": 0.91}, {"card_id": "KB-MITRE-BRUTE-003", "card_type": "security_knowledge", "title": "账号爆破（Hydra 类工具）识别与处置", "attack_category": "Brute_Force", ...（截断）
```

### 处置动作提交（封禁/限速，需审批）（`POST /tools/request_response`）

调试样例值（平台调试页照填）：

```json
{
  "case_id": "PREFLIGHT-001",
  "action": "none",
  "evidence_log_ids": [],
  "reason": "调试连通性，无需处置"
}
```

| 检查项 | 结果 | 说明 |
| :--- | :--- | :--- |
| HTTP 200 | 通过 | 实际 200 |
| Content-Type 为 application/json | 通过 | application/json |
| UTF-8 无 BOM | 通过 | 无 BOM |
| 可按 UTF-8 解码 | 通过 | ok |
| 响应体为可解析 JSON | 通过 | ok |
| 响应体积 ≤ 256KB | 通过 | 0.2KB |
| 时延 ≤ 5.0s | 通过 | 3ms |

> 注意：证据表在内存，平台单次调试无法预热；用 action=none 取得一次 200 使节点可选，真实证据校验仍在服务端生效

实测响应（截断）：

```json
{"status": "no_action", "approval_id": null, "executed": false, "detail": "action=none 表示本案例无需处置，未提交任何动作，也未产生任何副作用", "rejected_evidence_ids": [], "mock": true}
```

## 三、全局兼容性检查

| 检查项 | 结果 | 说明 |
| :--- | :--- | :--- |
| 参数文档完整（共 18 个参数） | 通过 | 全部具备 description 与 examples |
| 仅使用 GET / POST | 通过 | GET、POST |

## 四、隧道打通后的操作顺序（照做即可）

1. 起服务：`./.venv/Scripts/python -m uvicorn api.app:app --app-dir src --host 127.0.0.1 --port 8000`
2. 开隧道（任选）：`cloudflared tunnel --url http://127.0.0.1:8000` 或 `npx localtunnel --port 8000`
3. 先在公网地址上自测一次：`curl https://<隧道域名>/health` 必须返回 200 且 body 为 JSON
4. 平台侧：新建 API 工具集，Base URL 填隧道域名（不带路径、不带尾斜杠）
5. 按本报告 §2 的「调试样例值」逐个创建能力项并点调试；`request_response` 用 `action=none`
6. 五个能力项全部显示「成功」后，再进入工作流编排（`week1_workflow_design.md` §3）

## 五、本报告证明不了什么

- 平台云端到本机的**真实网络可达性**（取决于隧道，不是本机能力）；
- 平台自己的超时/体积/重试策略（本报告用的是保守阈值，不是平台真实限制）；
- 平台对返回体字段的解析行为（如它是否只取部分字段）。
