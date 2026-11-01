# SecLog 工具服务（FastAPI）· 本地启动与调用说明

模块负责人：`@chensz-u`（Issue #4）。本目录提供恒脑平台【API 工具】所需的全部五个能力项，
第一周为**显式 Mock 骨架**：查询类接口返回带 `meta.mock=true` 的演示数据，
处置类接口只登记待审批单，不产生任何真实封禁副作用。

## 1. 启动

```bash
# 项目根目录，使用隔离 venv（勿装到全局 Python）
.venv/Scripts/python -m pip install -r requirements.txt      # 首次
.venv/Scripts/python -m uvicorn api.app:app --app-dir src --host 127.0.0.1 --port 8000
```

* OpenAPI 文档：<http://127.0.0.1:8000/docs>
* 健康检查：`curl http://127.0.0.1:8000/health`
* 暴露给恒脑云端时必须经公网隧道（natfrp / frp），**平台无法访问 localhost 与私网 IP**。

## 2. 五个能力项

| 方法 | 路径 | 用途 | 后端状态 |
| :--- | :--- | :--- | :--- |
| GET | `/health` | 健康检查，平台 API 工具"调试"准入 | 真实可用 |
| POST | `/tools/query_logs` | 按 `src_ip` / `dest_ip` / `trace_id` / `log_source` / `time_window` / `limit` 查全链路日志 | Mock（ClickHouse 未接入） |
| POST | `/tools/get_context` | 用户行为基线 + 资产重要性/维护窗口/白名单 | Mock（画像库/资产库未接入） |
| POST | `/tools/search_knowledge` | 安全知识卡与已确认正反案例卡检索 | Mock（Qdrant 未接入） |
| POST | `/tools/request_response` | 提交处置动作与证据编号，校验证据真实性 | 未接入权限网关，仅登记待审批 |

## 3. 三条结果语义（评测与工作流都依赖它）

| 情形 | HTTP | 响应特征 |
| :--- | :--- | :--- |
| 查到了 | 200 | `meta.total > 0`，`items` 非空 |
| 零结果（正常"没查到"） | 200 | `meta.total = 0`，`items = []` |
| 参数错误 | 422 | `{"code":"invalid_params", "message":..., "details":{"errors":[...]}}` |
| 后端不可用（要求真实后端但未接入） | 503 | `{"code":"backend_unavailable", ...}` |

> 零结果 ≠ 后端故障 ≠ 参数错误。三者必须分开，否则模型会把"没查到"误当成"没有攻击"。

## 4. 调用示例

```bash
# 查日志（建议每次都带 case_id，使证据归属本次调查）
curl -s -X POST http://127.0.0.1:8000/tools/query_logs \
  -H 'Content-Type: application/json' \
  -d '{"case_id":"EVAL-CHAIN-001","trace_id":"CHAIN-ATTACK-01","limit":50}'

# 提交处置（证据必须是上面查回来的 log_id，否则被拒）
curl -s -X POST http://127.0.0.1:8000/tools/request_response \
  -H 'Content-Type: application/json' \
  -d '{"case_id":"EVAL-CHAIN-001","action":"block_ip","target_ip":"198.51.100.23",
       "evidence_log_ids":["LOG-20261027-0001","LOG-20261027-0008"],
       "reason":"爆破后注入成功，需封禁"}'
```

处置接口的三种结果：

| 场景 | `status` | 说明 |
| :--- | :--- | :--- |
| 证据是伪造的、或属于别的 case | `rejected` | `rejected_evidence_ids` 列出被拒编号 |
| 证据合法、动作为封禁/限速 | `approval_required` | 生成 `approval_id`，`executed=false`，**未执行** |
| `action=none` | `no_action` | 明确"无需处置"，与"被拒绝"区分 |

模型在 `reason` 里写"已获管理员审批"**不构成授权**：审批结论只能来自恒脑【交互节点】
（`confirm_block`）或权限服务的程序化回执。当前接口只登记待审批申请，不执行实际处置。

## 5. MCP 与 HTTP 的区别

`src/mcp_server/` 是用 MCP 官方 SDK 暴露的**协议端点**（`tools/list` / `tools/call`），
与本目录的 REST 路由不是一回事。恒脑平台的【API 工具】走 HTTP，MCP 服务面向支持 MCP 的客户端。
两者复用同一份业务实现与同一份证据登记表。见 `src/mcp_server/server.py` 顶部说明。

## 6. 目录

```
src/api/
├── app.py            # FastAPI 应用与五个路由（含统一错误体）
├── schemas.py        # 请求/响应模型（带语义描述与样例值，平台注册用）
├── mock_data.py      # 显式 Mock 数据，每条带 mock 标识
├── evidence_check.py # 证据登记与程序校验（按 case 隔离）
├── config.py         # 边界常量（时间窗/limit/动作白名单）
└── README.md
```


## 7. 2026-11-01 联调更新

- 日志查询会先按时间窗过滤，再统计总数、截断条数和登记证据。Mock 固定回放时刻为 `2026-10-27T14:26:00Z`，返回 `meta.reference_time`；`1m` 命中 1 条，`1h` 命中 4 条攻击链日志。真实后端尚未接入。
- 省略 `case_id` 时可以查询，但不登记证据。不同案例必须分别查询，不能借用他案证据；登记表仍为进程内状态。
- `POST /tools/verify_results` 接收开始节点的 `case_id` 和模型的 `results`，结合服务器案例证据表校验结论。工作流在审批之前调用，校验失败应停止。
- 联合提供 REST 和 MCP 时启动 `.venv/Scripts/python -m uvicorn api.service:app --app-dir src --host 127.0.0.1 --port 8000`。`/investigation/` 只提供四个读取工具，供自规划节点使用；`/mcp/` 包含五个工具，处置工具只绑定在审批后的独立节点。不要用两个独立进程分别提供查询和处置，否则内存证据表不共享。
- 公网 MCP 使用 `SECLOG_PUBLIC_HOST` 配置确切主机名后重启服务，SDK 保留 Host 校验。
- HTTP MCP 使用无状态传输，避免平台复用重启前的会话 ID 时出现 404。业务证据表仍为同一进程内状态，重启后需重新调查取证。
- 当前平台代码节点使用 `handler(args: Args)` 和 `args.input.<参数名>`。本地纯函数的 `main(dict)` 不能直接作为该平台入口。
