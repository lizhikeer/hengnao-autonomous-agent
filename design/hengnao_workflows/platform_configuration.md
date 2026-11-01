# 恒脑平台实际配置（2026-11-01）

本文件记录已在平台配置的对象。早期设计中的 `{{start.input}}` 不是当前平台“引用”模式的语法；引用使用 `$.节点ID.字段`，模板渲染才使用双花括号。完整运行结果见本目录验收记录。

## 工具服务

本机用 `api.service:app` 同时提供 REST 与 MCP，共享同一案例证据表。公开联调地址是临时 Cloudflare 隧道，停机或重建隧道后必须更新平台地址和输入中的 `service_url`。

| 对象 | 实际配置 |
| --- | --- |
| API 工具集 | SecLog-调查工具集，ID `2115052665990348802`，草稿 |
| 已在线验证的 API | GET `/health`；cURL 导入的“全链路日志查询_标准JSON”，POST `/tools/query_logs`，Content-Type 为 application/json |
| SecLog_MCP | streamable-http，URL 以 `/mcp/` 结尾，五个工具 |
| SecLog_只读调查 | streamable-http，URL 以 `/investigation/` 结尾，四个读取工具，不含处置工具 |

API 旧能力项的空 body 探测绿勾不代表业务参数调用成功。11 月 1 日重新以实际 JSON 参数调用日志接口，拿到四条带 Mock 标记的攻击链日志；截图在 `evidence/api_query_success.png`。旧能力项保留为草稿，其中未重新验证的地址不能作为已通过项。

## 工作流

名称：SecLog_第一周调查；ID：`2116857000076312578`；私有草稿。

| 节点 | 配置 |
| --- | --- |
| 开始 | 字符串参数 input，内容为告警 JSON |
| node0 / 代码_oJWNih | `platform_nodes/code_clean.py`；input 引用 `$.kv_user.input` |
| node1 / 自规划_bcfHeN | input 引用 `$.node0.result_key`；HengNao-v4 256K；只绑定 SecLog_只读调查 |
| node6 / 大模型_2Po61x | input 引用 `$.node1.result_key`；HengNao-v4 256K，Temperature=0.1，max_tokens=2048；guided_json 使用 `src/ai_engine/schemas/agent_results.schema.json` 全文，十一字段全必填 |
| node2 / 代码_vOC87D | `platform_nodes/code_verify.py`；input 引用 `$.node6.result_key`，seed 引用 `$.kv_user.input`；调用服务端 verify_results 校验；新增 Object 输出 triage，引用自身 result_key，再做 JsonPath `$.result_key` |
| node3 / 交互_W5ivDJ | confirm_block 单选：A=批准提交申请，B=拒绝；只申请、不执行封禁；回答等待 600 秒 |
| node4 / 工具_EygqDc | SecLog_MCP / seclog_request_response；参数来自 `$.node2.triage` 对应字段 |
| node5 / 代码_cIKKc1 | `platform_nodes/code_report.py`；input 引用 `$.node2.triage`；新增 Object 输出 payload，引用自身 result_key，再做 JsonPath `$.result_key` |
| 结束 | 回答 `$.node5.payload.report`；十一项输出逐项引用 `$.node5.payload.results.<字段>`，布尔和数组保留类型 |

平台代码入口是 `handler(args: Args)`。代码返回 dict 后，平台默认 result_key 实际是序列化字符串，必须通过输出参数的 JsonPath 处理得到 Object，不能直接对默认 result_key 访问子字段。

主路径：开始 → node0 → node1 → node6 → node2 → node3。选 A 后走 node4 → node5 → 结束；拒绝或无回答走 node5 → 结束。审批边条件分别为 `"A" in node3.confirm_block._answer` 与 `not ("A" in node3.confirm_block._answer)`。字段是 `_answer`，不是 `answer`。

处置参数：reason=attack_chain_summary、case_id=case_id、action=recommended_action、evidence_log_ids=evidence_log_ids、target_ip=attacker_ip，均取自 node2.triage。模型自己的调查节点拿不到处置工具，因此无法在提问前提交申请。

## 复现输入与启动

PowerShell 启动联合服务（替换确切主机名）：

```powershell
$env:SECLOG_PUBLIC_HOST='<隧道主机名>'
.venv\Scripts\python.exe -m uvicorn api.service:app --app-dir src --host 127.0.0.1 --port 8000
```

在另一个终端用官方 cloudflared 启动 `tunnel --url http://127.0.0.1:8000 --no-autoupdate --protocol http2`，将返回的主机名写入前述环境变量并重启服务，再更新平台两个 MCP URL 和 API URL。

```json
{"case_id":"EVAL-CHAIN-001","trace_id":"CHAIN-ATTACK-01","src_ip":"198.51.100.23","asset_id":"web-prod-01","service_url":"https://<当前隧道主机名>"}
```

试运行到交互问答后，选 A 或 B，再点发送；不点击发送不算回答。当前后端只返回 `approval_required`、`executed=false`，没有真实权限网关、封禁和邮件发送。

Mock 使用固定回放时间 `2026-10-27T14:26:00Z`，不是实时安全监测。证据表在内存中，重启后需要重新查询。程序校验能证明编号由该事件查询返回，不能独立证明上游日志未被篡改，也不能保证模型的攻击因果判断一定正确。
