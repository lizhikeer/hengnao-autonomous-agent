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

---

## Week 3（V2）配置变更

### 一、公网入口以架构文档为准

正式入口是 `https://seclog.91666.icu:18443`（国内 IPv4 中转 → NAS），见
`docs/架构变更说明_2026-11-12.md`。上文的 Cloudflare 隧道地址是历史记录，
**不再作为平台配置依据**；重建隧道后不要回写旧地址。

### 二、调查节点只读，处置独立成节点

| 节点 | 变更 | 配置 |
| --- | --- | --- |
| node1 / 自规划 | 调查提示词升级 | `platform_nodes/investigation_prompt.txt`；强制"先上下文 + `seclog_search_knowledge`（带 `case_id`）→ 按知识卡 `investigation_steps` 定向补查 `log_source` → 按 `error_revision_note` 复查 → 再下结论"；仍只绑定 `SecLog_只读调查`（`/investigation/`，四个读取工具） |
| node3 / 交互 | 确认是否提交申请 | `confirm_block` 单选 A/B，选项值配置为单个字母。A 允许提交申请，B、空值和超时均按拒绝处理。等待 600 秒。 |
| **node7 / 代码（新增）** | 受控处置步骤 | `platform_nodes/code_response_step.py`。分别将 `triage`、`answer`、`seed` 引用到 `$.node2.triage`、`$.node3.confirm_block._answer`、`$.kv_user.input`。将 `result_key` 按前文配置解析为 Object 输出 `payload`，包含 `receipt` 与 `results`。 |
| node5 / 代码 | 报告节点 | `input` 引用 `$.node7.payload.results`，`receipt` 引用 `$.node7.payload.receipt`。 |
| 结束 | 输出不变 | 十一项仍引用 `$.node5.payload.results.<字段>` |

主路径为开始 → node0 → node1 → node6 → node2 → node3 → node7 → node5 → 结束。
若平台需配置分支，两条边均通往 node7，由它按选项值处理。只有单个字符串 A 会提交申请。B 和无回答生成 `REJECTED`，有回执可进报告。

### 三、回执状态口径

`code_response_step.py` 原样透出服务端状态，不做二次加工：

| 状态 | 含义 | 是否执行 |
| --- | --- | :--- |
| `no_action` | 结论为无需处置 | 否 |
| `REJECTED` | 人工未批准 / 拒绝 | 否 |
| `approval_required` | 已登记待审批单，等待权限网关或审批回执 | 否 |
| `EXECUTED` | 模拟状态机已写入执行审计，回执带 `simulation=true`、`mock=true` | 否 |
| `BLOCKED_BY_POLICY` | 策略网关拦截（禁止动作 / 白名单 / 目标类型越界 / 缺证据） | 否，fail-closed |
| `APPROVAL_TIMEOUT` | 工单到期拒批 | 否 |

服务端返回 `approval_required` 却没有 `approval_id` 时，代码节点直接抛错——
"没登记成功"不能被当成"待审批"。

### 四、本地 HTTP 验证和平台前置条件

本地验证命令为 `python -m pytest tests/test_w3_response_http.py -q`。测试用临时目录记录模拟审计。

1. 在独立测试进程设 `SECLOG_RESPONSE_MODE=simulation` 和临时 `SECLOG_STATE_DIR`。
   `SECLOG_RESPONSE_SUBMIT_TOKEN` 为提交凭据，`SECLOG_RESPONSE_APPROVAL_TOKENS_JSON`
   为审批人到各自凭据的映射。两类凭据独立配置。
2. 调查完成后，交互节点的 A 只确认提交申请。节点通过配置的 `submit_token` 调用
   `POST /tools/request_response`，发送本案证据和 `asset_id`，读取回执中的工单号。
3. 审批人在独立审批入口用其 Bearer 凭据调用 `POST /tools/approve_response`。请求注明
   `case_id`、`approval_id`、`decision`（`approve` 或 `reject`）。批准时填
   `expected_effect` 和 `rollback_plan`，拒绝时可附 `reason`。
   动作、目标和证据来自服务端保存的待审工单。待审工单随测试进程重启清空。

平台演示还需要 NAS 测试部署、公网 HTTPS 和恒脑登录。平台审批结算需要可验证的审批人身份，
审批凭据只由审批入口使用。`data/agent_traces/v2/` 当前记录本地回放，线上原始轨迹须从平台导出。
