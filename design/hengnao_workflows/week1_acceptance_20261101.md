# 第一周补齐与验收记录（2026-11-01）

## 独立验收后的修复与在线复验

以下为同日后续结果；原始交付记录保留在下方，测试数量和提交状态以本节及 GitHub PR 为准。

- 修复处置接口跳过空证据编号的问题。空字符串单独提交或混入合法编号时，REST/MCP 共用校验均拒绝申请，不生成审批单。
- 修复本地调查控制器在轮次耗尽、仅有不足以定论的可疑日志时直接判安全的问题。现在保留已查证据，输出 `insufficient_evidence`、`recommended_action=none`、`requires_human_approval=true`。
- 增加 8 个回归用例；相关八个测试文件合计 **107 passed in 3.75s**。原有完整攻击链、正常流量、案例隔离和契约测试保持通过。
- 平台“全链路日志查询_标准JSON”的 `case_id`、`trace_id`、`time_window` 参数描述已保存并重新读取确认。使用现有样例参数在线调试返回四条 Mock 日志。
- 经授权重启 `api.service:app` 加载修复，保留现有隧道及平台配置。通过原公网地址对 REST/MCP 分别测试空字符串、空白字符串、单独提交、混入合法编号，共 **8 项全部拒绝**，均为 `executed=false`、`approval_id=null`。健康检查和带旧 MCP Session ID 的工具发现同时通过。原始响应见 `evidence/online_blank_evidence_20261101.json`。
- 独立验收还实际重跑了平台批准与拒绝分支，均返回报告及通过严格契约的十一字段结果。批准分支只登记模拟待审批单，拒绝分支跳过处置工具。两次分别引用四条和三条证据，调查完整性仍需后续评测。

本轮提交关联 Issue #4；团队契约确认仍有待回复项，不把本地 Schema 定义等同于团队已确认。未接入真实后端，未执行真实处置，未发布平台工作流。

## 原始交付记录

对应 Issue #4，负责人 chensz-u。代码保留在本地 `feature/agent-mcp-skeleton`，未 commit、push 或创建 PR，也未修改 GitHub Issue 状态。平台操作使用陈盛漳账号，智能体保留私有草稿。

## 本次修复

日志查询以前只校验时间窗格式，没有真正按时间过滤。现在先按固定 Mock 回放时刻过滤，再统计、截断和登记证据：同一攻击链 `1m` 返回 1 条，`1h` 返回 4 条，返回体明确给出 `meta.reference_time`。

以前省略 case_id 的查询会登记共享证据，其他事件可以借用。现在这种查询不登记证据；每个事件只能引用自己查询到的编号，同一编号要用于不同事件时必须分别查询。

补齐同进程 REST/MCP 联合服务、四个工具的只读调查入口、服务端结论校验接口，并去掉本地调查控制器在审批前提交处置申请的行为。调查模型只绑定读取工具，处置工具放在审批后的独立节点。MCP HTTP 使用无状态传输，修复服务重启后平台复用旧会话导致的 404。

## 实际验证

| 检查 | 结果与证据 |
| --- | --- |
| 本地测试 | `.venv\Scripts\python.exe -m pytest tests -q --tb=short`：**99 passed in 3.84s** |
| 链路模拟 | `tests/e2e_workflow_sim.py` 四例通过；主链路、拒绝、良性旁路和字段残缺记录在 `e2e_reports/`。这是本地模拟，不冒充平台执行 |
| MCP 接口与证据共享 | 官方 SDK 验证只读端点四个工具，1m 查询一条；同案例跨 MCP/REST 可提交待审批，其他案例被拒绝 |
| MCP 重启兼容 | 新增回归测试：带旧 Session ID 调用两个 HTTP 端点仍可列出工具，调查端点没有处置工具 |
| 公网重启验证 | 最终联合服务重启后，经现有公网隧道携带旧 Session ID 调用只读 MCP，返回 200，列出读取工具且不包含处置工具 |
| 恒脑 API 在线调试 | 健康检查成功；cURL 导入的日志查询以实际 JSON 参数返回四条，见 `evidence/api_query_success.png` |
| 恒脑多轮调查 | 实际自规划节点查询日志、上下文和安全知识，随后 Guided JSON 整理为十一字段，服务端按案例证据表核对后进入交互节点 |
| 平台批准路径 | 选 A 并发送后，处置工具、报告节点和结束节点全部成功；回执 `approval_required`、`executed=false`，见 `evidence/platform_response_receipt.json` |
| 平台拒绝路径 | 选 B 并发送后，处置工具未运行，报告及结束节点成功；见 `evidence/platform_rejected_approval.json`、`evidence/workflow_rejected_success.png` |
| 最终输出 | 批准和拒绝两次实际平台输出均重新通过本地 AgentResults 严格契约校验；原始结果见 `evidence/platform_approved_output.json`、`evidence/platform_rejected_output.json` |

联调中先后发现并修复了代码节点默认输出为字符串、结束节点引用格式错误、MCP 旧会话失效等问题。完整测试曾因联合服务修改了 REST 应用的生命周期而失败；已改成独立挂载应用，最终 99 项全部通过。

## 第一周交付状态

五个 REST 接口及 Pydantic 契约、MCP 协议服务、结论十一字段契约与本地测试已完成。平台健康检查及至少一个实际参数查询成功；首版工作流已搭建并跑通批准、拒绝两条路径。配置说明、三个代码节点、调查提示词、截图与实际输出已归档，见 [platform_configuration.md](platform_configuration.md) 和 `platform_nodes/`。未伪造平台导出 JSON，以实际配置说明交付。

当前平台工作流为九个节点（含开始、结束），路径为：开始 → 预处理 → 自规划调查 → Guided JSON → 服务端校验 → 交互审批；批准后提交申请，再生成报告；拒绝则直接生成报告。模型节点 Temperature=0.1。自规划节点的八次调用上限目前写在提示词中，尚未证明平台有对应硬性计数门禁。

## 使用范围

当前是第一周的 Mock 工具服务和可运行工作流。ClickHouse、Qdrant/BGE、真实权限网关、实际封禁和邮件尚未接入。程序校验确认的是“编号由该案例实际查询返回”、字段类型和处置规则，不能保证原始日志真实性、证据充分性或攻击因果判断正确。同一输入两次平台运行分别输出 HIGH 和 CRITICAL，模型诊断稳定性仍需后续独立案例评测。

API 工具集仍为草稿；旧的上下文、知识检索和处置 API 能力项保留旧隧道地址，未作为本次通过项。实际工作流使用新 MCP 工具，API 验收使用已验证的健康检查和“全链路日志查询_标准JSON”。

联调服务与临时隧道目前保持运行；地址 `https://enhance-gold-startup-earth.trycloudflare.com` 不保证长期有效。服务重启会清空案例证据，需要重新调查。恢复方法及平台地址更新位置见配置说明。
