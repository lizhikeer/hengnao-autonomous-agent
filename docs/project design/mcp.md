# MCP 工具清单

**现成工具负责查数据，自建工具负责项目业务；权限检查、评分和定时任务由后台负责。**

## 1、现成工具

| 用途 | 工具 | 项目怎么用 |
| --- | --- | --- |
| 查日志、做统计 | [ClickHouse 官方 MCP](https://github.com/ClickHouse/mcp-clickhouse) | 复用查询能力；使用只读账号，限制数据范围、耗时和返回量 |
| 查知识、历史案例 | [Qdrant 官方 MCP](https://github.com/qdrant/mcp-server-qdrant) | 按项目、审核状态和有效期过滤；正式案例由审核后台写入 |
| 解析抓包、查网络日志 | [zeek-mcp](https://github.com/lidless-labs/zeek-mcp) | 调用 Zeek 解析已有 PCAP，查询 Zeek／Suricata 日志；抓包另由服务器完成 |
| 发钉钉消息（可选） | [钉钉 MCP](https://github.com/open-dingtalk/dingtalk-mcp) | 发送告警和审批入口，审批身份由后台验证 |
| 发邮件（备选） | [mcp-server-email](https://github.com/boutquin/mcp-server-email) | 本期优先复用 SMTP 函数，不开放完整邮箱操作 |
| 管理项目问题（可选） | [GitHub 官方 MCP](https://github.com/github/github-mcp-server) | 查询 Issue、PR、测试状态，创建问题记录；限定本项目仓库 |

## 2、我们要封装的工具

统一做成一个 **SecLog MCP 服务**，用 [MCP 官方 Python SDK](https://github.com/modelcontextprotocol/python-sdk) 包装原项目函数和 HTTP 接口。下列接口名为拟定名称。

| 用途 | 接口 | 要做的事 |
| --- | --- | --- |
| 查用户和资产 | `get_user_profile`、`get_asset_context` | 返回历史行为、资产信息、维护窗口和保护名单 |
| 查调查记录和证据 | `get_investigation`、`get_evidence` | 返回调查状态、证据原文及编号 |
| 申请处置、查结果 | `request_response`、`get_response_status` | 提交动作和证据，后台授权后执行或进入审批 |
| 检查效果、申请撤销 | `check_response_effect`、`request_revoke` | 检查防御是否生效、正常业务是否受影响，并支持撤销申请 |
| 提交候选案例 | `submit_case_candidate` | 保存调查经验，审核通过后进入正式案例库 |
| 创建通知任务 | `enqueue_notification` | 写入通知任务表，后台发送邮件或钉钉消息 |

接入流程

**恒脑 Agent → SecLog MCP／API → FastAPI 权限检查＋OPA → 数据库或执行器。**

远程 MCP 使用恒脑支持的 HTTP 传输方式；仅支持本地 stdio 的工具由服务器适配。数据库和执行凭据保存在后台。
