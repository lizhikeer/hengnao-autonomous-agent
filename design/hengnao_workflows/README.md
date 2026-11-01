# 恒脑工作流归档（`design/hengnao_workflows/`）

本目录归档 `@chensz-u` 负责的恒脑平台侧内容：智能体工作流编排设计、与上下游的接口契约、以及第一周验收报告。

**2026-11-01 更新：** 当前实际平台配置见 [platform_configuration.md](platform_configuration.md)，平台代码入口与提示词见 `platform_nodes/`，在线调试截图见 `evidence/`。下方早期设计和 10 月 27 日验收记录保留历史过程；其中“平台尚未搭建”、92 项测试及旧隧道地址已经过时。

最新验收结论见 [week1_acceptance_20261101.md](week1_acceptance_20261101.md)：修复独立验收发现的问题后，本地 107 项测试通过，原公网 REST/MCP 空编号复验八项通过；平台批准、拒绝两条路径均实际跑通。

## 文件说明

| 文件 | 内容 | 使用方式 |
| :--- | :--- | :--- |
| `week1_workflow_design.md` | 首版工作流编排设计：节点拓扑与边条件、平台 API 工具注册表（可照填）、各节点配置与可直接粘贴的 Prompt/代码、Guided JSON 配置、轮次与停止条件、平台接口真实结构、设计取舍、阻塞项清单 | 平台搭建时逐节照填；评审时逐节核对 |
| `api_contract_for_a_c.md` | 与 A 组（日志清洗）、C 组（算分/通知）、以及知识库模块的字段映射与待确认清单 | 与对应负责人对接时用，变更先在此登记 |
| `week1_acceptance.md` | 第一周验收报告：变更清单、复现命令与实测结果、已实现/Mock/未接入/未验证分类、Issue checklist 逐项状态 | 交 Codex 与 `@lizhikeer` 验收 |
| `platform_preflight.md` | 平台调试等价预检：按平台调试的行为方式对五个能力项各发一次请求，逐项检查状态码/编码/体积/时延/参数文档完整性 | 隧道与账号到位后照此逐条点调试，无需现场试错 |
| `e2e_reports/` | 端到端链路模拟报告（`TC-01`~`TC-04` + `SUMMARY.md`）：主链路、审批驳回、白名单旁路、字段残缺四条路径的节点轨迹与输出 | 证明拓扑逻辑闭合；可直接用于答辩演示材料 |

## 与代码的对应关系

| 设计文档里的内容 | 对应的可执行实现 |
| :--- | :--- |
| §2 API 工具注册表 | `src/api/schemas.py`（参数语义与样例值即取自该处） |
| §3.2 输入预处理代码节点 | `src/ai_engine/preprocess.py`（同源规则，本地可跑的版本） |
| §3.3 模型节点 Prompt 的决策清单 | `src/ai_engine/investigation.py` 的 `decide()`（同一套判断的可执行参照） |
| §3.4 程序校验代码节点 | `src/ai_engine/verify.py` 为本地纯函数；实际平台入口见 `platform_nodes/code_verify.py`，通过服务端查询登记表核对证据 |
| §3.7 结束节点 results 映射 | `src/ai_engine/schemas/agent_results.schema.json`（11 字段，required 非空） |
| §6 平台接口结构 | 以 `docs/平台文档/恒脑智能体服务-开放服务接口 .pdf` 为准，纠正了 md 文档中的示例偏差 |

## 注意

* 本目录**不含**平台导出的编排 JSON。原因见 `week1_workflow_design.md` §6.4：
  官方 PDF 只给出 `llm_basic` 一种节点类型的导入字段，代码/交互/插件/结束节点的导入结构未公开，
  在拿到平台真实导出样例前不编造格式。
* 平台 API 调试和节点连线已实际执行；当前智能体保留私有草稿，运行记录以最新验收记录为准。
