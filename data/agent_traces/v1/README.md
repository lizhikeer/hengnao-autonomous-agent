# Agent 调查结果与运行轨迹（Trace Log）归档规范 · V1

> **产出者**：`tests/run_v1_traces.py` / 恒脑平台导出（`@chensz-u`）
> **归档与核验**：`@ribbonfish-jun`（任务包 A / Issue #19）
> **消费方**：`@zyh060911`（`scripts/eval_runner.py` 算分 / Issue #21）、`@Tr4cy-cyber`（错题修订卡 / Issue #20）

---

## 一、为什么要归档轨迹

Agent 每次多轮调查的过程（调了哪些工具、每次查到什么、为何变更假设、最终输出什么）必须与最终判定分开落盘，否则：

1. 算分脚本只能拿到最终结论，无法解释「为什么这题判错」；
2. 错误案例无法复现，`@Tr4cy-cyber` 的错题修订卡无从下手；
3. 三轮迭代（`v1/` → `v2/` → `v3/`）无法做同 case 的逐轮对比。

---

## 二、目录与文件命名约定

```text
data/agent_traces/
├── v1/                              # V1 基线版（当前：已产 01~03，待补跑 04~10）
│   ├── CHAIN-CASE-01.json           # AgentResults，严格 11 字段
│   ├── CHAIN-CASE-01.trace.json     # 运行元数据 + 轨迹 + 自检 + 评测对照
│   ├── ...
│   └── SUMMARY.md                   # 汇总表（由实际运行信息生成）
├── v2/                              # V2 迭代版（第 3 周）
├── v3/                              # V3 迭代版（第 4 周）
└── legacy/                          # 改版前旧产物，禁止与新结果混用
```

- **命名**：文件名前缀即 `case_id`，与 `data/full_chain_logs/*_truth.json` 一一对应。
- **禁止**：把同一个 case 的多个版本混写进同一个文件；版本号只体现在目录名上。

---

## 三、`*.json`：严格 11 字段契约（供 `eval_runner.py` 算分）

```json
{
  "case_id": "CHAIN-CASE-01",
  "is_malicious": true,
  "attack_type": "SQL_Injection_After_Brute_Force_After_Scan",
  "risk_level": "HIGH",
  "attacker_ip": "198.51.100.23",
  "victim_asset": "web-prod-01",
  "evidence_log_ids": ["LOG-20261027-0103", "LOG-20261027-0112"],
  "attack_chain_summary": "...",
  "recommended_action": "block_ip",
  "requires_human_approval": true,
  "unknown_items": "..."
}
```

`AgentResults` 启用了 `extra="forbid"`，**不要往 `*.json` 里加任何运行元数据或轨迹字段**，运行过程信息一律放进 `*.trace.json`。

---

## 四、`*.trace.json`：运行元数据、轨迹、自检与评测对照

### 4.1 `run`：运行事实

| 字段 | 说明 |
| :--- | :--- |
| `run_id` | 运行标识（UTC 时间戳），同一天多次运行可区分 |
| `started_at` / `finished_at` / `duration_ms` | 起止时间与耗时 |
| `controller` | 控制器版本，当前为 `rule_based_v1_controller` 或恒脑平台实跑标识 |
| `env.data_source_mode` / `env.search_mode` | 实际环境变量值（`auto`/`clickhouse`/`dataset_replay`/`mock`） |
| `code_version.commit` / `.branch` / `.dirty_worktree` | 代码版本。**`dirty_worktree=true` 表示跑的是未提交代码**，不能作为正式版本归档 |
| `data_source` | 本次实际数据来源 |
| `rounds` | 调查轮次 |
| `step_status_counts` | `{ok, empty, error}` 各多少步 |

### 4.2 `trace.steps[]`：每轮工具调用

| 字段 | 说明 |
| :--- | :--- |
| `round` / `tool` / `args` / `why` | 第几轮、调什么、参数、为什么调（决策理由） |
| `data_source` | 该步返回的 `meta.data_source` |
| `returned_log_ids` | 返回的日志编号 |
| `status` | `ok`（有命中）/ `empty`（零命中）/ `error`（调用失败） |
| `error.code` / `error.message` / `error.details` | 仅 `error` 时存在，例如 `backend_unavailable` + 缺依赖原因 |
| `response` | 仅 `ok`/`empty` 时存在，脱敏后的响应（长文本截断、列表标注真实长度） |

> 失败步骤不再只记录 `returned_total=null`，必须保留错误码与具体原因。

### 4.3 `checks` 与 `evaluation`

- **`checks`（自检）**：`schema_valid`、`verify_ok`、`verify_problems`、`evidence_count`、`evidence_all_registered`、`unregistered_evidence`、审批状态与建议动作。
- **`evaluation`（与 truth 对照，仅评测观察）**：`malicious_match`、`risk_match`、`attacker_ip_match`、`truth_attack_type`、`normalized_truth_attack_type`、`truth_normalization_rule`、`attack_type_exact_match`、`attack_type_covers_truth`、`evidence_recall`。

---

## 五、归档时的三条硬要求

1. **`*.json`（或平台导出的 `final_output`）必须原样保存**，人工不得修改任何字段——否则算分失真；判错的案例正是 V2/V3 迭代与错题卡的核心依据。
2. **`trace.steps[]` 里的工具调用参数与状态必须如实记录**，包括调错工具、查空（`empty`）、后端报错（`error`），不得删改美化。
3. **`evidence_log_ids` 只记录 Agent 自己给出的编号**，不得事后人工补全；证据真实性由后端 `evidence_check` 与 `eval_runner.py` 共同核验。

---

## 六、当前进度与 Known Limitations

- PR #24 合入后，`data/agent_traces/v1/` 已包含 `CHAIN-CASE-01` ~ `CHAIN-CASE-03` 的本地回放结果与轨迹（基于 `dataset_replay` 控制器 `rule_based_v1_controller`）。
- 随着 PR #25 合入 `CHAIN-CASE-04` ~ `CHAIN-CASE-10` 共 7 组全链路日志（累计 10 组、200 条），可立即运行 `python tests/run_v1_traces.py`（以及在恒脑平台侧实跑）补齐 04~10 的 V1 产物并交由 `scripts/eval_runner.py` 算分。
- 已知限制：① 当前 `v1/` 已归档的 01~03 为 `dataset_replay` 控制器产出，非恒脑平台实跑；② 检索工具在本地回放环境未挂载 BGE 权重与 Qdrant 时会如实记 `status=error`（`backend_unavailable`）。
