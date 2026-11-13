# V1 调查结果与轨迹格式（`data/agent_traces/v1/`）

**产出者**：`tests/run_v1_traces.py`（`@chensz-u`）
**消费方**：Issue #19（归档）、Issue #21（算分）

## 文件命名

```
CHAIN-CASE-01.json          # AgentResults，严格 11 字段
CHAIN-CASE-01.trace.json    # 运行元数据 + 轨迹 + 自检 + 评测对照
SUMMARY.md                  # 汇总表（由实际运行信息生成）
```

文件名即 `case_id`，与 `data/full_chain_logs/*_truth.json` 配对。
**改版前的旧产物**保存在 `data/agent_traces/legacy/v1-before-context-and-seven-class/`，
不要与新结果混用。

## `*.json`：只放 11 字段契约

```json
{
  "case_id": "CHAIN-CASE-01",
  "is_malicious": true,
  "attack_type": "SQL_Injection_After_Brute_Force_After_Scan",
  "risk_level": "HIGH",
  "attacker_ip": "198.51.100.23",
  "victim_asset": "web-prod-01",
  "evidence_log_ids": ["..."],
  "attack_chain_summary": "...",
  "recommended_action": "block_ip",
  "requires_human_approval": true,
  "unknown_items": "..."
}
```

`AgentResults` 用 `extra="forbid"`，**不要往这里加运行信息**，一律进 `.trace.json`。

## `*.trace.json`

### `run`：运行事实

| 字段 | 说明 |
| :--- | :--- |
| `run_id` | 运行标识（UTC 时间戳），同一天多次运行可区分 |
| `started_at` / `finished_at` / `duration_ms` | 时间与耗时 |
| `controller` | 控制器版本，当前 `rule_based_v1_controller` |
| `env.data_source_mode` / `env.search_mode` | 实际环境变量值（`auto`/`clickhouse`/`dataset_replay`/`mock`） |
| `code_version.commit` / `.branch` / `.dirty_worktree` | 代码版本。**`dirty_worktree=true` 表示跑的是未提交代码**，不能当作某个提交的产物 |
| `data_source` | 本次实际数据来源 |
| `rounds` | 调查轮次 |
| `step_status_counts` | `{ok, empty, error}` 各多少步 |

### `trace.steps[]`：每轮工具调用

| 字段 | 说明 |
| :--- | :--- |
| `round` / `tool` / `args` / `why` | 第几轮、调什么、参数、为什么调（决策理由） |
| `data_source` | 该步返回的 `meta.data_source` |
| `returned_log_ids` | 返回的日志编号 |
| `status` | `ok`（有命中）/ `empty`（零命中）/ `error`（调用失败） |
| `error.code` / `error.message` / `error.details` | 仅 `error` 时存在，例如 `backend_unavailable` + 缺依赖原因 |
| `response` | 仅 `ok`/`empty` 时存在，脱敏后的响应（长文本截断、列表标注真实长度） |

失败步骤**不再只有 `returned_total=null`**，可以直接看到错误码与原因。

### `checks`：自检

`schema_valid`、`verify_ok`、`verify_problems`、`evidence_count`、
`evidence_all_registered`、`unregistered_evidence`、审批状态与建议动作。

### `evaluation`：与 truth 对照（仅评测观察）

| 字段 | 含义 |
| :--- | :--- |
| `malicious_match` / `risk_match` / `attacker_ip_match` | 布尔对照 |
| `truth_attack_type` / `normalized_truth_attack_type` | 原始与归一化后的 truth 类型 |
| `truth_normalization_rule` | **非空表示用了评测侧映射规则**（truth 本身不在七类内时） |
| `attack_type_exact_match` | 字符串完全相等（通常为 false，我方保留侦察段） |
| `attack_type_covers_truth` | truth 的每一段是否都出现在本结论里（推荐指标） |
| `evidence_recall` | `|交集| / |truth 证据|` |

## 已知限制

* 控制器是规则版：证据取"攻击阶段全部日志"（恶意场景）或"带账号的行为日志"（良性场景），
  与 truth 人工挑选的关键证据不完全重合，`evidence_recall` 会低于 1；
* 检索工具当前不可用（缺依赖与服务），`status=error` + `error.code=backend_unavailable` 如实记录，
  `unknown_items` 会写明"未检索到处置知识卡"；
* 所有结果为 `dataset_replay` 回放产出，**不是**恒脑平台实跑。
