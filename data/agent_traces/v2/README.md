# Agent 调查结果与运行轨迹归档 · V2（Week 3）

> 产出者：`tests/run_v2_traces.py`（本地回放）/ 恒脑平台导出（平台实跑）
> 归档与核验：`@ribbonfish-jun`（Issue #33） · 算分与对比：`@zyh060911`（Issue #35）
> 规范沿用 `data/agent_traces/v1/README.md`，本文只写 **V2 的差异与运行方式**。

## 一、文件与运行来源

| 文件 | 内容 |
| :--- | :--- |
| `CHAIN-CASE-XX.json` | 严格 11 字段结论，**原样保存，未人工改写** |
| `CHAIN-CASE-XX.trace.json` | 运行元数据 + 每轮工具调用 + 结论依据 + RAG 事实 |
| `SUMMARY.md` | 十案例汇总（含检索状态、卡片补查数、错题复查数） |
| `EVALUATION.md` | 由 `scripts/eval_runner.py` 现场算分（评分逻辑与标准答案未改动） |

> `run.code_version.dirty_worktree` 为 `true`：本批结果是在同一分支**提交前**跑出来的，
> 代码与轨迹一起提交。`commit` 字段记录的是当时的基线（`68d0783`，即 `origin/main`），
> 复核时请以分支上的这次提交为准，而不是把它当成"来自某个旧提交的产物"。

**运行来源必须分开看**：

- 本目录当前内容是 `run.origin = local_replay`，控制器 `rule_based_v2_controller`，
  数据源 `dataset_replay`（`data/full_chain_logs/`），检索为 `lexical_fallback`（降级）；
- **不是**恒脑平台实跑，也**不是** NAS ClickHouse + 公网 HTTPS 的实跑结果。
  平台实跑导出后应写 `run.origin = platform`，并与本地回放分开放置，不得混为一份数据。

复现命令：

```bash
# 本地回放（缺 sentence-transformers / qdrant-client 时使用词面降级检索）
SECLOG_DATA_SOURCE=dataset_replay SECLOG_SEARCH_MODE=lexical_fallback \
  python tests/run_v2_traces.py

# 单案例
SECLOG_SEARCH_MODE=lexical_fallback python tests/run_v2_traces.py CHAIN-CASE-06
```

## 二、`*.trace.json` 相比 V1 新增的字段

### 2.1 `run.origin` 与 `run.controller`

`origin` 取值 `local_replay` / `platform`；`controller` 为 `rule_based_v2_controller`。
归档时**不要把本地回放写成平台验证**。

### 2.2 `trace.steps[].triggered_by`

仅补查步骤有值，记录"哪张卡的第几步要求查哪个日志源"：

```json
{
  "card_id": "KB-BF-001",
  "card_type": "security_knowledge",
  "step_index": 2,
  "step": "关联认证日志，核对失败登录记录、账户名称和时间分布",
  "declared_log_sources": ["nginx_access", "auth_log"],
  "log_source": "auth_log"
}
```

### 2.3 `rag`

| 字段 | 说明 |
| :--- | :--- |
| `retrieval_state` | `ok` / `zero_hit` / `degraded` / `degraded_zero_hit` / `failed` / `not_called` |
| `retrieval_mode` / `degraded` / `notes` | 检索模式与降级原因（失败是 503，不等于零命中） |
| `cards_used` | 参与本次调查的前 3 张卡（含是否带 `error_revision_note`） |
| `card_triggered_queries` | 卡片驱动的补查：轮次、卡号、步骤、日志源、返回条数、新增条数 |
| `revision_checks` | 错题卡复查：卡号、提示原文（截断）、复查项、结论 |

### 2.4 `evidence_plan`

证据分组：`attack` / `impact` / `correlated_attempt` / `post_compromise` /
`authorized_scan` / `benign_retry_pattern` / `account_activity` / `bulk_transfer`。
轨迹据此回答"这条证据支撑结论的哪一部分"。

## 三、本次结果的已知限制（如实记录，不做美化）

1. **检索是降级模式**：本机缺少 `sentence-transformers` / `qdrant-client` / NumPy，
   无法跑 BGE + Qdrant + FTS5 混合检索，改用源清单校验过的知识卡做词面检索。
   轨迹中 `rag.retrieval_state = degraded`，`EVALUATION.md` 的结论只代表"流程可跑通"，
   不代表混合检索效果。需要 #31 的索引与模型权重到位后重跑。
2. **补查未带来新日志**：数据集回放按 `trace_id` 一次返回整条故事链，
   卡片驱动的定向补查（按 `log_source` + 2h 窗口）必然与首轮重复，`new_log_ids = 0`。
   在 ClickHouse 真实库上同一查询才是"按源定向核验"，这是回放环境的固有限制。
3. **错题卡尚未入库**：`data/case_memories/` 为空（#31 候选案例与错题卡管线未交付），
   本次复查只能消费 40 张安全知识卡自带的 `error_revision_note`。
4. **平台实跑未完成**：缺少 NAS ClickHouse / 公网 HTTPS / 恒脑平台交互节点的操作权限，
   `run.origin` 全部是 `local_replay`。

## 四、归档三条硬要求（同 V1）

1. `*.json` 原样保存，不按标准答案改写任何字段；
2. `trace.steps[]` 如实记录调用参数与状态，包括查空（`empty`）与报错（`error`）；
3. `evidence_log_ids` 只记录 Agent 自己给出的编号，真实性由 `evidence_check` 与
   `eval_runner.py` 共同核验。
