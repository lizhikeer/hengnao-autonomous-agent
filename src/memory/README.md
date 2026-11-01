# src/memory/ —— 案例记忆与状态库

**归属：`@Snowed-night`**

职责：调查记录、候选案例、审核状态、审批单的 SQLite 状态库；审核通过后转入 Qdrant `verified_cases`。

## 三类案例的状态机

```
调查结束
   │
   ├─ 诊断 / 证据 / 处置 三项标签分别打分
   │
   ├─ 全部通过审核 ──> verified_correct_case   ──> 写入 Qdrant，可被检索
   ├─ 存在错误项   ──> verified_error_revision ──> 写入 Qdrant，检索时附带「错误原因 + 正确修订」
   └─ 未审核       ──> pending_case            ──> 仅存 SQLite，**不进检索库**
```

## 边界

| 允许 | 禁止 |
| :--- | :--- |
| 读写 `data/case_memories/`、SQLite 状态库 | 未经审核直接把候选案例写入 Qdrant |
| 定义案例卡 Schema | 存放真实用户凭据或未脱敏日志 |

W1 只冻结 Schema 与表结构，实现排在 W3（见 `docs/project design/项目分工与前期架构设计.md` §四）。
