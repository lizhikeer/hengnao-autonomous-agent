# V2 调查报告汇总（Week 3）

- 运行来源：`local_replay`（本地回放）
- 运行时间：2026-11-19T08:20:59.227339+00:00（run_id `20261119T082059Z`）
- 控制器：`rule_based_v2_controller`（`src/ai_engine/investigation.py`）
- 数据源：`dataset_replay`（配置模式 `dataset_replay`）
- 检索模式：`lexical_fallback`；各案例检索状态：`degraded`
- 代码版本：`e0d71c3`（分支 `feature/w3-v2-investigation-rag-response`，工作区**有未提交改动**）
- 标准答案仅用于本表与 EVALUATION.md 的评测对照，未参与任何调查步骤；结论原样保存，未人工改写

| 场景 | 结论 | 风险 | 恶意 | 证据数 | 轮次 | 契约校验 | 检索状态 | 卡片补查 | 错题复查 | 覆盖 truth 分类 | 证据召回 |
| :--- | :--- | :--- | :--- | --: | --: | :--- | :--- | --: | --: | :--- | --: |
| CHAIN-CASE-01 | SQL_Injection_After_Brute_Force_After_Scan | HIGH | True | 21 | 5 | 通过 | `degraded` | 2 | 2 | True | 1.0 |
| CHAIN-CASE-02 | C2_Exfiltration_After_Malicious_Upload | HIGH | True | 10 | 5 | 通过 | `degraded` | 2 | 2 | True | 1.0 |
| CHAIN-CASE-03 | none | LOW | False | 9 | 5 | 通过 | `degraded` | 2 | 2 | True | 1.0 |
| CHAIN-CASE-04 | XSS | HIGH | True | 10 | 5 | 通过 | `degraded` | 2 | 1 | False | 1.0 |
| CHAIN-CASE-05 | Path_Traversal_Privilege | HIGH | True | 11 | 5 | 通过 | `degraded` | 2 | 1 | False | 1.0 |
| CHAIN-CASE-06 | Brute_Force | HIGH | True | 10 | 5 | 通过 | `degraded` | 2 | 2 | False | 1.0 |
| CHAIN-CASE-07 | Scan | MEDIUM | True | 15 | 4 | 通过 | `degraded` | 1 | 1 | False | 1.0 |
| CHAIN-CASE-08 | C2_Exfiltration | HIGH | True | 12 | 5 | 通过 | `degraded` | 2 | 2 | False | 1.0 |
| CHAIN-CASE-09 | none | LOW | False | 13 | 4 | 通过 | `degraded` | 1 | 1 | False | 1.0 |
| CHAIN-CASE-10 | none | LOW | False | 10 | 5 | 通过 | `degraded` | 2 | 2 | False | 1.0 |

> 上表数字均由本次实际运行得出；`EVALUATION.md` 由 `scripts/eval_runner.py` 现场算分生成。
