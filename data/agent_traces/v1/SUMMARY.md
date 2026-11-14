# V1 调查实跑汇总

- 运行时间：2026-11-12T10:11:07.087570+00:00（run_id `20261112T101107Z`）
- 数据源：`dataset_replay`（时间基准 = 各场景最新日志；配置模式 `dataset_replay`）
- 控制器：`rule_based_v1_controller`（`src/ai_engine/investigation.py`）
- 代码版本：`6a44c10`（分支 `feature/w2-tool-integration`，工作区**有未提交改动**）
- 标准答案仅用于本表的评测对照，未参与任何调查步骤

| 场景 | 结论 | 风险 | 恶意 | 证据数 | 轮次 | 契约校验 | 恶意判定一致 | 风险一致 | 覆盖 truth 分类 | 证据召回 | 工具状态 |
| :--- | :--- | :--- | :--- | --: | --: | :--- | :--- | :--- | :--- | --: | :--- |
| CHAIN-CASE-01 | SQL_Injection_After_Brute_Force_After_Scan | HIGH | True | 16 | 3 | 通过 | True | True | True | 0.833 | ok:2、error:1 |
| CHAIN-CASE-02 | Path_Traversal_Privilege_After_Malicious_Upload | HIGH | True | 6 | 3 | 通过 | True | True | False | 0.667 | ok:2、error:1 |
| CHAIN-CASE-03 | insufficient_evidence | LOW | False | 4 | 2 | 通过 | True | True | False | 0.4 | ok:2 |

> 数据来源与结论均为本次实际运行所得，未经人工修饰。
> 检索步骤失败 2 次（backend_unavailable），错误码与原因见各 `.trace.json` 中 `search_knowledge` 步骤的 `error` 字段。
