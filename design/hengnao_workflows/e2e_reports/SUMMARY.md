# 端到端链路模拟汇总

| 用例 | 分支 | 结论 | 断言 | 报告 |
| :--- | :--- | :--- | :--- | :--- |
| TC-01 SQL 注入 + 前置爆破（主链路，审批通过） | `investigate` | SQL_Injection_After_Brute_Force / HIGH | 通过（6/6） | [TC-01.md](./TC-01.md) |
| TC-02 同一攻击链，人工审批驳回（门禁生效验证） | `investigate` | SQL_Injection_After_Brute_Force / HIGH | 通过（2/2） | [TC-02.md](./TC-02.md) |
| TC-03 健康检查探针流量（白名单旁路，不调模型） | `whitelist` | — | 通过（2/2） | [TC-03.md](./TC-03.md) |
| TC-04 缺少源 IP 的截断日志（反问补字段，不编造攻击源） | `ask` | — | 通过（3/3） | [TC-04.md](./TC-04.md) |

> 全部用例均使用显式 Mock 数据（`meta.mock=true`），仅验证链路逻辑，不代表真实检出效果。
