# config/ —— 运行时配置

本目录放**运行时可变的配置**，与代码分离。改配置不需要重新构建镜像，但要重启相关容器才生效。

| 文件 | 用途 | 消费方 |
| :--- | :--- | :--- |
| `risk-scoring-v1.json` | 风险评估：reason_code → 风险分量、风险等级阈值 | `src/detection/scoring.py`（启动即加载） |
| `acceptance-thresholds-v1.json` | 验收指标阈值 | `src/operations/config.py` |
| `assets.yaml` | 资产台账：资产 ID、重要性、暴露面、日志来源 | 清洗脚本（填 `asset_id`）、Agent 工具层、处置校验 |
| `maintenance-windows.yaml` | 维护窗口：什么时间、什么资产上的什么行为属于正常运维 | `src/detection/rules.py` 的 `DetectionContext` |
| `response-policy.yaml` | 处置授权：动作枚举、自动/审批、时长上限、白名单 | 受控处置执行器、审批节点 |

## 三条硬规则

**1. `response-policy.yaml` 的 `actions` 是唯一权威枚举**

任何地方出现新的处置动作，都必须先在这里登记。目前有两处需要对齐：

| 位置 | 现状 | 处理 |
| :--- | :--- | :--- |
| `src/api/config.py` | `ALLOWED_RESPONSE_ACTIONS` = `block_ip` / `block_ip_short_term` / `rate_limit` / `none` | 与本文件一致 ✅ |
| `data/knowledge_cards/*.json` | 用了 `rate_limit_ip` / `isolate_account` | `rate_limit_ip` 是本文件 `rate_limit` 的别名，已登记在 `aliases`；`isolate_account` 已补进枚举 |

> 知识卡里的 `rate_limit_ip` 与 API 的 `rate_limit` 是同一件事。执行器在受理前必须做别名归一化，
> 否则会出现「知识卡建议限速、执行器报动作不合法」。这个不一致应该在 W3 统一，不要长期靠别名兜。

**2. `asset_id` 只能来自 `assets.yaml`**

清洗脚本遇到无法归属的资产，填 `unknown`，不要自造名字。`unknown` 出现频次高说明台账不全，
应回溯补登记，而不是改清洗逻辑把它掩盖掉。

**3. 维护窗口是降权因子，不是免死金牌**

窗口内的行为仍会生成线索，只是风险分被 `maintenance_window`（-8）拉低。
`never_exempt` 里列出的行为在任何窗口内都照常告警——例如维护窗口内的 SQL 注入。

## 修改流程

1. 改 YAML/JSON
2. 本地校验语法：`python3 -c "import yaml,json; ..."`
3. 提 PR，说明改了什么、为什么改、影响哪些判定
4. 合入后重启相关容器：`docker compose --env-file ../.env restart api`

`risk-scoring-v1.json` 是团队共享资产，改它需要 `@lizhikeer` 与 `@chensz-u` 双确认，
因为会直接影响所有线索的风险定级。
