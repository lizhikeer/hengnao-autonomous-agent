# 与 A 组（日志）、C 组（算分/通知）的接口交接说明（Week 1）

> 编写：`@chensz-u` ｜ 对应 Issue：#4
> **性质声明**：本文是**我方（工具服务 + Agent 契约）对上下游的交接建议与需要确认的问题清单**，
> **不是**"团队已冻结契约"的声明。契约冻结需由 `@lizhikeer` 组织评审后写入
> `docs/project design/项目分工与前期架构设计.md` §5；在此之前任何一方改动字段都需先在本文件登记。

---

## 一、总览：三段接口面

```
A 组（@ribbonfish-jun）               我方（@chensz-u）                 C 组（@zyh060911）
日志清洗 / 攻击故事链日志包   ──►   LogItem（query_logs 返回）   ──►   评测算分脚本
标准证据链答案卡                     AgentResults（results 11 字段） ◄──   标准答案 JSON 比对
                                    ▲
                                    │ KnowledgeCard 检索结果
                          @Snowed-night（Qdrant 知识卡/案例卡）
```

三处接口面各自独立，不要混：
1. **日志面**：A 组产出的日志 JSONL → 入库 → 我方 `LogItem`（字段必须能一一映射）；
2. **结论面**：我方 `AgentResults` → 恒脑结束节点 `results` → C 组算分脚本；
3. **知识面**：`@Snowed-night` 的 `KnowledgeCard` payload → 我方 `search_knowledge` 返回结构。

---

## 二、与 A 组（`@ribbonfish-jun`）：日志字段映射

### 2.1 映射表（以 `项目分工与前期架构设计.md` §5.1 为基准）

| 统一 Schema 字段 | 我方 `LogItem` 字段 | 类型 | 必填 | 备注 |
| :--- | :--- | :--- | :--- | :--- |
| `log_id` | `log_id` | string | 是 | **格式必须是 `LOG-YYYYMMDD-NNNN`**，平台侧 `code_verify` 用该正则做格式校验，格式不符会被判为无效证据 |
| `trace_id` | `trace_id` | string | 是 | 同一攻击故事链的全部日志必须共享；`query_logs` 用它做阶段串联 |
| `timestamp` | `timestamp` | string | 是 | ISO8601 **UTC**，带 `Z`（如 `2026-10-27T14:20:05Z`）；不要给本地时间 |
| `log_source` | `log_source` | string | 是 | 枚举必须落在 `nginx_access | auth_log | zeek_conn | zeek_http` 内 |
| `src_ip` / `dest_ip` | 同名 | string | 是 | IPv4 点分十进制 |
| `asset_id` | `asset_id` | string | 否 | 有则填（如 `web-prod-01`），用于 `get_context` 关联资产上下文 |
| `user` | `user` | string | 否 | 认证日志必有；Web 访问日志可空 |
| `action_Or_method` | `action_or_method` | string | 否 | ⚠️ 原 Schema 拼写为 `action_Or_method`（大小写混用），我方已规范为 `action_or_method`，**请 A 组按全小写下发**，否则字段会丢失 |
| `uri_or_target` | `uri_or_target` | string | 否 | 完整保留 Path+Query，不要截断（注入载荷常在 query 里） |
| `payload_summary` | `payload_summary` | string | 否 | 敏感字段请脱敏，但仍需保留攻击特征（如 `' OR 1=1--`） |
| `status_code` | `status_code` | int | 否 | 网络流日志可空 → 我方用 `Optional[int]` |
| `user_agent` | `user_agent` | string | 否 | 攻击工具指纹（sqlmap/hydra）是重要线索，请勿丢弃 |
| `attack_stage_hint` | `attack_stage_hint` | string | 是 | 枚举 `recon/brute_force/exploitation/c2_callback/benign`，**我方多轮调查的阶段判断完全依赖它** |

### 2.2 需要 A 组确认的问题

1. `log_id` 能否全部符合 `LOG-YYYYMMDD-NNNN`（8 位日期 + 4 位序号）？若编号规则不同，请在此登记，我方改正则。
2. `trace_id` 的生成规则是谁负责？A 组是否保证同一故事链（扫描→爆破→利用→外连）共享同一 `trace_id`？
3. 正常背景流量是否也带 `attack_stage_hint="benign"`？我方用它区分"恶意判定"与"良性对照"，
   若缺失，`_guess_attacker_ip` 会把正常流量源 IP 也纳入统计。
4. Zeek 网络流日志里"受害主机外连"的方向：`src_ip` 是受害主机、`dest_ip` 是外部 C2 地址，
   与我方 mock 数据一致吗？（我方 `LOG-20261027-0022` 就是这么模拟的）
5. 样例日志包什么时候能提供 3 组（对应 W1 里程碑）？我方拿到后会把 `src/api/mock_data.py`
   替换为读取真实 JSONL 的实现，接口契约不变。

### 2.3 我方替换点（A 组不必改我代码）

| 要替换的 | 位置 | 替换后 |
| :--- | :--- | :--- |
| `MOCK_LOGS` 常量 | `src/api/mock_data.py` | 改为查 ClickHouse 的连接器（属 @lizhikeer 的存储层） |
| `query_mock_logs()` | 同上 | 改为参数化 SQL（字段白名单不变，禁止拼 SQL） |
| `meta.mock` / `data_source` | `src/api/app.py` | 真实接入后改为 `false` / `"clickhouse"`，`backend_available=true` |

---

## 三、与 C 组（`@zyh060911`）：结论契约与算分口径

### 3.1 结论契约（不可临时改名）

`AgentResults` 共 11 个字段，**全部 required**，定义见 `src/ai_engine/schemas/agent_results.schema.json`：

| 字段 | 类型 | 枚举/约束 | 算分时的用法 |
| :--- | :--- | :--- | :--- |
| `case_id` | string | 与评测集 case_id 对齐 | 配对键 |
| `is_malicious` | bool | — | 二分类主指标 |
| `attack_type` | string | 自由文本；证据不足时为 `insufficient_evidence` | 需按"包含/前缀"策略匹配，不要做严格相等 |
| `risk_level` | enum | LOW/MEDIUM/HIGH/CRITICAL | 分级一致性 |
| `attacker_ip` | string | 必须来自已查日志 | 溯源准确率 |
| `victim_asset` | string | asset_id 或 IP | 溯源准确率 |
| `evidence_log_ids` | array&lt;string&gt; | 可为空数组（此时必须 insufficient） | 证据支持率（召回为主） |
| `attack_chain_summary` | string | 非空 | 人工评审用，不自动算分 |
| `recommended_action` | enum | block_ip/block_ip_short_term/rate_limit/none | 处置正确率 |
| `requires_human_approval` | bool | 高危动作必须 true | 一致性检查（违反即扣分） |
| `unknown_items` | string | 可空串 | 信息完整度评分 |

### 3.2 三条必须分开统计的规则

1. **`insufficient_evidence` 不等于 `is_malicious=false` 的负例。**
   标准答案若是"恶意"，而 Agent 输出 `insufficient_evidence`，这是**调查不足（Abstain）**，
   不是误判为正常（False Negative），也不该算作正确（True Negative）。
   建议在算分脚本里单列 `abstain_rate` 与 `abstain_but_should_detect` 两项。
2. **`evidence_log_ids` 为空但 `is_malicious=true` 是非法输出**，契约层会拒绝（`model_validator`）。
   算分脚本遇到这种数据应判为 `invalid_output` 并计入错误，不要静默当 0 分处理。
3. **`action=none` 与 `status=rejected` 不是一回事**：前者是"无需处置"，后者是"证据校验未通过"。
   通知/台账里请分别记录，避免把证据造假误记为"无需处置"。

### 3.3 建议的指标定义（供 C 组参考，最终口径由 C 组定）

| 指标 | 建议算法 |
| :--- | :--- |
| 诊断准确率 | `is_malicious` 与标准答案一致，且 `attack_type` 命中（标准答案的类型名包含在输出里，或反之） |
| 证据支持率 | `evidence_log_ids ∩ 标准证据链 / 标准证据链`（召回），另给"引用伪造编号数"作为惩罚项 |
| 处置正确率 | `recommended_action` 与标准答案完全一致；`block_ip` 与 `block_ip_short_term` 视为近似（0.5 分） |
| 审批合规率 | 高危动作且 `requires_human_approval=true` 的比例，应为 100% |
| 弃权率 | `attack_type == insufficient_evidence` 的比例，单列观察 |

### 3.4 评测隔离红线

* 标准答案 JSON **不得**进入 Qdrant 可检索集合（`verified_cases` / `security_knowledge`），
  也不得作为 Few-Shot 示例注入模型提示词 —— 否则评测失效。
* 我方 Mock 数据**只用于本地联调与演示**，不能用于任何对外报告的准确率。
  真实评分必须基于 A 组的真实/仿真日志包 + C 组的独立评测集。
* 我方接口返回 `meta.mock=true` 时必须被算分脚本识别为"演示数据"，建议直接跳过并告警。

### 3.5 通知衔接（SMTP 模块属 C 组）

| 通知场景 | 触发条件 | 正文来源 |
| :--- | :--- | :--- |
| 高危研判告警 | `risk_level in {HIGH, CRITICAL}` | 结束节点的 Markdown 报告 + 附 `results` JSON |
| 审批申请 | `requires_human_approval=true` 且 `status=approval_required` | `approval_id` + 证据编号 + 攻击链摘要 |
| 处置结果 | 处置动作执行或驳回后 | `status` + `executed` + `detail` |

正文渲染用 C 组的 HTML 模板；我方只保证 `results` 与 `approval_id` 字段稳定，不介入邮件实现。

---

## 四、与 `@Snowed-night`：知识卡字段对齐

我方 `search_knowledge` 返回的 `KnowledgeCard`：

| 字段 | 对应 Qdrant payload 建议键 | 说明 |
| :--- | :--- | :--- |
| `card_id` | `card_id` | 主键 |
| `card_type` | `card_type` | `security_knowledge` / `verified_correct_case` / `verified_error_revision` |
| `title` / `attack_category` / `mitre_id` | 同名 | 过滤与展示 |
| `key_indicators` | `key_indicators` | array&lt;string&gt; |
| `recommended_action` | `recommended_action` | 与 `AgentResults.recommended_action` 同枚举，便于对齐 |
| `score` | 检索时回填 | 我方不参与打分，只透传 |

需确认：候选案例卡（未审核）是否**物理隔离**在另一集合，避免被我方接口检索到。
按架构文档要求，未审核案例绝不能进入 `verified_cases`。

---

## 五、变更流程

1. 任何字段增删改，先在本文件 §2.1 / §3.1 表格中登记并注明日期与提出人；
2. 我方同步修改 `src/api/schemas.py` 与 `src/ai_engine/results_schema.py`，
   运行 `pytest tests/test_results_schema.py` 确保 Schema 文件与代码一致；
3. 由 `@lizhikeer` 评审后写入 `docs/project design/项目分工与前期架构设计.md` §5，
   才算"团队已冻结"。在此之前，冲突以本文件 + 评审结论为准。

---

## 六、待确认清单汇总（对方回复后在此更新）

| 编号 | 对象 | 问题 | 状态 |
| :--- | :--- | :--- | :--- |
| Q-A1 | @ribbonfish-jun | `log_id` 是否统一为 `LOG-YYYYMMDD-NNNN` | 待回复 |
| Q-A2 | @ribbonfish-jun | `trace_id` 是否由 A 组保证同故事链唯一共享 | 待回复 |
| Q-A3 | @ribbonfish-jun | 正常流量是否标 `attack_stage_hint=benign` | 待回复 |
| Q-A4 | @ribbonfish-jun | 外连方向约定（src=受害主机 / dest=C2） | 待回复 |
| Q-A5 | @ribbonfish-jun | 3 组全链路样例日志包交付时间 | 待回复 |
| Q-C1 | @zyh060911 | `attack_type` 匹配策略（包含/前缀/严格） | 待回复 |
| Q-C2 | @zyh060911 | 弃权（insufficient）是否单列指标 | 待回复 |
| Q-C3 | @zyh060911 | 是否识别 `meta.mock=true` 并跳过演示数据 | 待回复 |
| Q-S1 | @Snowed-night | 未审核候选案例是否物理隔离 | 待回复 |
| Q-S2 | @Snowed-night | `recommended_action` 枚举是否与结论契约一致 | 待回复 |
