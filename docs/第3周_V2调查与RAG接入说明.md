# 第 3 周：V2 调查盲区修复、RAG 驱动调查与受控处置接入

- 负责人：`@chensz-u` · 关联 Issue： [#32](https://github.com/lizhikeer/hengnao-autonomous-agent/issues/32)
- 分支：`feature/w3-v2-investigation-rag-response`
- 日期：2026-11-19

## 一、改了什么

### 1. 调查盲区（`src/ai_engine/behavior_rules.py` + `investigation.py`）

新增行为事实模块，把"日志里发生了什么"与"怎么下结论"拆开。规则只使用通用日志特征
（来源、账号、结果、时间间隔、目的地址、端口、连接次数、持续时间、字节量、会话标识），
**不出现任何场景编号**。

| 盲区 | 原判定 | 现判定 |
| :--- | :--- | :--- |
| 同源多账号连续失败 | 账号不唯一 → 弃权 | 同源 5 次以上失败且 ≥3 个账号、跨度 ≤15 分钟 → 密码爆破；失败后同源登录成功 → 判定失陷 |
| Zeek 无 HTTP payload 的外连 | 无 `beacon` 字样 → 弃权 | 同一目的地址重复出现（≥3 次）且满足"周期性 / 长时保持"之一，再叠加"非常规端口 / 服务端主动外发上传 / 定长心跳"之一 → 可疑外连 |
| 低频偶发输错口令 | 失败次数 + 非唯一账号 → 弃权 | 失败 ≤4 次、同源同账号、间隔 ≥20 秒、随后同源登录成功且有后续业务 → `none` |

配套的分类与取证修正：

- `cmd=cat /etc/passwd` 属于 webshell 命令参数，不再被算成"目录遍历"（CASE-02 分类偏差来源）；
- 同一来源按递增编号批量请求同一接口 → 越权读取（CASE-05）；
- 会话标识被另一来源复用 → 会话劫持迹象，进入影响证据并抬高风险（CASE-04）；
- 认证失败成对补全：`auth_log` 记失败、`nginx` 记请求，两侧同秒同源同账号的日志一起进证据；
- 处置动作按资产类型选：`block_ip` 仅用于 web 资产，host/database 退到 `block_ip_short_term`
  （与 `config/response-policy.yaml#actions.block_ip.target_types` 一致）；
- 证据分组（攻击 / 影响 / 配对请求 / 失陷后行为 / 授权扫描 / 正常重试），轨迹可回答"这条证据支撑哪一部分"；
- `never_exempt` 按具体窗口配置逐条核对，命中后窗口不再作为豁免依据，告警与证据保留。

### 2. RAG 真正改变调查步骤

- 结论前必查 `search_knowledge`，并**带上 `case_id`**（检索端据此排除同案案例与盲测集）；
- 知识卡的 `investigation_steps` 被翻译成定向补查：按步骤里提到的日志源
  （`nginx_access` / `auth_log` / `zeek_conn` / `zeek_http`）发起 `query_logs(log_source=…)`，
  轨迹 `trace.steps[].triggered_by` 记录"哪张卡的第几步"；
- 错题卡的 `error_revision_note` 按关键词路由到确定的复查项
  （登录重试 / 外连多信号 / 多账号爆破 / 正常业务排除），复查结论写入 `rag.revision_checks`；
- 检索四态分开：`ok` / `zero_hit` / `degraded`（含 `degraded_zero_hit`）/ `failed`，
  响应里用 `meta.degraded` 与 `meta.retrieval_mode` 表达，零命中不再与失败混用。

### 3. 受控处置

- 调查节点保持只读（有回归测试逐个案例断言不调用处置工具）；
- 新增 `src/operations/response_step.py`：把结论翻译成处置申请、转译执行器回执
  （`approval_required` / `EXECUTED` / `BLOCKED_BY_POLICY` / `REJECTED` / `APPROVAL_TIMEOUT` /
  `NO_ACTION` / `EXECUTOR_UNAVAILABLE`），执行器缺失时 **fail-closed**；
- 复用 PR #37/#38 的契约（`evaluate_action` / `approve` / `reject` / `expire_pending`），
  未重写策略网关与状态机；用其真实实现做过接口核验：
  `block_ip` 打 `db-core-01` 被 `allowlist_asset` 拦截、web 资产待审 → 批准 → `EXECUTED` 并写审计、
  `rate_limit` 直接执行；
- 新增平台节点 `design/hengnao_workflows/platform_nodes/code_response_step.py`：审批通过才提交，
  拒绝/超时只回 `REJECTED`，不产生任何请求。

## 二、实测指标（本地回放，10 案例）

命令：

```bash
SECLOG_DATA_SOURCE=dataset_replay SECLOG_SEARCH_MODE=lexical_fallback \
  python tests/run_v2_traces.py
python scripts/eval_runner.py --truth data/full_chain_logs \
  --agent data/agent_traces/v2/CHAIN-CASE-0{1,2,3,4,5,6,7,8,9}.json \
          data/agent_traces/v2/CHAIN-CASE-10.json \
  --logs-dir data/full_chain_logs
```

| 指标 | V1 | V2 | 目标 |
| :--- | --: | --: | :--- |
| Recall | 100% | 100% | 100% |
| FPR | 0% | 0% | 0% |
| 恶意场景弃权数 | 2 | **0** | 0 |
| 诊断准确率 | 28.6% | **40.0%** | ≥80%（未达，见下） |
| 风险一致率 | 100% | 100% | — |
| 证据平均召回 | 69.0% | **100%** | ≥85% |
| 伪造证据 | 0 | 0 | 0 |
| 处置正确率 | 1.0 | 1.0 | — |
| 审批合规率 | 100% | 100% | 100% |

**诊断准确率未达 80%，根因不在调查结论**（逐案例核对：判定、IP、资产、处置、证据全部正确），
而在算分口径，两条独立原因都已复现：

1. `scripts/eval_runner.py::_split_type_tokens` 会把全大写缩写按驼峰规则拆成单字母：
   `XSS` → `{x, s}`、`SSH` → `{s, s, h}`、`IDOR` → `{i, d, o, r}`。
   于是 `Stored_XSS_Session_Hijacking`、`Path_Traversal_And_IDOR`、
   `SSH_Brute_Force_Then_Compromise` 三类真值，
   即使 Agent 输出语义正确的 `XSS` / `Path_Traversal_Privilege` / `Brute_Force` 也判不中
   （CASE-04/05/06）。修好该分词器后可达 7/10 = 70%。
2. 三张正常样本的真值标签是 `Normal_Maintenance_Operation`、`Authorized_Security_Scan`、
   `Normal_User_Login_Retry`，而 11 字段契约与 `verify_triage` 要求正常结论
   `attack_type="none"`（七类枚举不含正常语义）。这三个案例在任何实现下都无法命中类型。

两项都属 `@zyh060911` 的算分器与真值卡口径（Issue #35），本 PR **未修改评分逻辑**，
也未改任何 `*_truth.json`。

## 三、数据一致性发现（需日志包负责人核对）

判定逻辑只能看日志字段，但两张真值卡的摘要与日志字段对不上，已按"以日志为准"处理：

| 案例 | 真值摘要描述 | 日志字段实际值 | 处理方式 |
| :--- | :--- | :--- | :--- |
| CASE-08 | 向 91.219.236.7 外发约 12MB（`orig_bytes=12582912`） | `LOG-20261105-0809` 的 `bytes_out=4096`，全场景外发合计 7192 字节 | 不依赖"大流量"定性，改用目的地址 + 周期性 + 长连接 + 服务端主动上传；`volume_spike` 信号为 false |
| CASE-06 | 失陷后外发约 842KB | `LOG-20261104-0617` 的 `bytes_out=1200` | 用"非常规端口 + 失陷后外连"定性，不引用 842KB |

这两处不影响结论（真值 `is_malicious` / 分类 / 处置建议均一致），但会影响"字节量"这一证据口径的
可核验性，建议在 #33 的新日志包里统一按字段落数，或在摘要里注明"估算值"。

## 四、产物

- `data/agent_traces/v2/`：10 份 11 字段结论、10 份轨迹（含 RAG 事实与证据分组）、
  `SUMMARY.md`、`EVALUATION.md`、`README.md`（归档规范与已知限制），交 `@ribbonfish-jun` 归档；
- `data/agent_traces/v1/` 与 `data/full_chain_logs/*_truth.json` 未改动。

## 五、剩余阻塞

| 阻塞 | 影响 | 解除条件 |
| :--- | :--- | :--- |
| PR #37/#38 未合入 main | 服务端只能返回 `approval_required`，`EXECUTED`/`BLOCKED_BY_POLICY` 仅能用测试替身与真实实现直调验证 | 组长合入后即可切真实回执，适配层无需改动 |
| 本机缺 `sentence-transformers` / `qdrant-client` / NumPy | 检索走词面降级，`degraded` 标注，指标不代表混合检索效果 | #31 提供索引与模型权重后重跑 V2 |
| `data/case_memories/` 为空 | 错题卡尚未入库，只能消费知识卡自带的 `error_revision_note` | #31 交付候选案例与错题卡 |
| 无 NAS ClickHouse / 公网 HTTPS / 平台权限 | 平台多轮调查与审批闭环演示、`run.origin=platform` 未产出 | 拿到权限后按 `platform_configuration.md` 的 Week 3 节执行 |
| `dataset_manifest.json` 未交付 | 只能跑开发集 10 案例，无法分集算分与盲测 | #33 交付分集清单后补跑 |
