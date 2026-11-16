# Issue #18 独立复验进度（2026-11-12）

本地 `feature/w2-tool-integration` 位于 `6a44c10`，含未提交改动。远端 `main` 位于 `ba156145`，领先本地 12 个提交，已合入 PR #22 和 PR #23。暂存的 `config/` 与远端一致。GitHub 上 Issue #18 仍分配给 `chensz-u`，状态为 Open，开发分支尚无远端分支或 PR。

本地独立复跑 **246 项测试通过**，三组 V1 内存复跑通过契约校验，结果和评测与归档一致。CASE-02 的 `attack_type_covers_truth=false`，CASE-03 的证据召回率为 0.4。新中转入口 `https://seclog.91666.icu:18443` 可访问，`/tools/query_logs` 返回 `meta.data_source=mock` 和 `backend_available=false`。ClickHouse 实库查询、真实混合检索和恒脑 V1 仍待联调。

部署前待修复：

1. **MCP 启动入口。** 当前 Dockerfile 启动 `src.api.app:app`。本地 ASGI 测试中，`/mcp/` 和 `/investigation/` 的工具列表请求均返回 404。远端采用 `src.api.service:app`，同一请求实测均返回 200。对齐时保留双通道启动入口和运行时配置打包。
2. **授权判断。** 用现有 YAML 配置复现了白名单外来源仍获授权，以及 `db-core-01` 非周日的行为仍获授权。调查器继续读取 `weekdays`，新配置使用 `days`。账号画像把全部登记资产填作 `allowed_assets`，还需核实真实授权范围。
3. **账号隔离契约。** `isolate_account` 已进入常量，但 REST 请求模型会拒绝该动作，现有请求也缺少账号目标字段。需统一第二周的策略、工具契约和审批行为。
4. **历史日志查询。** §1.12.4 的 `24h` 查询按服务器当前时间回溯，无法用来验证历史 CASE-01 的条数。应以 NAS 实库的场景 ID、时间范围及分源计数为准，再通过公网 API 交叉验证。

以下保留此前各轮的修复与验收记录。

---

# 第十轮：接入账号授权范围并补齐 10 案例 V1（2026-11-16）

## 1. 授权范围接入

最新 `main` 的 `config/response-policy.yaml#allowlist.users` 已为 `ops_*` 和 `ops` 配置 `common_src_ips` 与 `allowed_assets`。`get_user_profile()` 现将这两项作为行为授权范围传给调查器，同时继续单独标记 `disposition_exempt`，不再把处置豁免与行为授权混为一谈。`common_src_ips` 支持单 IP 和 CIDR；无效 IP 或配置项不匹配授权范围。

CASE-03 重新回放后判定为 `none`，风险 `LOW`，4 条证据，2 轮；来源 `10.0.0.66`、目标 `web-prod-01` 均命中授权范围，行为落在配置的维护窗口内。

## 2. V1 轨迹与 10 案例算分

`tests/run_v1_traces.py` 已对 CASE-01～CASE-10 全部重跑。结果 JSON、轨迹 JSON、`SUMMARY.md` 与 `EVALUATION.md` 均由程序生成；truth 只用于独立评测，未参与调查。全部 10 个结果通过 AgentResults 契约校验，所有引用证据均已登记。

主要指标：检测 Recall 100%、正常业务误报率 50%、弃权率 30%、诊断准确率 14.3%、风险等级一致率 85.7%、平均证据召回率 49.0%、高危动作审批合规率 100%。CASE-06 与 CASE-08 对恶意场景弃权；CASE-09 将授权扫描误判为恶意。以上差异保留在产物中，后续应作为错题分析输入，不按 truth 直接改写调查结论。

产物位置：`data/agent_traces/v1/`。本轮来源为本地 `dataset_replay`，控制器为 `rule_based_v1_controller`，不是恒脑平台模型运行结果。

## 3. 回归与外部依赖

全量测试：`268 passed`；`git diff --check` 通过。

真实检索检查仍缺 `sentence-transformers`、`qdrant-client`、NumPy、BGE 权重、可用 Qdrant 服务和 SQLite 知识库。本轮对 `https://seclog.91666.icu:18443/health` 的 TCP 连接超时；未能验证该中转上的应用、ClickHouse 数据源或恒脑平台工作流。工作区没有 `CLICKHOUSE_DSN` 等本地连接配置，因此没有发起真实 ClickHouse 查询。

## 4. 当前交付边界

已完成本地授权范围接入、CIDR 匹配、CASE-03 回放、CASE-01～CASE-10 轨迹生成和 10 案例算分。恒脑平台联调、ClickHouse 实库和真实混合检索仍未完成；Issue #18 不应据此标记为整体验收通过。

---

# 第九轮：运行时依赖修复 + 干净环境验证 + 暂存整理（2026-11-12 深夜）

## 1. 依赖冲突（已修）

`docker/api/Dockerfile` 只装 `requirements/base.txt` + `requirements/api.txt`，两份都**没有 `mcp`**，
而容器入口 `src.api.service:app` 会 `from mcp.server.fastmcp import FastMCP` → 启动即 ImportError。

冲突链条：

| 包 | 旧锁定 | mcp 1.30.0 要求 | 处理 |
| :--- | :--- | :--- | :--- |
| `mcp` | 未列 | — | `api.txt` 增 `mcp==1.30.0` |
| `pydantic` | 2.8.2（base） | `>=2.11.0` | 升 **2.14.1** |
| `httpx` | 0.27.0（api） | `>=0.27.1,<1.0` | 升 **0.28.1** |
| `uvicorn` | 0.30.1（api） | `>=0.31.1` | 升 **0.54.0** |
| `fastapi` | 0.111.0（api） | starlette `>=0.27` | 升 **0.162.0**（与 starlette 1.10 配套） |

**单一入口**：根 `requirements.txt` 改为 `-r requirements/runtime.txt`，
`runtime.txt` 再 `-r base.txt` + `-r api.txt`。原来根目录与 `requirements/` 各锁一套，
版本还不一致（根有 mcp 但缺 clickhouse/PyYAML，子目录反之），这次只保留一条路径。

保留项：`clickhouse-connect==0.8.9`、`PyYAML==6.0.3`、双通道入口 `src.api.service:app`、
`COPY config/` 与 `COPY data/`。

`qdrant-client` 统一到 **1.15.1**（与 `requirements/knowledge-base.txt` 一致，避免两套）。

## 2. 干净环境验证（Python 3.11.15）

Docker daemon 不可用（`npipe:////./pipe/dockerDesktopLinuxEngine` 连接失败），
改用 uv 拉取 CPython 3.11.15 建隔离环境，按 `requirements/runtime.txt` **从零安装**：

```bash
uv venv --python 3.11 "$TEMP/w2verify311"
uv pip install -r requirements/runtime.txt \
  --python "$TEMP/w2verify311/Scripts/python.exe" \
  --index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

安装结果：**无依赖冲突，一次成功**（pydantic 2.14.1 / fastapi 0.162.0 / uvicorn 0.54.0 /
httpx 0.28.1 / starlette 1.10.0 / mcp 1.30.0）。

启动与验证（`SECLOG_DATA_SOURCE=dataset_replay`）：

| 检查 | 结果 |
| :--- | :--- |
| `GET /health` | **200** |
| `POST /tools/query_logs`（`CHAIN-CASE-01` + 10-27 绝对窗口） | **29 条**，`data_source=dataset_replay` |
| `POST /mcp/` tools/list | **5 个**（含 `request_response`） |
| `POST /investigation/` tools/list | **4 个**，无 `request_response` |

> **镜像未实测**：Docker daemon 未运行，未执行 `docker build`。以上是"同依赖清单 + 同入口"
> 的等价验证；镜像层面的验证待 Docker 可用后补，命令见 §4。

## 3. 暂存范围

当前 Git 仍处 `MERGE_HEAD=ba15614`（PR #23 已合入但未提交）。已按交付范围暂存：

| 类别 | 内容 |
| :--- | :--- |
| 运行时依赖 | `requirements.txt`、`requirements/base.txt`、`requirements/api.txt` |
| 双通道部署 | `docker/api/Dockerfile` |
| 工具层 | `src/api/{app,service,config,schemas,datasource,asset_context,knowledge_adapter,evidence_check}.py`、`src/mcp_server/server.py` |
| 调查层 | `src/ai_engine/{investigation,verify,attack_types,redaction}.py` |
| 测试 | `tests/`（含 `test_independent_acceptance.py`、`test_w2_*.py`、`run_v1_traces.py`、`check_knowledge_ready.py`） |
| 验收材料 | `design/hengnao_workflows/{week2_acceptance,attack_classification,pr_progress_note}.md` |
| 评测产物 | `data/agent_traces/v1/`（3 份结果 + 3 份 trace + README + SUMMARY） |

**未暂存**（刻意排除）：`data/agent_traces/legacy/`（历史归档，体积大且非交付物）、
`docs/superpowers/`（无关临时文档）。无 `.env`、凭据、日志混入。

核对命令与结果：

```bash
git diff --cached --stat origin/main   # 40 files changed, 9060 insertions(+), 191 deletions(-)
git diff --cached --check origin/main  # exit=0，无空白错误
```

## 4. 测试与镜像复测

```
pytest tests/ -q        → 265 passed in 9.87s
git diff --cached --check origin/main → 通过
```

Docker 可用后的镜像验证命令（本次未执行）：

```bash
docker build -f docker/api/Dockerfile -t seclog-api:w2 .
docker run --rm -p 8000:8000 \
  -e SECLOG_DATA_SOURCE=dataset_replay \
  -e SECLOG_PUBLIC_HOST=seclog.91666.icu,seclog.91666.icu:18443 \
  seclog-api:w2
curl -s localhost:8000/health
curl -s -X POST localhost:8000/tools/query_logs -H 'Content-Type: application/json' \
  -d '{"trace_id":"CHAIN-CASE-01","time_start":"2026-10-27T14:00:00Z","time_end":"2026-10-27T15:00:00Z","limit":200}'
```

## 5. 后端验证状态

| 项 | 状态 |
| :--- | :--- |
| 干净 3.11 环境安装 + 启动 | **已验证**（本节 §2） |
| Docker 镜像构建/启动 | **未实测**（daemon 不可用） |
| NAS 部署 | **未执行** |
| ClickHouse 实库 | **未验证** |
| 真实混合检索 | **未验证**（缺 BGE 权重 / Qdrant / `sentence-transformers`） |
| 恒脑 V1 | **未运行**（中转数据源仍 mock） |

---


# 第八轮：MCP 时间窗 / 公网 Host / 毫秒边界（2026-11-12 夜）

## Git 状态

工作区处于 `MERGE_HEAD`（`ba15614`，PR #23）未提交状态；暂存区含 main 的 21 个文件变更，
未跟踪文件（验收文档、`data/agent_traces/`、`src/ai_engine/attack_types.py` 等）保持原样。
**本轮未 commit / 未 push / 未建 PR**。

## 1. MCP 历史时间窗（原不一致已修）

**复现**：`trace_id=CHAIN-CASE-01` + `time_start=2026-11-01` —— REST 返回 **0 条**，
`/investigation/` 返回 **29 条**。原因是 `seclog_query_logs` 没有声明 `time_start`/`time_end`，
参数被丢弃后回落到默认窗口。

**修复**：`src/mcp_server/server.py` 的 `seclog_query_logs` 增加 `time_start` / `time_end`
并透传到 `QueryLogsRequest`；工具说明补上"时间窗语义 + 数据源看 `meta.data_source`"。
`/mcp/` 与 `/investigation/` 复用同一个 tool 对象，说明自动同步。

**验证（真实 `tools/call`，独立进程起 `src.api.service:app`）**：

| 条件 | REST | `/mcp/` | `/investigation/` | `time_base` |
| :--- | --: | --: | --: | :--- |
| 11 月窗口 | 0 | 0 | 0 | `absolute` |
| 10-27 14:00~15:00 | 29 | 29 | 同 REST | `absolute` |

证据 ID 顺序逐条比对一致；历史场景在调查中沿用传入的 `time_start/time_end`
（`InvestigationSession.seed_*` 不变，绝对窗口随每次 `query_logs` 调用传入）。

## 2. 公网 MCP Host（421 已解除）

原实现只把 `SECLOG_PUBLIC_HOST` 原值追加进 `allowed_hosts`，而反代转发时常带端口，
`Host: seclog.91666.icu:18443` 被 SDK 判为非法 → 421。

改为 `register_public_hosts()`：支持逗号分隔多个主机；对每个值同时登记**原值**与**无端口形式**
（无端口时补 `:443`/`:80`，带端口时补纯域名）；**不关闭** `enable_dns_rebinding_protection`。

实测（本地，`SECLOG_PUBLIC_HOST=seclog.91666.icu,seclog.91666.icu:18443`）：

| Host 头 | 结果 |
| :--- | :--- |
| `seclog.91666.icu:18443` | 200 |
| `seclog.91666.icu` | 200 |
| `evil.example.com` | 421（校验仍生效） |

公开 Host 下 `/investigation/` 工具列表 = 4 个（`health` / `query_logs` / `get_context` / `search_knowledge`），
无 `request_response`。

> 中转实际转发给应用的 Host 值无法从外部确认，因此部署时把两种形式都写进环境变量；
> 若确认只保留一种，可精简。

## 3. ClickHouse 毫秒边界（已修，假驱动验证）

`clickhouse-connect==0.8.9` 对普通 `datetime` 参数按秒序列化，`.123` 会变 `.000`。
改用 `DT64Param` 绑定，明细查询与 count 查询复用同一组参数。

假驱动捕获实际绑定值验证：

| 用例 | 结果 |
| :--- | :--- |
| `.123` / `.124` 两个边界 | `format()` 分别输出 `.123000` / `.124000`，不再被抹平 |
| count 与明细 | 两条 SQL 共用同一 params，边界一致 |
| 相对窗口 | 仍是 `INTERVAL` 分支，`window_seconds=3600`，不受影响 |

**NAS 实库未验证**：`seclog.91666.icu` 只开放 18443，`8123`/`9000` 不可达；
需部署后用 `time_start` 查询复核毫秒边界记录。

## 4. CASE-03 授权缺口（保留 `insufficient_evidence`）

现状：`ops_zhang` 命中 `ops_*`、`web-prod-01` 已登记、3 条行为全在 `02:00–03:30` 窗口内，
但 `config/` 只有**处置豁免名单**，没有「账号 → 允许来源 / 允许资产」的授权范围，
无法确认 `10.0.0.66 → web-prod-01` 属于授权运维。

**需要组长确认**：`ops_zhang` 的合法来源网段与可操作资产清单。
仓库目前没有该配置契约，补齐后我会新增读取逻辑并覆盖「授权 / 越权 / 缺配置」三种用例；
在确认前不自行编造范围。

## 5. 测试

```
pytest tests/ -q        → 265 passed in 7.77s
git diff --check HEAD   → 通过（仅 CRLF 提示）
```

新增：`tests/test_w2_clickhouse_binding.py`（3 例）、`test_w2_mcp_consistency.py` +4 例（含 3 个端到端）。

## 6. V1（内存复跑，与上轮一致）

| 场景 | 结论 | 风险 | 证据 | 召回 |
| :--- | :--- | :--- | --: | --: |
| CHAIN-CASE-01 | `SQL_Injection_After_Brute_Force_After_Scan` | HIGH | 16 | 0.833 |
| CHAIN-CASE-02 | `Path_Traversal_Privilege_After_Malicious_Upload` | HIGH | 6 | 0.667 |
| CHAIN-CASE-03 | `insufficient_evidence` | LOW | 4 | 0.4 |

## 7. 后端状态

| 项 | 状态 | 依据 |
| :--- | :--- | :--- |
| NAS 部署 | **未执行** | 需组长用本文镜像部署 |
| ClickHouse 实库 | **未验证** | 中转仍旧镜像；8123 不对外 |
| 真实混合检索 | **未验证** | 缺 `sentence-transformers`/`qdrant-client`/BGE 权重/Qdrant/建库 |
| 恒脑 V1 | **未运行** | 数据源仍 mock |

## 8. 部署与复测（部署后执行）

```bash
docker build -f docker/api/Dockerfile -t seclog-api:w2-merged .
# 环境变量
#   SECLOG_DATA_SOURCE=clickhouse
#   CLICKHOUSE_DSN=http://<nas>:8123
#   SECLOG_CONFIG_DIR=/app/config
#   SECLOG_PUBLIC_HOST=seclog.91666.icu,seclog.91666.icu:18443
```

```bash
# 毫秒边界 + 历史场景（用绝对窗口，不要用 time_window）
curl -sk -X POST https://seclog.91666.icu:18443/tools/query_logs \
  -H 'Content-Type: application/json' \
  -d '{"trace_id":"CHAIN-CASE-01","time_start":"2026-10-27T14:00:00.123Z","time_end":"2026-10-27T14:17:02.124Z","limit":200}' \
  | jq '.meta.data_source, .meta.time_base, .meta.total'

# MCP 入口（Host 校验 + 只读工具集）
curl -s -X POST https://seclog.91666.icu:18443/investigation/ \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2024-11-05' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | grep -o '"name":"[a-z_]*"'
```

---


# 第七轮：合并 main + 四项复验修复（2026-11-12 晚）

## 基线

`origin/main` 已合入 `feature/w2-tool-integration`（`git merge --no-commit --no-ff origin/main`，
**未产生提交**，工作区同时含 main 的 21 个文件变更与本分支改动）。合并前把 `config/` 从暂存移除，
避免与 main 的同名文件冲突；合并后重新补上 `COPY config/`。

## 1. 部署入口（原 404 已修）

| 项 | 处理 |
| :--- | :--- |
| 启动入口 | 用回 main 的 `uvicorn src.api.service:app`（REST + `/mcp` + `/investigation` 同进程） |
| PYTHONPATH | `ENV PYTHONPATH=/app:/app/src` —— `service.py` 内部是 `from api.app`，必须两段路径 |
| 运行时配置 | 补 `COPY config/`、`COPY data/full_chain_logs/`、`COPY data/knowledge_cards/`（main 的 Dockerfile 没有） |

**实测（`src.api.service:app`）**：

| 入口 | 结果 |
| :--- | :--- |
| `GET /health` | 200 |
| `POST /tools/query_logs` | 200，`data_source=dataset_replay`，`total=29` |
| `POST /mcp/`（tools/list） | 5 个工具：`health` / `query_logs` / `get_context` / `search_knowledge` / **`request_response`** |
| `POST /investigation/`（tools/list） | 4 个工具，**不含 `request_response`**（只读调查，无处置能力） |

## 2. 授权判断（已修）

| 问题 | 处理 |
| :--- | :--- |
| 调查器读 `weekdays`，配置写 `days` → 窗口永远不匹配 | `_in_window` 兼容两者 |
| `allowlist`（处置豁免）被当成行为授权 | `get_user_profile` 拆成 `disposition_exempt`（只影响自动处置）与 `source_scope_provided`/`asset_scope_provided`（行为授权），后者当前为 **false** |
| 账号画像把全部登记资产填作 `allowed_assets` → 越权测不出 | 不再伪造授权范围；未提供即标 `asset_scope_provided=false` |
| 缺来源/资产授权依据仍判正常 | 缺任一项即 `checks[...]=False`，结论落到 `insufficient_evidence` 并写明缺什么 |

**CASE-03 结果**：`none` → **`insufficient_evidence`**。理由：账号 `ops_zhang` 命中 `ops_*`、
资产已登记、3 条行为全部在 `02:00–03:30` 窗口内，但 `config/` **没有提供账号-来源与账号-资产授权范围**，
无法确认 `10.0.0.66 → web-prod-01` 属于授权运维。按"以实际证据判定"处理，未为保留 `none` 放宽。

> 需要组长补一份 account-scope（账号 → 允许来源 / 允许资产），补齐后 CASE-03 才能合法判 `none`。

新增回归 6 项：配置齐全判正常、缺来源授权、越权资产、`db-core-01` 非周日窗口、
仅豁免名单不构成授权、`isolate_account` 三条契约。

## 3. `isolate_account` 契约（已纳入）

`config/response-policy.yaml` 已定义该动作（risk=high、auto_execute=false、requires_evidence=true、
target_types=[web,host]），故本周纳入接口契约：

| 层 | 变更 |
| :--- | :--- |
| REST `RequestResponseRequest.action` | 枚举增 `isolate_account` |
| 目标字段 | 新增 `target_user`；`isolate_account` 必须用它，且不接受 `target_ip`；IP 类动作反之 |
| 高危集合 | `HIGH_RISK_ACTIONS` 增 `isolate_account` |
| MCP `seclog_request_response` | 增 `target_user` 参数 |
| 审批单文案 | 明确写出"目标账号 xxx" |

支持边界：**只登记待审批，不执行**（`executed=false`）；权限网关与执行器仍未接入。

## 4. 历史场景查询（已补）

相对窗口（`time_window`）从**服务器当前时间**回溯，验证不了 10 月的 CASE-01。新增绝对时间窗：

| 参数 | 说明 |
| :--- | :--- |
| `time_start` / `time_end` | ISO8601 UTC；只给 `time_start` 时按 1 小时 |
| 互斥 | 与 `time_window`/`time_window_minutes` 同时给 → 422 |
| 校验 | `time_end <= time_start` → 422 |
| `meta.time_base` | 绝对窗口时为 `absolute` |

实测（回放）：`CHAIN-CASE-01` + `2026-10-27T14:00:00Z~15:00:00Z` → **29 条**；
换 `2026-11-01` 起 → **0 条**（证明不再从"现在"回溯）。

ClickHouse 分支同样支持（`timestamp >= {start} AND <= {end}`），但**未能实测**：中转仍是旧镜像、
NAS 的 8123 不对外开放。

## 5. 测试

```
pytest tests/ -q  → 258 passed in 7.38s
git diff --check  → 通过（仅 CRLF 提示）
```

## 6. V1 结果（内存复跑，`data/agent_traces/v1/`）

| 场景 | 结论 | 风险 | 证据 | 召回 | covers |
| :--- | :--- | :--- | --: | --: | :--- |
| CHAIN-CASE-01 | `SQL_Injection_After_Brute_Force_After_Scan` | HIGH | 16 | 0.833 | true |
| CHAIN-CASE-02 | `Path_Traversal_Privilege_After_Malicious_Upload` | HIGH | 6 | 0.667 | **false** |
| CHAIN-CASE-03 | `insufficient_evidence` | LOW | 4 | 0.4 | **false** |

CASE-02 差异（保留如实记录）：`_c2_signal` 要求 payload 含明确回连描述（beacon 等），
该场景 4 条 c2 日志只有 `conn_state=SF`，故不计入 `C2_Exfiltration`。

## 7. 三类后端状态

| 项 | 状态 | 证据 |
| :--- | :--- | :--- |
| ClickHouse 实库 | **未验证** | 需先部署新镜像；部署后用本文 §8 命令复测 |
| 混合检索 | **未验证** | 本地缺 `sentence-transformers`/`qdrant-client`/`numpy` + BGE 权重 + Qdrant + 建库 |
| 恒脑平台 | **未运行** | 中转数据源仍是 mock，跑不出真实 V1 |

## 8. 部署与复测

```bash
docker build -f docker/api/Dockerfile -t seclog-api:w2-merged .
# 环境变量：SECLOG_DATA_SOURCE=clickhouse
#           CLICKHOUSE_DSN=http://<nas>:8123（含账号）
#           SECLOG_CONFIG_DIR=/app/config
#           SECLOG_PUBLIC_HOST=seclog.91666.icu
```

```bash
# 1) 数据源
curl -sk -X POST https://seclog.91666.icu:18443/tools/query_logs \
  -H 'Content-Type: application/json' \
  -d '{"trace_id":"CHAIN-CASE-01","time_start":"2026-10-27T14:00:00Z","time_end":"2026-10-27T15:00:00Z","limit":200}' \
  | jq '.meta.data_source, .meta.time_base, .meta.total'

# 2) 只读调查入口不应有处置工具
curl -s -X POST https://seclog.91666.icu:18443/investigation/ \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2024-11-05' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | grep -o '"name":"[a-z_]*"'

# 3) 配置来源
curl -sk -X POST https://seclog.91666.icu:18443/tools/get_context \
  -H 'Content-Type: application/json' \
  -d '{"user":"ops_zhang","asset_id":"web-prod-01","at_time":"2026-10-29T18:10:00Z"}' \
  | jq '.meta.dataset, .asset_context.in_maintenance_window'
```

以实测为准：CASE-01 的条数取决于 NAS 实库入库结果，**不把 29 条写成固定通过条件**。

---


# ClickHouse 错误脱敏修复（2026-11-08）

- `src/api/datasource.py`：在 ClickHouse 连接和查询错误生成边界脱敏驱动异常及 details.dsn，对外地址移除用户名和密码；保留 backend_unavailable 及 import/connect/query 失败阶段、主机、端口。健康诊断返回的 DSN 也使用无凭据地址，真实驱动仍收到原始连接参数。
- `src/ai_engine/redaction.py`：共享文案脱敏增加 URL userinfo 移除，保留已有 password/passwd/pwd 键值处理。
- `tests/test_independent_acceptance.py`：新增连接失败和查询失败两个 run_one 层用例，均注入合成 DSN 与假驱动，不连接网络。完整 result/trace 不含合成用户名、DSN 密码或键值密码残片，仍保留错误码、阶段和安全诊断信息。

修复前独立用例集 **2 failed / 49 passed**；修复后全量命令 `.venv\Scripts\python.exe -B -m pytest tests/ -q -p no:cacheprovider --tb=short` 实测 **246 passed in 4.86s**，独立验收共 51 项。`git diff --check` 通过。

三组 V1 仅通过 run_one() 内存复跑：结论、证据、授权依据、结论依据、自检、评测和工具状态与当前归档一致。仅保留此前已记录的 CASE-01 items[25].payload_summary 脱敏显示差异，本轮无新增差异。原始日志、truth、当前与历史归档在复跑前后哈希一致。

本地回放和模拟 ClickHouse 失败路径已验证；真实 ClickHouse、真实混合检索及恒脑平台未验证。本轮未安装依赖、连接真实后端、操作平台/隧道或提交、推送、创建 PR。

---

# 第四次独立复验修复（2026-11-08，当前状态）

- `src/ai_engine/investigation.py::_c2_signal`：以完整 URL 主机、括号 IP 或裸 IP 为提取单位，经 ipaddress 解析后精确比较。IPv6 的点分十进制尾部不再作为独立 IPv4；IPv4、IPv6 及带端口 URL 正例保留，同主机/时间/路径/成功响应/连接状态检查不变。
- 新增 `src/ai_engine/redaction.py::redact_text`，调查结果中的后端错误与 Trace error.message 共用同一密码脱敏逻辑；在截断、序列化之前处理。已有 error.details 和载荷脱敏继续使用该逻辑。
- 在 run_one 层注入带占位密码的检索 503，完整 result 与 trace 均不含原文或残片，同时保留失败状态、backend_unavailable 和 next=keep。

新增 5 项参数化回归；修复前独立用例集 **3 failed / 46 passed**（IPv6 尾部误匹配、同一混合 IPv6 不能正确匹配、结果错误文案泄漏）；修复后全量 **244 passed in 4.41s**，独立用例共 49 项。命令：`.venv\Scripts\python.exe -B -m pytest tests/ -q -p no:cacheprovider --tb=short`。`git diff --check` 通过。

三组 V1 仅调用 run_one() 内存复跑：分类、风险、证据、授权依据、结论依据、自检、评测和工具状态与当前归档一致。工具响应仅存在上一轮已记录的 CASE-01 items[25].payload_summary 脱敏显示差异，本轮没有新增轨迹差异。复跑前后原始日志、truth、当前与历史归档哈希一致，未写入归档。

本地回放已验证，真实混合检索和恒脑平台仍未验证。本轮未安装依赖、连接真实后端、执行处置、操作平台/隧道或 commit/push/创建 PR。

---

# 第三次独立复验修复（2026-11-08，当前状态）

本轮只修改 `src/ai_engine/investigation.py`、`tests/run_v1_traces.py`、`tests/test_independent_acceptance.py` 及本报告，保留此前未提交成果。

- C2 关联：从载荷提取完整地址并经 ipaddress 解析后比较，198.51.100.80 不再匹配 198.51.100.8；同地址正例仍通过。原有主机、前置时间、真实路径、成功响应及当前连接状态条件保留。
- 异常请求目标：只捕获单条候选 urlsplit 的 ValueError；不使用该候选确认 C2，日志编号和解析失败原因进入待查项，其他有效证据继续处理，返回合法 11 字段结果。
- Trace 脱敏：password/passwd/pwd 的 JSON 字符串、单双引号键值、普通 key=value 全值遮盖，保留引号、分隔符和相邻字段。结构化敏感字段继续脱敏，测试只使用占位值。

验证：新增 16 项参数化用例。修复前独立用例集 12 failed / 32 passed；修复后 44 passed in 0.48s。全量命令 `.venv\Scripts\python.exe -B -m pytest tests/ -q -p no:cacheprovider --tb=short` 实测 **239 passed in 4.26s**；`git diff --check` 通过（仅既有换行提示）。

仅调用 run_one() 内存复跑三组场景，分类、风险、证据、授权依据、结论依据、自检、评测与工具状态均与当前归档一致。工具步骤仅 CASE-01 的 `trace.steps[0].response.items[25].payload_summary` 因新脱敏匹配而显示不同，其余步骤完全相同。未执行产物写入入口，当前和历史文件哈希在复跑前后保持一致；没有为这处显示差异覆盖已有归档。原始日志和 truth 未修改。

本地回放已验证；真实混合检索仍受依赖/模型/服务阻塞，恒脑平台未验证。本轮未安装依赖、连接真实后端、执行处置、操作平台/隧道或 commit/push/创建 PR。

---

# 第二次独立复验修复（2026-11-08，当前状态）

本节覆盖最新复验列出的四项缺陷及三项归档问题；下文保留历史记录。

- 场景识别统一采用大小写无关的 CHAIN- 前缀，后端对具体 trace_id 仍精确匹配。Mock、回放、ClickHouse 的 case_id 场景过滤保持一致；未知小写场景不再转为全库查询。
- 服务账号授权识别清洗后的 auth_log/login_success/sshd 与 session_opened，回归直接调用 normalize_logs.py 的 parse_auth_line，而非手造 ssh_login 动作。
- C2 前置关联要求实际 Webshell 请求路径、成功响应、先于连接的时间，以及载荷中指向同一外部目标的线索。查询参数里的文件名或 404 请求不构成前置行为。该规则仍为启发式，只支持有关联依据的可疑回连，不证明数据外传。
- 回放排序、分类首次时间和 C2 关联均比较解析后的 UTC 时间，不再用字符串比较毫秒时间戳。
- V1 场景发现复用回放加载器，支持只有 JSONL 的目录。
- Trace 按字段和载荷键值脱敏 password/passwd/pwd；当前及历史轨迹均检查通过。历史轨迹仅脱敏，没有重跑或改结论，记录见 data/agent_traces/legacy/REDACTION.md。原始数据包未改。
- unknown_items 区分检索未调用、调用失败和成功零命中，保留实际失败原因。

验证：全量 223 passed in 4.25s；独立验收反例文件在强化 404 时间条件后 28 passed in 0.43s。git diff --check 通过。三个场景重新运行并通过契约校验，分类/风险/证据数保持上一版本：CASE-01 16 条、召回 0.833；CASE-02 6 条、召回 0.667；CASE-03 4 条、召回 0.4。运行状态文案与 Trace 已更新。

修复前快照：data/agent_traces/legacy/v1-before-second-audit-20261108T174856/（已做密码脱敏）。当前产物：data/agent_traces/v1/。

未 commit、push、创建 PR 或操作平台/隧道。真实混合检索、ClickHouse 实例与恒脑平台仍未验证，本地修复不代表整体 Issue 通过终验。

---

# 独立验收报告修复记录（2026-11-08，本节为当前状态）

下方旧验收记录保留为历史，不代表当前测试数、规则或输出。

## 修复与验证

- **P1 串案**：精确 trace_id 零命中后不再丢弃场景条件查询全库；未知 CHAIN- 场景 case_id 返回空，不回退全部场景。
- **P1 证据登记**：先构造并校验整批 LogItem 和响应，再登记可返回记录；无效行返回 503，不留下证据。登记和检查两端均独立拒绝空白 ID。
- **P1 授权**：缺来源/实际资产、资产与当前上下文不匹配、服务账号交互式 SSH 均保留不确定性。混合资产暂不自动批准，需取得对应上下文；无账号但有资产时仍调用资产查询。
- **P1 普通流量误判**：普通 cmd=sort 不再算恶意上传；批量失败统计限于 auth_log。C2 要求当前成功状态 conn_state=SF、同主机之前明确 Webshell 路径、外部目标及回连行为；端口、备份/健康心跳、停用描述、历史状态均不能单独证明 C2。该规则仍是本地启发式，不等于已验证生产检测能力。目标未知时不给封禁建议，交人工复核。
- **P2 时序**：按行为日志首次出现时间组织分类，不按固定目录顺序。时间并列的情况不宣称先后，仅输出主分类，其余类别保留在 conclusion_basis 并提示时序不确定。CASE-02 已改为上传之后遍历。
- **P2 分类语义**：拒绝空分段、尾随 _After_、none/insufficient_evidence 参与组合。历史兼容类别仍保留既有兼容范围，未更改团队枚举契约。
- **P2 数据格式和精度**：回放支持 JSON 数组与 JSONL；保留时间戳小数精度，毫秒超界日志不进入窗口。
- **P2 状态与轨迹**：工具错误写为调用失败而非零命中；恶意结论同时保留未解释的线索；Trace 不再只留前十条日志，保留完整响应列表及原有字段脱敏策略。

新增 `tests/test_independent_acceptance.py`，18 个反例/正例检查。执行：

```text
.venv\Scripts\python.exe -B -m pytest tests/ -q -p no:cacheprovider --tb=short
213 passed in 4.27s
.venv\Scripts\python.exe -B tests/run_v1_traces.py
三个场景通过契约校验
 git diff --check
通过
```

旧测试不再将只有端口、心跳或无时间顺序的样例当作已确认 C2 链；新增关联 Webshell 和精确连接状态的正例验证。

## 当前产物

修复前快照：`data/agent_traces/legacy/v1-before-independent-audit-20261108T144729/`。
当前结果与完整轨迹：`data/agent_traces/v1/`。

| 场景 | 分类 | 风险 | 证据数 | 召回 |
| --- | --- | --- | ---: | ---: |
| CHAIN-CASE-01 | SQL_Injection_After_Brute_Force_After_Scan | HIGH | 16 | 0.833 |
| CHAIN-CASE-02 | Path_Traversal_Privilege_After_Malicious_Upload | HIGH | 6 | 0.667 |
| CHAIN-CASE-03 | none | LOW | 4 | 0.4 |

CASE-02 当前增加实际资产查询，仍有未能确认的外连线索。未修改 truth。真实混合检索仍受本地依赖/模型/服务阻塞；本轮未操作恒脑平台和固定隧道。修复回归通过不代表 Issue #18 已完成真实集成或通过独立终验。

未 commit、push、创建 PR 或修改 GitHub Issue。

---

# 最新验收：认证失败与 C2 判据修复（2026-11-08）

本节为当前状态；下方此前修复记录中的测试数、场景结果和风险规则属于历史版本。

- 复现阶段：新增三项回归测试均失败，确认单次输错密码、分散来源失败、端口加标签被误判。
- 修复后：`python -B -m pytest tests/ -q -p no:cacheprovider`，195 passed in 4.93s。
- 普通单次认证失败及失败后成功不再直接判爆破。暂定本地关联规则为同来源、同目标、同账号五分钟内至少五条不同编号的失败日志；这不是团队冻结阈值。明确攻击工具线索另行保留。
- C2 不再依据人工标签或端口；明确 beacon/c2_callback 行为描述作为可疑回连依据，只有同时记录 conn_state=SF 才陈述连接建立。端口、Minecraft/tunnel 等泛化字符串不构成确认依据。
- 流量达到 1MB 不证明数据外传，当前控制器不据此产出 CRITICAL。真实外传确认尚无实现，保留为能力边界。
- 两个旧测试调整了事实依据：链路正例补明确 beacon 与 SF；大流量回连用例验证 HIGH 而非确认外传。这是修正原测试把端口/字节量等同于确认外传的错误预期。
- 修复前完整产物：`data/agent_traces/legacy/v1-before-auth-c2-fix-20261108T135634/`。
- 当前产物：`data/agent_traces/v1/`，三场景严格契约校验通过。

| 场景 | 分类 | 风险 | 证据数 | 召回 |
| --- | --- | --- | ---: | ---: |
| CHAIN-CASE-01 | SQL_Injection_After_Brute_Force_After_Scan | HIGH | 16 | 0.833 |
| CHAIN-CASE-02 | Malicious_Upload_After_Path_Traversal_Privilege | HIGH | 6 | 0.667 |
| CHAIN-CASE-03 | none | LOW | 4 | 0.4 |

CASE-02 移除了缺少当前行为依据的 C2 分类，不能解读为已经排除回连；未解释日志仍保留待查。未改 truth 或评测映射以维持旧成绩。

本地回放已验证；恒脑平台未联调；真实混合检索仍未验证。本轮没有安装后端依赖、操作平台或隧道，也没有 commit、push 或创建 PR。

---

# Week 2 验收报告 · 工具层接入真实日志与混合检索（修复版）

> Issue：`lizhikeer/hengnao-autonomous-agent#18`
> 负责人：`@chensz-u`
> 分支：`feature/w2-tool-integration`（基于 `origin/main` @ `6a44c10`）
> 本轮**未 commit、未 push、未建 PR、未修改 Issue**

---

## 0. 三类结果必须分开看

| 维度 | 状态 | 证据 |
| :--- | :--- | :--- |
| **① 本地规则控制器（离线回放）** | **已跑通** | `data/agent_traces/v1/`，3 个场景，**246 项测试通过**；已对齐 PR #23 的 `config/` 单一配置源（§1.12.1） |
| **② 真实 ClickHouse 后端** | **未接通** | 中转 `seclog.91666.icu:18443` 实测仍返回 `data_source: mock`（旧镜像），`8123`/`9000` 不对外开放（§1.12.3） |
| **③ 恒脑平台联调** | **未运行** | 中转数据源是 mock，平台侧无法跑出真实 V1；待②部署后执行 |
| **④ 真实混合检索集成** | **未验证** | 本地缺 3 个依赖 + BGE 权重 + Qdrant + 建库（§1.12.5） |

**检索适配层已有确定性测试（注入假 `hybrid_search`），那只证明接线正确，不等于真实检索可用。**

---

## 1. 本轮修复的六个问题

### 1.1 回放时间窗与 `reference_time` 不一致 —— **已修复**

**问题**：旧实现先按字段过滤，再用过滤结果的最新时间算窗口，而 `reference_time` 报的是整个场景的最新时间。
实测 `CHAIN-CASE-01 + log_source=auth_log + time_window=1m` 返回了比声明窗口早 10 分钟的日志。

**根因**：`_apply_window` 作用在"过滤后的子集"上，基准与响应字段取自"完整场景"，两者不是同一个锚点。

**修法**（`src/api/datasource.py`）：顺序改为 **完整场景定基准 → 套时间窗 → 字段过滤**；
多场景查询时 `reference_time` 置 `null`，改由新增的 `meta.scenario_time_bases[]`
逐场景给出 `reference_time / window_start / window_end / matched`。

**验证**：

| 用例 | 修复前 | 修复后 |
| :--- | :--- | :--- |
| auth_log + 1m | 返回 14:06/14:07 两条（窗口外） | **0 条**（该来源最后活动在 10 分钟前） |
| auth_log + 1h | 时间越界 | 5 条，全部落在 `[window_start, window_end]` |
| 跨场景 `dest_ip=10.0.0.15` | 单一 `reference_time` 概括三个场景 | `reference_time=null` + 3 条独立基准 |

新增测试：`test_window_anchored_on_scenario_not_filtered_subset`、
`test_window_result_within_reported_bounds`、`test_window_boundary_inclusive_on_exact_edge`（临时数据集精确测边界）、
`test_multi_scenario_reports_per_scenario_bases`。

### 1.2 正常运维判定没有真正使用上下文 —— **已修复**

**问题**：`get_context` 被调用，但维护窗口/账号/白名单不参与最终判定，调用时也没传 `at_time`；
把上下文整个改成不可用，CHAIN-CASE-03 仍输出 `none`。

**修法**（`src/ai_engine/investigation.py`）：

1. `get_context` 增加 `at_time`（取最后一次可疑行为的日志时间）；
2. 新增 `_authorization()`：核对**账号已登记 / 账号类型可执行该操作 / 来源 IP 符合基线 / 目标资产在授权范围 / 时间在维护窗口内**；
3. 只有在**全部核对通过且无未解释行为**时才判 `none`；否则走 `insufficient_evidence` 并写明缺哪一项；
4. 上下文不可用、`at_time` 缺失导致窗口无法判断 → 一律保留不确定性，不判正常；
5. `attack_stage_hint` 定位为**线索**：缺失归为 `unknown`（不再默认 benign）；
   攻击成立还需要行为痕迹佐证（外部攻击源或载荷特征），单凭 `exploitation` 标签不确认攻击。

**验证**（`tests/test_w2_context_usage.py`，10 例）：

| 情形 | 结果 |
| :--- | :--- |
| 账号/来源/资产/窗口全匹配 | `none` / LOW，结论写明依据 |
| 窗口外 | `insufficient_evidence`，`unknown_items` 指出维护窗口 |
| 来源 IP 不在账号基线 | `insufficient_evidence`，指出来源 IP |
| 账号未登记 | `insufficient_evidence`，指出账号名 |
| 上下文整体不可用 | `insufficient_evidence`，指出"上下文不可用" |
| `in_maintenance_window=null`（无 at_time） | `insufficient_evidence`，不默认在窗口内 |
| 去掉全部 `attack_stage_hint` | `insufficient_evidence`（未知不当作正常） |
| 只有 `exploitation` 标签、无行为痕迹 | 不确认攻击（`is_malicious=false`） |
| 标签 + 外部源 + 注入特征 | 确认攻击，分类含 `SQL_Injection` |

### 1.3 七类实际只有六类 —— **已修复**

**问题**：上一版把「恶意上传」与「遍历越权」合并为 `File_Upload_Traversal`，把 XSS 与 RCE 合并为 `XSS_RCE`，
而测试名写着"七类"却断言 6 个值。

**修法**（`src/ai_engine/attack_types.py`）：拆成七个独立取值
`Scan / Brute_Force / SQL_Injection / XSS / Path_Traversal_Privilege / Malicious_Upload / C2_Exfiltration`；
**结果分类与知识卡分类分离**：知识卡仍只有 5 类，通过 `knowledge_category` 做多对一映射
（`XSS→XSS_RCE`，`Path_Traversal_Privilege`/`Malicious_Upload→File_Upload_Traversal`），
映射不反过来合并结果类。`verify.py` 内联枚举同步更新，并把旧合并码放进 `COMPAT_SEGMENTS` 仅作兼容。

**验证**（`tests/test_w2_classification.py`，20 例）：七类逐一可区分、结果→知识卡映射正确（含多对一）、
组合类型合法、非法类型被拒、旧码可归一化但不属于七类清单。

### 1.4 运行轨迹不可核验 —— **已修复**

**问题**：轨迹只记录数量与 `log_id`，检索失败步骤只有 `returned_total=null`，看不出失败原因。

**修法**（`tests/run_v1_traces.py`）：

* 每步记录 `tool / args / why / data_source`，并按 `ok / empty / error` 归类；
* 失败保留 `error.code / error.message / error.details`；成功与零命中保留脱敏后的 `response`（长文本截断、列表标注真实长度）；
* `run` 段新增 `run_id`、`env.data_source_mode`、`env.search_mode`、`code_version`（commit / branch / **dirty_worktree**）、`step_status_counts`；
* 结果 JSON 仍是严格 11 字段，元数据全在 `.trace.json`；
* 改版前产物已快照到 `data/agent_traces/legacy/v1-before-context-and-seven-class/` 作为旧基线；
* SUMMARY 由实际运行信息生成（不再硬编码"回放成功/检索不可用"）。

实际结果：CASE-01 工具状态 `ok:2、error:1`；CASE-02 `ok:1、error:1`；CASE-03 `ok:2`。
`code_version` 如实标注 `6a44c10` + **工作区有未提交改动**。

### 1.5 检索适配缺少有效验证 —— **已补适配测试，真实集成仍未验证**

**问题**：原测试"成功或抛不可用都算通过"，只证明错误处理。

**修法**（`tests/test_w2_knowledge_adapter.py`，9 例）：注入假 `hybrid_search`，确定性验证
参数按真实签名传递（`query` / 关键字 `top_k` / `filters`，且 `attack_category` 并入 filters）、
只透传白名单过滤键、字段映射与多余字段裁剪、未知 `card_type` 兜底、
**零命中算成功**、后端异常包装为 `KnowledgeUnavailable(stage=search)`、
导入失败与执行失败可区分、API 层返回 503 且不夹带卡片、Mock 模式显式标 `mock=true`。

**真实集成**：另用 `tests/check_knowledge_ready.py` 逐项检查（见 §6），**不具备条件**，未运行真实查询。

### 1.6 验收文档错误 —— **已纠正**

| 原表述 | 实际 |
| :--- | :--- |
| "CHAIN-CASE-03 truth 无证据" | truth **有 5 条**证据（`0301/0302/0313/0314/0315`），本次命中 **2 条，召回 0.4** |
| "attack_type_covers_truth=true"（笼统） | CASE-01 天然覆盖；**CASE-02、CASE-03 依赖评测侧 truth 归一化规则**才为 true |
| 把差异解释为"只是口径差异、不是错判" | 不成立：CASE-02 的 truth 类型 `Webshell_Upload_And_C2_Callback` **不在七类内**，不做映射无法比对；CASE-03 证据召回 0.4 说明证据选择仍不理想 |

同时修正了 CASE-03 的证据选择逻辑：全良性场景改为取**带账号的行为日志**（支撑授权判断），
而不是"最后 5 条"（与判断依据无关）。召回由 0 提升到 0.4，仍未达 1.0，如实保留。

---

### 1.7 独立验收提出的四个反例 —— **已修复**

| 反例 | 修复前实际结果 | 修复后 |
| :--- | :--- | :--- |
| ① 外部 IP + `exploitation` 标签 + `/index.html` 普通访问 | `is_malicious=true` / `Unknown_Attack` / `block_ip` | `insufficient_evidence`，不给处置建议 |
| ② 授权配置全空（`common_src_ips=[]`、`allowed_assets=[]`、窗口空） | `attack_type=none`（把空值当"不限范围"） | `insufficient_evidence`，指出来源/资产依据缺失 |
| ③ 同批日志混入 `intruder`，只返回 ops_zhang 画像 | `attack_type=none`（一个画像批准整批） | `insufficient_evidence`，指出"同一批日志出现多个账号" |
| ④ `benign` 标签 + `UNION SELECT sleep(5)` + `sqlmap` | `attack_type=none`（标签掩盖载荷） | `SQL_Injection` / 恶意 / 需审批 |

**统一改法**（不是逐个 case 加分支）：

1. **判定顺序**：先看行为事实 → 再谈授权 → 标签只作分类线索。
   新增 `_behavior_facts()`：从 URI/载荷/UA 提取攻击特征（`attack`）、成功迹象（`impact`）、
   有标签无特征的"未解释行为"（`unexplained`）。外部 IP 只影响 `attacker_ip` 取值，不参与定性。
2. **授权核对**：画像必须与日志账号**一一对应**（多账号直接失败）；来源/资产配置为空视为
   "未提供依据"而非"不限范围"；维护窗口**逐条日志**判断，只有运维/服务类账号才要求，
   普通业务访问不强行套窗口。
3. **分类**：`_attack_type` 优先用行为事实推出的类别，阶段标签只补 facts 覆盖不到的阶段，
   因此 `benign+注入载荷` 也能给出 `SQL_Injection`。

**回归测试**（`tests/test_w2_context_usage.py` 新增 6 例）：四个反例 + "授权匹配仍正常收束"
+ "窗口外单条不能批准整体"。

### 1.8 轨迹保留判定依据 —— **已修复**

`_redact()` 不再按统一递归深度截断，改为**按用途**：维护窗口（`weekdays/start/end/timezone`）、
`evaluated_at`、`per_log_in_window`、账号授权范围等判定依据字段保留原值，只有长文本按字符截断并标注长度。
trace 新增 `context_decision` 段。新增断言 `test_trace_keeps_decision_evidence_not_ellipsis`。

---

### 1.9 第三轮：弱关键词误判、证据错配、缺窗口配置 —— **已修复**

| 问题 | 修复前实际结果 | 修复后 |
| :--- | :--- | :--- |
| A 普通 `/robots.txt` 访问（benign / 200 / 浏览器 UA） | `Scan` / HIGH / `block_ip` | `none` / LOW / `none` |
| B 普通头像上传（`/upload/avatar`、`filename=avatar.png`） | `Malicious_Upload` / HIGH / `block_ip` | `none` / LOW / `none` |
| C 结论与证据不一致（L1 普通访问 + L2 `UNION SELECT sleep(5)`） | 结论 `SQL_Injection`，证据 `["L1"]` | 结论 `SQL_Injection`，证据 `["L2"]` |
| D 仅缺维护窗口配置（来源/资产都匹配） | `none`（跳过核验） | `insufficient_evidence`，指出缺窗口配置 |

**统一改法**：

1. **特征分级**（`attack_types.STRONG_INDICATORS` / `WEAK_INDICATORS` + `classify_signals()`）：
   `union select`、`sqlmap`、`shell.php`、`cmd=`、`../` 等属强特征；`robots.txt`、`upload`、
   `filename=`、`multipart/form-data`、`.php` 属弱特征——正常业务天天出现，单独不构成攻击。
   **没有为这两条路径硬编码白名单**，是靠"强/弱"这个通用规则。
2. **2xx 不再单独等于影响**：它只表示请求被处理过。现在是"强特征 + 2xx → HIGH"、
   "强特征 + 被拒（4xx）→ MEDIUM"；`C2_Exfiltration` 以外连建立为准。
3. **证据跟着判定走**：`_evidence_ids(facts)` 从行为事实取，不再按 `attack_stage_hint` 挑。
   有攻击 → 取命中强特征的日志；弃权 → 取未解释线索；判正常 → 取带账号的行为日志。
4. **是否需要维护窗口由账号类型决定**（`WINDOW_REQUIRED_ACCOUNT_TYPES = {legit_operator, service}`），
   不再取决于 `maintenance_windows` 是否非空——配置缺失现在是"无法核验"而不是"不需要核验"；
   普通业务账号（`application_admin`）不要求窗口。

**回归测试**（`tests/test_w2_context_usage.py` 新增 7 例）：两个误判反例、2xx 不单独定影响、
真实 webshell 仍被识别、证据指向触发日志、缺窗口配置阻断授权、业务账号不需窗口。

---

### 1.10 第四轮：判定与下游结论不同源 —— **已修复**

| 反例 | 修复前 | 修复后 |
| :--- | :--- | :--- |
| ① L1（benign 标签 + 注入载荷 + 外部源 IP） | `attacker_ip="unknown"`（按标签跳过） | `attacker_ip="198.51.100.23"` |
| ② 追加一条只有 `recon` 标签的普通访问 | 分类凭空变成 `SQL_Injection_After_Scan` | 仍是 `SQL_Injection` |
| ③ 追加一条只有 `c2_callback` 标签的普通访问 | 分类变成 `C2_Exfiltration_After_SQL_Injection`，摘要称"发起可疑外连" | 仍是 `SQL_Injection`，摘要无外连 |
| ④ 注入 200 + 无关日志 `bytes_out=2MB`（仅带 c2 标签） | `CRITICAL`（拼成"确认外传"） | `HIGH`，摘要写明"未确认利用成功" |

**统一改法：分类、攻击源、风险、摘要、证据全部从同一份 `_behavior_facts()` 派生。**

1. `_guess_attacker_ip(facts)`：从**攻击行为日志**定位来源，不再按 `benign` 标签排除；
   没有攻击/未解释日志时返回 `None`（判正常的场景不把访客 IP 当攻击源）。
2. `_attack_type(facts)`：只用事实推出的类别，**删除用 `attack_stage_hint` 补阶段的逻辑**。
3. `_chain_summary(facts, ...)`：逐类计数生成，摘要里每个阶段（扫描/爆破/注入/外连）都有对应日志与次数。
4. 风险：`CRITICAL` 要求**外连日志自身**累计外发 ≥1MB；`HIGH` 为有外连或有响应；其余 `MEDIUM`。
   不再把"另一条日志的字节数"与"这条日志的影响"拼接。
5. 标签带来的、无证据支撑的疑点写入 `unknown_items`（"仅作待查线索，未计入结论"）。

**回归测试**（`tests/test_w2_context_usage.py` 新增 7 例）：攻击源溯源、recon 标签不加 Scan、
c2 标签不加 C2、无关 2MB 不升 CRITICAL、真外连仍升 CRITICAL、摘要阶段可追溯、改标签不改事实结论。

**一处旧测试的语义调整**：`test_full_chain_produces_malicious_conclusion` 原先三段日志只靠阶段标签，
修复后分类要求行为证据，故给爆破段补 `hydra` UA、外连段补 `dest_port=4444`——这是补齐测试数据的
行为特征，不是放宽断言。

---

### 1.11 复核：三项反例已在 1.10 修复；本轮补的是"依据可核验"

本轮收到的反例与 §1.10 相同。**复核结论：代码层已在上一轮修复，本轮未改动判定逻辑。**

复核方式：用同一组构造（`tests/test_w2_context_usage.py` 的 `_log`/`_profile`/`_asset`/`_session`）重跑，
当前实际输出：

| 反例 | 当前结果 | 结论 |
| :--- | :--- | :--- |
| ① L1（benign + 注入 + 外部 IP + 403） | `SQL_Injection` / MEDIUM / **`attacker_ip=198.51.100.23`** / 证据 `["L1"]` | 已修复 |
| ② 追加 `recon` 标签的普通访问 | `SQL_Injection`（无 Scan 段） | 已修复 |
| ③ 追加 `c2_callback` 标签的普通访问 | `SQL_Injection`（无 C2 段，摘要无外连） | 已修复 |
| ④ 注入 200 + 无关 2MB（仅 c2 标签） | `SQL_Injection` / **HIGH**（非 CRITICAL），摘要写"未确认利用成功" | 已修复 |

**本轮真正补上的缺口：轨迹不能核对"依据"。**

审查第五点要求"轨迹应能核对分类、风险和摘要分别依据哪些日志"，此前 trace 只有 `steps`、
`checks`、`context_decision`，缺少结论依据。本轮新增 `conclusion_basis`：

```json
"conclusion_basis": {
  "attack_type": {"value": "...", "segments": [{"code": "Scan", "log_ids": [...]}, ...]},
  "risk_level": {"value": "HIGH", "rule": "强特征请求得到响应（未确认利用成功）", "log_ids": [...]},
  "attacker_ip": {"value": "198.51.100.23", "log_ids": [...]},
  "summary": {"text": "...", "stage_counts": {"Scan": 7, "Brute_Force": 5, "SQL_Injection": 4}}
}
```

实现方式：`build_results()` 计算完分类/风险/摘要后调用 `_record_conclusion_basis()` 写入
`session.findings`，`run_v1_traces.py` 再落到 trace。**结果对象仍是严格 11 字段**，依据全在 trace。

新增测试 `test_trace_records_what_each_conclusion_rests_on`：逐场景断言
① 每段分类的 `log_ids` 非空且属于证据；② 风险有规则名与依据；③ 攻击源确定时必须有来源日志；
④ 摘要文本与结果一致、阶段计数 ≥1。CASE-01 实测：Scan 7 条、Brute_Force 5 条、SQL_Injection 4 条。

---

### 1.12 对齐 PR #23：配置单一来源 + 真实后端现状（2026-11-12）

**背景**：组长合入 PR #23（`config/assets.yaml`、`maintenance-windows.yaml`、`response-policy.yaml`
+ `src/detection/context_builder.py`），并给出新中转 `https://seclog.91666.icu:18443`。

#### 1.12.1 消除两套配置（已完成）

| 问题 | 处理 |
| :--- | :--- |
| 第二周自建 `data/asset_context/asset_context.json` 与 `config/*.yaml` **两套台账各自生效**（连 `backup-01` 的 IP 都不同：我是 10.0.0.20，组长是 10.0.0.40） | 删除自建 JSON，`src/api/asset_context.py` 改为**只读 `config/`**（`SECLOG_CONFIG_DIR` 可覆盖） |
| 字段口径不同（我 `importance`，组长 `criticality`；我 `weekdays`，组长 `days`） | 对外仍给 `importance`（API 契约历史字段），内部映射 `criticality.upper()`；窗口按 `days` 解析并额外返回顶层 `timezone` |
| 处置动作枚举缺 `isolate_account` | `src/api/config.py` 的 `ALLOWED_RESPONSE_ACTIONS` 补齐，并注明"权威来源是 `config/response-policy.yaml` 的 `actions`" |
| 账号画像：配置里没有账号台账，只有白名单 | `get_user_profile` 改为匹配 `allowlist.users`（支持 `ops_*` 通配），命中才返回 `legit_operator`；未命中返回 `None`（不编造画像） |
| 授权核对硬套 `common_src_ips` 导致 CASE-03 被弃权 | 区分两种口径：画像明确给出 `common_src_ips` 才作为硬条件；只有 `allowed_src_ips`（豁免名单）则不作硬条件 |

#### 1.12.2 镜像内缺配置（已修）

`docker/api/Dockerfile` 原来只 `COPY src/`，容器里没有 `config/`，
`get_context` 会因找不到 `assets.yaml` 直接 503。已补：

```dockerfile
COPY config/ /app/config/
COPY data/full_chain_logs/ /app/data/full_chain_logs/
COPY data/knowledge_cards/ /app/data/knowledge_cards/
```

#### 1.12.3 真实后端：**未接通**（阻塞在部署）

**中转现状（实测 2026-11-12 15:40）**：

| 检查 | 结果 |
| :--- | :--- |
| `GET /health` | 200，但响应体 `"mock_mode": true` |
| `POST /tools/query_logs {"trace_id":"CHAIN-CASE-01"}` | `total: 0`、`"data_source":"mock"` |
| `GET /openapi.json` | 描述写着"第一周骨架：查询类工具返回显式 Mock 数据" |

**结论：中转跑的是第一周旧镜像**，不含本分支的 ClickHouse 适配层与配置对齐。

另：`seclog.91666.icu` 只对外开放 18443，`8123`/`9000` 均不可达，本地无 `clickhouse-connect`，
**无法从本机直连 ClickHouse 验证**。

#### 1.12.4 交付给组长的部署清单

| 项 | 值 |
| :--- | :--- |
| 代码 | 本分支 `feature/w2-tool-integration` 工作区（未提交，需先打 tag 或 commit 后构建） |
| 构建 | `docker build -f docker/api/Dockerfile -t seclog-api:w2-config-align .` |
| 必需环境变量 | `SECLOG_DATA_SOURCE=clickhouse`、`CLICKHOUSE_DSN=http://<nas>:8123`（含账号密码）、`SECLOG_CONFIG_DIR=/app/config` |
| 可选 | `SECLOG_SEARCH_MODE=auto`（检索就绪后再开）、`SECLOG_DEBUG_REQ=0`（默认关） |
| 依赖 | `requirements/base.txt` 已含 `clickhouse-connect==0.8.9`、`PyYAML`；镜像构建会自动装 |

复测命令（部署后由我或组长执行）：

```bash
# 1) 数据源必须变成 clickhouse
curl -sk -X POST https://seclog.91666.icu:18443/tools/query_logs   -H 'Content-Type: application/json'   -d '{"trace_id":"CHAIN-CASE-01","limit":3}' | jq '.meta.data_source, .meta.total'
# 期望： "clickhouse" 与 >0

# 2) 配置必须来自 config/
curl -sk -X POST https://seclog.91666.icu:18443/tools/get_context   -H 'Content-Type: application/json'   -d '{"user":"ops_zhang","asset_id":"web-prod-01","at_time":"2026-10-29T18:10:00Z"}'   | jq '.meta.dataset, .asset_context.in_maintenance_window, .user_profile.account_type'
# 期望： "config" / true / "legit_operator"

# 3) 已知条件核对（476 行里 CHAIN-CASE-01 应为 29 条）
curl -sk -X POST https://seclog.91666.icu:18443/tools/query_logs   -H 'Content-Type: application/json'   -d '{"trace_id":"CHAIN-CASE-01","log_source":"auth_log","time_window":"24h","limit":200}'   | jq '.meta.total, [.items[].log_id] | .[0:3]'
```

#### 1.12.5 混合检索：**仍未验证**

本地逐项检查（`tests/check_knowledge_ready.py`）：缺 `sentence-transformers`、`qdrant-client`、
`numpy`、BGE 权重、Qdrant 服务、SQLite 知识库；知识卡源文件 6 个齐备。
组长上次报告"BGE 权重未挂载、Qdrant 未建库"，本轮未能复核 NAS 侧状态（无直连）。

解除条件与复测：依赖装好后 `SECLOG_SEARCH_MODE=auto`，
`POST /tools/search_knowledge {"query":"SQL 注入如何处置"}` 应返回 `meta.data_source=hybrid_search`
且 `items[].card_id` 非空。

#### 1.12.6 V1 回放结果（本地，新配置）

| 场景 | 结论 | 风险 | 证据 | 召回 | 与上轮差异 |
| :--- | :--- | :--- | --: | --: | :--- |
| CHAIN-CASE-01 | `SQL_Injection_After_Brute_Force_After_Scan` | HIGH | 16 | 0.833 | 不变 |
| CHAIN-CASE-02 | `Path_Traversal_Privilege_After_Malicious_Upload` | HIGH | 6 | 0.667 | **丢 `C2_Exfiltration`**：`_c2_signal` 已改为"仅凭端口不能证明 C2"，需 payload 含 beacon 等明确回连描述；该场景 4 条 c2 日志只有 `conn_state=SF`，故不计入。这是既有严格化设计，未为对齐 truth 放宽 |
| CHAIN-CASE-03 | `none` | LOW | 4 | 0.4 | 恢复正常判定（配置对齐后授权核对通过） |

CASE-03 授权依据（trace `context_decision`）：账号 `ops_zhang` 命中 `ops_*` 白名单、
资产 `web-prod-01` 已在台账、3 条账号行为全部落在 `02:00–03:30` 窗口内（`per_log_in_window` 逐条为 true）。

> `never_exempt` 的语义由调查层保证：攻击事实优先于授权判断，窗口内的注入/上传照常告警。

---

## 2. 改动文件

| 文件 | 改动 |
| :--- | :--- |
| `src/api/datasource.py` | 时间窗顺序修正、`scenario_time_bases`、删除废弃的 `_apply_window`、`dataset` 用相对路径 |
| `src/api/schemas.py` | `QueryMeta.scenario_time_bases` 新字段 |
| `src/api/app.py` | 透传 `scenario_time_bases`；`get_context` 用相对路径标注 |
| `src/ai_engine/investigation.py` | `_authorization` / `_corroborate_attack` / `_focus_time` / `_build_non_attack`；阶段缺失归 unknown；证据选择改为账号行为日志；`get_context` 传 `at_time` |
| `src/ai_engine/attack_types.py` | 七类拆分、`COMPAT_SEGMENTS`、别名与新映射 |
| `src/ai_engine/verify.py` | 七类枚举同步 |
| `tests/run_v1_traces.py` | 轨迹增强、代码版本、truth 归一化规则、旧基线快照、SUMMARY 由实跑生成 |
| `tests/test_w2_context_usage.py` | 新增（10 例） |
| `tests/test_w2_knowledge_adapter.py` | 新增（9 例） |
| `tests/check_knowledge_ready.py` | 新增（依赖逐项检查） |
| `tests/test_w2_real_data.py` | 追加 4 例时间窗测试 |
| `tests/test_w2_classification.py` | 断言更新为七类 + 追加 5 例 |
| `tests/test_investigation.py` | 假上下文补齐授权字段（原假数据无 `account_type`/`common_src_ips`） |
| `design/hengnao_workflows/attack_classification.md` | 七类 + 映射表 + truth 差异 |
| `data/agent_traces/v1/README.md` | 轨迹字段说明（含 status/error/code_version） |

---

## 3. 测试命令与结果

```bash
./.venv/Scripts/python -m pytest tests/ -q
```
→ **246 passed in 6.21s**（含 PR #23 带来的评测/检测用例；本轮 246 全绿）

```bash
./.venv/Scripts/python tests/run_v1_traces.py
```
→ 3 个场景全部通过契约校验，产物写入 `data/agent_traces/v1/`

```bash
./.venv/Scripts/python tests/check_knowledge_ready.py
```
→ 退出码 3，逐项列出缺失组件（见 §6）

---

## 4. V1 新产物（`data/agent_traces/v1/`）

产物位置：
- `data/agent_traces/v1/` —— 本轮（第三轮修复后）结果
- `data/agent_traces/legacy/v1-before-conclusion-basis/` —— 本轮修复前归档（14:25 前后，判定同上，仅缺结论依据字段）
- `data/agent_traces/legacy/v1-before-source-consistency/` —— 第四轮修复前归档（2026-11-08 14:45 前后）
- `data/agent_traces/legacy/v1-before-weak-signal-fix/` —— 第三轮修复前归档（14:00 前后）
- `data/agent_traces/legacy/v1-before-context-and-seven-class/` —— 更早基线（6 类口径）


| 场景 | 结论 | 风险 | 证据 | 轮次 | 契约 | 恶意一致 | 风险一致 | 覆盖 truth 分类 | 证据召回 | 工具状态 |
| :--- | :--- | :--- | --: | --: | :-- | :-- | :-- | :-- | --: | :-- |
| CHAIN-CASE-01 | `SQL_Injection_After_Brute_Force_After_Scan` | HIGH | 16 | 3 | 通过 | True | True | True（天然） | **0.833** | ok:2、error:1 |
| CHAIN-CASE-02 | `C2_Exfiltration_After_Malicious_Upload_After_Path_Traversal_Privilege` | HIGH | 10 | 2 | 通过 | True | True | True（**依赖归一化规则**） | 1.0 | ok:1、error:1 |
| CHAIN-CASE-03 | `none` | LOW | 4 | 2 | 通过 | True | True | True（**依赖归一化规则**） | **0.4** | ok:2 |

**必须说明的三点**：

1. `attack_type_exact_match`：CASE-01/02 为 **false**（我方保留侦察段 / truth 未用七类写法），
   **CASE-03 为 true**（归一化后双方都是 `none`）。因此主指标用 `attack_type_covers_truth`；
2. CASE-02 / CASE-03 的覆盖成立**依赖 `_TRUTH_RULES` 里的显式映射**
   （`Webshell_Upload_And_C2_Callback → C2_Exfiltration_After_Malicious_Upload`、
   `Normal_Maintenance_Operation → none`），映射名已写入 trace 的 `truth_normalization_rule`；
3. CASE-03 证据召回 0.4（2/5）：truth 取的是运维关键节点（首次登录、导出、SSH），
   我方取全部带账号的行为日志，交集只有登录两条。**这是真实差距，未做修饰。**
4. **本轮指标变化（相对修复前基线）**，均为判定收紧后的真实结果，没有为了维持旧数字改规则：

| 场景 | 证据数 | 召回 | 变化原因 |
| :--- | :--- | :--- | :--- |
| CASE-01 | 23 → **11** | 1.0 → **0.667** | 侦察阶段日志（`robots.txt`、`/.git/config`）现在属**弱特征**，只作线索不进证据；truth 的 6 条里有 2 条正是这类，故召回下降 |
| CASE-02 | 13 → **10** | 1.0 | 分类增加 `Path_Traversal_Privilege`：`cmd=cat+/etc/passwd` 同时具备命令执行与敏感文件读取特征，两个强特征都成立 |
| CASE-03 | 4 | 0.4 | 无变化 |

> 精度与召回的取舍在这里是显性的：把"普通访问当证据"会虚高召回，收紧后召回下降但证据更能支撑结论。

5. **第四轮（判定同源）带来的变化**：

| 场景 | 变化 | 原因 |
| :--- | :--- | :--- |
| CASE-01 | 证据 11 → **16**，召回 0.667 → **0.833** | 补入爆破日志（`reason=invalid_password` 是明确行为特征）；攻击源由 `unknown` 变为 `198.51.100.23` |
| CASE-02 | 分类去掉尾部 `_After_Scan` | 侦察阶段只有标签、无扫描行为特征，不再补阶段；`covers_truth` 仍为 true |
| CASE-03 | `attacker_ip` 由 `203.0.113.90` 变为 `unknown` | 正常场景无攻击日志，不应把访客 IP 当攻击源 |

---

## 5. Issue #18 验收条件状态

| 状态 | 项目 |
| :--- | :--- |
| **已通过** | 回放后端接线、6 个查询条件、case_id 与场景关系、案例隔离、`meta.data_source` 准确、Mock 开关与不静默降级、时间基准可复现且与窗口一致、七类拆分与映射、上下文参与判定、`attack_stage_hint` 只作线索、REST/MCP 一致、11 字段契约、第一周安全约束未回退、V1 三场景实跑、轨迹可核验、truth 只用于评测、产物可按 case_id 配对、检索适配确定性测试 |
| **失败** | 无（本轮未出现测试或产物校验失败；CASE-03 证据召回 0.4 属质量不足，不算失败项） |
| **未运行** | 恒脑平台联调（固定隧道未提供）；累计 10 组场景（现有 3 组） |
| **外部阻塞** | 真实混合检索集成（缺 4 项依赖 + 模型 + 服务 + 建库，§6）；ClickHouse 真实库（本轮不在范围内，Issue 允许回放交付）；与 #19/#21 归档算分格式对齐 |

> 不写"第二周完成"：检索集成未验证、平台未联调、场景数只有 3 组。

---

## 6. 检索依赖逐项检查结果

`tests/check_knowledge_ready.py` 实际输出：

```
[MISS ] import sentence_transformers     ModuleNotFoundError
[MISS ] import qdrant_client             ModuleNotFoundError
[MISS ] import numpy                     ModuleNotFoundError
[MISS ] import src.knowledge.search      ModuleNotFoundError: No module named 'qdrant_client'
[OK   ] KnowledgeConfig                  model=BAAI/bge-small-zh-v1.5 qdrant_url=http://localhost:6333
[MISS ] BGE 模型文件                      未找到：BGE_MODEL_PATH 未设，HF 缓存无 bge-*
[MISS ] Qdrant 存储                       http://localhost:6333 不可达
[MISS ] SQLite 知识库                     work/knowledge.sqlite3 未建库
[OK   ] 知识卡源文件                       6 个（5 张卡 + manifest）
```

**这是逐项检查结果，不是从一条导入错误推断的。** 缺项分三类：
① Python 依赖 3 个；② 模型与 Qdrant 服务；③ 知识库建库（有源文件，只差入库脚本运行）。
解除后 `SECLOG_SEARCH_MODE=auto` 即走真实检索，代码无需改。

---

## 7. 剩余阻塞与需要队友提供

| 编号 | 阻塞项 | 缺什么 | 责任方 |
| :-- | :--- | :--- | :--- |
| B1 | 检索集成 | 3 个 Python 依赖 + BGE 模型 + Qdrant 服务 + 建 SQLite 库 | @Snowed-night / @lizhikeer |
| B2 | 平台联调 | natfrp 固定域名 | @lizhikeer |
| B3 | 归档算分格式 | Issue #21 的字段与命名约定 | @zyh060911 |
| B4 | 场景数量 | 目标累计 10 组，现有 3 组 | @ribbonfish-jun（#19） |
| B5 | truth 口径 | 2/3 份 truth 的 `attack_type` 不在七类内 | @ribbonfish-jun / @Snowed-night |
| B6 | 资产配置来源 | 无 CMDB 导出，现用自建 `data/asset_context/` | @lizhikeer |
| B7 | ClickHouse | 依赖 + 实例 + 表数据（Issue 允许用回放交付，本轮未扩范围） | @lizhikeer |

---

## 8. 边界声明

* 未 commit / push / 建 PR / 改 Issue；未操作恒脑平台；未执行真实封禁、隔离或外发；
* `docs/superpowers/` 未改动；
* 本地规则控制器结果、恒脑平台结果、真实检索验证三者已分开描述，未互相替代；
* 单元测试通过不等于真实检索联调通过；离线回放通过不等于平台已通过。
