## Issue #18 进度更新（2026-11-12 深夜）

**分支**：`feature/w2-tool-integration` → **目标分支 `main`**（关联 #18）
**审批人**：`lizhikeer`
**基线**：工作区处于 `MERGE_HEAD`（`ba15614`，PR #23 已合入但未提交）
**测试**：`pytest tests/ -q` → **265 passed**；`git diff --cached --check origin/main` 通过
**PR 规模**：40 files changed, 9060 insertions(+), 191 deletions(-)

### 本轮修复：Docker 运行时依赖装不上 MCP

`docker/api/Dockerfile` 只装 `requirements/base.txt` + `requirements/api.txt`，
两份都没有 `mcp`，而容器入口 `src.api.service:app` 要 `from mcp.server.fastmcp import FastMCP`
——镜像起来就 ImportError。根 `requirements.txt` 与 `requirements/` 还各锁了一套，版本互相打架。

| 包 | 旧锁定 | mcp 1.30.0 需要 | 现在 |
| :--- | :--- | :--- | :--- |
| `mcp` | 未列 | — | **1.30.0** |
| `pydantic` | 2.8.2 | `>=2.11.0` | **2.14.1** |
| `httpx` | 0.27.0 | `>=0.27.1` | **0.28.1** |
| `uvicorn` | 0.30.1 | `>=0.31.1` | **0.54.0** |
| `fastapi` | 0.111.0 | starlette `>=0.27` | **0.162.0** |

根 `requirements.txt` 改为指向 `requirements/runtime.txt`，只留一条安装路径。
`clickhouse-connect==0.8.9`、`PyYAML`、`src.api.service:app`、`COPY config/` 均保留。

### 干净环境验证（Docker 未实测）

Docker daemon 不可用（`dockerDesktopLinuxEngine` 管道连不上），改用 uv 拉 **CPython 3.11.15**
建隔离环境，按 `requirements/runtime.txt` 从零安装：

```bash
uv venv --python 3.11 "$TEMP/w2verify311"
uv pip install -r requirements/runtime.txt --python "$TEMP/w2verify311/Scripts/python.exe"
```

结果：**依赖解析无冲突、一次装完**。启动后：

| 检查 | 结果 |
| :--- | :--- |
| `/health` | 200 |
| `/tools/query_logs`（`CHAIN-CASE-01` + 10-27 绝对窗口） | 29 条，`data_source=dataset_replay` |
| `/mcp/` tools/list | 5 个（含 `request_response`） |
| `/investigation/` tools/list | 4 个，无 `request_response` |

> **镜像本身没有实测**（daemon 未运行）。Docker 可用后用：
> `docker build -f docker/api/Dockerfile -t seclog-api:w2 .` → `docker run --rm -p 8000:8000 -e SECLOG_DATA_SOURCE=dataset_replay seclog-api:w2`

### 暂存范围

已暂存 40 个文件：运行时依赖 3 份、Dockerfile、`src/api/*`、`src/ai_engine/*`、`src/mcp_server/*`、
`tests/*`（含独立验收用例与 `run_v1_traces.py`）、`design/hengnao_workflows/*.md`、
`data/agent_traces/v1/` 的 3 份结果 + 3 份 trace + README/SUMMARY。

**没有暂存**：`data/agent_traces/legacy/`（历史归档）、`docs/superpowers/`（无关临时文档）、
无 `.env` / 凭据 / 日志。

---

## 本地续作进度（2026-11-16）

基于最新 `origin/main`（`e581305`）新建分支 `feature/w2-account-scope-v1-traces`。本轮将 `response-policy.yaml` 中 `ops_*` / `ops` 的来源与资产范围接入账号画像；CIDR 形式来源范围按网段匹配。处置豁免仍与行为授权分开。

CASE-03 回放现为 `none` / `LOW`，证据 4 条。CASE-01～CASE-10 已全部重跑并生成轨迹；10 案例评测摘要：Recall 100%、FPR 50%、弃权率 30%、诊断准确率 14.3%、风险等级一致率 85.7%、平均证据召回率 49.0%、高危审批合规率 100%。CASE-06、CASE-08 恶意场景弃权，CASE-09 授权扫描误报；结果保留原样，供后续错题复盘。

验证：`pytest tests/ -q` → **268 passed**；`git diff --check` 通过。

仍未完成的 Issue #18 外部联调：本次访问 `https://seclog.91666.icu:18443/health` TCP 超时；检索依赖、BGE 权重、Qdrant 与知识库未就绪；本地未发现 ClickHouse DSN。因此没有验证 ClickHouse 实库、真实混合检索或恒脑平台执行。Issue #18 仍不能整体关闭。

本轮对应产物见 `data/agent_traces/v1/`，验收记录见 `design/hengnao_workflows/week2_acceptance.md` 第十轮。

### 前一轮修复（2026-11-12 晚）

**1. MCP 历史时间窗不一致**
复现：`CHAIN-CASE-01` + `time_start=2026-11-01`，REST 返回 0 条，`/investigation/` 返回 29 条——
`seclog_query_logs` 没声明 `time_start/time_end`，参数被丢弃后回落到默认窗口。
已补齐并透传，`/mcp/` 与 `/investigation/` 复用同一工具定义。

真实 `tools/call` 验证（独立进程起双通道服务）：

| 条件 | REST | `/mcp/` | `/investigation/` | `time_base` |
| :--- | --: | --: | --: | :--- |
| 11 月窗口 | 0 | 0 | 0 | `absolute` |
| 10-27 14:00~15:00 | 29 | 29 | 同 REST | `absolute` |

证据 ID 逐条一致。

**2. 公网 MCP Host 校验（421）**
原实现只把 `SECLOG_PUBLIC_HOST` 原值加入 `allowed_hosts`，反代带端口时被判非法。
改为 `register_public_hosts()`：支持逗号分隔多主机，对每个值同时登记原值与无端口形式，
**不关闭** DNS rebinding 校验。

实测 `seclog.91666.icu:18443` → 200、`seclog.91666.icu` → 200、`evil.example.com` → 421。
公开 Host 下 `/investigation/` 仍是 4 个只读工具，无 `request_response`。

**3. ClickHouse 毫秒边界**
`clickhouse-connect==0.8.9` 对普通 `datetime` 按秒序列化，`.123` 会变 `.000`。
改用 `DT64Param`，明细与 count 复用同一组参数。假驱动验证：`.123`/`.124` 分别输出
`.123000`/`.124000`，不再抹平；相对窗口分支不受影响。

> NAS 实库未验证（中转仍旧镜像，8123/9000 不对外）。

**4. `isolate_account` 契约**（上一轮已做，本轮保持）
REST 枚举 + `target_user`（与 `target_ip` 互斥）、MCP 同参数、审批单写明目标账号；
只登记待审批（`executed=false`），不执行真实隔离。

### 需要 @lizhikeer 确认（阻塞 CASE-03 判定）

CASE-03 目前是 `insufficient_evidence`，原因不是判定逻辑有 bug，而是**配置缺一项**：

- `ops_zhang` 命中 `config/response-policy.yaml#allowlist.users` 的 `ops_*`
  —— 但那是**处置豁免名单**（不自动隔离），不等于「该账号可以从 10.0.0.66 操作 web-prod-01」；
- `config/assets.yaml`、`maintenance-windows.yaml` 里也没有「账号 → 允许来源 / 允许资产」的授权范围；
- 现有证据只能证明：账号是运维类、资产已登记、3 条行为都在 `02:00–03:30` 窗口内，
  无法证明来源与资产在授权范围内。

**请确认**：`ops_zhang` 的合法来源网段、可操作的资产清单（例如「10.0.0.0/24 内、仅 web-prod-01/backup-01」）。
拿到后我会新增一份 account-scope 配置读取（不复用 allowlist），并补「授权通过 / 越权资产 / 缺配置」
三种用例。**在确认前不自行编造范围**，所以 CASE-03 暂时保持弃权。

### 实测结果（本地回放，本轮未变）

| 场景 | 结论 | 风险 | 证据 | 召回 |
| :--- | :--- | :--- | --: | --: |
| CHAIN-CASE-01 | `SQL_Injection_After_Brute_Force_After_Scan` | HIGH | 16 | 0.833 |
| CHAIN-CASE-02 | `Path_Traversal_Privilege_After_Malicious_Upload` | HIGH | 6 | 0.667 |
| CHAIN-CASE-03 | `insufficient_evidence` | LOW | 4 | 0.4 |

CASE-02 的 `C2_Exfiltration` 仍未计入：`_c2_signal` 要求 payload 含明确回连描述，
该场景 4 条外连日志只有 `conn_state=SF`。这是既有严格化设计，未为对齐 truth 放宽。

### 仍阻塞

| 项 | 现状 | 需要 |
| :--- | :--- | :--- |
| NAS 部署 | 未执行 | 用本分支镜像部署 |
| ClickHouse 实库 | 未验证 | 部署后按验收文档第八轮 §8 复测（用 `time_start` 绝对窗口） |
| 真实混合检索 | 未验证 | BGE 权重 + Qdrant 建库 + `sentence-transformers` |
| 恒脑 V1 | 未运行 | 数据源就绪后再跑 |
| 账号授权范围 | 缺配置 | 见上方「需要确认」 |

部署环境变量：`SECLOG_DATA_SOURCE=clickhouse`、`CLICKHOUSE_DSN`、`SECLOG_CONFIG_DIR=/app/config`、
`SECLOG_PUBLIC_HOST=seclog.91666.icu,seclog.91666.icu:18443`。

> 未推送、未建 PR、未改 Issue；原始日志、truth 与历史轨迹保持原样。
> 本轮额外安装了 `clickhouse-connect==0.8.9` 用于毫秒绑定验证（与 `requirements/base.txt` 一致）。

---

<details>
<summary>上一轮记录（2026-11-12 下午）</summary>

**本轮修复**：部署入口 404（改用 `src.api.service:app` + PYTHONPATH + `COPY config/`）、
授权判断（`days` 字段、豁免 vs 授权、缺依据弃权）、`isolate_account` 契约、历史场景查询（绝对时间窗）。
**测试**：258 passed。**V1**：CASE-01 16/0.833、CASE-02 6/0.667、CASE-03 insufficient/0.4。

</details>
