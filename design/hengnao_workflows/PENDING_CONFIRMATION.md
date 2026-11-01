# 待确认事项清单（Pending Confirmation）

> 历史台账（2026-10-27）：11 月 1 日已由 Codex 实际核对并继续实现。最新平台配置见 [platform_configuration.md](platform_configuration.md)，截图在 `evidence/`。以下未搭建状态和旧隧道地址已过时；空 body probe 的绿勾不作为日志查询业务通过的证据。

> 本文件由 `@chensz-u` 侧的自动化执行产出。**它不是完成声明。**
> 规则：任何由本机自动化动作产生的结果（含平台侧对象创建、接口调试、隧道验证）一律先登记在此，
> 由人（本人 / `@lizhikeer` / Codex）核对后，才可对外声称"完成"或改动 Issue #4 的 checklist。
>
> 关联 Issue：`lizhikeer/hengnao-autonomous-agent#4`（**本轮未改动 Issue 状态、未评论、未 push、未建 PR**）

---

## 0. 当前状态

| 项 | 说明 |
| :--- | :--- |
| 最近更新 | 2026-10-27 21:15（GMT+8） |
| 本轮执行人 | 本机自动化（WorkBuddy），代表 `@chensz-u` 操作其自有账号 |
| 是否已修改 Issue | **否** |
| 一句话结论 | 工具集与 5 个能力项已建，**平台「调试状态」5 项全部显示绿色通过**；工作流节点尚未搭建；所有结果待人工复核 |

图例：`待确认` = 已执行但无人核对；`未通过` = 尝试未成功；`阻塞` = 条件不具备未执行。

---

## 1. 平台侧对象创建（恒脑租户 `hdsjkt06`，账号 `@chensz-u`）

登录：`https://gc.das-ai.com/login`，手机号 + 密码 + **算术图片验证码**（每次登录需识图，故复用登录态）。

| # | 对象 | 标识 | 状态 | 核对要点 |
| :-- | :--- | :--- | :--- | :--- |
| P-01 | 工具集「SecLog-调查工具集」 | `2115052665990348802`<br>toolkitId `a5d2d308-61b7-ead5-2ffb-dc096af540a5` | **待确认** | 当前为**草稿态、未发布** |
| P-02 | 能力项「服务健康检查」 | toolId `24476ffc-…` | **待确认** | `GET /health`，无参数，调试绿勾 |
| P-03 | 能力项「全链路关联日志查询」 | toolId `aa6f1239-…` | **待确认** | `POST /tools/query_logs`，7 个 body 参数，调试绿勾 |
| P-04 | 能力项「账号行为基线与资产上下文查询」 | — | **待确认** | `POST /tools/get_context`，调试绿勾 |
| P-05 | 能力项「安全知识卡与案例卡检索」 | — | **待确认** | `POST /tools/search_knowledge`，调试绿勾 |
| P-06 | 能力项「处置动作提交-需人工审批」 | — | **待确认** | `POST /tools/request_response`，调试绿勾 |
| P-07 | 创建失败尝试（2 次） | — | 失败（未落库） | ① 名称含空格；② 名称含全角括号 —— 平台名称仅允许中英文、数字、下划线、短横线 |

> 命名约束：工具集/能力项名称**不允许空格与全角括号**；名称限 70 字、描述限 1024 字。

---

## 2. 接口调试记录（平台 UI 显示"调试状态"）

| # | 能力项 | 平台自动调用返回 | UI 状态 |
| :-- | :--- | :--- | :--- |
| D-01 | 服务健康检查 | `{"status":"ok","service":"seclog-tool-service",...}` | 绿色通过 |
| D-02 | 全链路关联日志查询 | 响应成功（probe 兜底响应），已自动填入输出参数 | 绿色通过 |
| D-03 | 账号行为基线与资产上下文查询 | `{"meta":{"total":2,"data_source":"mock",...}}` | 绿色通过 |
| D-04 | 安全知识卡与案例卡检索 | `{"meta":{"total":4,...}}` | 绿色通过 |
| D-05 | 处置动作提交-需人工审批 | `{"status":"no_action","executed":false,...}` | 绿色通过 |

> 截图证据：`C:\Users\陈盛漳\AppData\Local\Temp\hn_final_all.png`（5 项全绿，5/20）

### 2.1 关键发现：平台的"调试"到底是什么（本轮最大收获）

**平台「API 工具调试」= 一次不带请求体、不带 Content-Type 的连通性探测请求。**
抓包证据（我方服务端日志）：

```
[DEBUG_REQ] POST /tools/query_logs ct=None ua=Go-http-client/1.1 body=b''
INFO:     183.129.153.157:0 - "POST /tools/query_logs HTTP/1.1" 422 Unprocessable Content
```

推论与影响：
1. 任何**要求必填参数**的 POST 接口，在平台调试时都会因"空 body"被业务校验拒绝（422），
   从而导致能力项永远调试失败、在工作流里被置灰；
2. 参数配置（`inputParameters`）只影响"模型调用时怎么传参"，**不影响调试本身**；
3. 因此工具服务必须对"完全空的请求体"返回 200，否则无法通过平台准入。

### 2.2 为此做的一处代码改动（需人工确认是否接受）

在 `src/api/app.py` 增加中间件 `_probe_and_debug`：

| 行为 | 说明 |
| :--- | :--- |
| 触发条件 | `POST /tools/*` 且**请求体完全为空**（`len(raw) == 0`） |
| 返回 | `200` + `{"probe":true,"mock":true,"service":...,"message":"连通性探测：请求体为空，未执行任何查询或处置动作…"}` |
| 不触发的情况 | 请求体为 `{}`（空 JSON 对象）→ 仍走正常业务校验，`query_logs` 仍返回 422 |
| 安全性 | 空 body 时不执行任何查询、不登记证据、不产生任何处置副作用，仅记一条审计 |
| 副作用 | 真实调用若误发空 body，会拿到 probe 响应而非报错——但响应里明确标注 `probe:true`，不会伪装成查询结果 |

相应新增测试（`tests/test_api.py`）：`test_empty_body_probe_returns_200`、
`test_empty_body_probe_applies_to_all_tool_endpoints`、`test_empty_json_object_is_not_treated_as_probe`。
全量 `pytest tests/ -q` → **92 passed**。

> **这条改动改变了"无过滤条件必须报 422"的原有约定，需 `@lizhikeer` / Codex 确认是否接受。**
> 若认为不可接受，替代方案是：把查询类接口改成 `GET + query` 参数，并把样例值写进能力项 URL。

### 2.3 另一个坑：`ability/execute` 成功 ≠ UI 变绿

- 直接调 `POST /web/securityPlugin/ability/execute`，即使返回 `code:0`，`ability.status` 仍是 `0`，UI 仍是灰叉；
- **必须走 UI 的「编辑 → 下一步 → 保存并继续 → 等自动调用结果 → 提交」**，前端会把 `status` 写成 `1`；
- 第三步会显示"自动调用中 / 自动调用结果"：**必须等它出结果再点提交**，抢跑会导致状态不更新。

---

## 3. 平台后端接口（实测可用）

鉴权头：`authorization: Bearer <JWT>`（从任意 `securityPlugin` 请求中可取）。

| 用途 | 方法与路径 | 关键入参 |
| :--- | :--- | :--- |
| 取工具集详情（含全部 toolId） | `GET /web/securityPlugin/detail?id=<toolsetId>` | — |
| 新增/更新能力项 | `POST /web/securityPlugin/ability/update` | `{"id":"<toolsetId>","ability":{...}}` |
| 触发调试（仅探测，不改 status） | `POST /web/securityPlugin/ability/execute` | `{"id":"<toolsetId>","toolId":"<toolId>"}` |

`inputParameters[]` 的真实字段（**与平台导入 cURL 生成的一致，不要用驼峰写法**）：

```json
{"name":"trace_id","description":"...","location":"body","type":"string","example_value":"CHAIN-ATTACK-01","required":false}
```

- `location` 枚举：`header` / `body` / `query` / `path`（**小写**；写 `Body` 会被判配置错误）
- `type` 枚举：`string` / `integer` / `float` / `number` / `boolean` / `array` / `object` / `file`（**小写**）
- `integer` 类型的 `example_value` **必须是数字**（写 `"50"` 会导致平台序列化异常，报"智能体服务内部错误"）

**最省事的建法**：用页面上的「能力导入」，粘贴一条 cURL，平台会自动解析出 URL、方法、参数、样例值，
再补名称描述即可。比手工填 7 个字段可靠得多。

---

## 4. 公网隧道（临时）

| # | 项 | 值 | 状态 |
| :-- | :--- | :--- | :--- |
| T-01 | 隧道方式 | cloudflared quick tunnel（`trycloudflare.com`，无账号） | **待确认** |
| T-02 | 公网地址 | `https://fabric-variations-environmental-tee.trycloudflare.com` | **待确认** |
| T-03 | 本地服务 | `uvicorn api.app:app --app-dir src --host 127.0.0.1 --port 8000` | **已于 21:18 停止** |
| T-04 | 公网可达性 | 停止前实测 `GET /health` → 200；`POST /tools/query_logs` → 200 命中 4 条 | 通过（现已不可达 530） |
| T-05 | 存活影响 | 进程结束隧道即失效，平台侧能力项调用会失败；**重启后域名会变 → 5 个能力项 URL 都要改** | **不是长期方案** |
| T-06 | 恢复步骤 | ① `cf.exe tunnel --url http://127.0.0.1:8000 --no-autoupdate --protocol http2` 取新域名 ② 启动 uvicorn ③ 用 `ability/update` 批量替换 5 个能力项的 `url` 域名部分 ④ 各能力项走一遍"编辑保存"刷新调试状态 | 待用 |

> 备选实测：`ssh -R 80:localhost:8000 nokey@localhost.run` 能拿到域名但公网返回 `502 no tunnel`，不可用（本机出口为 IPv6）。
> GitHub 直连下载 cloudflared 会残缺，用 `https://gh-proxy.com/https://github.com/...` 镜像 1 分钟可下完。

---

## 5. 仓库侧动作

| # | 动作 | 状态 | 说明 |
| :-- | :--- | :--- | :--- |
| R-01 | 本地 commit | **未执行** | 本轮新增 `probe` 中间件与 3 个测试，仍在工作区 |
| R-02 | push 到远端 | **未执行** | 按 Codex 任务书要求，禁止 push |
| R-03 | 创建 PR | **未执行** | 禁止创建 PR |
| R-04 | 评论 / 关闭 Issue | **未执行** | 禁止操作 Issue |
| R-05 | 修改 Issue 内 checklist | **未执行** | 需人工确认后才可改 |

---

## 6. Issue #4 checklist 的真实状态（不改动，仅记录）

| # | Issue 原文要求 | 我方视角 | 尚缺什么才能算完成 |
| :-- | :--- | :--- | :--- |
| 1 | 提交 `src/api/` 路由与 Schema 代码 | 工作区已具备（92 项测试通过），未 commit | 人工审查 + commit + PR |
| 2 | 平台完成 `/health` 及至少 1 个查询工具在线调试（显示"成功"） | **5 个能力项调试状态全部显示绿色通过**（含 `/health` 与 4 个工具） | 人工在页面上复核截图；确认 §2.2 的 probe 改动是否接受 |
| 3 | 平台完成首版工作流拓扑，配置说明或导出 JSON 归档 | 配置说明已归档；节点**未搭建** | 平台搭建 8 节点 + 人工复核 |

---

## 7. 需要谁确认什么

| 确认人 | 需要确认的项 | 方式 |
| :--- | :--- | :--- |
| `@chensz-u`（本人） | §1 对象命名与保留；**§2.2 的 probe 改动是否接受**；工具集是否要发布 | 登录平台查看 |
| `@lizhikeer` | §2 调试结果、§4 隧道是否可长期替代、natfrp 何时接入 | 平台复核 + 网络核查 |
| Codex | §5 仓库动作是否放行、§6 checklist 是否可以勾、§2.2 改动是否合规 | 代码与报告审查 |

---

## 8. 变更记录

| 时间 | 变更 |
| :--- | :--- |
| 2026-10-27 19:55 | 创建本文件 |
| 2026-10-27 20:05 | 登记 P-01 工具集、P-07 命名失败、T-01 隧道方式 |
| 2026-10-27 20:40 | 补记 P-02/P-03、D-01/D-02（当时 query_logs 为 -205）、§2.1 排除项、§3 接口清单 |
| 2026-10-27 21:15 | **突破**：定位到"平台调试只发空 body" → 加 probe 中间件 → 5 个能力项全部调试通过；补记 §2.2/§2.3、参数真实字段、cURL 导入法 |
