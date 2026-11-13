# Agent 调查运行轨迹（Trace Log）归档规范 · V1

> 归属：`@ribbonfish-jun`（任务包 A）｜ 数据来源：`@chensz-u` 在恒脑平台跑出的 V1 版 Agent 调查输出
> 用途：供 `@zyh060911` 的 `scripts/eval_runner.py` 读取，逐 case 对比标准答案算分

## 一、为什么要归档

Agent 每次多轮调查的过程（调了哪些工具、每次查到什么、为什么改主意、最终输出什么）必须落盘，
否则：

1. 算分脚本只能拿到最终结果，无法解释「为什么这题判错」；
2. 错误案例无法复现，`@Tr4cy-cyber` 的错题修订卡无从下手；
3. 三轮迭代（V1→V2→V3）无法做同 case 的逐轮对比。

## 二、目录约定

```
data/agent_traces/
├── v1/                  # V1 基线版 Agent 的 10 个 case 运行结果
│   ├── CHAIN-CASE-01.json
│   ├── ...
│   └── CHAIN-CASE-10.json
├── v2/                  # V2 版（第 3 周）
└── v3/                  # V3 版（第 4 周）
```

**命名**：`<case_id>.json`，与 `data/full_chain_logs/` 里对应场景的 `trace_id` 一一对应。
**禁止**：把同一个 case 的多个版本混写进同一个文件；版本号只体现在目录名上。

## 三、单个 trace 文件格式（建议，待与 `@chensz-u` 最终对齐）

```json
{
  "trace_id": "CHAIN-CASE-04",
  "case_id": "CHAIN-CASE-04",
  "agent_version": "V1",
  "run_at": "2026-11-08T10:00:00Z",
  "model": "恒脑平台-<基座模型标识>",
  "total_elapsed_ms": 18432,
  "rounds": [
    {
      "round": 1,
      "thought": "首条告警来自 198.51.100.61 对 /comment.php 的 POST，先查该 IP 的全量访问日志",
      "tool": "query_logs",
      "args": {"src_ip": "198.51.100.61", "time_window": "2026-11-03T09:00:00Z/2026-11-03T10:00:00Z"},
      "result_count": 12,
      "result_summary": "命中 12 条，含 2 条含 <script> 的 POST",
      "elapsed_ms": 1203
    },
    {
      "round": 2,
      "thought": "怀疑存储型 XSS，查同一会话在不同 IP 上的复用情况",
      "tool": "query_logs",
      "args": {"session_id": "sess-a91c", "time_window": "2026-11-03T09:00:00Z/2026-11-03T10:00:00Z"},
      "result_count": 4,
      "result_summary": "发现 sess-a91c 在 198.51.100.61 上访问 /admin/*",
      "elapsed_ms": 986
    }
  ],
  "tool_call_count": 2,
  "final_output": {
    "case_id": "CHAIN-CASE-04",
    "is_malicious": true,
    "attack_type": "Stored_XSS_Session_Hijacking",
    "risk_level": "HIGH",
    "attacker_ip": "198.51.100.61",
    "victim_asset": "web-prod-01",
    "evidence_log_ids": ["LOG-20261103-0404", "LOG-20261103-0407", "LOG-20261103-0409"],
    "attack_chain_summary": "...",
    "recommended_action": "block_ip",
    "requires_human_approval": true,
    "unknown_items": ""
  }
}
```

## 四、归档时的三点硬要求

1. **`final_output` 必须是 Agent 原样输出**，人工不得修改任何字段——否则算分失真。判错就是判错，
   错误样本正好用于 `@Tr4cy-cyber` 的错题修订卡。
2. **`rounds` 里的 `tool` / `args` 要如实记录**，包括调错工具、查空结果的情况；这类轨迹是
   V2/V3 优化 Prompt 与工具约束的主要依据。
3. **`evidence_log_ids` 只记录 Agent 自己给出的编号**，不要事后补正；编号真实性由
   `@chensz-u` 的后端校验节点判定，与归档文件互为印证。

## 五、当前状态

`@chensz-u` 的 V1 Agent 尚未在这 10 个场景上完成跑批，本目录先建立规范与结构。
跑出结果后由 `@ribbonfish-jun` 按上述格式归档，并同步给 `@zyh060911` 接入算分。
