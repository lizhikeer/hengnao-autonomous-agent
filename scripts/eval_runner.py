# -*- coding: utf-8 -*-
"""恒脑自主安全智能体 —— 自动化评测算分脚本（任务包 C · W2 交付）

定位与职责
==========
本脚本位于评测链路的终点：A 组（日志清洗）产出全链路故事日志包与标准答案卡
（data/full_chain_logs/chain_case_*_truth.json），Agent 在恒脑平台上调查后输出
遵循 11 字段 AgentResults 契约的 JSON（见 src/ai_engine/schemas/agent_results.schema.json），
本脚本按 case_id 将两者配对，计算四维评测指标并输出可直接粘贴进
docs/iterations/ 台账的 Markdown 报告。

四维评测标准（对齐 docs/project design/database/知识库总体设计.md §4
              与 design/hengnao_workflows/api_contract_for_a_c.md §3.3）
==========================================================
1. 检测维度（Detection）
   - 攻击检出率 Recall  = TP / (TP + FN)：标准答案为恶意、Agent 也判恶意的比例；
   - 正常业务误报率 FPR = FP / (FP + TN)：标准答案为正常运维、却被误判为恶意的比例；
   - 弃权率 Abstain Rate：attack_type == "insufficient_evidence" 的比例，单列统计，
     不混入 TP/FN/FP/TN 任何一类（api_contract §3.2 规则 1）；
   - abstain_but_should_detect：标准答案为恶意却被 Agent 弃权的案例数（调查不足）。
2. 调查维度（Investigation）
   - 诊断准确率：is_malicious 与标准答案一致，且 attacker_ip / victim_asset 匹配，
     且 attack_type 命中核心攻击类别（子串/关键词匹配，见 _attack_type_hit 的注释）；
   - 风险等级一致率：risk_level 与标准答案完全一致的比例（契约的"分级一致性"）。
3. 证据维度（Evidence）
   - 证据支持率 Evidence Recall = |Agent evidence ∩ 标准证据| / |标准证据|；
   - 伪造/无效证据计数：id 不符合 LOG-YYYYMMDD-NNNN 格式，或不在该场景
     真实日志包（--logs-dir 下的 JSON 文件）中；
   - 非法输出 invalid_output：is_malicious=true 但 evidence_log_ids 为空
     （契约 model_validator 明确拒绝的输出，api_contract §3.2 规则 2）。
4. 防御维度（Defense）
   - 处置正确率：recommended_action 与标准答案完全一致得 1.0；
     block_ip 与 block_ip_short_term 互为近似得 0.5；其余 0 分；
   - 正常业务受损（误封）：标准答案为正常、Agent 却下达封禁/限速类动作；
   - 审批合规率：Agent 下达高危动作（block_ip / block_ip_short_term）时
     requires_human_approval 必须为 true 的比例，理想 100%。

防演示数据污染（api_contract §3.4 红线）
========================================
Agent 结果 JSON 若携带 meta.mock == true，说明是 Mock 演示数据，默认直接跳过并告警，
绝不计入正式评测报告；如确需查看可用 --include-mock 强制纳入，但输出中会显著标注。

用法
====
    # 正式评测：标准答案目录/文件 + Agent 输出目录/文件
    python scripts/eval_runner.py --truth data/full_chain_logs --agent output/agent_results --output report.md

    # 自测（零外部输入，读取仓库内置 3 张标准答案卡并构造模拟 Agent 输出）
    python scripts/eval_runner.py --selftest

    # 常用可选项
    --logs-dir data/full_chain_logs   # 真实日志包目录，用于证据存在性校验（默认同上）
    --include-mock                    # 允许 meta.mock=true 的演示数据进入评测（不推荐）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

# ---------------------------------------------------------------------------
# 常量与正则：与团队冻结契约严格对齐，禁止随意修改
# ---------------------------------------------------------------------------

# 弃权标记：证据不足时 AgentResults.attack_type 的固定取值（schema 强约定）
ABSTAIN_TYPE = "insufficient_evidence"

# 高危处置动作：下达时 requires_human_approval 必须为 true（契约 description 约定）
HIGH_RISK_ACTIONS = {"block_ip", "block_ip_short_term"}

# 近似处置动作对：完全不同但防御意图相近，按 api_contract §3.3 记 0.5 分
ACTION_NEAR_PAIRS = {frozenset(("block_ip", "block_ip_short_term"))}

# 证据编号格式：平台 code_verify 用的同一正则口径（api_contract §2.1 表格）
LOG_ID_PATTERN = re.compile(r"^LOG-\d{8}-\d{4}$")

# attack_type 匹配时可忽略的连接词（多阶段描述里的"先后"关系词，不承载攻击语义）
TYPE_STOPWORDS = {"after", "and", "before", "with", "via", "then"}

# 已知缩写别名：将 Agent 输出中常见的缩写展开为标准词，用于关键词命中判断
# 例：标准答案 SQL_Injection_After_Brute_Force，Agent 输出含 SQLi 也应算命中
TOKEN_ALIASES = {
    "sqli": {"sql", "injection"},
    "sql_injection": {"sql", "injection"},
    "c2": {"c2", "callback"},
}

# Agent 输出 JSON 中演示数据的标记路径：顶层 meta.mock == true
MOCK_FLAG_PATH = ("meta", "mock")

# 仓库根目录：scripts/ 的上一级，用于解析默认相对路径
REPO_ROOT = Path(__file__).resolve().parents[1]

# 默认输入位置：A 组 W1 冻结的标准答案与日志包目录
DEFAULT_TRUTH_DIR = REPO_ROOT / "data" / "full_chain_logs"
DEFAULT_LOGS_DIR = DEFAULT_TRUTH_DIR


# ---------------------------------------------------------------------------
# 小工具函数：编码、加载、归一化
# ---------------------------------------------------------------------------


def _force_utf8_stdout() -> None:
    """Windows 控制台默认 GBK，打印中文/特殊字符可能抛 UnicodeEncodeError。

    统一把 stdout/stderr 重配为 UTF-8（Python 3.7+），保证报告在任何终端可打印。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:  # 非 TextIOWrapper（如测试捕获 stdout）时跳过
            pass


def _load_json(path: Path) -> Any:
    """读取单个 JSON 文件；解析失败时抛 ValueError 由上层统一计入错误清单。

    使用 utf-8-sig：自动剥离 Windows 工具（PowerShell / 记事本）导出时
    添加的 UTF-8 BOM 头；无 BOM 的标准 UTF-8 文件同样正常解析。
    """
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def _iter_json_records(paths: Iterable[str]) -> list[tuple[Path, dict]]:
    """把 CLI 传入的目录/文件列表展开为 (路径, dict) 记录序列。

    支持三种文件形态：
    1. 单个 JSON 对象（一个 case 一个文件，最常见的 Agent 导出格式）；
    2. JSON 数组（一次导出多个 case）；
    3. JSON Lines（每行一个 case）。
    目录则递归展开其中全部 .json / .jsonl 文件。
    """
    records: list[tuple[Path, dict]] = []
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.json")))
            files.extend(sorted(p.rglob("*.jsonl")))
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(f"路径不存在：{p}")

    for f in files:
        try:
            data = _load_json(f)
        except ValueError as exc:
            raise ValueError(f"{f}: JSON 解析失败（{exc}）") from exc
        if isinstance(data, dict):
            records.append((f, data))
        elif isinstance(data, list):
            # 数组形态：允许嵌套 dict 列表；JSONL 文件按行拆分
            if data and all(isinstance(item, dict) for item in data):
                records.extend((f, item) for item in data)
        elif f.suffix == ".jsonl":
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    records.append((f, json.loads(line)))
    return records


def _norm_text(value: str) -> str:
    """字符串归一化：去首尾空白、转小写（IP/资产标识的大小写差异不参与判分）。"""
    return str(value).strip().lower()


def _split_type_tokens(attack_type: str) -> set[str]:
    """把 attack_type 拆成语义词集合。

    处理三种书写风格并统一为小写词：
    - snake_case：SQL_Injection_After_Brute_Force → {sql, injection, after, brute, force}
    - camelCase ：SqlInjection → {sql, injection}（在驼峰边界切开）
    - 中文描述  ：SQL 注入 → {sql, 注入}（按空白切分，中文整体保留）
    停用词与别名在命中判断时再处理，这里只做机械切分。
    """
    text = str(attack_type)
    expanded: list[str] = []
    token = ""
    for ch in text:
        # 驼峰边界：前一个字符是小写字母、当前是大写字母 → 插入分隔符
        if ch.isupper() and token and token[-1].islower():
            expanded.append(token)
            token = ch.lower()
        elif ch.isalnum():
            token += ch.lower()
        else:  # 下划线 / 连字符 / 空格 / 标点都是天然分隔符
            if token:
                expanded.append(token)
            token = ""
            if "\u4e00" <= ch <= "\u9fff":  # 中文逐字保留，供"正常运维"类描述匹配
                expanded.append(ch)
    if token:
        expanded.append(token)
    return set(expanded)


def _attack_type_hit(truth_type: str, agent_type: str) -> bool:
    """判断 Agent 的 attack_type 是否命中标准答案的核心攻击类别。

    策略（对齐 api_contract Q-C1 的"包含/关键词"建议，不做严格相等）：
    1. 双向包含：归一化后一方完整出现在另一方中（Agent 输出更具体时也算命中）；
    2. 核心词覆盖：标准答案去掉连接词后得到核心词集合，Agent 词集合（含别名展开，
       如 sqli → sql + injection）覆盖其中至少一半即命中。
    例：truth=SQL_Injection_After_Brute_Force，agent 含 SQL_Injection 或 SQLi 均命中。
    """
    t_tokens = {t for t in _split_type_tokens(truth_type) if t not in TYPE_STOPWORDS}
    a_tokens = _split_type_tokens(agent_type)
    # 别名展开：把缩写拆成标准词，两边统一词表
    a_expanded: set[str] = set()
    for tok in a_tokens:
        a_expanded.add(tok)
        a_expanded |= TOKEN_ALIASES.get(tok, set())
    # 同样对 truth 词做别名扩展（保证双向词表一致）
    t_expanded: set[str] = set()
    for tok in t_tokens:
        t_expanded.add(tok)
        t_expanded |= TOKEN_ALIASES.get(tok, set())

    if not t_expanded or not a_expanded:
        return False
    # 条件 1：双向包含（多阶段长描述 vs 短输出的兼容判断）
    t_norm, a_norm = "".join(sorted(t_expanded)), "".join(sorted(a_expanded))
    if t_norm in a_norm or a_norm in t_norm:
        return True
    # 条件 2：核心词覆盖过半
    overlap = t_expanded & a_expanded
    return len(overlap) * 2 >= len(t_expanded)


def _extract_mock_flag(record: dict) -> bool:
    """按 MOCK_FLAG_PATH 逐层下钻读取 meta.mock 标记，结构不完整视为非 Mock。"""
    node: Any = record
    for key in MOCK_FLAG_PATH:
        if not isinstance(node, dict) or key not in node:
            return False
        node = node[key]
    return node is True


# ---------------------------------------------------------------------------
# 标准答案 / 日志包加载
# ---------------------------------------------------------------------------


def load_truth_map(truth_paths: Iterable[str]) -> dict[str, dict]:
    """加载标准答案卡，返回 case_id -> truth 字典。

    标准答案卡复用 AgentResults 的 11 字段结构，case_id 是唯一配对键；
    重复 case_id 属于数据缺陷，直接报错（静默覆盖会污染评测）。
    """
    truth_map: dict[str, dict] = {}
    for path, record in _iter_json_records(truth_paths):
        case_id = _norm_text(record.get("case_id", ""))
        if not case_id:
            # 默认 truth 目录（data/full_chain_logs）同时存放日志包 JSON：
            # 日志条目带 log_id/trace_id 而无 case_id，按内容识别后跳过，
            # 避免把整目录传给 --truth 时被日志包文件阻断。
            if "log_id" in record or "trace_id" in record:
                continue
            raise ValueError(f"{path}: 标准答案卡缺少 case_id 字段")
        if case_id in truth_map:
            raise ValueError(f"标准答案卡 case_id 重复：{case_id}（{path}）")
        truth_map[case_id] = record
    if not truth_map:
        raise ValueError("未加载到任何标准答案卡，请检查 --truth 路径")
    return truth_map


def load_real_log_ids(logs_dir: Path) -> dict[str, set[str]]:
    """扫描日志包目录，返回 case_id（以 trace_id 为准）-> 真实 log_id 集合。

    日志包文件名不规则（chain_case_01_sqli.json 等），但包内每条日志的
    trace_id 与答案卡 case_id 一一对应，因此以 trace_id 作为归并键最可靠；
    文件缺少 trace_id 的记录跳过（不参与存在性校验）。
    """
    real_ids: dict[str, set[str]] = {}
    if not logs_dir.is_dir():
        return real_ids
    for f in sorted(list(logs_dir.glob("*.json")) + list(logs_dir.glob("*.jsonl"))):
        if f.stem.endswith("_truth"):  # 答案卡不是日志包
            continue
        try:
            data = _load_json(f)
        except ValueError:
            continue  # 日志包损坏不阻塞评测，只影响存在性校验覆盖面
        items = data if isinstance(data, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            trace = _norm_text(str(item.get("trace_id", "")))
            log_id = str(item.get("log_id", "")).strip()
            if trace and log_id:
                real_ids.setdefault(trace, set()).add(log_id)
    return real_ids


# ---------------------------------------------------------------------------
# 单案例四维评分
# ---------------------------------------------------------------------------


def score_case(
    truth: dict, agent: dict, real_log_ids: Optional[set[str]] = None
) -> dict[str, Any]:
    """对单个配对成功的案例计算四维明细，返回供汇总与明细表共用的结果字典。

    设计说明：
    - detection_label 只取 TP/TN/FP/FN 四值之一或 ABSTAIN（弃权单列，
      不参与二分类混淆矩阵，也不参与防御/调查维度的分母）；
    - evidence_recall 在标准证据为空时记 1.0（无可召回证据视为"没有失分点"）；
    - action_score 取值 1.0 / 0.5 / 0.0；弃权案例不计防御分（记 None，汇总时剔除）。
    """
    truth_mal = bool(truth.get("is_malicious", False))
    agent_mal = bool(agent.get("is_malicious", False))
    agent_type = str(agent.get("attack_type", ""))
    abstain = agent_type == ABSTAIN_TYPE

    # ---- 检测维度：二分类标签（弃权优先级最高，单独归类）----
    if abstain:
        label = "ABSTAIN"
    elif truth_mal and agent_mal:
        label = "TP"
    elif truth_mal and not agent_mal:
        label = "FN"
    elif not truth_mal and agent_mal:
        label = "FP"
    else:
        label = "TN"

    result: dict[str, Any] = {
        "label": label,
        "abstain": abstain,
        "truth_malicious": truth_mal,
        "agent_malicious": agent_mal,
        "agent_attack_type": agent_type,
    }

    # ---- 调查维度 ----
    # IP / 资产匹配：归一化后严格相等；Agent 输出必须是已查日志中出现的真实值
    ip_ok = _norm_text(agent.get("attacker_ip", "")) == _norm_text(truth.get("attacker_ip", ""))
    asset_ok = _norm_text(agent.get("victim_asset", "")) == _norm_text(truth.get("victim_asset", ""))
    type_ok = (not abstain) and _attack_type_hit(str(truth.get("attack_type", "")), agent_type)
    mal_ok = truth_mal == agent_mal
    result.update(
        {
            "ip_match": ip_ok,
            "asset_match": asset_ok,
            "type_hit": type_ok,
            "malicious_match": mal_ok,
            "diagnosis_ok": mal_ok and ip_ok and asset_ok and type_ok,
            "risk_match": _norm_text(agent.get("risk_level", "")) == _norm_text(truth.get("risk_level", "")),
        }
    )

    # ---- 证据维度 ----
    truth_ev = [str(x).strip() for x in truth.get("evidence_log_ids", [])]
    agent_ev = [str(x).strip() for x in agent.get("evidence_log_ids", [])]
    hit = set(agent_ev) & set(truth_ev)
    recall = len(hit) / len(truth_ev) if truth_ev else 1.0

    # 伪造/无效证据：格式非法，或（提供了真实日志包时）不在该场景日志包中
    bad_format = [e for e in agent_ev if not LOG_ID_PATTERN.match(e)]
    if real_log_ids:
        hallucinated = [e for e in agent_ev if e not in real_log_ids and e not in truth_ev]
    else:
        hallucinated = list(bad_format)  # 无日志包时退化为纯格式校验
    # 非法输出：恶意判定却拿不出任何证据（契约 model_validator 明确禁止）
    invalid_output = agent_mal and not agent_ev

    result.update(
        {
            "evidence_recall": recall,
            "evidence_hit": sorted(hit),
            "evidence_missing": sorted(set(truth_ev) - set(agent_ev)),
            "evidence_bad_format": bad_format,
            "evidence_hallucinated": [e for e in hallucinated if e not in bad_format],
            "evidence_invalid_output": invalid_output,
        }
    )

    # ---- 防御维度 ----
    truth_action = _norm_text(truth.get("recommended_action", ""))
    agent_action = _norm_text(agent.get("recommended_action", ""))
    approval = bool(agent.get("requires_human_approval", False))
    if abstain:
        action_score: Optional[float] = None  # 弃权不计防御分
        false_block = False
        approval_ok: Optional[bool] = None
    elif agent_action == truth_action:
        action_score = 1.0
    elif {agent_action, truth_action} in ACTION_NEAR_PAIRS:
        action_score = 0.5
    else:
        action_score = 0.0
    # 正常业务受损：标准答案无处置，Agent 却下达封禁/限速类动作
    false_block = (not truth_mal) and agent_action in HIGH_RISK_ACTIONS | {"rate_limit"}
    # 审批合规：高危动作必须请求人工审批；非高危动作不参与该指标
    needs_approval = agent_action in HIGH_RISK_ACTIONS
    approval_ok = approval if needs_approval else None

    result.update(
        {
            "action_score": action_score,
            "false_block": false_block,
            "needs_approval": needs_approval,
            "approval_ok": approval_ok,
        }
    )
    return result


# ---------------------------------------------------------------------------
# 汇总与 Markdown 报告
# ---------------------------------------------------------------------------


def aggregate(paired: list[tuple[str, dict]]) -> dict[str, Any]:
    """把逐案例明细聚合成四维汇总指标。

    分母约定（与 api_contract §3.2/§3.3 口径一致）：
    - Recall/FPR 基于 TP/TN/FP/FN（弃权不计入混淆矩阵）；
    - 诊断准确率/风险一致率/证据召回基于全部非弃权案例；
    - 处置正确率基于"有防御分"的案例（弃权与非法输出不计）；
    - 审批合规率基于"下达了高危动作"的案例（无高危动作时记 None）。
    """
    n_total = len(paired)
    tp = sum(1 for _, r in paired if r["label"] == "TP")
    fn = sum(1 for _, r in paired if r["label"] == "FN")
    fp = sum(1 for _, r in paired if r["label"] == "FP")
    tn = sum(1 for _, r in paired if r["label"] == "TN")
    abstain_all = sum(1 for _, r in paired if r["abstain"])
    abstain_mal = sum(1 for _, r in paired if r["abstain"] and r["truth_malicious"])

    non_abstain = [(cid, r) for cid, r in paired if not r["abstain"]]
    n_eval = len(non_abstain)
    diag_ok = sum(1 for _, r in non_abstain if r["diagnosis_ok"])
    risk_ok = sum(1 for _, r in non_abstain if r["risk_match"])

    scored = [(cid, r) for cid, r in paired if r["action_score"] is not None]
    action_avg = (
        sum(r["action_score"] for _, r in scored) / len(scored) if scored else None
    )
    high_risk = [(cid, r) for cid, r in paired if r["needs_approval"]]
    approval_rate = (
        sum(1 for _, r in high_risk if r["approval_ok"]) / len(high_risk)
        if high_risk
        else None
    )

    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    ev_avg = (
        sum(r["evidence_recall"] for _, r in non_abstain) / n_eval if n_eval else None
    )

    return {
        "total_cases": n_total,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "abstain_total": abstain_all,
        "abstain_but_should_detect": abstain_mal,
        "abstain_rate": abstain_all / n_total if n_total else None,
        "recall": recall,
        "fpr": fpr,
        "invalid_output_count": sum(1 for _, r in paired if r["evidence_invalid_output"]),
        "diagnosis_accuracy": diag_ok / n_eval if n_eval else None,
        "risk_consistency": risk_ok / n_eval if n_eval else None,
        "evidence_recall_avg": ev_avg,
        "hallucinated_total": sum(
            len(r["evidence_hallucinated"]) + len(r["evidence_bad_format"])
            for _, r in paired
        ),
        "action_accuracy": action_avg,
        "false_block_count": sum(1 for _, r in paired if r["false_block"]),
        "approval_compliance": approval_rate,
        "high_risk_count": len(high_risk),
    }


def _fmt(value: Any, pct: bool = False) -> str:
    """Markdown 单元格格式化：None → N/A，比例类转百分数保留 1 位小数。"""
    if value is None:
        return "N/A"
    if pct:
        return f"{value * 100:.1f}%"
    return str(value)


def render_markdown(
    summary: dict[str, Any],
    paired: list[tuple[str, dict]],
    skipped_mock: list[tuple[Path, str]],
    unpaired_agent: list[str],
    missed_truth: list[str],
    round_title: str,
) -> str:
    """渲染 Markdown 报告：标题警示 + 指标汇总表 + 逐案例明细表。

    报告面向两种读者：粘贴进 docs/iterations/ 台账时看汇总表；
    定位失败案例时按明细表的"证据缺失/伪造"列逐行排查。
    """
    lines: list[str] = [f"# {round_title}", ""]
    lines.append(f"- 评测案例总数：{summary['total_cases']}")
    lines.append(f"- 生成时间：{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}（本地）")
    if skipped_mock:
        lines.append("")
        lines.append(f"> [警告] **防演示数据污染**：跳过 {len(skipped_mock)} 条 meta.mock=true 的 Mock 结果（"
                      + "、".join(str(p) for p, _ in skipped_mock) + "），未计入本报告。")
    if unpaired_agent:
        lines.append("")
        lines.append(f"> [警告] **未配对 Agent 输出**（标准答案中无对应 case_id）：{', '.join(unpaired_agent)}")
    if missed_truth:
        lines.append("")
        lines.append(f"> [警告] **Agent 未提交**（该 case 无任何输出）：{', '.join(missed_truth)}")

    lines += [
        "",
        "## 一、单轮评测指标汇总",
        "",
        "| 维度 | 指标 | 数值 |",
        "| --- | --- | --- |",
        f"| 检测 | 攻击检出率 Recall (TP/{summary['tp']}+{summary['fn']}) | {_fmt(summary['recall'], pct=True)} |",
        f"| 检测 | 正常业务误报率 FPR (FP/{summary['fp']}+{summary['tn']}) | {_fmt(summary['fpr'], pct=True)} |",
        f"| 检测 | 弃权率（单列统计） | {_fmt(summary['abstain_rate'], pct=True)} |",
        f"| 检测 | 恶意场景中被弃权数 abstain_but_should_detect | {summary['abstain_but_should_detect']} |",
        f"| 调查 | 诊断准确率（判定+IP+资产+类型四项全对） | {_fmt(summary['diagnosis_accuracy'], pct=True)} |",
        f"| 调查 | 风险等级一致率 | {_fmt(summary['risk_consistency'], pct=True)} |",
        f"| 证据 | 证据支持率 Evidence Recall（平均） | {_fmt(summary['evidence_recall_avg'], pct=True)} |",
        f"| 证据 | 伪造/无效证据计数 | {summary['hallucinated_total']} |",
        f"| 证据 | 非法输出（恶意判定但证据为空） | {summary['invalid_output_count']} |",
        f"| 防御 | 处置正确率（1.0=一致 / 0.5=近似封禁 / 0=错误） | {_fmt(summary['action_accuracy'])} |",
        f"| 防御 | 正常业务受损（误封）案例数 | {summary['false_block_count']} |",
        f"| 防御 | 审批合规率（高危动作共 {summary['high_risk_count']} 例） | {_fmt(summary['approval_compliance'], pct=True)} |",
        "",
        "## 二、逐案例得分明细",
        "",
        "| case_id | 判定 | 诊断 | 类型命中 | IP | 资产 | 证据召回 | 缺失证据 | 伪造证据 | 处置分 | 误封 | 审批合规 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cid, r in paired:
        # 审批列三态：None=不参与（非高危动作）/ True=合规 / False=违规
        if r["approval_ok"] is None:
            appr = "N/A"
        elif r["approval_ok"]:
            appr = "合规"
        else:
            appr = "违规"
        lines.append(
            "| {cid} | {label} | {diag} | {thit} | {ip} | {asset} | {evr} | {miss} | {hall} | {act} | {fblk} | {appr} |".format(
                cid=cid,
                label=r["label"],
                # 勾叉用中文"是/否"，避免特殊符号在 GBK 终端/编辑器下变成乱码问号
                diag="是" if r["diagnosis_ok"] else "否",
                thit="是" if r["type_hit"] else "否",
                ip="是" if r["ip_match"] else "否",
                asset="是" if r["asset_match"] else "否",
                evr=_fmt(r["evidence_recall"], pct=True),
                miss=str(len(r["evidence_missing"])) if r["evidence_missing"] else "0",
                hall=str(len(r["evidence_hallucinated"]) + len(r["evidence_bad_format"]))
                if (r["evidence_hallucinated"] or r["evidence_bad_format"])
                else "0",
                act=_fmt(r["action_score"]),
                fblk="是（误封）" if r["false_block"] else "否",
                appr=appr,
            )
        )
    # 为明细表附上缺失/伪造证据的具体编号，便于台账溯源
    detail_rows: list[str] = []
    for cid, r in paired:
        problems: list[str] = []
        if r["evidence_missing"]:
            problems.append("缺失: " + ", ".join(r["evidence_missing"]))
        if r["evidence_hallucinated"]:
            problems.append("伪造(不在日志包): " + ", ".join(r["evidence_hallucinated"]))
        if r["evidence_bad_format"]:
            problems.append("格式非法: " + ", ".join(r["evidence_bad_format"]))
        if r["evidence_invalid_output"]:
            problems.append("非法输出: 恶意判定但证据为空")
        if r["agent_attack_type"] == ABSTAIN_TYPE:
            problems.append("弃权(insufficient_evidence)")
        if problems:
            detail_rows.append(f"- **{cid}**：{'；'.join(problems)}")
    if detail_rows:
        lines += ["", "### 异常明细归因", ""]
        lines.extend(detail_rows)
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 评测主流程
# ---------------------------------------------------------------------------


def run_eval(
    truth_paths: list[str],
    agent_paths: Optional[list[str]] = None,
    agent_records: Optional[list[dict]] = None,
    logs_dir: Path = DEFAULT_LOGS_DIR,
    include_mock: bool = False,
    round_title: str = "单轮评测报告",
) -> str:
    """完整评测流程：加载 → mock 过滤 → 配对 → 单案例打分 → 汇总 → Markdown。

    Agent 结果有两个等价入口：
    - agent_paths：从磁盘目录/文件读取（正式 CLI 评测）；
    - agent_records：直接传入内存中的结果列表（selftest / 单元测试复用）。
    返回 Markdown 字符串；是否写文件 / 打印由 CLI 层决定，本函数保持纯函数。
    """
    truth_map = load_truth_map(truth_paths)
    real_ids = load_real_log_ids(logs_dir)

    skipped_mock: list[tuple[Path, str]] = []
    unpaired_agent: list[str] = []
    seen_cases: set[str] = set()
    paired: list[tuple[str, dict]] = []

    # 统一“从文件加载”与“内存注入”两种来源，后续逻辑只面向 (路径, 记录) 序列
    if agent_records is not None:
        agent_iter: list[tuple[Path, dict]] = [(Path("<memory>"), r) for r in agent_records]
    else:
        agent_iter = _iter_json_records(agent_paths or [])

    for path, record in agent_iter:
        # 防演示数据污染红线：Mock 结果默认直接跳过并告警
        if _extract_mock_flag(record) and not include_mock:
            skipped_mock.append((path, str(record.get("case_id", "?"))))
            continue
        case_id = _norm_text(record.get("case_id", ""))
        if not case_id:
            unpaired_agent.append(f"{path}(缺少 case_id)")
            continue
        if case_id not in truth_map:
            unpaired_agent.append(case_id)
            continue
        if case_id in seen_cases:
            raise ValueError(f"Agent 输出 case_id 重复：{case_id}（{path}）")
        seen_cases.add(case_id)
        paired.append((case_id, score_case(truth_map[case_id], record, real_ids.get(case_id))))

    missed_truth = [cid for cid in truth_map if cid not in seen_cases]
    summary = aggregate(paired)
    return render_markdown(
        summary, paired, skipped_mock, unpaired_agent, missed_truth, round_title
    )


# ---------------------------------------------------------------------------
# 自测模式：读取仓库内置 3 张标准答案卡 + 构造覆盖全部失败模式的模拟输出
# ---------------------------------------------------------------------------

def _selftest_agent_records() -> tuple[list[dict], list[dict]]:
    """构造两组模拟 Agent 输出，覆盖任务书要求的全部失败模式。

    第一轮（主评测，对应 3 张真实答案卡）：
    - CHAIN-CASE-01 全对：四维全部满分（验证算分上界）；
    - CHAIN-CASE-02 漏查证据 + 伪造编号：真实证据只引用 3/6，另塞一个
      不在日志包中的 id 与一个格式非法 id（验证证据召回扣分与伪造计数）；
    - CHAIN-CASE-03 误报：把正常运维判成数据外泄并建议封禁（验证 FPR、
      诊断不命中、误封与审批合规联动）。
    第二轮（弃权专项）：
    - 两个恶意场景输出 insufficient_evidence（验证弃权单列、
      abstain_but_should_detect=2，且不计入 FN）；
    - 正常场景正确输出 none（验证弃权不影响 TN 统计）。
    """
    round1 = [
        {   # 全对样例：字段与 truth 完全一致
            "case_id": "CHAIN-CASE-01",
            "is_malicious": True,
            "attack_type": "SQL_Injection_After_Brute_Force",
            "risk_level": "HIGH",
            "attacker_ip": "198.51.100.23",
            "victim_asset": "web-prod-01",
            "evidence_log_ids": [
                "LOG-20261027-0103", "LOG-20261027-0104", "LOG-20261027-0112",
                "LOG-20261027-0113", "LOG-20261027-0126", "LOG-20261027-0127",
            ],
            "attack_chain_summary": "攻击源先扫描后台入口，再爆破 admin 失败，最后 sqlmap 注入绕过认证并导出 users/orders 表。",
            "recommended_action": "block_ip",
            "requires_human_approval": True,
            "unknown_items": "",
        },
        {   # 漏查证据 + 伪造编号：召回 3/6=50%，并触发格式校验与日志包存在性校验
            "case_id": "CHAIN-CASE-02",
            "is_malicious": True,
            "attack_type": "Webshell_Upload",  # 关键词命中 truth 的 Webshell_Upload_And_C2_Callback
            "risk_level": "HIGH",
            "attacker_ip": "203.0.113.45",
            "victim_asset": "web-prod-01",
            "evidence_log_ids": [
                "LOG-20261028-0206", "LOG-20261028-0207", "LOG-20261028-0211",
                "LOG-99999999-9999",      # 格式非法：月份 99 不存在但正则可过 → 用日志包校验抓出
                "LOG-20261028-9999",      # 格式合法但不在真实日志包 → 伪造证据
            ],
            "attack_chain_summary": "上传 webshell 后执行命令，存在外连行为，但未完成全链取证。",
            "recommended_action": "block_ip_short_term",  # 与 truth 的 block_ip 构成近似 → 0.5 分
            "requires_human_approval": True,
            "unknown_items": "未获取 Zeek 外连日志，C2 归属待确认。",
        },
        {   # 误报样例：正常运维被判为内部数据外泄并误封（FP + 误封 + 审批违规）
            "case_id": "CHAIN-CASE-03",
            "is_malicious": True,
            "attack_type": "Insider_Data_Exfiltration",
            "risk_level": "CRITICAL",
            "attacker_ip": "10.0.0.66",
            "victim_asset": "web-prod-01",
            "evidence_log_ids": ["LOG-20261029-0313"],
            "attack_chain_summary": "内网账号批量导出订单表，疑似数据外泄。",
            "recommended_action": "block_ip",  # truth 为 none → 0 分 + 误封标记
            "requires_human_approval": False,  # 高危动作但未请求审批 → 审批违规
            "unknown_items": "未核实维护窗口。",
        },
    ]
    round2 = [
        {   # 恶意场景弃权：不计 FN，单列 abstain_but_should_detect
            "case_id": "CHAIN-CASE-01",
            "is_malicious": False,
            "attack_type": "insufficient_evidence",
            "risk_level": "LOW",
            "attacker_ip": "198.51.100.23",
            "victim_asset": "web-prod-01",
            "evidence_log_ids": [],
            "attack_chain_summary": "日志查询超时，无法完成取证，转人工处理。",
            "recommended_action": "none",
            "requires_human_approval": True,
            "unknown_items": "缺少 nginx 与 auth 日志。",
        },
        {   # 正常场景弃权：不应计入 FP/TN，仅观察弃权率
            "case_id": "CHAIN-CASE-03",
            "is_malicious": False,
            "attack_type": "insufficient_evidence",
            "risk_level": "LOW",
            "attacker_ip": "10.0.0.66",
            "victim_asset": "web-prod-01",
            "evidence_log_ids": [],
            "attack_chain_summary": "证据不足，无法判断是否为白名单运维。",
            "recommended_action": "none",
            "requires_human_approval": True,
            "unknown_items": "缺少运维基线数据。",
        },
    ]
    return round1, round2


def run_selftest(truth_paths: Optional[list[str]] = None) -> int:
    """自测入口：两轮模拟评测 + 断言关键指标，全部通过返回 0。

    断言使用近似比较（浮点）与精确计数，覆盖任务书列出的四类场景：
    全对 / 漏查证据 / 误报 / 弃权。任何断言失败都会打印原因并返回 1。
    """
    _force_utf8_stdout()
    if truth_paths is None:
        # 默认用仓库内置标准答案卡（A 组 W1 冻结产物）
        truth_paths = [str(DEFAULT_TRUTH_DIR)]
    round1, round2 = _selftest_agent_records()
    real_ids = load_real_log_ids(DEFAULT_LOGS_DIR)

    # 第一轮：主评测（复用 run_eval 的内存注入入口，保持与 CLI 完全一致的算分路径）
    print("=" * 64)
    print("【自测 · 第一轮】主评测：全对 / 漏证据+伪造 / 误报")
    print("=" * 64)
    report1 = run_eval(
        truth_paths=truth_paths,
        agent_records=round1,
        round_title="自测 · 主评测轮",
    )
    print(report1)
    truth_map = load_truth_map(truth_paths)
    # truth_map 的键经 _norm_text 归一化（小写），内存记录的 case_id 需同样归一化后再查
    paired1 = [
        (r["case_id"], score_case(truth_map[_norm_text(r["case_id"])], r,
                                  real_ids.get(_norm_text(r["case_id"]))))
        for r in round1
    ]
    summary1 = aggregate(paired1)

    # 第二轮：弃权专项
    print("=" * 64)
    print("【自测 · 第二轮】弃权专项：恶意场景弃权单列，不混入 FN/FP")
    print("=" * 64)
    paired2 = [
        (r["case_id"], score_case(truth_map[_norm_text(r["case_id"])], r,
                                  real_ids.get(_norm_text(r["case_id"]))))
        for r in round2
    ]
    summary2 = aggregate(paired2)
    print(render_markdown(summary2, paired2, [], [], [], "自测 · 弃权专项轮"))

    # ---- 断言区：任何一项失败即自测不通过 ----
    checks: list[tuple[str, bool]] = [
        ("CASE-01 应为 TP（全对）", paired1[0][1]["label"] == "TP"),
        ("CASE-01 诊断应全对", paired1[0][1]["diagnosis_ok"] is True),
        ("CASE-01 处置分应 1.0", paired1[0][1]["action_score"] == 1.0),
        ("CASE-02 证据召回应 50%（3/6）", abs(paired1[1][1]["evidence_recall"] - 0.5) < 1e-9),
        ("CASE-02 应检出 2 条伪造/无效证据",
         len(paired1[1][1]["evidence_hallucinated"]) + len(paired1[1][1]["evidence_bad_format"]) == 2),
        ("CASE-02 近似封禁应得 0.5 分", paired1[1][1]["action_score"] == 0.5),
        ("CASE-03 应为 FP（误报）", paired1[2][1]["label"] == "FP"),
        ("CASE-03 应标记误封", paired1[2][1]["false_block"] is True),
        ("CASE-03 审批应违规", paired1[2][1]["approval_ok"] is False),
        ("主评测 FPR 应 100%（1 个正常场景全误报）", summary1["fpr"] == 1.0),
        ("弃权轮 CASE-01 应为 ABSTAIN", paired2[0][1]["label"] == "ABSTAIN"),
        ("弃权轮 abstain_but_should_detect 应为 1", summary2["abstain_but_should_detect"] == 1),
        ("弃权轮 Recall 不应被弃权污染（TP+FN=0 → None）", summary2["recall"] is None),
    ]
    failed = [name for name, ok in checks if not ok]
    print("=" * 64)
    if failed:
        print(f"[失败] 自测未通过，共 {len(failed)} 项断言失败：")
        for name in failed:
            print(f"   - {name}")
        return 1
    print(f"[通过] 自测全部通过（{len(checks)} 项断言）")
    return 0


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eval_runner",
        description="恒脑自主安全智能体 · 四维自动化评测算分脚本（检测/调查/证据/防御）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：python scripts/eval_runner.py --selftest",
    )
    parser.add_argument("--truth", nargs="*", default=None,
                        help="标准答案卡目录/文件（默认 data/full_chain_logs）")
    parser.add_argument("--agent", nargs="*", default=None,
                        help="Agent 输出 JSON 目录/文件（11 字段契约）")
    parser.add_argument("--logs-dir", default=str(DEFAULT_LOGS_DIR),
                        help="真实日志包目录，用于证据存在性校验")
    parser.add_argument("--output", default=None,
                        help="评测报告输出路径（.md）；缺省仅打印到控制台")
    parser.add_argument("--include-mock", action="store_true",
                        help="允许 meta.mock=true 的演示数据参与评测（默认跳过并告警）")
    parser.add_argument("--selftest", action="store_true",
                        help="自测模式：读取内置标准答案卡 + 模拟 Agent 输出运行算分")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    _force_utf8_stdout()
    args = build_parser().parse_args(argv)

    # --selftest 优先：无需任何外部输入即可验证脚本正确性
    if args.selftest:
        return run_selftest(truth_paths=args.truth)

    if not args.agent:
        print("错误：正式评测需要 --agent 指定 Agent 输出路径；"
              "若只想验证脚本可用，请运行 python scripts/eval_runner.py --selftest")
        return 2
    truth_paths = args.truth if args.truth else [str(DEFAULT_TRUTH_DIR)]

    try:
        report = run_eval(
            truth_paths=truth_paths,
            agent_paths=args.agent,
            logs_dir=Path(args.logs_dir),
            include_mock=args.include_mock,
            round_title="恒脑 Agent 单轮评测报告",
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"评测失败：{exc}")
        return 2

    print(report)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        print(f"[已保存] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
