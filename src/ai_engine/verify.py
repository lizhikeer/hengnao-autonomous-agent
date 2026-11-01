"""模型输出的程序校验（纯标准库实现，由本地服务和测试调用）。

与 `results_schema.AgentResults` 的分工：
* 本模块做**结构 + 业务规则**校验，不依赖 pydantic；实际平台 handler 通过服务端接口调用；
* `AgentResults` 做**类型 + 多余字段**的严格校验，在服务端与测试里兜底。

两者规则同源（见 `design/hengnao_workflows/week1_workflow_design.md` §3.4），
测试 `tests/test_contract_adversarial.py` 会用同一批对抗样本同时打这两层。

为什么要有这一层：
模型节点开了 Guided JSON 也不能保证输出干净——它仍可能包 ```json 代码块、
把 HIGH 写成"高危"、把数组写成字符串、或者判了恶意却一条证据都不给。
这些错误在进入处置环节前必须被拦住，且要给出人能看懂的拒绝理由。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

LOG_ID_RE = re.compile(r"^LOG-\d{8}-\d{4}$")

REQUIRED_FIELDS = (
    "case_id",
    "is_malicious",
    "attack_type",
    "risk_level",
    "attacker_ip",
    "victim_asset",
    "evidence_log_ids",
    "attack_chain_summary",
    "recommended_action",
    "requires_human_approval",
    "unknown_items",
)
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTIONS = ("block_ip", "block_ip_short_term", "rate_limit", "none")
HIGH_RISK_ACTIONS = ("block_ip", "block_ip_short_term")
INSUFFICIENT = "insufficient_evidence"


@dataclass
class VerifyResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        return "校验通过" if self.ok else "；".join(self.problems)


def strip_code_fence(raw: str) -> str:
    """去掉模型常见的外层 ```json ... ``` 包装与首尾空白。"""
    text = (raw or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def verify_triage(
    raw: str | dict[str, Any], *,
    evidence_log_ids: list[str] | None = None,
    case_id: str | None = None,
) -> VerifyResult:
    """校验一次研判输出，返回是否可进入后续处置环节。"""
    problems: list[str] = []

    if isinstance(raw, dict):
        data = raw
    else:
        text = strip_code_fence(str(raw))
        try:
            data = json.loads(text)
        except Exception as exc:
            return VerifyResult(False, [f"输出不是合法 JSON：{exc}"], {})
        if not isinstance(data, dict):
            return VerifyResult(False, ["输出不是 JSON 对象"], {})

    missing = [k for k in REQUIRED_FIELDS if k not in data]
    if missing:
        problems.append("缺少必填字段：" + ",".join(missing))

    # --- 证据数组 ---
    ids = data.get("evidence_log_ids", [])
    if not isinstance(ids, list):
        problems.append("evidence_log_ids 必须是数组")
        ids = []
    bad_type = [i for i in ids if not isinstance(i, str)]
    if bad_type:
        problems.append(f"证据编号必须为字符串：{bad_type[:3]}")
    bad_fmt = [i for i in ids if isinstance(i, str) and not LOG_ID_RE.match(i)]
    if bad_fmt:
        problems.append("证据编号格式非法（应为 LOG-YYYYMMDD-NNNN）：" + ",".join(bad_fmt[:5]))
    dup = sorted({i for i in ids if isinstance(i, str) and ids.count(i) > 1})
    if dup:
        problems.append("证据编号重复：" + ",".join(dup[:5]))

    if case_id is not None and data.get("case_id") != case_id:
        problems.append("输出 case_id 与当前调查不一致")
    if evidence_log_ids is not None:
        known = set(evidence_log_ids)
        foreign = [i for i in ids if isinstance(i, str) and i not in known]
        if foreign:
            problems.append("引用了本次工具查询未返回的证据：" + ",".join(foreign))

    # --- 布尔字段不能被字符串糊弄 ---
    if not isinstance(data.get("is_malicious"), bool):
        problems.append("is_malicious 必须是布尔值")
    if not isinstance(data.get("requires_human_approval"), bool):
        problems.append("requires_human_approval 必须是布尔值")

    # --- 枚举 ---
    if data.get("risk_level") not in RISK_LEVELS:
        problems.append(f"risk_level 取值非法：{data.get('risk_level')!r}，应为 {'/'.join(RISK_LEVELS)}")
    if data.get("recommended_action") not in ACTIONS:
        problems.append(
            f"recommended_action 取值非法：{data.get('recommended_action')!r}，应为 {'/'.join(ACTIONS)}"
        )

    # --- 结论与证据的联动 ---
    is_malicious = data.get("is_malicious") is True
    if is_malicious and not ids:
        problems.append("判定为恶意但未提供任何证据编号")
    if not ids and data.get("attack_type") != INSUFFICIENT:
        problems.append("无证据时 attack_type 必须为 insufficient_evidence，不得给出具体攻击结论")
    if data.get("attack_type") == INSUFFICIENT and data.get("requires_human_approval") is not True:
        problems.append("证据不足时必须标记 requires_human_approval=true，交人工复核")

    # --- 高危动作必须审批 ---
    if data.get("recommended_action") in HIGH_RISK_ACTIONS and data.get("requires_human_approval") is not True:
        problems.append("高危动作必须把 requires_human_approval 置为 true")

    # --- 空值检查 ---
    for key in ("case_id", "attack_type", "attacker_ip", "victim_asset", "attack_chain_summary"):
        if isinstance(data.get(key), str) and not data[key].strip():
            problems.append(f"{key} 不能为空字符串")

    return VerifyResult(not problems, problems, data)


def main(args):
    """恒脑代码节点入口。query_results 必须绑定实际查询节点输出，不能取自模型。"""
    rows = args.get("query_results", [])
    if isinstance(rows, str):
        try:
            rows = json.loads(rows)
        except (ValueError, TypeError):
            rows = None
    if isinstance(rows, dict):
        rows = rows.get("items")
    case_id = args.get("case_id")
    if not isinstance(rows, list) or not isinstance(case_id, str) or not case_id.strip():
        return {"verified": False, "verify_msg": "缺少当前案例编号或可信查询返回", "triage": {}}
    ids = [row["log_id"] for row in rows
           if isinstance(row, dict) and isinstance(row.get("log_id"), str)]
    result = verify_triage(args.get("triage", ""), evidence_log_ids=ids, case_id=case_id)
    return {"verified": result.ok, "verify_msg": result.summary(), "triage": result.data}
