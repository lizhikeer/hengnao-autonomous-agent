"""Agent 结构化输出契约（Issue #4 冻结的 11 字段）。

用途有三：
1. **恒脑【结束节点】结构化输出**的字段定义 —— 平台 Open API 会把它原样放进 ``results``；
2. **Guided JSON** 约束的 Schema 来源 —— 模型节点开 Guided JSON 时必须粘贴完整
   ``{"type":"object","properties":{...},"required":[...]}``，且 ``required`` 不得为空；
3. **评测脚本（@zyh060911）无损解析**的基准 —— 字段名、类型、枚举值一律不可临时改动。

为什么用 Pydantic 生成而不是手写 JSON
------------------------------------
手写 JSON Schema 与代码容易漂移：改了模型没改文件，评测端就会拿到过期契约。
这里以 ``AgentResults`` 为唯一真源，``schemas/agent_results.schema.json`` 由
``write_schema_file()`` 生成，测试里断言文件与代码完全一致（``assert_schema_in_sync``）。

关于"证据不足"的表达（重要，勿误读）
------------------------------------
Issue #4 冻结的 11 个字段里 ``is_malicious`` 是布尔值，没有"未知"这一态。
因此**证据不足时不允许直接判为非恶意**：
``build_insufficient_evidence()`` 会产出 ``attack_type="insufficient_evidence"``、
``risk_level="LOW"``、``requires_human_approval=True``，并在 ``unknown_items``
中逐条写明缺什么证据，让下游（人、算分脚本）能一眼区分"查清了没事"与"没查清"。
设计说明书 v0.2 §9 的 ``verdict``（BENIGN/SUSPICIOUS/MALICIOUS/INSUFFICIENT_DATA）
四态是更理想的表达，但它是另一套更细的输出契约，本周不擅自改动 Issue 已冻结的字段，
只作为后续迭代建议登记在 week1_workflow_design.md。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SCHEMA_PATH = SCHEMA_DIR / "agent_results.schema.json"
EXAMPLE_PATH = SCHEMA_DIR / "agent_results.example.json"

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
RECOMMENDED_ACTIONS = ("block_ip", "block_ip_short_term", "rate_limit", "none")
INSUFFICIENT_ATTACK_TYPE = "insufficient_evidence"


class AgentResults(BaseModel):
    """Agent 结束节点 ``results`` 的强契约。11 个字段全部必填。"""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"$schema": "https://json-schema.org/draft/2020-12/schema"},
    )

    case_id: str = Field(
        min_length=1,
        max_length=64,
        description="本次调查的案例编号，与评测集/日志包的 case_id 对齐",
        examples=["EVAL-CHAIN-001"],
    )
    is_malicious: bool = Field(
        description="是否判定为恶意。注意：证据不足时不得据此为 false 推断'安全'，须看 attack_type 与 unknown_items",
        examples=[True],
    )
    attack_type: str = Field(
        min_length=1,
        max_length=128,
        description="攻击类型（自由文本，建议用下划线连接的多阶段描述）；证据不足时固定填 insufficient_evidence",
        examples=["SQL_Injection_After_Brute_Force"],
    )
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="风险等级四档：LOW/MEDIUM/HIGH/CRITICAL",
        examples=["HIGH"],
    )
    attacker_ip: str = Field(
        min_length=1,
        max_length=64,
        description="攻击源 IP。禁止编造：必须是本次已查询日志中出现过的地址",
        examples=["198.51.100.23"],
    )
    victim_asset: str = Field(
        min_length=1,
        max_length=128,
        description="受害资产标识（asset_id 或 IP），同样须来自已查询证据",
        examples=["web-prod-01"],
    )
    evidence_log_ids: list[str] = Field(
        description="支撑结论的证据日志编号列表，每个编号必须由本次调查的 /tools/query_logs 真实返回；"
        "伪造或跨 case 引用会被 /tools/request_response 拒绝。"
        "空数组是合法取值，含义是'本次未取得可引用证据'，此时 attack_type 必须为 insufficient_evidence "
        "且 requires_human_approval 必须为 true（由模型校验强制）；绝不允许塞入占位编号充数",
        examples=[["LOG-20261027-0001", "LOG-20261027-0008", "LOG-20261027-0015"]],
    )
    attack_chain_summary: str = Field(
        min_length=1,
        max_length=2000,
        description="攻击链中文摘要：按阶段还原攻击者做了什么、成功了没有",
        examples=[
            "攻击源 198.51.100.23 先对 /admin 执行账号爆破失败，"
            "随后针对登录接口发起 SQL 注入绕过认证并尝试导出敏感表数据。"
        ],
    )
    recommended_action: Literal["block_ip", "block_ip_short_term", "rate_limit", "none"] = Field(
        description="处置建议：block_ip(封禁)/block_ip_short_term(短时封禁)/rate_limit(限速)/none(无需处置)",
        examples=["block_ip"],
    )
    requires_human_approval: bool = Field(
        description="是否需要人工审批。高危动作、证据不足、结论不确定时必须为 true",
        examples=[True],
    )
    unknown_items: str = Field(
        description="未确认事项说明（可为空字符串，但字段必须存在）。"
        "证据不足时必须逐条写明缺什么，不得用'无'敷衍",
        examples=["暂未获取到数据库内部审计日志，需进一步确认敏感表具体泄露行数。"],
    )

    # -- 契约联动校验（防止"证据不足却下结论"这类幻觉） -------------------

    @model_validator(mode="after")
    def _check_evidence_consistency(self) -> "AgentResults":
        if not self.evidence_log_ids:
            if self.attack_type != INSUFFICIENT_ATTACK_TYPE:
                raise ValueError(
                    "evidence_log_ids 为空时 attack_type 必须为 insufficient_evidence："
                    "没有证据不得给出具体攻击类型结论"
                )
            if not self.requires_human_approval:
                raise ValueError("证据为空时必须标记 requires_human_approval=true，交人工复核")
        if self.is_malicious and not self.evidence_log_ids:
            raise ValueError("判定为恶意时 evidence_log_ids 不得为空：恶意结论必须有日志支撑")
        return self

    # -- 派生判断（不进入 JSON 输出，避免污染契约） -------------------------

    @property
    def is_insufficient(self) -> bool:
        """是否为"证据不足"这一特殊结论。"""
        return self.attack_type == INSUFFICIENT_ATTACK_TYPE

    def to_results(self) -> dict[str, Any]:
        """导出为结束节点 ``results`` 使用的纯 dict。"""
        return self.model_dump()


def model_json_schema() -> dict[str, Any]:
    """当前代码对应的正式 JSON Schema（``required`` 为 11 个字段，非空）。"""
    return AgentResults.model_json_schema()


def write_schema_file() -> Path:
    """把代码生成的 Schema 落盘（维护时用，非运行时调用）。"""
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(
        json.dumps(model_json_schema(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return SCHEMA_PATH


def load_schema() -> dict[str, Any]:
    """读取落盘的 Schema 文件。"""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def load_example() -> dict[str, Any]:
    """读取示例 results（用于契约自检与文档引用）。"""
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


def validate_results(payload: dict[str, Any]) -> AgentResults:
    """按契约校验一个 results 字典，非法时抛 ``pydantic.ValidationError``。"""
    return AgentResults.model_validate(payload)


def assert_schema_in_sync() -> None:
    """断言落盘 Schema 与代码一致（测试用）。"""
    if not SCHEMA_PATH.exists():
        raise AssertionError(f"缺少 Schema 文件：{SCHEMA_PATH}，请先运行 write_schema_file()")
    on_disk = load_schema()
    generated = model_json_schema()
    if on_disk != generated:
        raise AssertionError(
            "agent_results.schema.json 与 AgentResults 模型不一致，"
            "请运行 python -c \"from ai_engine.results_schema import write_schema_file; write_schema_file()\" 重新生成"
        )


def build_insufficient_evidence(
    *,
    case_id: str,
    attacker_ip: str,
    victim_asset: str,
    evidence_log_ids: list[str],
    missing: list[str],
    summary: str = "",
    risk_level: str = "LOW",
) -> AgentResults:
    """构造"证据不足"结论：不把查不清当成没事。

    - ``attack_type`` 固定为 ``insufficient_evidence``，与真实的 ``none``（查清了没事）区分；
    - ``requires_human_approval`` 恒为 True，强制人工介入；
    - ``unknown_items`` 逐条列出缺失证据。
    """
    unknown = "；".join(missing) if missing else "证据链不完整，具体缺失项未明确"
    return AgentResults(
        case_id=case_id,
        is_malicious=False,
        attack_type=INSUFFICIENT_ATTACK_TYPE,
        risk_level=risk_level,  # type: ignore[arg-type]
        attacker_ip=attacker_ip or "unknown",
        victim_asset=victim_asset or "unknown",
        evidence_log_ids=list(evidence_log_ids),
        attack_chain_summary=summary
        or "现有证据不足以判定攻击是否成立，未作出恶意结论；已列出缺失证据，需补充调查或人工复核。",
        recommended_action="none",
        requires_human_approval=True,
        unknown_items=f"证据不足未定论。缺失项：{unknown}",
    )
