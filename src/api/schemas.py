"""SecLog 工具服务的 Pydantic 请求 / 响应模型。

面向恒脑平台【API 工具】注册要求：
- 每个参数必须带明确语义描述（description）与样例值（examples），
  这是恒脑大模型构造 HTTP 请求的唯一依据（见 docs/平台文档/恒脑平台核心开发参考手册_LLM.md 第四节）。
- 仅使用 GET / POST。
- 所有查询结果区分：零结果（200 空列表）、参数错误（422）、后端失败（503）。
- 真实后端（ClickHouse / Qdrant / 权限网关）未接入时，Mock 数据带 ``mock: true``
  与 ``data_source: "mock"`` 显式标识，绝不伪装成真实查询成功。
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from .config import (
    ALLOWED_LOG_SOURCES,
    LIMIT_MAX,
    LIMIT_MIN,
    TIME_WINDOW_MAX_MINUTES,
    TIME_WINDOW_MIN_MINUTES,
)

# ---------------------------------------------------------------------------
# 通用结构
# ---------------------------------------------------------------------------


class QueryMeta(BaseModel):
    """查询元信息：标识数据来源、是否 Mock、以及后端可用性。"""

    reference_time: Optional[str] = Field(default=None, description="日志时间窗的回放基准时刻；仅 Mock 查询提供", examples=["2026-10-27T14:26:00+00:00"])
    total: int = Field(
        description="本次查询命中的日志/记录总数（分页前）",
        examples=[3, 0],
    )
    data_source: Literal["mock"] = Field(
        description='数据来源标识。第一周骨架固定为 "mock"；接入真实 ClickHouse/Qdrant 后变更为 "clickhouse"/"qdrant"',
        examples=["mock"],
    )
    mock: Literal[True] = Field(
        description="恒为 true 直到真实后端接入。消费方（恒脑模型节点）必须把 mock 数据视为演示样例而非真实证据",
        examples=[True],
    )
    backend_available: bool = Field(
        description="真实后端是否可用。骨架阶段恒为 false；false 时返回的数据仅是 Mock 样例",
        examples=[False],
    )


class VerifyResultsRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=64, description="来自工作流开始节点的案例编号", examples=["EVAL-CHAIN-001"])
    results: dict[str, Any] = Field(description="待校验的模型结构化结论", examples=[{"case_id": "EVAL-CHAIN-001"}])


class ErrorBody(BaseModel):
    """标准错误体。"""

    code: Literal[
        "invalid_params",
        "backend_unavailable",
        "not_found",
        "evidence_rejected",
        "approval_required",
        "permission_service_unavailable",
    ] = Field(description="机器可读错误码", examples=["backend_unavailable"])
    message: str = Field(
        description="人类可读错误说明（中文）",
        examples=["ClickHouse 后端未接入，当前仅提供 Mock 数据"],
    )
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="补充信息，例如被拒绝的证据编号列表、参数校验失败明细",
        examples=[{"rejected_log_ids": ["LOG-FAKE-999"]}],
    )


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """健康检查响应：恒脑平台第一周连通性调试准入验证用。"""

    status: Literal["ok"] = Field(description="服务健康状态", examples=["ok"])
    service: Literal["seclog-tool-service"] = Field(
        description="服务名", examples=["seclog-tool-service"]
    )
    version: str = Field(description="服务版本号", examples=["0.1.0"])
    mock_mode: Literal[True] = Field(
        description="恒为 true：第一周所有查询工具均为 Mock 实现",
        examples=[True],
    )


# ---------------------------------------------------------------------------
# POST /tools/query_logs
# ---------------------------------------------------------------------------


class QueryLogsRequest(BaseModel):
    """全链路关联日志查询请求（ClickHouse 后端，当前 Mock）。

    至少提供一个过滤条件（src_ip / dest_ip / trace_id / log_source 非 all），
    避免无界全表扫描。
    """

    case_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"\S",
        description="本次调查案例编号。带上后返回的 log_id 只能由同一 case 引用；不带只查询，不登记处置证据",
        examples=["EVAL-CHAIN-001"],
    )
    src_ip: Optional[str] = Field(
        default=None,
        description="源 IP 过滤，IPv4/IPv6 格式。攻击溯源时通常填可疑攻击源 IP",
        examples=["198.51.100.23"],
    )
    dest_ip: Optional[str] = Field(
        default=None,
        description="目标 IP 过滤（受害资产 IP）",
        examples=["10.0.0.15"],
    )
    trace_id: Optional[str] = Field(
        default=None,
        description="全链路追踪 ID，用于串联同一攻击故事链的多阶段日志",
        examples=["CHAIN-ATTACK-01"],
    )
    log_source: Literal["nginx_access", "auth_log", "zeek_conn", "zeek_http", "all"] = Field(
        default="all",
        description="日志来源白名单枚举：nginx_access(Web访问)/auth_log(认证)/zeek_conn(网络流)/zeek_http(HTTP还原)/all(全部)",
        examples=["nginx_access"],
    )
    time_window: Optional[str] = Field(
        default=None,
        pattern=r"^\d{1,4}[mhd]$",
        description="相对回溯时间窗，单位 m(分钟)/h(小时)/d(天)，如 30m、1h、7d。与 time_window_minutes 二选一；都不填时默认 1h",
        examples=["1h"],
    )
    time_window_minutes: Optional[int] = Field(
        default=None,
        ge=TIME_WINDOW_MIN_MINUTES,
        le=TIME_WINDOW_MAX_MINUTES,
        description="相对回溯时间窗（分钟），1 ~ 10080（7 天）。与 time_window 二选一，冲突时返回参数错误",
        examples=[60],
    )
    limit: int = Field(
        default=50,
        ge=LIMIT_MIN,
        le=LIMIT_MAX,
        description="返回条数上限，1 ~ 200，默认 50",
        examples=[50],
    )


class LogItem(BaseModel):
    """单条标准化日志（字段对齐全链路日志统一 Schema）。"""

    log_id: str = Field(description="日志唯一编号，Agent 证据引用必须使用此 ID", examples=["LOG-20261027-0001"])
    trace_id: str = Field(description="全链路追踪 ID", examples=["CHAIN-ATTACK-01"])
    timestamp: str = Field(description="日志时间，ISO8601 UTC", examples=["2026-10-27T14:20:05Z"])
    log_source: str = Field(description="日志来源", examples=["nginx_access"])
    src_ip: str = Field(description="源 IP", examples=["198.51.100.23"])
    dest_ip: str = Field(description="目标 IP", examples=["10.0.0.15"])
    asset_id: Optional[str] = Field(default=None, description="受害资产 ID", examples=["web-prod-01"])
    user: Optional[str] = Field(default=None, description="涉及账号", examples=["admin"])
    action_or_method: Optional[str] = Field(default=None, description="HTTP 方法或动作", examples=["POST"])
    uri_or_target: Optional[str] = Field(default=None, description="URI 或攻击目标", examples=["/admin/login.php"])
    payload_summary: Optional[str] = Field(default=None, description="载荷摘要", examples=["username=admin&password=' OR 1=1--"])
    status_code: Optional[int] = Field(default=None, description="HTTP 状态码", examples=[200])
    user_agent: Optional[str] = Field(default=None, description="User-Agent", examples=["sqlmap/1.7.2"])
    attack_stage_hint: Optional[str] = Field(
        default=None,
        description="攻击阶段提示：recon/brute_force/exploitation/c2_callback/benign",
        examples=["exploitation"],
    )


class QueryLogsResponse(BaseModel):
    """日志查询响应。零结果时 items 为空数组且 total=0（HTTP 200），
    后端失败时返回 503 + ErrorBody，两者不可混淆。"""

    meta: QueryMeta = Field(description="查询元信息（含 Mock 标识）")
    items: list[LogItem] = Field(description="命中的日志列表，零结果为空数组")


# ---------------------------------------------------------------------------
# POST /tools/get_context
# ---------------------------------------------------------------------------


class GetContextRequest(BaseModel):
    """用户画像 + 资产上下文合并查询请求。"""

    user: Optional[str] = Field(
        default=None,
        description="目标账号名（与 asset_id 至少填一项）",
        examples=["admin"],
    )
    asset_id: Optional[str] = Field(
        default=None,
        description="目标资产 ID（与 user 至少填一项）",
        examples=["web-prod-01"],
    )


class GetContextResponse(BaseModel):
    """整合 get_user_profile 与 get_asset_context 的响应。"""

    meta: QueryMeta = Field(description="查询元信息（含 Mock 标识）")
    user_profile: Optional[dict[str, Any]] = Field(
        default=None,
        description="用户行为基线：历史活跃时段、常用源 IP、近期登录成败统计",
        examples=[{"user": "admin", "active_hours": "09:00-19:00 CST", "common_src_ips": ["203.0.113.7"], "failed_logins_24h": 0}],
    )
    asset_context: Optional[dict[str, Any]] = Field(
        default=None,
        description="资产上下文：重要性等级、维护窗口、白名单状态",
        examples=[{"asset_id": "web-prod-01", "importance": "HIGH", "maintenance_window": None, "whitelisted": False}],
    )


# ---------------------------------------------------------------------------
# POST /tools/search_knowledge
# ---------------------------------------------------------------------------


class SearchKnowledgeRequest(BaseModel):
    """安全知识卡 / 已确认案例卡混合检索请求（Qdrant 后端，当前 Mock）。"""

    query: str = Field(
        min_length=2,
        max_length=500,
        description="检索问题或现象描述（中文/英文均可），例如攻击特征、处置方法",
        examples=["SQL 注入绕过认证后如何处置，是否需要短时封禁 IP"],
    )
    attack_category: Optional[str] = Field(
        default=None,
        description="按攻击类别过滤，如 SQL_Injection / Brute_Force / XSS / Path_Traversal",
        examples=["SQL_Injection"],
    )
    limit: int = Field(
        default=5,
        ge=1,
        le=20,
        description="返回知识卡数量上限，1 ~ 20，默认 5",
        examples=[5],
    )


class KnowledgeCard(BaseModel):
    """知识卡（结构对齐 docs/project design/项目分工与前期架构设计.md 5.2）。"""

    card_id: str = Field(description="卡片唯一编号", examples=["KB-OWASP-SQLI-001"])
    card_type: Literal["security_knowledge", "verified_correct_case", "verified_error_revision"] = Field(
        description="卡片类型：安全知识/已确认正确案例/已确认错误修订案例",
        examples=["security_knowledge"],
    )
    title: str = Field(description="卡片标题", examples=["SQL 注入攻击调查与处置指南"])
    attack_category: Optional[str] = Field(default=None, description="攻击类别", examples=["SQL_Injection"])
    mitre_id: Optional[str] = Field(default=None, description="MITRE ATT&CK 技术编号", examples=["T1190"])
    key_indicators: list[str] = Field(default_factory=list, description="关键判别特征列表")
    recommended_action: Optional[str] = Field(default=None, description="推荐处置动作", examples=["block_ip_short_term"])
    score: float = Field(description="检索相关度得分 0~1", examples=[0.87])


class SearchKnowledgeResponse(BaseModel):
    """知识检索响应。零结果（无匹配卡片）时 items 为空数组。"""

    meta: QueryMeta = Field(description="查询元信息（含 Mock 标识）")
    items: list[KnowledgeCard] = Field(description="匹配的知识卡/案例卡列表")


# ---------------------------------------------------------------------------
# POST /tools/request_response
# ---------------------------------------------------------------------------


class RequestResponseRequest(BaseModel):
    """处置动作提交请求。

    程序性安全约束（骨架阶段即强制）：
    - evidence_log_ids 中每个 ID 必须属于**当前调查会话已通过 /tools/query_logs 查询返回**的证据，
      伪造 ID 或引用其他调查任务的证据会被拒绝（evidence_rejected）。
    - 高危动作（block_ip 等）在权限服务未接入时一律不执行，返回 approval_required +
      permission_service_unavailable 状态，等待恒脑【交互节点】人工审批结果。
    - 模型自称"已审批"不构成授权：审批状态只能来自权限网关/交互节点的程序化回执。
    """

    case_id: str = Field(
        min_length=1,
        max_length=64,
        description="本次调查案例编号，用于隔离证据归属（不同 case 的证据不可混用）",
        examples=["EVAL-CHAIN-001"],
    )
    action: Literal["block_ip", "block_ip_short_term", "rate_limit", "none"] = Field(
        description="处置动作白名单枚举：block_ip(封禁IP,高危)/block_ip_short_term(短时封禁,高危)/rate_limit(限速,低危)/none(无需处置)",
        examples=["block_ip"],
    )
    target_ip: Optional[str] = Field(
        default=None,
        description="处置目标 IP（action 为 block_ip/block_ip_short_term/rate_limit 时必填）",
        examples=["198.51.100.23"],
    )
    evidence_log_ids: list[str] = Field(
        default_factory=list,
        description="支撑本次处置的证据日志编号列表，必须来自当前 case 已查询返回的 log_id；action=none 时可为空数组",
        examples=[["LOG-20261027-0001", "LOG-20261027-0008"]],
    )
    reason: str = Field(
        min_length=5,
        max_length=1000,
        description="处置理由摘要（将进入审批单与审计日志）",
        examples=["攻击源 198.51.100.23 完成账号爆破后 SQL 注入成功，需短时封禁"],
    )

    @model_validator(mode="after")
    def _target_ip_required(self) -> "RequestResponseRequest":
        """处置类动作必须有明确目标与证据；action=none 则两者都不应指定。"""
        if self.action != "none" and not self.target_ip:
            raise ValueError("action 为 block_ip/block_ip_short_term/rate_limit 时 target_ip 必填")
        if self.action != "none" and not self.evidence_log_ids:
            raise ValueError("处置类动作必须提供至少一条 evidence_log_ids，无证据不得处置")
        if self.action == "none" and self.target_ip:
            raise ValueError("action=none 表示无需处置，不应指定 target_ip")
        return self


class RequestResponseResponse(BaseModel):
    """处置提交响应：骨架阶段**不产生任何真实副作用**（不封 IP、不改防火墙、不发邮件）。"""

    status: Literal["approval_required", "rejected", "executed", "no_action"] = Field(
        description="处置状态四态：no_action(无需处置，action=none)/rejected(证据校验未通过)/approval_required(待审批，本周全部动作都落在这一态)/executed(已执行，本周不会出现)",
        examples=["approval_required"],
    )
    approval_id: Optional[str] = Field(
        default=None,
        description="审批单编号（status=approval_required 时返回）",
        examples=["APPR-20261027-0001"],
    )
    executed: Literal[False] = Field(
        description="恒为 false 直到权限网关与执行器真实接入。消费方不得据此宣称处置已生效",
        examples=[False],
    )
    detail: str = Field(
        description="状态说明（中文）",
        examples=["权限服务未接入，处置动作已登记为待审批，未产生任何真实封禁副作用"],
    )
    rejected_evidence_ids: list[str] = Field(
        default_factory=list,
        description="被程序校验拒绝的证据编号（伪造、不属于本 case 或未被查询返回）",
        examples=[["LOG-FAKE-999"]],
    )
    mock: Literal[True] = Field(description="Mock 标识：登记动作仅写入本地 Mock 审批表", examples=[True])
