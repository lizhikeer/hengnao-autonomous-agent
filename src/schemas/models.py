from __future__ import annotations

from datetime import date, datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field


RiskLevel = Literal["low", "medium", "high", "critical"]
SourceType = Literal["vpn", "oa", "api", "system", "file", "database", "security_device"]
LogResult = Literal["success", "fail", "denied", "error"]
AIStatus = Literal["not_required", "pending", "analyzed", "failed"]
AnomalyStatus = Literal["new", "investigating", "closed", "false_positive", "pending_review", "rejected"]
FallbackLevel = Literal["none", "peer_group", "department", "global"]
FeedbackType = Literal[
    "rule_weight",
    "baseline_threshold",
    "false_positive",
    "new_pattern",
    "data_contract",
]
FeedbackTargetComponent = Literal["rule", "baseline", "scoring", "data_contract"]
ReviewStatus = Literal["pending", "accepted", "rejected"]
BaselinePeriodType = Literal[
    "global",
    "rolling",
    "weekday",
    "calendar_month",
    "month_phase",
    "weekday_month_phase",
]
BaselineMergeMode = Literal["append", "replace", "adjust"]
BaselineOverrideSource = Literal["manual", "ai_feedback"]
BaselineOverrideStatus = Literal["pending", "active", "rejected", "revoked", "expired"]
TaskRunStatus = Literal["queued", "running", "succeeded", "failed", "needs_review", "cancelled"]
NotificationStatus = Literal["pending", "delivering", "delivered", "retry_wait", "dead_letter"]
UserRiskWindow = Literal["24h", "7d", "30d", "custom"]
ResponseItemT = TypeVar("ResponseItemT")


class ListResponse(BaseModel, Generic[ResponseItemT]):
    """Standard paginated API list shape."""

    items: list[ResponseItemT] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class ErrorResponse(BaseModel):
    """Standard API error response."""

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class NormalizedLog(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str
    event_time: datetime
    ingest_time: datetime
    tenant_id: str
    source_type: SourceType
    log_type: str

    user_id: str | None = None
    account_type: str | None = "unknown"
    user_role: str | None = None
    department: str | None = None
    host: str | None = None

    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    geo: dict[str, Any] = Field(default_factory=dict)

    action: str
    object_type: str | None = None
    object_id: str | None = None
    resource: str | None = None
    result: LogResult

    severity: int = Field(default=0, ge=0, le=10)
    user_agent: str | None = None
    protocol: str | None = None
    auth_method: str | None = None
    session_id: str | None = None
    trace_id: str | None = None

    scenario_id: str | None = None
    scenario_type: str | None = None
    attack_chain_id: str | None = None
    step_index: int | None = None
    injected_label: str | None = None

    message: str
    raw_log: str
    risk_tags: list[str] = Field(default_factory=list)
    attrs: dict[str, Any] = Field(default_factory=dict)


class AnomalyEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str
    event_time: datetime
    detect_time: datetime
    tenant_id: str

    user_id: str | None = None
    src_ip: str | None = None
    host: str | None = None
    source_type: SourceType | None = None
    action: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    attack_type: str | None = None

    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    risk_components: dict[str, Any] = Field(default_factory=dict)
    rule_hits: list[str] = Field(default_factory=list)
    baseline_deviations: list[dict[str, Any]] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    related_event_ids: list[str] = Field(default_factory=list)

    scenario_id: str | None = None
    scenario_type: str | None = None
    attack_chain_id: str | None = None

    ai_status: AIStatus = "not_required"
    status: AnomalyStatus = "new"
    model_version: str | None = None
    scoring_version: str | None = None
    created_at: datetime


class AIJudgement(BaseModel):
    model_config = ConfigDict(extra="allow")

    judgement_id: str
    event_id: str
    created_at: datetime
    model_name: str
    model_version: str | None = None
    risk_level: RiskLevel
    attack_type: str
    judgement: str
    key_reasons: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    feedback_suggestions: dict[str, Any] = Field(default_factory=dict)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    is_mock: bool


class AIFeedback(BaseModel):
    model_config = ConfigDict(extra="allow")

    feedback_id: str
    event_id: str
    judgement_id: str | None = None
    tenant_id: str
    user_id: str | None = None
    feedback_type: FeedbackType
    suggestion: str
    target_component: FeedbackTargetComponent
    confidence: float = Field(ge=0, le=1)
    review_status: ReviewStatus = "pending"
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_reason: str | None = None
    applied_override_id: str | None = None
    applied_version: str | None = None
    created_at: datetime


class FeedbackCreateRequest(BaseModel):
    """Compact request body for human or AI-suggested feedback submission."""

    event_id: str
    judgement_id: str | None = None
    tenant_id: str = "default"
    user_id: str | None = None
    feedback_type: FeedbackType
    suggestion: str
    target_component: FeedbackTargetComponent
    confidence: float = Field(default=1.0, ge=0, le=1)


class UserDailyFeature(BaseModel):
    model_config = ConfigDict(extra="allow")

    feature_date: date
    tenant_id: str
    user_id: str
    account_type: str | None = "unknown"

    login_count: int = Field(ge=0)
    failed_login_count: int = Field(ge=0)
    success_login_count: int = Field(ge=0)
    distinct_src_ip_count: int = Field(ge=0)
    distinct_host_count: int = Field(ge=0)
    distinct_action_count: int = Field(ge=0)

    first_seen_time: datetime
    last_seen_time: datetime

    night_event_count: int = Field(ge=0)
    sensitive_action_count: int = Field(ge=0)
    download_count: int = Field(ge=0)
    permission_change_count: int = Field(ge=0)
    new_source_count: int = Field(ge=0)
    maintenance_window_hit_count: int = Field(default=0, ge=0)

    profile_metrics: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class UserBaseline(BaseModel):
    model_config = ConfigDict(extra="allow")

    baseline_date: date
    tenant_id: str
    user_id: str
    model_version: str
    period_type: BaselinePeriodType = "global"
    period_key: str = "all"
    trained_from: date
    trained_to: date
    sample_days: int = Field(ge=0)
    sample_count: int = Field(ge=0)
    baseline_confidence: float = Field(ge=0, le=1)

    who_profile: dict[str, Any] = Field(default_factory=dict)
    time_profile: dict[str, Any] = Field(default_factory=dict)
    location_profile: dict[str, Any] = Field(default_factory=dict)
    access_profile: dict[str, Any] = Field(default_factory=dict)
    volume_profile: dict[str, Any] = Field(default_factory=dict)
    result_profile: dict[str, Any] = Field(default_factory=dict)
    why_profile: dict[str, Any] = Field(default_factory=dict)

    fallback_level: FallbackLevel = "none"
    selected_baseline: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class BaselineOverride(BaseModel):
    model_config = ConfigDict(extra="allow")

    override_id: str
    tenant_id: str = "default"
    user_id: str = ""
    profile_group: Literal["who", "time", "location", "access", "volume", "result", "why"]
    feature_name: str
    period_type: BaselinePeriodType
    period_key: str
    merge_mode: BaselineMergeMode
    override_value: dict[str, Any]
    source_type: BaselineOverrideSource
    source_feedback_id: str | None = None
    reason: str
    status: BaselineOverrideStatus
    effective_from: datetime
    effective_to: datetime | None = None
    created_by: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    model_version: str
    created_at: datetime
    updated_at: datetime


class BaselineOverrideCreateRequest(BaseModel):
    tenant_id: str = "default"
    user_id: str
    profile_group: Literal["who", "time", "location", "access", "volume", "result", "why"]
    feature_name: str
    period_type: BaselinePeriodType
    period_key: str
    merge_mode: BaselineMergeMode
    override_value: dict[str, Any]
    reason: str = Field(min_length=1)
    effective_from: datetime
    effective_to: datetime | None = None
    created_by: str = Field(default="analyst", min_length=1)


class BaselineOverrideRevokeRequest(BaseModel):
    revoked_by: str = Field(default="analyst", min_length=1)
    reason: str = Field(min_length=1)


class FeedbackReviewOverride(BaseModel):
    profile_group: Literal["who", "time", "location", "access", "volume", "result", "why"]
    feature_name: str
    period_type: BaselinePeriodType
    period_key: str
    merge_mode: BaselineMergeMode
    override_value: dict[str, Any]
    effective_from: datetime
    effective_to: datetime | None = None


class FeedbackReviewRequest(BaseModel):
    decision: Literal["accepted", "rejected"]
    reviewed_by: str = Field(default="analyst", min_length=1)
    review_reason: str = Field(min_length=1)
    override: FeedbackReviewOverride | None = None


class FeedbackReviewResponse(BaseModel):
    feedback: AIFeedback
    override: BaselineOverride | None = None
    applied_override_id: str | None = None
    applied_version: str | None = None


class DataQualityMetric(BaseModel):
    model_config = ConfigDict(extra="allow")

    metric_date: date
    tenant_id: str
    source_type: SourceType | str

    generated_count: int = Field(ge=0)
    injected_anomaly_count: int = Field(default=0, ge=0)
    injected_high_risk_count: int = Field(default=0, ge=0)
    raw_logs_count: int = Field(ge=0)
    parsed_logs_count: int = Field(ge=0)
    clickhouse_insert_count: int = Field(ge=0)
    security_logs_count: int = Field(ge=0)

    raw_size_bytes: int = Field(ge=0)
    table_size_bytes: int = Field(ge=0)
    compression_ratio: float = Field(ge=0)

    missing_event_time_rate: float = Field(ge=0, le=1)
    missing_user_id_rate: float = Field(ge=0, le=1)
    missing_src_ip_rate: float = Field(ge=0, le=1)
    missing_action_rate: float = Field(ge=0, le=1)
    missing_result_rate: float = Field(ge=0, le=1)
    parse_error_rate: float = Field(ge=0, le=1)
    event_id_traceability_rate: float = Field(default=1.0, ge=0, le=1)
    created_at: datetime


class OperationsTaskRun(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    task_name: str
    tenant_id: str = "default"
    target_date: date
    idempotency_key: str
    scheduled_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: TaskRunStatus
    attempt: int = Field(default=1, ge=1)
    input_watermark: dict[str, Any] = Field(default_factory=dict)
    output_refs: dict[str, Any] = Field(default_factory=dict)
    code_version: str
    error_code: str = ""
    error_message: str = ""
    version: int = Field(default=1, ge=1)


class AcceptanceReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    report_id: str
    tenant_id: str = "default"
    status: Literal["passed", "failed", "needs_review"]
    git_commit: str
    compose_config_digest: str
    scenario_version: str
    policy_version: str
    baseline_model_version: str
    ai_model: str
    ai_is_mock: bool
    threshold_version: str
    sample_from: datetime | None = None
    sample_to: datetime | None = None
    normal_scenario_count: int = Field(default=0, ge=0)
    attack_scenario_count: int = Field(default=0, ge=0)
    created_at: datetime
    run_id: str = ""
    summary: dict[str, Any] = Field(default_factory=dict)


class AcceptanceMetric(BaseModel):
    model_config = ConfigDict(extra="allow")

    report_id: str
    metric_name: str
    scenario_type: str = "overall"
    numerator: float = 0
    denominator: float = 0
    value: float
    threshold_operator: Literal["<=", ">=", "<", ">"]
    threshold_value: float
    passed: bool
    unit: str = "ratio"
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class NotificationOutbox(BaseModel):
    model_config = ConfigDict(extra="allow")

    outbox_id: str
    idempotency_key: str
    event_id: str
    tenant_id: str = "default"
    channel: str = "webhook"
    destination: str
    payload: dict[str, Any]
    status: NotificationStatus = "pending"
    attempt_count: int = Field(default=0, ge=0)
    next_attempt_at: datetime
    last_error: str = ""
    created_at: datetime
    updated_at: datetime
    delivered_at: datetime | None = None
    version: int = Field(default=1, ge=1)


class NotificationAttempt(BaseModel):
    model_config = ConfigDict(extra="allow")

    attempt_id: str
    outbox_id: str
    attempt: int = Field(ge=1)
    started_at: datetime
    finished_at: datetime
    success: bool
    response_status: int | None = None
    duration_ms: int = Field(default=0, ge=0)
    error_code: str = ""
    error_message: str = ""
    response_body: str = ""


class ParseFailure(BaseModel):
    model_config = ConfigDict(extra="allow")

    failure_id: str
    occurred_at: datetime
    source_topic: str
    partition: int = 0
    offset: int = 0
    raw_payload: str
    error_code: str
    error_message: str


class BaselineRebuildResponse(BaseModel):
    """Response for rebuilding user behavior baselines."""

    rebuilt_count: int = Field(ge=0)


class LogAggregateTimeRange(BaseModel):
    """Time window for ClickHouse-backed log aggregation."""

    model_config = ConfigDict(populate_by_name=True)

    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None


class LogAggregateRequest(BaseModel):
    """Request body for aggregating normalized logs."""

    time_range: LogAggregateTimeRange | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    group_by: list[str] = Field(default_factory=lambda: ["event_date"])
    metrics: list[str] = Field(default_factory=lambda: ["count"])
    limit: int = Field(default=500, ge=1)


class LogAggregateResponse(BaseModel):
    """Generic row response for log aggregation results."""

    items: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceChain(BaseModel):
    """Evidence summary for anomaly detail views and AI context."""

    rule_hits: list[str] = Field(default_factory=list)
    baseline_deviations: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    risk_components: dict[str, Any] = Field(default_factory=dict)
    ai_status: AIStatus = "not_required"
    risk_reason: str = ""


class AnomalyDetailResponse(BaseModel):
    """Composed anomaly detail contract."""

    anomaly: AnomalyEvent
    baseline: dict[str, Any] = Field(default_factory=dict)
    related_logs: list[NormalizedLog] = Field(default_factory=list)
    ai_judgement: dict[str, Any] = Field(default_factory=dict)
    evidence_chain: EvidenceChain = Field(default_factory=EvidenceChain)


class DailyReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    report_id: str
    date: str
    created_at: datetime
    overall_score: float
    log_count: int
    alert_count: int
    high_risk_count: int
    major_risks: list[str]
    high_risk_users: list[str]
    typical_alerts: list[dict[str, Any]]
    ai_summary: str
    recommendation: str
    markdown: str
    run_id: str = ""
    input_watermark: dict[str, Any] = Field(default_factory=dict)
    quality_status: str = "unknown"


class NormalizedLogListResponse(ListResponse[NormalizedLog]):
    """Reusable list response for structured logs."""


class AnomalyEventListResponse(ListResponse[AnomalyEvent]):
    """Reusable list response for anomaly events."""


class UserBaselineListResponse(ListResponse[UserBaseline]):
    """Reusable list response for user baselines."""


class BaselineOverrideListResponse(ListResponse[BaselineOverride]):
    """Reusable list response for baseline overrides."""


class AIFeedbackListResponse(ListResponse[AIFeedback]):
    """Reusable list response for AI feedback."""


class AIJudgementListResponse(ListResponse[AIJudgement]):
    """Reusable list response for AI judgements."""


class DailyReportListResponse(ListResponse[DailyReport]):
    """Reusable list response for daily reports."""


class OperationsTaskRunListResponse(ListResponse[OperationsTaskRun]):
    """Reusable list response for operations task runs."""


class AcceptanceReportListResponse(ListResponse[AcceptanceReport]):
    """Reusable list response for acceptance reports."""


class AcceptanceReportDetail(BaseModel):
    report: AcceptanceReport
    metrics: list[AcceptanceMetric] = Field(default_factory=list)


class NotificationOutboxListResponse(ListResponse[NotificationOutbox]):
    """Reusable list response for notification outbox records."""


class StatsOverviewResponse(BaseModel):
    """Workbench overview counters backed by ClickHouse."""

    log_count: int = Field(default=0, ge=0)
    latest_log_ingest_time: datetime | None = None
    anomaly_count: int = Field(default=0, ge=0)
    high_risk_count: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    # Workbench health: AI judgement backlog, baseline coverage, and whether a
    # daily report has been generated yet.
    ai_pending_count: int = Field(default=0, ge=0)
    baseline_user_count: int = Field(default=0, ge=0)
    latest_report_date: date | None = None


class UserRiskStats(BaseModel):
    """User risk ranking row derived from anomaly_events."""

    user_id: str
    window: UserRiskWindow = "7d"
    anomaly_count: int = Field(default=0, ge=0)
    high_risk_count: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    max_risk_score: float = Field(default=0, ge=0, le=100)
    active_risk_score: float = Field(default=0, ge=0)
    decayed_risk_score: float = Field(default=0, ge=0)
    false_positive_excluded_count: int = Field(default=0, ge=0)
    latest_event_time: datetime | None = None


class UserRiskStatsListResponse(ListResponse[UserRiskStats]):
    """Reusable list response for user risk ranking."""
