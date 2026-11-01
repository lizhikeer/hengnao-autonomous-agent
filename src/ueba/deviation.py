from __future__ import annotations

"""用户行为偏离求值模块（持久化证据链）。

- UserContext / load_user_context：封装对 ClickHouse 基线与 seen_sources 的持久化查询。
- BaselineDeviation / evaluate_deviations：基于 UserContext 评估每条日志的 baseline 偏离，
  产出 9 字段契约证据数组；低置信度基线（confidence < 0.6）触发 severity 动态降级。

evaluate_deviations 为纯函数，缺少用户基线时返回样本不足降级证据，而不把“没有历史”
误判为“没有偏离”。
"""

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Literal, Protocol

DeviationType = Literal[
    "rare_login_hour",
    "new_source_ip",
    "new_geo_location",
    "failed_login_spike",
    "download_volume_spike",
    "insufficient_history",
    "low_baseline_confidence",
    "peer_group_fallback",
    "global_baseline_fallback",
    "sensitive_resource_access",
    "outside_active_hours",
]
EvidenceSource = Literal["user_baseline", "seen_sources", "daily_feature", "peer_group", "global"]
Severity = Literal["low", "medium", "high", "critical"]

_SEVERITY_DOWNGRADE: dict[str, str] = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "low",
}


class DeviationStorage(Protocol):
    """load_user_context 所需的最小存储契约。"""

    def get_user_baseline(
        self,
        user_id: str,
        *,
        tenant_id: str | None = None,
        baseline_date: Any = None,
    ) -> dict[str, Any] | None:
        ...

    def query_user_seen_sources(
        self,
        *,
        tenant_id: str = "default",
        user_id: str | None = None,
        source_type: str | None = None,
        source_key: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        ...


@dataclass(frozen=True)
class BaselineDeviation:
    """P1 阶段 9 字段正式偏离证据契约。"""

    feature: str
    profile_group: str
    expected: Any
    actual: Any
    deviation_type: str
    severity: str
    confidence: float
    evidence_source: str
    sample_days: int
    period_type: str | None = None
    period_key: str | None = None
    model_version: str | None = None
    override_ids: tuple[str, ...] = ()
    fallback_level: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "feature": self.feature,
            "profile_group": self.profile_group,
            "expected": self.expected,
            "actual": self.actual,
            "deviation_type": self.deviation_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_source": self.evidence_source,
            "sample_days": self.sample_days,
        }
        if self.period_type:
            payload["period_type"] = self.period_type
        if self.period_key:
            payload["period_key"] = self.period_key
        if self.model_version:
            payload["model_version"] = self.model_version
        if self.override_ids:
            payload["override_ids"] = list(self.override_ids)
        if self.fallback_level:
            payload["fallback_level"] = self.fallback_level
        return payload


@dataclass(frozen=True)
class UserContext:
    """单用户持久化上下文快照。"""

    tenant_id: str
    user_id: str | None
    baseline: dict[str, Any] | None = None
    seen_sources: set[str] = field(default_factory=set)
    daily_feature: dict[str, Any] | None = None

    @property
    def sample_days(self) -> int:
        if self.baseline is None:
            return 0
        return int(self.baseline.get("sample_days", 0))

    @property
    def confidence(self) -> float:
        if self.baseline is None:
            return 0.0
        return float(self.baseline.get("baseline_confidence", 0.0))


def load_user_context(
    storage: DeviationStorage,
    tenant_id: str,
    user_id: str | None,
    event_time: date | datetime | None = None,
) -> UserContext:
    """加载单用户持久化上下文（基线 + seen_sources）。"""
    if not user_id:
        return UserContext(tenant_id=tenant_id, user_id=None)

    baseline_date = event_time.date() if isinstance(event_time, datetime) else event_time
    baseline = storage.get_user_baseline(user_id, tenant_id=tenant_id, baseline_date=baseline_date)
    rows = storage.query_user_seen_sources(
        tenant_id=tenant_id,
        user_id=user_id,
        source_type="ip",
        limit=10000,
    )
    seen: set[str] = {str(r["source_key"]) for r in rows if r.get("source_key")}
    return UserContext(
        tenant_id=tenant_id,
        user_id=user_id,
        baseline=baseline,
        seen_sources=seen,
    )


def _safe_severity(severity: str, confidence: float) -> str:
    """confidence < 0.6 时动态降级一级，控制误报。"""
    if confidence >= 0.6:
        return severity
    return _SEVERITY_DOWNGRADE.get(severity, severity)


def evaluate_deviations(log: Any, context: UserContext) -> list[BaselineDeviation]:
    """评估单条日志的所有 baseline 偏离，输出 9 字段契约。"""
    if context.baseline is None:
        return [_fallback_deviation(log, context, "insufficient_history", "medium", "global")]

    deviations: list[BaselineDeviation] = []
    conf = context.confidence
    days = context.sample_days
    fallback_level = str(context.baseline.get("fallback_level") or "none")
    if conf < 0.6:
        deviations.append(
            _fallback_deviation(
                log,
                context,
                _fallback_type(fallback_level, conf),
                "low",
                _fallback_source(fallback_level),
            )
        )

    location_profile = _dict_value(context.baseline.get("location_profile"))
    common_ips = _common_values(location_profile.get("common_ips"))
    src_ip = getattr(log, "src_ip", None)
    src_ip_is_common = bool(src_ip and common_ips and src_ip in common_ips)
    src_ip_is_seen = bool(src_ip and src_ip in context.seen_sources)
    if src_ip and not src_ip_is_common and not src_ip_is_seen and (common_ips or context.seen_sources):
        deviations.append(
            _baseline_deviation(
                context,
                feature="src_ip",
                profile_group="location",
                expected=common_ips or sorted(context.seen_sources),
                actual=src_ip,
                deviation_type="new_source_ip",
                severity=_safe_severity("high", conf),
                confidence=conf,
                evidence_source="user_baseline" if common_ips else "seen_sources",
                sample_days=days,
            )
        )

    time_profile = _dict_value(context.baseline.get("time_profile"))
    active_hours = _common_values(time_profile.get("active_hours"))
    event_hour = getattr(log.event_time, "hour", 0) if hasattr(log, "event_time") else 0
    if active_hours and not _hour_in_ranges(event_hour, active_hours):
        deviations.append(
            _baseline_deviation(
                context,
                feature="event_hour",
                profile_group="time",
                expected=active_hours,
                actual=f"{event_hour:02d}:00",
                deviation_type="outside_active_hours",
                severity=_safe_severity("medium", conf),
                confidence=conf,
                evidence_source="user_baseline",
                sample_days=days,
            )
        )

    access_profile = _dict_value(context.baseline.get("access_profile"))
    common_resources = _common_values(access_profile.get("common_resources"))
    resource = getattr(log, "resource", None)
    if resource and common_resources and resource not in common_resources:
        deviations.append(
            _baseline_deviation(
                context,
                feature="resource",
                profile_group="access",
                expected=common_resources,
                actual=resource,
                deviation_type="sensitive_resource_access",
                severity=_safe_severity("high", conf),
                confidence=conf,
                evidence_source="user_baseline",
                sample_days=days,
            )
        )

    result_profile = _dict_value(context.baseline.get("result_profile"))
    failed_login_count = _metric_value(log, context.daily_feature, "failed_login_count")
    failed_login_threshold = _profile_threshold(result_profile, "failed_login_count")
    if (
        failed_login_count is not None
        and failed_login_threshold is not None
        and failed_login_count > failed_login_threshold
    ):
        deviations.append(
            _baseline_deviation(
                context,
                feature="failed_login_count",
                profile_group="result",
                expected=f"<= {failed_login_threshold:g}",
                actual=_display_number(failed_login_count),
                deviation_type="failed_login_spike",
                severity=_safe_severity(_numeric_severity(failed_login_count, failed_login_threshold), conf),
                confidence=conf,
                evidence_source=_metric_evidence_source(context.daily_feature),
                sample_days=days,
            )
        )

    download_count = _metric_value(log, context.daily_feature, "download_count")
    download_threshold = _profile_threshold(access_profile, "download_count")
    if (
        download_count is not None
        and download_threshold is not None
        and download_count > download_threshold
    ):
        deviations.append(
            _baseline_deviation(
                context,
                feature="download_count",
                profile_group="access",
                expected=f"<= {download_threshold:g}",
                actual=_display_number(download_count),
                deviation_type="download_volume_spike",
                severity=_safe_severity(_numeric_severity(download_count, download_threshold), conf),
                confidence=conf,
                evidence_source=_metric_evidence_source(context.daily_feature),
                sample_days=days,
            )
        )

    return deviations


def is_seen_source(context: UserContext, source_key: str) -> bool:
    """source_key 是否在用户持久化 seen_sources 中。"""
    return source_key in context.seen_sources


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _common_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if not isinstance(value, dict):
        return []
    if isinstance(value.get("common_values"), list):
        return [str(item) for item in value["common_values"]]
    if isinstance(value.get("value_histogram"), dict):
        return [str(item) for item in value["value_histogram"].keys()]
    return []


def _hour_in_ranges(hour: int, ranges: list[str]) -> bool:
    for item in ranges:
        if _hour_in_range(hour, item):
            return True
    return False


def _hour_in_range(hour: int, value: str) -> bool:
    if "-" not in value:
        return value.startswith(f"{hour:02d}:") or value == str(hour)
    start_raw, end_raw = value.split("-", 1)
    start = _parse_hour(start_raw)
    end = _parse_hour(end_raw)
    if start is None or end is None:
        return False
    if start <= end:
        return start <= hour < end
    return hour >= start or hour < end


def _parse_hour(value: str) -> int | None:
    raw = value.strip().split(":", 1)[0]
    if not raw.isdigit():
        return None
    hour = int(raw)
    return hour if 0 <= hour <= 23 else None


def _fallback_deviation(
    log: Any,
    context: UserContext,
    deviation_type: str,
    severity: str,
    evidence_source: str,
) -> BaselineDeviation:
    return _baseline_deviation(
        context,
        feature="baseline_history",
        profile_group="why",
        expected="sufficient_user_baseline",
        actual=_fallback_actual(log, context),
        deviation_type=deviation_type,
        severity=severity,
        confidence=context.confidence,
        evidence_source=evidence_source,
        sample_days=context.sample_days,
    )


def _baseline_deviation(context: UserContext, **payload: Any) -> BaselineDeviation:
    baseline = context.baseline or {}
    selected = baseline.get("selected_baseline")
    selected = selected if isinstance(selected, dict) else {}
    return BaselineDeviation(
        **payload,
        period_type=str(selected.get("period_type") or baseline.get("period_type") or "") or None,
        period_key=str(selected.get("period_key") or baseline.get("period_key") or "") or None,
        model_version=str(selected.get("model_version") or baseline.get("model_version") or "") or None,
        override_ids=tuple(str(item) for item in selected.get("override_ids", []) if item),
        fallback_level=str(selected.get("fallback_level") or baseline.get("fallback_level") or "") or None,
    )


def _fallback_actual(log: Any, context: UserContext) -> str:
    user_id = context.user_id or getattr(log, "user_id", None) or "unknown"
    if context.baseline is None:
        return f"user {user_id} has no baseline"
    return f"confidence {context.confidence:g}, sample_days {context.sample_days}"


def _fallback_type(fallback_level: str, confidence: float) -> str:
    if fallback_level == "peer_group":
        return "peer_group_fallback"
    if fallback_level in {"department", "global"}:
        return "global_baseline_fallback"
    if confidence < 0.6:
        return "low_baseline_confidence"
    return "insufficient_history"


def _fallback_source(fallback_level: str) -> str:
    if fallback_level == "peer_group":
        return "peer_group"
    if fallback_level in {"department", "global"}:
        return "global"
    return "user_baseline"


def _metric_value(log: Any, daily_feature: dict[str, Any] | None, field: str) -> float | None:
    if daily_feature and field in daily_feature:
        return _float_value(daily_feature.get(field))
    attrs = getattr(log, "attrs", None)
    if isinstance(attrs, dict) and field in attrs:
        return _float_value(attrs.get(field))
    return _float_value(getattr(log, field, None))


def _profile_threshold(profile: dict[str, Any], feature_name: str) -> float | None:
    value = profile.get(feature_name)
    if isinstance(value, dict):
        for key in ("p99", "p99_value", "p95", "p95_value"):
            threshold = _float_value(value.get(key))
            if threshold is not None:
                return threshold
    return _float_value(value)


def _numeric_severity(actual: float, threshold: float) -> str:
    if threshold <= 0:
        return "critical" if actual >= 5 else "high"
    ratio = actual / threshold
    if ratio >= 3:
        return "critical"
    if ratio >= 2:
        return "high"
    return "medium"


def _metric_evidence_source(daily_feature: dict[str, Any] | None) -> str:
    return "daily_feature" if daily_feature else "user_baseline"


def _float_value(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except ValueError:
        return None


def _display_number(value: float) -> int | float:
    return int(value) if value.is_integer() else value
