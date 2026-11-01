from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, timezone
from typing import Any, Iterable


WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

MIN_SAMPLE_DAYS = {
    "weekday_month_phase": 3,
    "weekday": 3,
    "month_phase": 3,
    "calendar_month": 2,
    "rolling": 3,
    "global": 1,
}


def month_phase(value: date | datetime) -> str:
    day = value.day
    if day <= 7:
        return "month_start"
    if day <= 23:
        return "month_middle"
    return "month_end"


def period_candidates(value: date | datetime) -> list[tuple[str, str]]:
    weekday = WEEKDAYS[value.weekday()]
    phase = month_phase(value)
    return [
        ("weekday_month_phase", f"{weekday}:{phase}"),
        ("weekday", weekday),
        ("month_phase", phase),
        ("calendar_month", str(value.month)),
        ("rolling", "30d"),
        ("global", "all"),
    ]


def select_periodic_baseline(
    baselines: Iterable[dict[str, Any]],
    *,
    event_time: date | datetime | None = None,
) -> dict[str, Any] | None:
    at = event_time or datetime.now(timezone.utc)
    by_period = {
        (str(item.get("period_type") or "global"), str(item.get("period_key") or "all")): item
        for item in baselines
    }
    for period_type, period_key in period_candidates(at):
        item = by_period.get((period_type, period_key))
        if item is None:
            continue
        minimum = MIN_SAMPLE_DAYS.get(period_type, 1)
        if int(item.get("sample_days") or 0) < minimum:
            continue
        return deepcopy(item)
    return None


def resolve_effective_baseline(
    baselines: Iterable[dict[str, Any]],
    overrides: Iterable[dict[str, Any]],
    *,
    event_time: date | datetime | None = None,
) -> dict[str, Any] | None:
    at = _as_datetime(event_time or datetime.now(timezone.utc))
    selected = select_periodic_baseline(baselines, event_time=at)
    if selected is None:
        return None

    applicable = [
        item
        for item in overrides
        if _is_active(item, at) and _matches_selected_period(item, selected)
    ]
    applicable.sort(key=_override_sort_key)

    applied_ids: list[str] = []
    for item in applicable:
        if apply_override(selected, item):
            applied_ids.append(str(item.get("override_id") or ""))
            selected["model_version"] = str(item.get("model_version") or selected.get("model_version") or "")

    selected["selected_baseline"] = {
        "period_type": selected.get("period_type", "global"),
        "period_key": selected.get("period_key", "all"),
        "fallback_level": selected.get("fallback_level", "none"),
        "override_ids": [item for item in applied_ids if item],
        "model_version": selected.get("model_version", ""),
    }
    return selected


def apply_override(baseline: dict[str, Any], override: dict[str, Any]) -> bool:
    profile_name = f"{override.get('profile_group')}_profile"
    profile = baseline.get(profile_name)
    if not isinstance(profile, dict):
        return False

    feature_name = str(override.get("feature_name") or "")
    if not feature_name:
        return False
    current = profile.get(feature_name)
    value = override.get("override_value")
    if not isinstance(value, dict):
        return False

    merge_mode = str(override.get("merge_mode") or "")
    if merge_mode == "append":
        profile[feature_name] = _append_value(current, value)
    elif merge_mode == "replace":
        profile[feature_name] = deepcopy(value)
    elif merge_mode == "adjust":
        profile[feature_name] = _adjust_value(current, value)
    else:
        return False
    return True


def _append_value(current: Any, value: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(current) if isinstance(current, dict) else {}
    existing = _string_list(result.get("common_values"))
    additions = _string_list(value.get("common_values"))
    result["common_values"] = list(dict.fromkeys([*existing, *additions]))
    if isinstance(value.get("value_histogram"), dict):
        histogram = result.get("value_histogram")
        merged = dict(histogram) if isinstance(histogram, dict) else {}
        merged.update(value["value_histogram"])
        result["value_histogram"] = merged
    for key, item in value.items():
        if key not in {"common_values", "value_histogram"}:
            result[key] = deepcopy(item)
    return result


def _adjust_value(current: Any, value: dict[str, Any]) -> Any:
    if isinstance(current, (int, float)) and not isinstance(current, bool):
        delta = _number(value.get("delta"))
        return current + delta if delta is not None else current

    result = deepcopy(current) if isinstance(current, dict) else {}
    default_delta = _number(value.get("delta"))
    for key in ("mean", "mean_value", "p50", "p50_value", "p95", "p95_value", "p99", "p99_value"):
        existing = _number(result.get(key))
        delta = _number(value.get(key))
        if delta is None:
            delta = default_delta
        if existing is not None and delta is not None:
            result[key] = existing + delta
    return result


def _is_active(item: dict[str, Any], at: datetime) -> bool:
    if str(item.get("status") or "") != "active":
        return False
    effective_from = _as_datetime(item.get("effective_from"))
    effective_to = _as_datetime(item.get("effective_to")) if item.get("effective_to") else None
    return effective_from <= at and (effective_to is None or at <= effective_to)


def _matches_selected_period(item: dict[str, Any], baseline: dict[str, Any]) -> bool:
    override_period = (str(item.get("period_type") or ""), str(item.get("period_key") or ""))
    selected_period = (
        str(baseline.get("period_type") or "global"),
        str(baseline.get("period_key") or "all"),
    )
    return override_period == ("global", "all") or override_period == selected_period


def _override_sort_key(item: dict[str, Any]) -> tuple[int, int, datetime, str]:
    group_priority = 1 if str(item.get("user_id") or "") else 0
    period_priority = 1 if str(item.get("period_type") or "") != "global" else 0
    updated_at = _as_datetime(item.get("updated_at") or item.get("created_at"))
    return group_priority, period_priority, updated_at, str(item.get("override_id") or "")


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item) for item in value if item is not None]


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except ValueError:
        return None
