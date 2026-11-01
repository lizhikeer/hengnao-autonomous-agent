from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "risk-scoring-v1.json"


@lru_cache(maxsize=4)
def load_scoring_policy(path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    policy_path = Path(path)
    with policy_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def scoring_version(policy: dict[str, Any] | None = None) -> str:
    resolved = policy or load_scoring_policy()
    return str(resolved.get("scoring_version") or "risk-scoring-unknown")


def risk_component_keys(policy: dict[str, Any] | None = None) -> tuple[str, ...]:
    resolved = policy or load_scoring_policy()
    return tuple(str(key) for key in resolved.get("component_max_scores", {}).keys())


RISK_COMPONENT_KEYS: tuple[str, ...] = risk_component_keys()


def score_event(
    *,
    reason_codes: Iterable[str],
    baseline_deviations: list[dict[str, Any]],
    risk_component_overrides: dict[str, int],
    policy: dict[str, Any] | None = None,
) -> tuple[dict[str, int], float, str, str]:
    resolved = policy or load_scoring_policy()
    components = risk_components(
        reason_codes=reason_codes,
        baseline_deviations=baseline_deviations,
        risk_component_overrides=risk_component_overrides,
        policy=resolved,
    )
    score = risk_score(components)
    return components, score, risk_level(score, resolved), scoring_version(resolved)


def risk_components(
    *,
    reason_codes: Iterable[str],
    baseline_deviations: list[dict[str, Any]],
    risk_component_overrides: dict[str, int],
    policy: dict[str, Any] | None = None,
) -> dict[str, int]:
    resolved = policy or load_scoring_policy()
    components = {key: 0 for key in risk_component_keys(resolved)}
    reason_map = resolved.get("reason_components", {})
    unknown = resolved.get("unknown_reason_components", {"rule_strength": 15})

    for reason_code in reason_codes:
        for key, score in reason_map.get(reason_code, unknown).items():
            if key in components:
                components[key] = _merge_component(key, components[key], int(score), resolved)

    baseline_score = max(
        [_baseline_deviation_score(item, resolved) for item in baseline_deviations],
        default=0,
    )
    components["baseline_deviation"] = _merge_component(
        "baseline_deviation",
        components.get("baseline_deviation", 0),
        baseline_score,
        resolved,
    )

    for key, score in risk_component_overrides.items():
        if key in components:
            components[key] = _merge_component(key, components[key], int(score), resolved)

    return components


def risk_score(components: dict[str, int]) -> float:
    return float(max(0, min(100, sum(components.values()))))


def risk_level(score: float, policy: dict[str, Any] | None = None) -> str:
    resolved = policy or load_scoring_policy()
    levels = resolved.get("risk_levels", {})
    for level in ("critical", "high", "medium", "low"):
        minimum = float(levels.get(level, {}).get("min", 0))
        if score >= minimum:
            return level
    return "low"


def _baseline_deviation_score(deviation: dict[str, Any], policy: dict[str, Any]) -> int:
    severity = str(deviation.get("severity", "low")).lower()
    scores = policy.get("baseline_severity_scores", {})
    return int(scores.get(severity, scores.get("low", 5)))


def _merge_component(key: str, current: int, candidate: int, policy: dict[str, Any]) -> int:
    bounded = _bound_component(key, candidate, policy)
    if key == "feedback_adjustment" and bounded < 0:
        return min(current, bounded)
    return max(current, bounded)


def _bound_component(key: str, score: int, policy: dict[str, Any]) -> int:
    maximum = int(policy.get("component_max_scores", {}).get(key, 100))
    if key == "feedback_adjustment":
        return max(-maximum, min(maximum, score))
    return max(0, min(maximum, score))
