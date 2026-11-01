from __future__ import annotations

"""异常事件生成器。

这个文件只负责一件事：把规则命中的结果整理成统一的 AnomalyEvent。
RuleEngine 负责“发现异常”，AnomalyEventBuilder 负责“写异常报告”。
"""

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
import hashlib
from typing import Any
import uuid

from src.detection.scoring import RISK_COMPONENT_KEYS, score_event
from src.schemas import AnomalyEvent, NormalizedLog

# reason_code 到 attack_type 的映射。
# reason_code 是具体原因，attack_type 是更大的攻击/异常类别。
REASON_ATTACK_TYPE_MAP = {
    "failed_login_spike": "brute_force",
    "credential_stuffing_pattern": "credential_stuffing",
    "new_source_ip": "account_takeover",
    "rare_login_hour": "suspicious_login",
    "sensitive_resource_access": "sensitive_access",
    "new_source_then_sensitive_access": "account_takeover",
    "admin_resource_access": "privilege_abuse",
    "high_api_rate": "api_abuse",
    "download_volume_spike": "data_exfiltration",
    "vpn_traffic_volume_spike": "data_exfiltration",
    "permission_change": "privilege_abuse",
    "lateral_movement_signal": "lateral_movement",
    "service_account_anomaly": "service_account_anomaly",
    "system_error_pattern": "system_anomaly",
}

# 同一个事件可能有多个 reason_code。这里决定 attack_type 冲突时优先显示哪个。
ATTACK_TYPE_PRIORITY = (
    "data_exfiltration",
    "credential_stuffing",
    "brute_force",
    "account_takeover",
    "privilege_abuse",
    "lateral_movement",
    "service_account_anomaly",
    "api_abuse",
    "sensitive_access",
    "suspicious_login",
    "system_anomaly",
)


class AnomalyEventBuilder:
    """统一构造 AnomalyEvent，避免 RuleEngine 里到处手写事件字段。"""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        # 测试时可以传入固定时间，避免 created_at/detect_time 每次都变化。
        self._clock = clock or _now

    def build(
        self,
        *,
        log: NormalizedLog,
        rule_hits: list[str],
        reason_codes: list[str],
        evidence: dict[str, Any] | None = None,
        related_event_ids: list[str] | None = None,
        baseline_deviations: list[dict[str, Any]] | None = None,
        risk_component_overrides: dict[str, int] | None = None,
        event_id_seed: str | None = None,
        attack_type: str | None = None,
        model_version: str = "rule-v1",
    ) -> AnomalyEvent:
        """把一条日志和命中的规则信息转换成标准异常事件。"""

        # 每个异常事件必须说明“哪些规则命中”和“为什么命中”。
        if not rule_hits:
            raise ValueError("rule_hits must not be empty")
        if not reason_codes:
            raise ValueError("reason_codes must not be empty")

        # 去重是为了避免同一个 reason_code 重复加分或重复展示。
        normalized_reason_codes = _dedupe(reason_codes)
        normalized_rule_hits = _dedupe(rule_hits)
        normalized_baseline_deviations = baseline_deviations or []

        # 先算风险明细，再由明细汇总出总分和等级。
        risk_components, risk_score, risk_level, scoring_version = score_event(
            reason_codes=normalized_reason_codes,
            baseline_deviations=normalized_baseline_deviations,
            risk_component_overrides=risk_component_overrides or {},
        )
        now = self._clock()

        # payload 的字段尽量贴近 AnomalyEvent schema，后续落库/API 展示都吃这一份结构。
        payload = {
            "event_id": _event_id(event_id_seed),
            "event_time": log.event_time,
            "detect_time": now,
            "tenant_id": log.tenant_id,
            "user_id": log.user_id,
            "src_ip": log.src_ip,
            "host": log.host,
            "source_type": log.source_type,
            "action": log.action,
            "object_type": log.object_type,
            "object_id": log.object_id,
            "attack_type": attack_type or _attack_type(normalized_reason_codes),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_components": risk_components,
            "rule_hits": normalized_rule_hits,
            "baseline_deviations": normalized_baseline_deviations,
            "reason_codes": normalized_reason_codes,
            "evidence": evidence or {},
            "related_event_ids": _related_event_ids(log.event_id, related_event_ids or []),
            "related_logs_summary": _related_logs_summary(log),
            "scenario_id": log.scenario_id,
            "scenario_type": log.scenario_type,
            "attack_chain_id": log.attack_chain_id,
            "ai_status": "pending" if risk_level in {"high", "critical"} else "not_required",
            "status": "new",
            "model_version": model_version,
            "scoring_version": scoring_version,
            "created_at": now,
        }
        return AnomalyEvent.model_validate(payload)


def _now() -> datetime:
    """返回当前 UTC 时间，作为默认检测时间。"""

    return datetime.now(timezone.utc)


def _event_id(seed: str | None) -> str:
    """有 seed 时生成稳定异常 ID；没有 seed 时保持随机 UUID。"""

    if not seed:
        return str(uuid.uuid4())
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"anom-{digest[:32]}"


def _attack_type(reason_codes: Iterable[str]) -> str:
    """根据 reason_codes 推断攻击类型。"""

    attack_types = {
        REASON_ATTACK_TYPE_MAP[reason_code]
        for reason_code in reason_codes
        if reason_code in REASON_ATTACK_TYPE_MAP
    }
    for attack_type in ATTACK_TYPE_PRIORITY:
        if attack_type in attack_types:
            return attack_type
    return "unknown"


def _related_event_ids(event_id: str, related_event_ids: list[str]) -> list[str]:
    """把当前日志 event_id 和关联事件 id 合并去重。"""

    return _dedupe([event_id, *related_event_ids])


def _related_logs_summary(log: NormalizedLog) -> str:
    """生成给前端/AI 快速阅读的日志摘要。"""

    return (
        f"user={log.user_id or 'unknown'} src_ip={log.src_ip or 'unknown'} "
        f"action={log.action} result={log.result} resource={log.resource or '-'}"
    )


def _dedupe(values: Iterable[str]) -> list[str]:
    """保持原顺序去重。"""

    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
