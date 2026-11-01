from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timedelta, timezone
from typing import Any

from src.config import settings
from src.schemas import (
    AIFeedback,
    AcceptanceMetric,
    AcceptanceReport,
    AIJudgement,
    AnomalyEvent,
    BaselineOverride,
    DailyReport,
    DataQualityMetric,
    NotificationAttempt,
    NotificationOutbox,
    OperationsTaskRun,
    ParseFailure,
    UserBaseline,
)


LOG_COLUMNS: tuple[str, ...] = (
    "event_id",
    "event_time",
    "ingest_time",
    "tenant_id",
    "source_type",
    "log_type",
    "user_id",
    "account_type",
    "user_role",
    "department",
    "host",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "geo",
    "action",
    "object_type",
    "object_id",
    "resource",
    "result",
    "severity",
    "user_agent",
    "protocol",
    "auth_method",
    "session_id",
    "trace_id",
    "scenario_id",
    "scenario_type",
    "attack_chain_id",
    "step_index",
    "injected_label",
    "message",
    "raw_log",
    "risk_tags",
    "attrs",
)
LOG_JSON_FIELDS = {"geo", "attrs"}
LOG_FILTERS = {
    "tenant_id",
    "source_type",
    "log_type",
    "user_id",
    "src_ip",
    "action",
    "result",
}

ANOMALY_COLUMNS: tuple[str, ...] = (
    "event_id",
    "event_time",
    "detect_time",
    "tenant_id",
    "user_id",
    "src_ip",
    "host",
    "source_type",
    "action",
    "object_type",
    "object_id",
    "attack_type",
    "risk_score",
    "risk_level",
    "risk_components",
    "rule_hits",
    "baseline_deviations",
    "reason_codes",
    "evidence",
    "related_event_ids",
    "scenario_id",
    "scenario_type",
    "attack_chain_id",
    "ai_status",
    "status",
    "model_version",
    "scoring_version",
    "created_at",
)
ANOMALY_JSON_FIELDS = {"risk_components", "baseline_deviations", "evidence"}

BASELINE_COLUMNS: tuple[str, ...] = (
    "baseline_date",
    "tenant_id",
    "user_id",
    "period_type",
    "period_key",
    "profile_group",
    "feature_name",
    "mean_value",
    "std_value",
    "p50_value",
    "p95_value",
    "p99_value",
    "common_values",
    "value_histogram",
    "sample_days",
    "sample_count",
    "baseline_confidence",
    "trained_from",
    "trained_to",
    "fallback_level",
    "model_version",
    "created_at",
)

BASELINE_OVERRIDE_COLUMNS: tuple[str, ...] = (
    "override_id",
    "tenant_id",
    "user_id",
    "profile_group",
    "feature_name",
    "period_type",
    "period_key",
    "merge_mode",
    "override_value",
    "source_type",
    "source_feedback_id",
    "reason",
    "status",
    "effective_from",
    "effective_to",
    "created_by",
    "reviewed_by",
    "reviewed_at",
    "model_version",
    "created_at",
    "updated_at",
)

DAILY_REPORT_COLUMNS: tuple[str, ...] = (
    "report_date",
    "tenant_id",
    "total_logs",
    "anomaly_count",
    "high_count",
    "critical_count",
    "overall_score",
    "top_risk_users",
    "top_attack_types",
    "key_events",
    "ai_summary",
    "recommended_actions",
    "markdown_body",
    "run_id",
    "input_watermark",
    "quality_status",
    "created_at",
)

OPERATIONS_TASK_RUN_COLUMNS: tuple[str, ...] = (
    "run_id",
    "task_name",
    "tenant_id",
    "target_date",
    "idempotency_key",
    "scheduled_at",
    "started_at",
    "finished_at",
    "status",
    "attempt",
    "input_watermark",
    "output_refs",
    "code_version",
    "error_code",
    "error_message",
    "version",
)

ACCEPTANCE_REPORT_COLUMNS: tuple[str, ...] = (
    "report_id",
    "tenant_id",
    "status",
    "git_commit",
    "compose_config_digest",
    "scenario_version",
    "policy_version",
    "baseline_model_version",
    "ai_model",
    "ai_is_mock",
    "threshold_version",
    "sample_from",
    "sample_to",
    "normal_scenario_count",
    "attack_scenario_count",
    "created_at",
    "run_id",
    "summary",
)

ACCEPTANCE_METRIC_COLUMNS: tuple[str, ...] = (
    "report_id",
    "metric_name",
    "scenario_type",
    "numerator",
    "denominator",
    "value",
    "threshold_operator",
    "threshold_value",
    "passed",
    "unit",
    "details",
    "created_at",
)

NOTIFICATION_OUTBOX_COLUMNS: tuple[str, ...] = (
    "outbox_id",
    "idempotency_key",
    "event_id",
    "tenant_id",
    "channel",
    "destination",
    "payload",
    "status",
    "attempt_count",
    "next_attempt_at",
    "last_error",
    "created_at",
    "updated_at",
    "delivered_at",
    "version",
)

NOTIFICATION_ATTEMPT_COLUMNS: tuple[str, ...] = (
    "attempt_id",
    "outbox_id",
    "attempt",
    "started_at",
    "finished_at",
    "success",
    "response_status",
    "duration_ms",
    "error_code",
    "error_message",
    "response_body",
)

PARSE_FAILURE_COLUMNS: tuple[str, ...] = (
    "failure_id",
    "occurred_at",
    "source_topic",
    "partition",
    "offset",
    "raw_payload",
    "error_code",
    "error_message",
)

AI_JUDGEMENT_COLUMNS: tuple[str, ...] = (
    "judgement_id",
    "event_id",
    "created_at",
    "model_name",
    "model_version",
    "risk_level",
    "attack_type",
    "judgement",
    "key_reasons",
    "recommended_actions",
    "confidence",
    "feedback_suggestions",
    "raw_response",
    "is_mock",
)

AI_FEEDBACK_COLUMNS: tuple[str, ...] = (
    "feedback_id",
    "event_id",
    "judgement_id",
    "tenant_id",
    "user_id",
    "feedback_type",
    "suggestion",
    "target_component",
    "confidence",
    "review_status",
    "reviewed_by",
    "reviewed_at",
    "review_reason",
    "applied_override_id",
    "applied_version",
    "created_at",
)

DATA_QUALITY_COLUMNS: tuple[str, ...] = (
    "metric_date",
    "tenant_id",
    "source_type",
    "generated_count",
    "injected_anomaly_count",
    "injected_high_risk_count",
    "raw_logs_count",
    "parsed_logs_count",
    "clickhouse_insert_count",
    "security_logs_count",
    "raw_size_bytes",
    "table_size_bytes",
    "compression_ratio",
    "missing_event_time_rate",
    "missing_user_id_rate",
    "missing_src_ip_rate",
    "missing_action_rate",
    "missing_result_rate",
    "parse_error_rate",
    "event_id_traceability_rate",
    "created_at",
)

DAILY_FEATURES_COLUMNS: tuple[str, ...] = (
    "feature_date",
    "tenant_id",
    "user_id",
    "account_type",
    "login_count",
    "failed_login_count",
    "success_login_count",
    "distinct_src_ip_count",
    "distinct_host_count",
    "distinct_action_count",
    "first_seen_time",
    "last_seen_time",
    "night_event_count",
    "sensitive_action_count",
    "download_count",
    "permission_change_count",
    "new_source_count",
    "maintenance_window_hit_count",
    "common_src_ips",
    "common_ip_prefixes",
    "common_hosts",
    "common_actions",
    "profile_metrics",
    "created_at",
)

SEEN_SOURCES_COLUMNS: tuple[str, ...] = (
    "tenant_id",
    "user_id",
    "source_type",
    "source_key",
    "first_seen_time",
    "last_seen_time",
    "seen_count",
    "created_at",
    "updated_at",
)

REASON_CODE_FEEDBACK_STATS_COLUMNS: tuple[str, ...] = (
    "tenant_id",
    "user_id",
    "reason_codes_combo",
    "fp_count",
    "confirmed_count",
    "last_updated",
)

DAILY_FEATURES_JSON_FIELDS: set[str] = {"profile_metrics", "common_src_ips", "common_ip_prefixes", "common_hosts", "common_actions"}
AI_JUDGEMENT_JSON_FIELDS = {"feedback_suggestions", "raw_response"}
BASELINE_OVERRIDE_JSON_FIELDS = {"override_value"}
DAILY_REPORT_JSON_FIELDS = set()

ALLOWED_AGGREGATE_GROUPS = {
    "tenant_id",
    "source_type",
    "log_type",
    "user_id",
    "src_ip",
    "action",
    "result",
    "event_date",
}
ALLOWED_AGGREGATE_METRICS = {
    "count": "count() AS count",
    "unique_users": "uniqExact(user_id) AS unique_users",
    "unique_src_ips": "uniqExact(src_ip) AS unique_src_ips",
    "avg_severity": "avg(severity) AS avg_severity",
    "max_severity": "max(severity) AS max_severity",
}


class ClickHouseStorage:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        username: str | None = None,
        password: str | None = None,
        client: Any | None = None,
    ):
        if client is not None:
            self.client = client
            return

        import clickhouse_connect

        self.client = clickhouse_connect.get_client(
            host=host or settings.clickhouse_host,
            port=port or settings.clickhouse_http_port,
            database=database or settings.clickhouse_database,
            username=username or settings.clickhouse_user,
            password=settings.clickhouse_password if password is None else password,
        )

    def health(self) -> bool:
        try:
            result = self.client.query("SELECT 1").result_rows
            return bool(result and result[0][0] == 1)
        except Exception:
            return False

    def latest_security_log_ingest_time(self) -> str | None:
        try:
            result = self.client.query("SELECT count(), max(ingest_time) FROM security_logs").result_rows
        except Exception:
            return None
        if not result or not result[0][0] or result[0][1] is None:
            return None
        return str(result[0][1])

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        return list(self.client.query(sql, parameters=parameters or {}).result_rows)

    def list_logs(
        self,
        *,
        tenant_id: str | None = None,
        source_type: str | None = None,
        log_type: str | None = None,
        user_id: str | None = None,
        src_ip: str | None = None,
        action: str | None = None,
        result: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_log_filters(
            tenant_id=tenant_id,
            source_type=source_type,
            log_type=log_type,
            user_id=user_id,
            src_ip=src_ip,
            action=action,
            result=result,
            start_time=start_time,
            end_time=end_time,
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)

        items = self._select_dicts(
            f"""
            SELECT {_columns_sql(LOG_COLUMNS)}
            FROM security_logs
            {where_sql}
            ORDER BY event_time DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM security_logs {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_log_row(item) for item in items], int(total or 0)

    def get_log(self, event_id: str) -> dict[str, Any] | None:
        items = self._select_dicts(
            f"""
            SELECT {_columns_sql(LOG_COLUMNS)}
            FROM security_logs
            WHERE event_id = {{event_id:String}}
            ORDER BY event_time DESC
            LIMIT 1
            """,
            {"event_id": event_id},
        )
        return _normalize_log_row(items[0]) if items else None

    def list_logs_by_event_ids(self, event_ids: Sequence[str]) -> list[dict[str, Any]]:
        if not event_ids:
            return []
        items = self._select_dicts(
            f"""
            SELECT {_columns_sql(LOG_COLUMNS)}
            FROM security_logs
            WHERE event_id IN {{event_ids:Array(String)}}
            ORDER BY event_time ASC
            LIMIT {{limit:UInt64}}
            """,
            {"event_ids": list(event_ids), "limit": max(1, len(event_ids))},
        )
        order = {event_id: index for index, event_id in enumerate(event_ids)}
        logs = [_normalize_log_row(item) for item in items]
        return sorted(logs, key=lambda item: order.get(str(item.get("event_id")), len(order)))

    def aggregate_logs(
        self,
        *,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        filters: dict[str, Any] | None = None,
        group_by: Sequence[str] | None = None,
        metrics: Sequence[str] | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        resolved_group_by = list(group_by or ["event_date"])
        resolved_metrics = list(metrics or ["count"])
        _assert_allowed_values(resolved_group_by, ALLOWED_AGGREGATE_GROUPS, "group_by")
        _assert_allowed_values(resolved_metrics, ALLOWED_AGGREGATE_METRICS.keys(), "metrics")

        field_filters, parameters = _build_log_filters(
            start_time=time_from,
            end_time=time_to,
            **{key: value for key, value in (filters or {}).items() if key in LOG_FILTERS},
        )
        ignored_filters = sorted(set(filters or {}) - LOG_FILTERS)
        if ignored_filters:
            raise ValueError(f"Unsupported log filters: {', '.join(ignored_filters)}")

        select_parts = [*resolved_group_by, *(ALLOWED_AGGREGATE_METRICS[item] for item in resolved_metrics)]
        parameters["limit"] = _normalize_limit(limit)
        group_sql = ", ".join(resolved_group_by)
        order_metric = resolved_metrics[0]
        return self._select_dicts(
            f"""
            SELECT {", ".join(select_parts)}
            FROM security_logs
            {_where(field_filters)}
            GROUP BY {group_sql}
            ORDER BY {order_metric} DESC
            LIMIT {{limit:UInt64}}
            """,
            parameters,
        )

    def list_anomalies(
        self,
        *,
        tenant_id: str | None = None,
        risk_level: str | None = None,
        user_id: str | None = None,
        src_ip: str | None = None,
        reason_code: str | None = None,
        ai_status: str | None = None,
        status: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_anomaly_filters(
            tenant_id=tenant_id,
            risk_level=risk_level,
            user_id=user_id,
            src_ip=src_ip,
            reason_code=reason_code,
            ai_status=ai_status,
            status=status,
            start_time=start_time,
            end_time=end_time,
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        items = self._select_dicts(
            f"""
            SELECT {_columns_sql(ANOMALY_COLUMNS)}
            FROM anomaly_events
            {where_sql}
            ORDER BY event_time DESC, risk_score DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM anomaly_events {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_anomaly_row(item) for item in items], int(total or 0)

    def get_anomaly(self, event_id: str) -> dict[str, Any] | None:
        items = self._select_dicts(
            f"""
            SELECT {_columns_sql(ANOMALY_COLUMNS)}
            FROM anomaly_events
            WHERE event_id = {{event_id:String}}
            ORDER BY detect_time DESC
            LIMIT 1
            """,
            {"event_id": event_id},
        )
        return _normalize_anomaly_row(items[0]) if items else None

    def insert_anomalies(self, anomalies: Sequence[AnomalyEvent | dict[str, Any]]) -> None:
        rows = [
            _row_from_payload(
                _model_payload(item),
                ANOMALY_COLUMNS,
                json_fields=ANOMALY_JSON_FIELDS,
                defaults={
                    "model_version": "",
                    "scoring_version": "",
                    "ai_status": "not_required",
                    "status": "new",
                    "user_id": "",
                    "src_ip": "",
                    "host": "",
                    "source_type": "",
                    "action": "",
                    "object_type": "",
                    "object_id": "",
                    "attack_type": "unknown",
                    "scenario_id": "",
                    "scenario_type": "",
                    "attack_chain_id": "",
                },
            )
            for item in anomalies
        ]
        if rows:
            self.client.insert("anomaly_events", rows, column_names=list(ANOMALY_COLUMNS))

    def update_anomaly_ai_status(self, event_id: str, ai_status: str) -> None:
        self.client.command(
            """
            ALTER TABLE anomaly_events
            UPDATE ai_status = {ai_status:String}
            WHERE event_id = {event_id:String}
            """,
            parameters={"event_id": event_id, "ai_status": ai_status},
        )

    def update_anomaly_status(self, event_id: str, status: str) -> None:
        self.client.command(
            """
            ALTER TABLE anomaly_events
            UPDATE status = {status:String}
            WHERE event_id = {event_id:String}
            """,
            parameters={"event_id": event_id, "status": status},
        )

    def aggregate_anomalies(
        self,
        *,
        field: str,
        tenant_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        _assert_allowed_values([field], {"attack_type", "user_id", "risk_level", "status"}, "anomaly aggregate field")
        filters, parameters = _build_anomaly_filters(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
        )
        parameters["limit"] = _normalize_limit(limit)
        return self._select_dicts(
            f"""
            SELECT {field} AS key, count() AS count
            FROM anomaly_events
            {_where(filters)}
            GROUP BY {field}
            ORDER BY count DESC
            LIMIT {{limit:UInt64}}
            """,
            parameters,
        )

    def list_user_risk_stats(
        self,
        *,
        tenant_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        window: str = "7d",
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        start_time, end_time, resolved_window = _resolve_user_risk_window(window, start_time, end_time)
        filters, parameters = _build_anomaly_filters(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
        )
        filters.append("user_id != ''")
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        parameters["decay_reference"] = end_time or datetime.now(timezone.utc)
        parameters["half_life_seconds"] = float(7 * 24 * 60 * 60)
        parameters["window"] = resolved_window
        rows = self._select_dicts(
            f"""
            SELECT
                user_id,
                {{window:String}} AS window,
                countIf(status != 'false_positive') AS anomaly_count,
                countIf(status != 'false_positive' AND risk_level IN ('high', 'critical')) AS high_risk_count,
                countIf(status != 'false_positive' AND risk_level = 'critical') AS critical_count,
                maxIf(risk_score, status != 'false_positive') AS max_risk_score,
                sumIf(risk_score, status != 'false_positive') AS active_risk_score,
                sumIf(
                    risk_score * pow(0.5, greatest(dateDiff('second', event_time, {{decay_reference:DateTime64(3)}}), 0) / {{half_life_seconds:Float64}}),
                    status != 'false_positive'
                ) AS decayed_risk_score,
                countIf(status = 'false_positive') AS false_positive_excluded_count,
                max(event_time) AS latest_event_time
            FROM anomaly_events
            {where_sql}
            GROUP BY user_id
            HAVING anomaly_count > 0
            ORDER BY decayed_risk_score DESC, high_risk_count DESC, max_risk_score DESC, anomaly_count DESC, latest_event_time DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"""
            SELECT count()
            FROM (
                SELECT user_id
                FROM anomaly_events
                {where_sql}
                GROUP BY user_id
                HAVING countIf(status != 'false_positive') > 0
            )
            """,
            parameters,
            default=0,
        )
        return rows, int(total or 0)

    def list_user_baselines(
        self,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        baseline_date: date | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_baseline_filters(
            tenant_id=tenant_id,
            user_id=user_id,
            baseline_date=baseline_date,
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        # Pick every period from the latest rebuild for the paginated users, then
        # resolve one period per user for the requested date.
        rows = self._select_dicts(
            f"""
            WITH baseline_keys AS (
                SELECT DISTINCT b.tenant_id, b.user_id, b.baseline_date,
                       b.period_type, b.period_key, b.model_version,
                       b.trained_from, b.trained_to
                FROM ueba_user_baseline AS b
                INNER JOIN (
                    SELECT tenant_id, user_id, max(baseline_date) AS baseline_date
                    FROM ueba_user_baseline
                    {where_sql}
                    GROUP BY tenant_id, user_id
                    ORDER BY user_id ASC
                    LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
                ) AS l
                    ON b.tenant_id = l.tenant_id
                   AND b.user_id = l.user_id
                   AND b.baseline_date = l.baseline_date
            )
            SELECT {_columns_sql(BASELINE_COLUMNS, "b")}
            FROM ueba_user_baseline AS b
            INNER JOIN baseline_keys AS k
                USING (
                    tenant_id, user_id, baseline_date, period_type, period_key,
                    model_version, trained_from, trained_to
                )
            ORDER BY b.user_id ASC, b.period_type ASC, b.period_key ASC,
                     b.profile_group ASC, b.feature_name ASC
            """,
            parameters,
        )
        total = self._select_scalar(
            f"""
            SELECT count(DISTINCT (tenant_id, user_id))
            FROM ueba_user_baseline
            {where_sql}
            """,
            parameters,
            default=0,
        )
        profiles = _baseline_rows_to_profiles(rows)
        return _select_user_periods(profiles, event_time=baseline_date), int(total or 0)

    def get_user_baseline(
        self,
        user_id: str,
        *,
        tenant_id: str | None = None,
        baseline_date: date | None = None,
    ) -> dict[str, Any] | None:
        filters, parameters = _build_baseline_filters(
            tenant_id=tenant_id,
            user_id=user_id,
            baseline_date=None,
        )
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(BASELINE_COLUMNS)}
            FROM ueba_user_baseline
            {_where(filters)}
              AND baseline_date = (
                  SELECT max(baseline_date)
                  FROM ueba_user_baseline
                  {_where(filters)}
              )
            ORDER BY period_type ASC, period_key ASC, profile_group ASC, feature_name ASC
            """,
            parameters,
        )
        profiles = _baseline_rows_to_profiles(rows)
        if not profiles:
            return None
        overrides, _total = self.list_baseline_overrides(
            tenant_id=tenant_id,
            status="active",
            limit=1000,
            offset=0,
        )
        overrides = [
            item
            for item in overrides
            if str(item.get("user_id") or "") in {"", user_id}
        ]
        from src.ueba.effective import resolve_effective_baseline

        return resolve_effective_baseline(
            profiles,
            overrides,
            event_time=baseline_date,
        )

    def list_baseline_overrides(
        self,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        status: str | None = None,
        source_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_filters(
            equals={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "status": status,
                "source_type": source_type,
            }
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(BASELINE_OVERRIDE_COLUMNS)}
            FROM ueba_baseline_overrides FINAL
            {where_sql}
            ORDER BY updated_at DESC, override_id ASC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM ueba_baseline_overrides FINAL {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_baseline_override_row(row) for row in rows], int(total or 0)

    def get_baseline_override(self, override_id: str) -> dict[str, Any] | None:
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(BASELINE_OVERRIDE_COLUMNS)}
            FROM ueba_baseline_overrides FINAL
            WHERE override_id = {{override_id:String}}
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            {"override_id": override_id},
        )
        return _normalize_baseline_override_row(rows[0]) if rows else None

    def insert_baseline_override(self, override: BaselineOverride | dict[str, Any]) -> None:
        row = _row_from_payload(
            _model_payload(override),
            BASELINE_OVERRIDE_COLUMNS,
            json_fields=BASELINE_OVERRIDE_JSON_FIELDS,
            defaults={
                "tenant_id": "default",
                "user_id": "",
                "source_feedback_id": "",
                "reviewed_by": "",
            },
        )
        self.client.insert(
            "ueba_baseline_overrides",
            [row],
            column_names=list(BASELINE_OVERRIDE_COLUMNS),
        )

    def update_baseline_override_status(
        self,
        override_id: str,
        *,
        status: str,
        reviewed_by: str,
        reason: str,
        updated_at: datetime,
    ) -> dict[str, Any] | None:
        existing = self.get_baseline_override(override_id)
        if existing is None:
            return None
        updated = {
            **existing,
            "status": status,
            "reviewed_by": reviewed_by,
            "reviewed_at": updated_at,
            "reason": f"{existing.get('reason') or ''}\n{reason}".strip(),
            "updated_at": updated_at,
        }
        self.insert_baseline_override(updated)
        return updated

    def insert_ai_judgement(self, judgement: AIJudgement | dict[str, Any]) -> None:
        payload = _model_payload(judgement)
        row = _row_from_payload(
            payload,
            AI_JUDGEMENT_COLUMNS,
            json_fields=AI_JUDGEMENT_JSON_FIELDS,
            defaults={"model_version": "", "is_mock": False},
        )
        self.client.insert("ai_judgements", [row], column_names=list(AI_JUDGEMENT_COLUMNS))

    def list_ai_judgements(
        self,
        *,
        event_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_filters(equals={"event_id": event_id})
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(AI_JUDGEMENT_COLUMNS)}
            FROM ai_judgements
            {where_sql}
            ORDER BY created_at DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM ai_judgements {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_ai_judgement_row(row) for row in rows], int(total or 0)

    def get_latest_ai_judgement(self, event_id: str) -> dict[str, Any] | None:
        items, _total = self.list_ai_judgements(event_id=event_id, limit=1, offset=0)
        return items[0] if items else None

    def insert_feedback(self, feedback: AIFeedback | dict[str, Any]) -> None:
        payload = _model_payload(feedback)
        row = _row_from_payload(
            payload,
            AI_FEEDBACK_COLUMNS,
            defaults={
                "judgement_id": "",
                "user_id": "",
                "review_status": "pending",
                "reviewed_by": "",
                "review_reason": "",
                "applied_override_id": "",
                "applied_version": "",
            },
        )
        self.client.insert("ai_feedback", [row], column_names=list(AI_FEEDBACK_COLUMNS))

    def list_feedback(
        self,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        review_status: str | None = None,
        target_component: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_filters(
            equals={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "review_status": review_status,
                "target_component": target_component,
            }
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(AI_FEEDBACK_COLUMNS)}
            FROM ai_feedback
            {where_sql}
            ORDER BY created_at DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM ai_feedback {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_feedback_row(row) for row in rows], int(total or 0)

    def get_feedback(self, feedback_id: str) -> dict[str, Any] | None:
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(AI_FEEDBACK_COLUMNS)}
            FROM ai_feedback
            WHERE feedback_id = {{feedback_id:String}}
            ORDER BY created_at DESC
            LIMIT 1
            """,
            {"feedback_id": feedback_id},
        )
        return _normalize_feedback_row(rows[0]) if rows else None

    def update_feedback_review(
        self,
        feedback_id: str,
        *,
        review_status: str,
        reviewed_by: str,
        reviewed_at: datetime,
        review_reason: str,
        applied_override_id: str = "",
        applied_version: str = "",
    ) -> None:
        self.client.command(
            """
            ALTER TABLE ai_feedback UPDATE
                review_status = {review_status:String},
                reviewed_by = {reviewed_by:String},
                reviewed_at = {reviewed_at:Nullable(DateTime)},
                review_reason = {review_reason:String},
                applied_override_id = {applied_override_id:String},
                applied_version = {applied_version:String}
            WHERE feedback_id = {feedback_id:String}
            """,
            parameters={
                "feedback_id": feedback_id,
                "review_status": review_status,
                "reviewed_by": reviewed_by,
                "reviewed_at": reviewed_at,
                "review_reason": review_reason,
                "applied_override_id": applied_override_id,
                "applied_version": applied_version,
            },
        )

    def insert_daily_report(self, report: DailyReport | dict[str, Any], *, tenant_id: str = "default") -> None:
        payload = _daily_report_payload(_model_payload(report), tenant_id=tenant_id)
        row = _row_from_payload(
            payload,
            DAILY_REPORT_COLUMNS,
            json_fields={"input_watermark"},
            defaults={"run_id": "", "input_watermark": {}, "quality_status": "unknown"},
        )
        self.client.insert("daily_security_reports", [row], column_names=list(DAILY_REPORT_COLUMNS))

    def insert_data_quality_metrics(self, metrics: Sequence[DataQualityMetric | dict[str, Any]]) -> None:
        rows = [
            _row_from_payload(_model_payload(metric), DATA_QUALITY_COLUMNS)
            for metric in metrics
        ]
        if rows:
            self.client.insert("data_quality_metrics", rows, column_names=list(DATA_QUALITY_COLUMNS))

    def list_data_quality_metrics(
        self,
        *,
        metric_date: date | None = None,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        filters, parameters = _build_filters(
            equals={"metric_date": metric_date, "tenant_id": tenant_id}
        )
        return self._select_dicts(
            f"""
            SELECT {_columns_sql(DATA_QUALITY_COLUMNS)}
            FROM data_quality_metrics
            {_where(filters)}
            ORDER BY metric_date DESC, source_type ASC, created_at DESC
            """,
            parameters,
        )

    def insert_task_run(self, run: OperationsTaskRun | dict[str, Any]) -> None:
        row = _row_from_payload(
            _model_payload(run),
            OPERATIONS_TASK_RUN_COLUMNS,
            json_fields={"input_watermark", "output_refs"},
            defaults={
                "started_at": None,
                "finished_at": None,
                "input_watermark": {},
                "output_refs": {},
                "error_code": "",
                "error_message": "",
            },
        )
        self.client.insert("operations_task_runs", [row], column_names=list(OPERATIONS_TASK_RUN_COLUMNS))

    def list_task_runs(
        self,
        *,
        task_name: str | None = None,
        tenant_id: str | None = None,
        status: str | None = None,
        target_date: date | None = None,
        idempotency_key: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_filters(
            equals={
                "task_name": task_name,
                "tenant_id": tenant_id,
                "status": status,
                "target_date": target_date,
                "idempotency_key": idempotency_key,
            }
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(OPERATIONS_TASK_RUN_COLUMNS)}
            FROM operations_task_runs FINAL
            {where_sql}
            ORDER BY scheduled_at DESC, attempt DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM operations_task_runs FINAL {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_task_run_row(row) for row in rows], int(total or 0)

    def get_task_run(self, run_id: str) -> dict[str, Any] | None:
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(OPERATIONS_TASK_RUN_COLUMNS)}
            FROM operations_task_runs FINAL
            WHERE run_id = {{run_id:String}}
            ORDER BY version DESC
            LIMIT 1
            """,
            {"run_id": run_id},
        )
        return _normalize_task_run_row(rows[0]) if rows else None

    def successful_task_run(self, idempotency_key: str) -> dict[str, Any] | None:
        rows, _total = self.list_task_runs(
            idempotency_key=idempotency_key,
            status="succeeded",
            limit=1,
            offset=0,
        )
        return rows[0] if rows else None

    def max_task_attempt(self, idempotency_key: str) -> int:
        return int(
            self._select_scalar(
                """
                SELECT max(attempt)
                FROM operations_task_runs FINAL
                WHERE idempotency_key = {idempotency_key:String}
                """,
                {"idempotency_key": idempotency_key},
                default=0,
            )
            or 0
        )

    def dependency_succeeded(
        self,
        *,
        task_name: str,
        tenant_id: str,
        target_date: date,
    ) -> bool:
        count = self._select_scalar(
            """
            SELECT count()
            FROM operations_task_runs FINAL
            WHERE task_name = {task_name:String}
              AND tenant_id = {tenant_id:String}
              AND target_date = {target_date:Date}
              AND status = 'succeeded'
            """,
            {"task_name": task_name, "tenant_id": tenant_id, "target_date": target_date},
            default=0,
        )
        return bool(count)

    def data_watermark(self, *, tenant_id: str, target_date: date) -> dict[str, Any]:
        rows = self._select_dicts(
            """
            SELECT
                count() AS security_logs_count,
                uniqExact(event_id) AS distinct_event_count,
                min(event_time) AS first_event_time,
                max(event_time) AS latest_event_time,
                max(ingest_time) AS latest_ingest_time,
                countIf(log_type = 'parse_error' OR has(risk_tags, 'parse_error')) AS parse_error_count
            FROM security_logs
            WHERE tenant_id = {tenant_id:String}
              AND event_date = {target_date:Date}
            """,
            {"tenant_id": tenant_id, "target_date": target_date},
        )
        return rows[0] if rows else {
            "security_logs_count": 0,
            "distinct_event_count": 0,
            "first_event_time": None,
            "latest_event_time": None,
            "latest_ingest_time": None,
            "parse_error_count": 0,
        }

    def insert_acceptance_report(
        self,
        report: AcceptanceReport | dict[str, Any],
        metrics: Sequence[AcceptanceMetric | dict[str, Any]],
    ) -> None:
        report_row = _row_from_payload(
            _model_payload(report),
            ACCEPTANCE_REPORT_COLUMNS,
            json_fields={"summary"},
            defaults={
                "sample_from": None,
                "sample_to": None,
                "run_id": "",
                "summary": {},
            },
        )
        self.client.insert("acceptance_reports", [report_row], column_names=list(ACCEPTANCE_REPORT_COLUMNS))
        metric_rows = [
            _row_from_payload(
                _model_payload(metric),
                ACCEPTANCE_METRIC_COLUMNS,
                json_fields={"details"},
                defaults={"scenario_type": "overall", "details": {}},
            )
            for metric in metrics
        ]
        if metric_rows:
            self.client.insert("acceptance_metrics", metric_rows, column_names=list(ACCEPTANCE_METRIC_COLUMNS))

    def list_acceptance_reports(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        limit: int = 30,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_filters(equals={"tenant_id": tenant_id, "status": status})
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(ACCEPTANCE_REPORT_COLUMNS)}
            FROM acceptance_reports FINAL
            {where_sql}
            ORDER BY created_at DESC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM acceptance_reports FINAL {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_acceptance_report_row(row) for row in rows], int(total or 0)

    def get_acceptance_report(self, report_id: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        reports = self._select_dicts(
            f"""
            SELECT {_columns_sql(ACCEPTANCE_REPORT_COLUMNS)}
            FROM acceptance_reports FINAL
            WHERE report_id = {{report_id:String}}
            LIMIT 1
            """,
            {"report_id": report_id},
        )
        metrics = self._select_dicts(
            f"""
            SELECT {_columns_sql(ACCEPTANCE_METRIC_COLUMNS)}
            FROM acceptance_metrics
            WHERE report_id = {{report_id:String}}
            ORDER BY metric_name ASC, scenario_type ASC
            """,
            {"report_id": report_id},
        )
        report = _normalize_acceptance_report_row(reports[0]) if reports else None
        return report, [_normalize_acceptance_metric_row(row) for row in metrics]

    def acceptance_scenario_rows(
        self,
        *,
        tenant_id: str = "default",
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        time_filters = ["tenant_id = {tenant_id:String}", "injected_label != ''"]
        anomaly_filters = ["tenant_id = {tenant_id:String}"]
        parameters: dict[str, Any] = {"tenant_id": tenant_id}
        if start_time is not None:
            time_filters.append("event_time >= {start_time:DateTime64(3)}")
            anomaly_filters.append("event_time >= {start_time:DateTime64(3)}")
            parameters["start_time"] = start_time
        if end_time is not None:
            time_filters.append("event_time <= {end_time:DateTime64(3)}")
            anomaly_filters.append("event_time <= {end_time:DateTime64(3)}")
            parameters["end_time"] = end_time
        logs = self._select_dicts(
            f"""
            SELECT
                event_id, event_time, ingest_time, source_type, user_id,
                scenario_id, scenario_type, attack_chain_id, step_index, injected_label
            FROM security_logs
            {_where(time_filters)}
            ORDER BY event_time ASC
            """,
            parameters,
        )
        anomalies = self._select_dicts(
            f"""
            SELECT
                event_id, event_time, detect_time, risk_level, risk_score,
                attack_type, reason_codes, scenario_id, scenario_type,
                attack_chain_id, related_event_ids, scoring_version
            FROM anomaly_events
            {_where(anomaly_filters)}
            ORDER BY detect_time ASC
            """,
            parameters,
        )
        judgements = self._select_dicts(
            """
            SELECT event_id, model_name, model_version, is_mock, created_at
            FROM ai_judgements
            ORDER BY created_at ASC
            """
        )
        deliveries = self._select_dicts(
            """
            SELECT event_id, delivered_at
            FROM notification_outbox FINAL
            WHERE tenant_id = {tenant_id:String}
              AND status = 'delivered'
            """,
            {"tenant_id": tenant_id},
        )
        return {"logs": logs, "anomalies": anomalies, "judgements": judgements, "deliveries": deliveries}

    def latest_baseline_model_version(self, tenant_id: str = "default") -> str:
        value = self._select_scalar(
            """
            SELECT argMax(model_version, created_at)
            FROM ueba_user_baseline
            WHERE tenant_id = {tenant_id:String}
            """,
            {"tenant_id": tenant_id},
            default="",
        )
        return str(value or "")

    def enqueue_notification(self, item: NotificationOutbox | dict[str, Any]) -> dict[str, Any]:
        payload = _model_payload(item)
        existing = self.get_notification_by_idempotency_key(str(payload["idempotency_key"]))
        if existing:
            return existing
        row = _row_from_payload(
            payload,
            NOTIFICATION_OUTBOX_COLUMNS,
            json_fields={"payload"},
            defaults={"last_error": "", "delivered_at": None},
        )
        self.client.insert("notification_outbox", [row], column_names=list(NOTIFICATION_OUTBOX_COLUMNS))
        return _normalize_notification_outbox_row(dict(payload))

    def get_notification_by_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(NOTIFICATION_OUTBOX_COLUMNS)}
            FROM notification_outbox FINAL
            WHERE idempotency_key = {{idempotency_key:String}}
            ORDER BY version DESC
            LIMIT 1
            """,
            {"idempotency_key": idempotency_key},
        )
        return _normalize_notification_outbox_row(rows[0]) if rows else None

    def get_notification(self, outbox_id: str) -> dict[str, Any] | None:
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(NOTIFICATION_OUTBOX_COLUMNS)}
            FROM notification_outbox FINAL
            WHERE outbox_id = {{outbox_id:String}}
            ORDER BY version DESC
            LIMIT 1
            """,
            {"outbox_id": outbox_id},
        )
        return _normalize_notification_outbox_row(rows[0]) if rows else None

    def list_notifications(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        due_before: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_filters(equals={"tenant_id": tenant_id, "status": status})
        if due_before is not None:
            filters.append("next_attempt_at <= {due_before:DateTime64(3)}")
            parameters["due_before"] = due_before
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(NOTIFICATION_OUTBOX_COLUMNS)}
            FROM notification_outbox FINAL
            {where_sql}
            ORDER BY next_attempt_at ASC, created_at ASC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM notification_outbox FINAL {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_notification_outbox_row(row) for row in rows], int(total or 0)

    def append_notification_state(self, item: NotificationOutbox | dict[str, Any]) -> None:
        row = _row_from_payload(
            _model_payload(item),
            NOTIFICATION_OUTBOX_COLUMNS,
            json_fields={"payload"},
            defaults={"last_error": "", "delivered_at": None},
        )
        self.client.insert("notification_outbox", [row], column_names=list(NOTIFICATION_OUTBOX_COLUMNS))

    def insert_notification_attempt(self, attempt: NotificationAttempt | dict[str, Any]) -> None:
        row = _row_from_payload(
            _model_payload(attempt),
            NOTIFICATION_ATTEMPT_COLUMNS,
            defaults={"response_status": None, "error_code": "", "error_message": "", "response_body": ""},
        )
        self.client.insert("notification_attempts", [row], column_names=list(NOTIFICATION_ATTEMPT_COLUMNS))

    def list_notification_attempts(self, outbox_id: str) -> list[dict[str, Any]]:
        return self._select_dicts(
            f"""
            SELECT {_columns_sql(NOTIFICATION_ATTEMPT_COLUMNS)}
            FROM notification_attempts
            WHERE outbox_id = {{outbox_id:String}}
            ORDER BY attempt ASC, started_at ASC
            """,
            {"outbox_id": outbox_id},
        )

    def insert_parse_failure(self, failure: ParseFailure | dict[str, Any]) -> None:
        row = _row_from_payload(_model_payload(failure), PARSE_FAILURE_COLUMNS)
        self.client.insert("parser_failures", [row], column_names=list(PARSE_FAILURE_COLUMNS))

    def security_log_quality_stats(self, event_ids: Sequence[str]) -> dict[str, Any]:
        if not event_ids:
            return {
                "security_logs_count": 0,
                "missing_event_time_count": 0,
                "missing_user_id_count": 0,
                "missing_src_ip_count": 0,
                "missing_action_count": 0,
                "missing_result_count": 0,
                "parse_error_count": 0,
            }
        sql = """
            SELECT
                count() AS security_logs_count,
                countIf(event_time IS NULL) AS missing_event_time_count,
                countIf(user_id = '') AS missing_user_id_count,
                countIf(src_ip = '') AS missing_src_ip_count,
                countIf(action = '') AS missing_action_count,
                countIf(result = '') AS missing_result_count,
                countIf(log_type = 'parse_error' OR has(risk_tags, 'parse_error')) AS parse_error_count
            FROM security_logs {final_clause}
            WHERE event_id IN {{event_ids:Array(String)}}
            """
        try:
            rows = self._select_dicts(
                sql.format(final_clause="FINAL"),
                {"event_ids": list(event_ids)},
            )
        except Exception:
            rows = self._select_dicts(
                sql.format(final_clause=""),
                {"event_ids": list(event_ids)},
            )
        return rows[0] if rows else {
            "security_logs_count": 0,
            "missing_event_time_count": 0,
            "missing_user_id_count": 0,
            "missing_src_ip_count": 0,
            "missing_action_count": 0,
            "missing_result_count": 0,
            "parse_error_count": 0,
        }

    def security_logs_daily_counts(
        self,
        *,
        metric_date: date,
        tenant_id: str,
        source_type: str,
    ) -> dict[str, Any]:
        """Real per-(date, source_type) counts straight from ClickHouse.

        Unlike :meth:`security_log_quality_stats`, this does not depend on the
        generator manifest's event_id list: it reports what actually landed in
        ``security_logs`` so data-quality metrics reflect true pipeline output
        rather than manifest-derived estimates.

        ``clickhouse_insert_count`` is the raw row count (may include
        not-yet-merged ReplacingMergeTree duplicates); ``parsed_logs_count`` is
        the distinct event_id count of records that were successfully parsed and
        persisted.
        """
        rows = self._select_dicts(
            """
            SELECT
                count() AS clickhouse_insert_count,
                uniqExact(event_id) AS parsed_logs_count,
                countIf(log_type = 'parse_error' OR has(risk_tags, 'parse_error')) AS parse_error_count,
                countIf(user_id = '') AS missing_user_id_count,
                countIf(src_ip = '') AS missing_src_ip_count,
                countIf(action = '') AS missing_action_count,
                countIf(result = '') AS missing_result_count
            FROM security_logs
            WHERE event_date = {metric_date:Date}
              AND tenant_id = {tenant_id:String}
              AND source_type = {source_type:String}
            """,
            {"metric_date": metric_date, "tenant_id": tenant_id, "source_type": source_type},
        )
        default = {
            "clickhouse_insert_count": 0,
            "parsed_logs_count": 0,
            "parse_error_count": 0,
            "missing_event_time_count": 0,
            "missing_user_id_count": 0,
            "missing_src_ip_count": 0,
            "missing_action_count": 0,
            "missing_result_count": 0,
        }
        if not rows:
            return default
        merged = {**default, **rows[0]}
        # event_time is non-nullable in the security_logs schema, so missing
        # event_time is always zero here; keep the key for a stable contract.
        merged["missing_event_time_count"] = 0
        return merged

    def security_logs_table_size_bytes(self) -> int:
        value = self._select_scalar(
            """
            SELECT sum(bytes_on_disk)
            FROM system.parts
            WHERE database = {database:String}
              AND table = 'security_logs'
              AND active
            """,
            {"database": settings.clickhouse_database},
            default=0,
        )
        return int(value or 0)

    def insert_user_baselines(self, baselines: Sequence[UserBaseline | dict[str, Any]]) -> None:
        """Insert baselines, replacing any existing entries for the same users."""
        if not baselines:
            return
        # Dedup: delete existing baselines for these users before inserting
        payloads = [_model_payload(b) for b in baselines]
        keys: set[tuple[str, str]] = set()
        for p in payloads:
            keys.add((str(p.get("tenant_id", "default")), str(p["user_id"])))
        for tenant_id, user_id in keys:
            self.client.command(
                "ALTER TABLE ueba_user_baseline DELETE WHERE tenant_id = {t:String} AND user_id = {u:String}",
                parameters={"t": tenant_id, "u": user_id},
            )
        rows: list[list[Any]] = []
        for payload in payloads:
            rows.extend(_baseline_rows_from_payload(payload))
        self.client.insert("ueba_user_baseline", rows, column_names=list(BASELINE_COLUMNS))

    def aggregate_daily_features_sql(
        self,
        *,
        metric_date: date,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate one day of ``security_logs`` into per-user feature rows.

        The grouping and counting run inside ClickHouse (``GROUP BY`` over a
        single partition day) instead of streaming up to 100k raw rows into
        Python, which is the scalable path under 1GB/day. The caller turns each
        returned row into a ``ueba_user_daily_features`` record.
        """
        filters = ["event_date = {metric_date:Date}", "user_id != ''"]
        parameters: dict[str, Any] = {"metric_date": metric_date}
        if tenant_id is not None:
            filters.append("tenant_id = {tenant_id:String}")
            parameters["tenant_id"] = tenant_id
        return self._select_dicts(
            f"""
            SELECT
                tenant_id,
                user_id,
                topK(1)(account_type) AS account_type_top,
                count() AS event_count,
                countIf(action = 'login') AS login_count,
                countIf(action = 'login' AND result = 'fail') AS failed_login_count,
                countIf(action = 'login' AND result = 'success') AS success_login_count,
                uniqExactIf(src_ip, src_ip != '') AS distinct_src_ip_count,
                uniqExactIf(dst_ip, dst_ip != '') AS distinct_host_count,
                uniqExactIf(action, action != '') AS distinct_action_count,
                min(event_time) AS first_seen_time,
                max(event_time) AS last_seen_time,
                countIf(toHour(event_time) >= 22 OR toHour(event_time) < 6) AS night_event_count,
                countIf(multiSearchAnyCaseInsensitive(action, ['download', 'export', 'admin', 'sensitive'])) AS sensitive_action_count,
                countIf(multiSearchAnyCaseInsensitive(action, ['download', 'export'])) AS download_count,
                countIf(multiSearchAnyCaseInsensitive(action, ['permission', 'grant', 'revoke', 'role'])) AS permission_change_count,
                topK(5)(src_ip) AS common_src_ips_raw,
                topK(5)(dst_ip) AS common_hosts_raw,
                topK(5)(action) AS common_actions_raw
            FROM security_logs
            {_where(filters)}
            GROUP BY tenant_id, user_id
            """,
            parameters,
        )

    def insert_user_daily_features(self, rows: list[dict[str, Any]]) -> None:
        processed: list[list[Any]] = []
        now_dt = datetime.now(timezone.utc)
        scopes: set[tuple[str, Any]] = set()
        for row in rows:
            row.setdefault("tenant_id", "default")
            row.setdefault("created_at", now_dt)
            scopes.add((str(row.get("tenant_id")), row.get("feature_date")))
            processed.append([row.get(col) for col in DAILY_FEATURES_COLUMNS])
        if not processed:
            return
        # Idempotent rebuild: clear any prior rows for the (tenant, feature_date)
        # pairs being written so repeated aggregation/backfill does not duplicate
        # daily features.
        for tenant_id, feature_date in scopes:
            if feature_date is None:
                continue
            self.client.command(
                """
                ALTER TABLE ueba_user_daily_features
                DELETE WHERE tenant_id = {tenant_id:String} AND feature_date = {feature_date:Date}
                """,
                parameters={"tenant_id": tenant_id, "feature_date": feature_date},
            )
        self.client.insert("ueba_user_daily_features", processed, column_names=list(DAILY_FEATURES_COLUMNS))

    def upsert_user_seen_sources(self, sources: list[dict[str, Any]]) -> None:
        processed: list[list[Any]] = []
        now_dt = datetime.now(timezone.utc)
        for s in sources:
            s.setdefault("tenant_id", "default")
            s.setdefault("created_at", now_dt)
            s.setdefault("updated_at", now_dt)
            s.setdefault("first_seen_time", now_dt)
            s.setdefault("last_seen_time", now_dt)
            processed.append([s.get(col) for col in SEEN_SOURCES_COLUMNS])
        if processed:
            self.client.insert("user_seen_sources", processed, column_names=list(SEEN_SOURCES_COLUMNS))

    def query_user_seen_sources(
        self,
        tenant_id: str = "default",
        user_id: str | None = None,
        source_type: str | None = None,
        source_key: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        filters: list[str] = ["tenant_id = {tenant_id:String}"]
        parameters: dict[str, Any] = {"tenant_id": tenant_id}
        if user_id:
            filters.append("user_id = {user_id:String}")
            parameters["user_id"] = user_id
        if source_type:
            filters.append("source_type = {source_type:String}")
            parameters["source_type"] = source_type
        if source_key:
            filters.append("source_key = {source_key:String}")
            parameters["source_key"] = source_key
        sql = f"SELECT * FROM user_seen_sources {_where(filters)} LIMIT {{limit:UInt64}}"
        return self._select_dicts(sql, parameters | {"limit": limit})

    def upsert_reason_code_feedback_stats(
        self,
        tenant_id: str,
        user_id: str,
        reason_codes_combo: str,
        *,
        fp_delta: int = 0,
        confirmed_delta: int = 0,
    ) -> None:
        """Increment fp_count or confirmed_count for a reason-codes combo."""
        existing = self._select_dicts(
            """
            SELECT fp_count, confirmed_count
            FROM reason_code_feedback_stats FINAL
            WHERE tenant_id = {t:String} AND user_id = {u:String}
              AND reason_codes_combo = {combo:String}
            LIMIT 1
            """,
            {"t": tenant_id, "u": user_id, "combo": reason_codes_combo},
        )
        if existing:
            row_val = existing[0]
            new_fp = int(row_val.get("fp_count", 0)) + fp_delta
            new_confirmed = int(row_val.get("confirmed_count", 0)) + confirmed_delta
        else:
            new_fp = max(0, fp_delta)
            new_confirmed = max(0, confirmed_delta)

        self.client.insert(
            "reason_code_feedback_stats",
            [[tenant_id, user_id, reason_codes_combo, new_fp, new_confirmed, datetime.now(timezone.utc)]],
            column_names=list(REASON_CODE_FEEDBACK_STATS_COLUMNS),
        )

    def get_user_reason_feedback_stats(
        self,
        tenant_id: str = "default",
        user_id: str | None = None,
    ) -> dict[str, dict[str, int]]:
        filters: list[str] = ["tenant_id = {t:String}"]
        parameters: dict[str, Any] = {"t": tenant_id}
        if user_id:
            filters.append("user_id = {u:String}")
            parameters["u"] = user_id
        rows = self._select_dicts(
            f"""
            SELECT user_id, reason_codes_combo, fp_count, confirmed_count
            FROM reason_code_feedback_stats FINAL
            {_where(filters)}
            """,
            parameters,
        )
        result: dict[str, dict[str, int]] = {}
        for r in rows:
            uid = str(r.get("user_id") or "")
            combo = str(r.get("reason_codes_combo") or "")
            key = f"{uid}:{combo}"
            result[key] = {
                "fp_count": int(r.get("fp_count") or 0),
                "confirmed_count": int(r.get("confirmed_count") or 0),
            }
        return result

    def list_daily_reports(
        self,
        *,
        tenant_id: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        limit: int = 30,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters, parameters = _build_daily_report_filters(
            tenant_id=tenant_id,
            start_date=start_date,
            end_date=end_date,
        )
        where_sql = _where(filters)
        parameters |= _pagination_parameters(limit=limit, offset=offset)
        rows = self._select_dicts(
            f"""
            SELECT {_columns_sql(DAILY_REPORT_COLUMNS)}
            FROM daily_security_reports
            {where_sql}
            ORDER BY report_date DESC, tenant_id ASC
            LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}
            """,
            parameters,
        )
        total = self._select_scalar(
            f"SELECT count() FROM daily_security_reports {where_sql}",
            parameters,
            default=0,
        )
        return [_normalize_daily_report_row(row) for row in rows], int(total or 0)

    def get_daily_report(self, *, tenant_id: str, report_date: date) -> dict[str, Any] | None:
        rows, _total = self.list_daily_reports(
            tenant_id=tenant_id,
            start_date=report_date,
            end_date=report_date,
            limit=1,
            offset=0,
        )
        return rows[0] if rows else None

    def get_stats_overview(
        self,
        *,
        tenant_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        log_filters, parameters = _build_log_filters(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
        )
        anomaly_filters, anomaly_parameters = _build_anomaly_filters(
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
        )
        parameters |= {f"anom_{key}": value for key, value in anomaly_parameters.items()}
        anomaly_where = _where(
            [clause.replace("{", "{anom_") for clause in anomaly_filters]
        )
        # baseline coverage and the latest report are scoped by tenant only; they
        # are not bounded by the event_time window used for logs/anomalies.
        tenant_clause = "WHERE tenant_id = {tenant_id:String}" if tenant_id is not None else ""
        row = self._select_dicts(
            f"""
            SELECT
                (SELECT count() FROM security_logs {_where(log_filters)}) AS log_count,
                (SELECT max(ingest_time) FROM security_logs {_where(log_filters)}) AS latest_log_ingest_time,
                (SELECT count() FROM anomaly_events {anomaly_where}) AS anomaly_count,
                (
                    SELECT count()
                    FROM anomaly_events
                    {_where([*anomaly_filters, "risk_level IN ('high', 'critical')"]).replace("{", "{anom_")}
                ) AS high_risk_count,
                (
                    SELECT count()
                    FROM anomaly_events
                    {_where([*anomaly_filters, "risk_level = 'critical'"]).replace("{", "{anom_")}
                ) AS critical_count,
                (
                    SELECT count()
                    FROM anomaly_events
                    {_where([*anomaly_filters, "ai_status = 'pending'"]).replace("{", "{anom_")}
                ) AS ai_pending_count,
                (SELECT uniqExact(user_id) FROM ueba_user_baseline {tenant_clause}) AS baseline_user_count,
                (SELECT max(report_date) FROM daily_security_reports {tenant_clause}) AS latest_report_date
            """,
            parameters,
        )
        return row[0] if row else {
            "log_count": 0,
            "latest_log_ingest_time": None,
            "anomaly_count": 0,
            "high_risk_count": 0,
            "critical_count": 0,
            "ai_pending_count": 0,
            "baseline_user_count": 0,
            "latest_report_date": None,
        }

    def _select_scalar(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        *,
        default: Any = None,
    ) -> Any:
        rows = self.query(sql, parameters)
        if not rows:
            return default
        return rows[0][0] if rows[0] else default

    def _select_dicts(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self.client.query(sql, parameters=parameters or {})
        rows = list(getattr(result, "result_rows", []))
        column_names = list(getattr(result, "column_names", []))
        if not column_names:
            column_names = _parse_select_aliases(sql)
        return [dict(zip(column_names, row)) for row in rows]


def _build_log_filters(
    *,
    tenant_id: str | None = None,
    source_type: str | None = None,
    log_type: str | None = None,
    user_id: str | None = None,
    src_ip: str | None = None,
    action: str | None = None,
    result: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[str], dict[str, Any]]:
    return _build_filters(
        equals={
            "tenant_id": tenant_id,
            "source_type": source_type,
            "log_type": log_type,
            "user_id": user_id,
            "src_ip": src_ip,
            "action": action,
            "result": result,
        },
        time_field="event_time",
        start_time=start_time,
        end_time=end_time,
    )


def _build_anomaly_filters(
    *,
    tenant_id: str | None = None,
    risk_level: str | None = None,
    user_id: str | None = None,
    src_ip: str | None = None,
    reason_code: str | None = None,
    ai_status: str | None = None,
    status: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[str], dict[str, Any]]:
    filters, parameters = _build_filters(
        equals={
            "tenant_id": tenant_id,
            "risk_level": risk_level,
            "user_id": user_id,
            "src_ip": src_ip,
            "ai_status": ai_status,
            "status": status,
        },
        time_field="event_time",
        start_time=start_time,
        end_time=end_time,
    )
    if reason_code:
        filters.append("has(reason_codes, {reason_code:String})")
        parameters["reason_code"] = reason_code
    return filters, parameters


def _resolve_user_risk_window(
    window: str,
    start_time: datetime | None,
    end_time: datetime | None,
) -> tuple[datetime | None, datetime | None, str]:
    resolved_window = window if window in {"24h", "7d", "30d", "custom"} else "7d"
    if resolved_window == "custom":
        return start_time, end_time, resolved_window

    reference_time = end_time or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    window_deltas = {
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    return reference_time - window_deltas[resolved_window], reference_time, resolved_window


def _build_baseline_filters(
    *,
    tenant_id: str | None = None,
    user_id: str | None = None,
    baseline_date: date | None = None,
) -> tuple[list[str], dict[str, Any]]:
    filters, parameters = _build_filters(
        equals={
            "tenant_id": tenant_id,
            "user_id": user_id,
            "baseline_date": baseline_date,
        }
    )
    return filters, parameters


def _build_daily_report_filters(
    *,
    tenant_id: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
) -> tuple[list[str], dict[str, Any]]:
    filters, parameters = _build_filters(equals={"tenant_id": tenant_id})
    if start_date:
        filters.append("report_date >= {start_date:Date}")
        parameters["start_date"] = start_date
    if end_date:
        filters.append("report_date <= {end_date:Date}")
        parameters["end_date"] = end_date
    return filters, parameters


def _build_filters(
    *,
    equals: dict[str, Any],
    time_field: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[str], dict[str, Any]]:
    filters: list[str] = []
    parameters: dict[str, Any] = {}
    for field, value in equals.items():
        if value is None:
            continue
        filters.append(f"{field} = {{{field}:{_clickhouse_type(value)}}}")
        parameters[field] = value
    if time_field and (start_time or end_time):
        if start_time:
            filters.append(f"{time_field} >= {{start_time:DateTime64(3)}}")
            parameters["start_time"] = start_time
        if end_time:
            filters.append(f"{time_field} <= {{end_time:DateTime64(3)}}")
            parameters["end_time"] = end_time
    return filters, parameters


def _where(filters: Sequence[str]) -> str:
    return f"WHERE {' AND '.join(filters)}" if filters else ""


def _columns_sql(columns: Sequence[str], table_alias: str | None = None) -> str:
    if not table_alias:
        return ", ".join(columns)
    return ", ".join(f"{table_alias}.{column} AS {column}" for column in columns)


def _pagination_parameters(*, limit: int, offset: int) -> dict[str, int]:
    return {
        "limit": _normalize_limit(limit),
        "offset": max(0, int(offset)),
    }


def _normalize_limit(limit: int) -> int:
    return max(1, int(limit))


def _clickhouse_type(value: Any) -> str:
    # 一处细节：datetime 需要写在 date 的前面，因为 datetime 是 date 的子类
    if isinstance(value, datetime):
        return "DateTime64(3)"
    if isinstance(value, date):
        return "Date"
    if isinstance(value, int):
        return "Int64"
    if isinstance(value, float):
        return "Float64"
    return "String"

# 调用 json_loads 把日志的 json 字段转化为 Python 对象
def _normalize_log_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    for field in LOG_JSON_FIELDS:
        normalized[field] = _json_loads(normalized.get(field), default={})
    return normalized


# 把表示基线偏离的 json 字段转化为列表，其他的转化为其他 Python 对象
def _normalize_anomaly_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    for field in ANOMALY_JSON_FIELDS:
        default = [] if field == "baseline_deviations" else {}
        normalized[field] = _json_loads(normalized.get(field), default=default)
    return normalized


def _normalize_ai_judgement_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    for field in AI_JUDGEMENT_JSON_FIELDS:
        normalized[field] = _json_loads(normalized.get(field), default={})
    normalized["is_mock"] = bool(normalized.get("is_mock"))
    return normalized


def _normalize_feedback_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    for field in ("judgement_id", "user_id", "reviewed_by", "review_reason", "applied_override_id", "applied_version"):
        if normalized.get(field) == "":
            normalized[field] = None
    return normalized


def _normalize_baseline_override_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["override_value"] = _json_loads(normalized.get("override_value"), default={})
    effective_to = normalized.get("effective_to")
    now = datetime.now(effective_to.tzinfo) if isinstance(effective_to, datetime) and effective_to.tzinfo else datetime.now()
    if (
        normalized.get("status") == "active"
        and isinstance(effective_to, datetime)
        and effective_to < now
    ):
        normalized["status"] = "expired"
    for field in ("source_feedback_id", "reviewed_by"):
        if normalized.get(field) == "":
            normalized[field] = None
    return normalized


# 把日报组织成适合接口返回的对象
def _normalize_daily_report_row(row: dict[str, Any]) -> dict[str, Any]:
    report_date = row.get("report_date")
    recommended_actions = _string_list(row.get("recommended_actions"))
    return {
        "report_id": f"{row.get('tenant_id', 'default')}:{report_date}",
        "date": str(report_date),
        "created_at": row.get("created_at"),
        "overall_score": row.get("overall_score", 0),
        "log_count": row.get("total_logs", 0),
        "alert_count": row.get("anomaly_count", 0),
        "high_risk_count": int(row.get("high_count") or 0) + int(row.get("critical_count") or 0),
        "major_risks": _string_list(row.get("top_attack_types")),
        "high_risk_users": _string_list(row.get("top_risk_users")),
        "typical_alerts": [{"event_id": event_id} for event_id in _string_list(row.get("key_events"))],
        "ai_summary": row.get("ai_summary", ""),
        "recommendation": "\n".join(recommended_actions),
        "markdown": row.get("markdown_body", ""),
        "run_id": row.get("run_id", ""),
        "input_watermark": _json_loads(row.get("input_watermark"), default={}),
        "quality_status": row.get("quality_status", "unknown"),
    }


def _normalize_task_run_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["input_watermark"] = _json_loads(normalized.get("input_watermark"), default={})
    normalized["output_refs"] = _json_loads(normalized.get("output_refs"), default={})
    return normalized


def _normalize_acceptance_report_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["ai_is_mock"] = bool(normalized.get("ai_is_mock"))
    normalized["summary"] = _json_loads(normalized.get("summary"), default={})
    return normalized


def _normalize_acceptance_metric_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["passed"] = bool(normalized.get("passed"))
    normalized["details"] = _json_loads(normalized.get("details"), default={})
    return normalized


def _normalize_notification_outbox_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["payload"] = _json_loads(normalized.get("payload"), default={})
    return normalized


# 把多行 baseline feature 合并成一个用户基线 profile
def _baseline_rows_to_profiles(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        # 构造：用户基线的唯一标识，即 key
        key = (
            row.get("baseline_date"),
            row.get("tenant_id"),
            row.get("user_id"),
            row.get("period_type") or "global",
            row.get("period_key") or "all",
            row.get("model_version"),
            row.get("trained_from"),
            row.get("trained_to"),
        )
        # 如果字段已经有，key 设为字典中的字段，否则取默认值
        item = grouped.setdefault(
            key,
            {
                "baseline_date": row.get("baseline_date"),
                "tenant_id": row.get("tenant_id"),
                "user_id": row.get("user_id"),
                "period_type": row.get("period_type") or "global",
                "period_key": row.get("period_key") or "all",
                "model_version": row.get("model_version"),
                "trained_from": row.get("trained_from"),
                "trained_to": row.get("trained_to"),
                "sample_days": row.get("sample_days", 0),
                "sample_count": row.get("sample_count", 0),
                "baseline_confidence": row.get("baseline_confidence", 0),
                "who_profile": {},
                "time_profile": {},
                "location_profile": {},
                "access_profile": {},
                "volume_profile": {},
                "result_profile": {},
                "why_profile": {},
                "fallback_level": row.get("fallback_level", "none"),
                "selected_baseline": {},
                "created_at": row.get("created_at"),
            },
        )
        # 取 max 值保险，一般没问题
        item["sample_days"] = max(int(item.get("sample_days") or 0), int(row.get("sample_days") or 0))
        item["sample_count"] = max(int(item.get("sample_count") or 0), int(row.get("sample_count") or 0))
        item["baseline_confidence"] = max(
            float(item.get("baseline_confidence") or 0),
            float(row.get("baseline_confidence") or 0),
        )

        profile_name = f"{row.get('profile_group')}_profile"
        if profile_name not in item:
            continue
        item[profile_name][str(row.get("feature_name"))] = {
            "mean_value": row.get("mean_value"),
            "std_value": row.get("std_value"),
            "p50_value": row.get("p50_value"),
            "p95_value": row.get("p95_value"),
            "p99_value": row.get("p99_value"),
            "common_values": _string_list(row.get("common_values")),
            "value_histogram": _json_loads(row.get("value_histogram"), default={}),
        }
    return list(grouped.values())


def _select_user_periods(
    profiles: Sequence[dict[str, Any]],
    *,
    event_time: date | datetime | None,
) -> list[dict[str, Any]]:
    from src.ueba.effective import select_periodic_baseline

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in profiles:
        key = (str(item.get("tenant_id") or "default"), str(item.get("user_id") or ""))
        grouped.setdefault(key, []).append(item)

    selected: list[dict[str, Any]] = []
    for items in grouped.values():
        item = select_periodic_baseline(items, event_time=event_time)
        if item is None:
            continue
        item["selected_baseline"] = {
            "period_type": item.get("period_type", "global"),
            "period_key": item.get("period_key", "all"),
            "fallback_level": item.get("fallback_level", "none"),
            "override_ids": [],
            "model_version": item.get("model_version", ""),
        }
        selected.append(item)
    return selected


def _daily_report_payload(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    report_date = _coerce_date(payload.get("date") or payload.get("report_date"))
    high_risk_count = int(payload.get("high_risk_count") or 0)
    typical_alerts = payload.get("typical_alerts") if isinstance(payload.get("typical_alerts"), list) else []
    key_events = [
        str(item.get("event_id"))
        for item in typical_alerts
        if isinstance(item, dict) and item.get("event_id")
    ]
    recommendation = payload.get("recommendation", "")
    recommended_actions = recommendation if isinstance(recommendation, list) else _split_non_empty_lines(str(recommendation))
    return {
        "report_date": report_date,
        "tenant_id": tenant_id,
        "total_logs": int(payload.get("log_count") or payload.get("total_logs") or 0),
        "anomaly_count": int(payload.get("alert_count") or payload.get("anomaly_count") or 0),
        "high_count": high_risk_count,
        "critical_count": int(payload.get("critical_count") or 0),
        "overall_score": float(payload.get("overall_score") or 0),
        "top_risk_users": _string_list(payload.get("high_risk_users") or payload.get("top_risk_users")),
        "top_attack_types": _string_list(payload.get("major_risks") or payload.get("top_attack_types")),
        "key_events": key_events or _string_list(payload.get("key_events")),
        "ai_summary": str(payload.get("ai_summary") or ""),
        "recommended_actions": recommended_actions,
        "markdown_body": str(payload.get("markdown") or payload.get("markdown_body") or ""),
        "run_id": str(payload.get("run_id") or ""),
        "input_watermark": payload.get("input_watermark") or {},
        "quality_status": str(payload.get("quality_status") or "unknown"),
        "created_at": payload.get("created_at"),
    }


def _baseline_rows_from_payload(payload: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    profile_names = {
        "who_profile": "who",
        "time_profile": "time",
        "location_profile": "location",
        "access_profile": "access",
        "volume_profile": "volume",
        "result_profile": "result",
        "why_profile": "why",
    }
    base = {
        "baseline_date": payload.get("baseline_date"),
        "tenant_id": payload.get("tenant_id") or "default",
        "user_id": payload.get("user_id") or "",
        "period_type": payload.get("period_type") or "global",
        "period_key": payload.get("period_key") or "all",
        "sample_days": payload.get("sample_days") or 0,
        "sample_count": payload.get("sample_count") or 0,
        "baseline_confidence": payload.get("baseline_confidence") or 0,
        "trained_from": payload.get("trained_from"),
        "trained_to": payload.get("trained_to"),
        "fallback_level": payload.get("fallback_level") or "none",
        "model_version": payload.get("model_version") or "",
        "created_at": payload.get("created_at"),
    }
    for profile_name, profile_group in profile_names.items():
        profile = payload.get(profile_name)
        if not isinstance(profile, dict):
            continue
        for feature_name, value in profile.items():
            feature_payload = {
                **base,
                "profile_group": profile_group,
                "feature_name": str(feature_name),
                **_baseline_feature_value(value),
            }
            rows.append(
                _row_from_payload(
                    feature_payload,
                    BASELINE_COLUMNS,
                    json_fields={"value_histogram"},
                    defaults={
                        "mean_value": None,
                        "std_value": None,
                        "p50_value": None,
                        "p95_value": None,
                        "p99_value": None,
                        "common_values": [],
                        "value_histogram": {},
                    },
                )
            )
    return rows


def _baseline_feature_value(value: Any) -> dict[str, Any]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return {"mean_value": float(value), "common_values": [], "value_histogram": {}}
    if isinstance(value, list):
        return {"common_values": _string_list(value), "value_histogram": {}}
    if isinstance(value, dict):
        numeric_fields = {}
        for src_key, tgt_key in (
            ("mean_value", "mean_value"), ("std_value", "std_value"),
            ("p50_value", "p50_value"), ("p95_value", "p95_value"), ("p99_value", "p99_value"),
            # Also accept short key names used by the baseline builder
            ("mean", "mean_value"), ("std", "std_value"),
            ("p50", "p50_value"), ("p95", "p95_value"), ("p99", "p99_value"),
        ):
            raw = value.get(src_key)
            if isinstance(raw, (int, float)):
                numeric_fields[tgt_key] = float(raw)
        common_values = value.get("common_values")
        histogram = value.get("value_histogram")
        if numeric_fields or common_values is not None or histogram is not None:
            return {
                **numeric_fields,
                "common_values": _string_list(common_values),
                "value_histogram": histogram if isinstance(histogram, dict) else {},
            }
        return {"common_values": [], "value_histogram": value}
    return {"common_values": [str(value)] if value not in (None, "") else [], "value_histogram": {}}


def _coerce_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _split_non_empty_lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


# 把 json 字符串转化成字典或者列表
def _json_loads(value: Any, *, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return default


# 和 loads 相反，python 对象转化为 json 字符串
def _json_dumps(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value if value is not None else {},
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return str(value)


# 把 string 和 Iterable 转化为列表
def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Iterable):
        return [str(item) for item in value if item is not None]
    return []


# 把 Pydantic 对象转化为字典
def _model_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    return dict(value)


# 把字典转化为可以放进数据库对应列的数据结构
def _row_from_payload(
    payload: dict[str, Any],
    columns: Sequence[str],
    *,
    json_fields: set[str] | None = None,
    defaults: dict[str, Any] | None = None,
) -> list[Any]:
    resolved_defaults = defaults or {}
    resolved_json_fields = json_fields or set()
    row: list[Any] = []
    for column in columns:
        value = payload.get(column, resolved_defaults.get(column))
        if value is None and column in resolved_defaults:
            value = resolved_defaults[column]
        if column in resolved_json_fields:
            value = _json_dumps(value)
        if isinstance(value, bool):
            value = int(value)
        row.append(value)
    return row


# 检查传入的内容是否在允许范围内（用 set 的差实现）
def _assert_allowed_values(values: Sequence[str], allowed: Iterable[str], label: str) -> None:
    allowed_set = set(allowed)
    invalid = sorted(set(values) - allowed_set)
    if invalid:
        raise ValueError(f"Unsupported {label}: {', '.join(invalid)}")


# 从 SELECT 中得到列名字段
def _parse_select_aliases(sql: str) -> list[str]:
    upper_sql = sql.upper()
    if "SELECT" not in upper_sql or "FROM" not in upper_sql:
        return []
    # 字符串切片，取 SELECT 和 FROM 之间的字段（本质[:]语法）
    select_sql = sql[upper_sql.index("SELECT") + len("SELECT"):upper_sql.index("FROM")]
    aliases: list[str] = []
    for raw_part in select_sql.split(","):
        part = raw_part.strip()
        if " AS " in part.upper():
            # 从右边第一个空格切，取右数第一个字段（即 AS 右边的字段，别名）
            aliases.append(part.rsplit(" ", 1)[-1])
        # 排除诸如 max(count) 这类字段
        elif part and "(" not in part:
            # 比如 b.tenant_id 执行后得到 tenant_id
            aliases.append(part.split(".")[-1])
    return aliases
