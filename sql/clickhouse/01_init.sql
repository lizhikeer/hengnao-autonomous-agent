CREATE DATABASE IF NOT EXISTS log_ai;

CREATE TABLE IF NOT EXISTS log_ai.security_logs
(
    event_id String,
    event_time DateTime64(3),
    event_date Date MATERIALIZED toDate(event_time),
    ingest_time DateTime64(3),
    tenant_id LowCardinality(String) DEFAULT 'default',
    source_type LowCardinality(String),
    log_type LowCardinality(String) DEFAULT '',
    user_id String DEFAULT '',
    account_type LowCardinality(String) DEFAULT 'unknown',
    user_role LowCardinality(String) DEFAULT '',
    department LowCardinality(String) DEFAULT '',
    host String DEFAULT '',
    src_ip String DEFAULT '',
    src_port Nullable(UInt16),
    dst_ip String DEFAULT '',
    dst_port Nullable(UInt16),
    geo String DEFAULT '{}',
    action LowCardinality(String),
    object_type LowCardinality(String) DEFAULT '',
    object_id String DEFAULT '',
    resource String DEFAULT '',
    result LowCardinality(String),
    severity UInt8 DEFAULT 0,
    user_agent String DEFAULT '',
    protocol LowCardinality(String) DEFAULT '',
    auth_method LowCardinality(String) DEFAULT '',
    session_id String DEFAULT '',
    trace_id String DEFAULT '',
    scenario_id String DEFAULT '',
    scenario_type LowCardinality(String) DEFAULT '',
    attack_chain_id String DEFAULT '',
    step_index Nullable(UInt16),
    injected_label LowCardinality(String) DEFAULT '',
    message String,
    raw_log String,
    risk_tags Array(String) DEFAULT [],
    attrs String DEFAULT '{}'
)
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_id, event_date, user_id, src_ip, source_type, event_time)
TTL toDateTime(event_time) + INTERVAL 90 DAY DELETE;

CREATE TABLE IF NOT EXISTS log_ai.parsed_logs_kafka_queue
(
    raw String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'kafka:9092',
    kafka_topic_list = 'parsed_logs',
    kafka_group_name = 'clickhouse-parsed-logs',
    kafka_format = 'JSONAsString',
    kafka_num_consumers = 1,
    kafka_skip_broken_messages = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS log_ai.parsed_logs_to_security_logs
TO log_ai.security_logs
AS
SELECT
    coalesce(nullIf(JSONExtractString(raw, 'event_id'), ''), toString(generateUUIDv4())) AS event_id,
    coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(raw, 'event_time'), 3), now64(3)) AS event_time,
    coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(raw, 'ingest_time'), 3), now64(3)) AS ingest_time,
    coalesce(nullIf(JSONExtractString(raw, 'tenant_id'), ''), 'default') AS tenant_id,
    coalesce(nullIf(JSONExtractString(raw, 'source_type'), ''), 'system') AS source_type,
    coalesce(nullIf(JSONExtractString(raw, 'log_type'), ''), '') AS log_type,
    coalesce(nullIf(JSONExtractString(raw, 'user_id'), ''), '') AS user_id,
    coalesce(nullIf(JSONExtractString(raw, 'account_type'), ''), 'unknown') AS account_type,
    coalesce(nullIf(JSONExtractString(raw, 'user_role'), ''), '') AS user_role,
    coalesce(nullIf(JSONExtractString(raw, 'department'), ''), '') AS department,
    coalesce(nullIf(JSONExtractString(raw, 'host'), ''), '') AS host,
    coalesce(nullIf(JSONExtractString(raw, 'src_ip'), ''), '') AS src_ip,
    JSONExtract(raw, 'src_port', 'Nullable(UInt16)') AS src_port,
    coalesce(nullIf(JSONExtractString(raw, 'dst_ip'), ''), '') AS dst_ip,
    JSONExtract(raw, 'dst_port', 'Nullable(UInt16)') AS dst_port,
    if(geo_raw IN ('', 'null'), '{}', geo_raw) AS geo,
    coalesce(nullIf(JSONExtractString(raw, 'action'), ''), 'access') AS action,
    coalesce(nullIf(JSONExtractString(raw, 'object_type'), ''), '') AS object_type,
    coalesce(nullIf(JSONExtractString(raw, 'object_id'), ''), '') AS object_id,
    coalesce(nullIf(JSONExtractString(raw, 'resource'), ''), '') AS resource,
    coalesce(nullIf(JSONExtractString(raw, 'result'), ''), 'error') AS result,
    JSONExtract(raw, 'severity', 'UInt8') AS severity,
    coalesce(nullIf(JSONExtractString(raw, 'user_agent'), ''), '') AS user_agent,
    coalesce(nullIf(JSONExtractString(raw, 'protocol'), ''), '') AS protocol,
    coalesce(nullIf(JSONExtractString(raw, 'auth_method'), ''), '') AS auth_method,
    coalesce(nullIf(JSONExtractString(raw, 'session_id'), ''), '') AS session_id,
    coalesce(nullIf(JSONExtractString(raw, 'trace_id'), ''), '') AS trace_id,
    coalesce(nullIf(JSONExtractString(raw, 'scenario_id'), ''), '') AS scenario_id,
    coalesce(nullIf(JSONExtractString(raw, 'scenario_type'), ''), '') AS scenario_type,
    coalesce(nullIf(JSONExtractString(raw, 'attack_chain_id'), ''), '') AS attack_chain_id,
    JSONExtract(raw, 'step_index', 'Nullable(UInt16)') AS step_index,
    coalesce(nullIf(JSONExtractString(raw, 'injected_label'), ''), '') AS injected_label,
    coalesce(nullIf(JSONExtractString(raw, 'message'), ''), raw) AS message,
    coalesce(nullIf(JSONExtractString(raw, 'raw_log'), ''), raw) AS raw_log,
    if(JSONHas(raw, 'risk_tags'), JSONExtract(raw, 'risk_tags', 'Array(String)'), emptyArrayString()) AS risk_tags,
    if(attrs_raw IN ('', 'null'), '{}', attrs_raw) AS attrs
FROM
(
    SELECT
        raw,
        JSONExtractRaw(raw, 'geo') AS geo_raw,
        JSONExtractRaw(raw, 'attrs') AS attrs_raw
    FROM log_ai.parsed_logs_kafka_queue
);

CREATE TABLE IF NOT EXISTS log_ai.user_seen_sources
(
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String,
    source_type LowCardinality(String),
    source_key String,
    first_seen_time DateTime64(3),
    last_seen_time DateTime64(3),
    seen_count UInt32 DEFAULT 0,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, user_id, source_type, source_key);

CREATE TABLE IF NOT EXISTS log_ai.anomaly_events
(
    event_id String,
    event_time DateTime64(3),
    event_date Date MATERIALIZED toDate(event_time),
    detect_time DateTime64(3),
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String DEFAULT '',
    src_ip String DEFAULT '',
    host String DEFAULT '',
    source_type LowCardinality(String) DEFAULT '',
    action LowCardinality(String) DEFAULT '',
    object_type LowCardinality(String) DEFAULT '',
    object_id String DEFAULT '',
    attack_type LowCardinality(String) DEFAULT 'unknown',
    risk_score Float32,
    risk_level LowCardinality(String),
    risk_components String DEFAULT '{}',
    rule_hits Array(String) DEFAULT [],
    baseline_deviations String DEFAULT '[]',
    reason_codes Array(String) DEFAULT [],
    evidence String DEFAULT '{}',
    related_event_ids Array(String) DEFAULT [],
    scenario_id String DEFAULT '',
    scenario_type LowCardinality(String) DEFAULT '',
    attack_chain_id String DEFAULT '',
    ai_status LowCardinality(String) DEFAULT 'not_required',
    status LowCardinality(String) DEFAULT 'new',
    model_version String DEFAULT '',
    scoring_version String DEFAULT '',
    created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_date, risk_level, risk_score, user_id, event_time);

CREATE TABLE IF NOT EXISTS log_ai.ueba_user_daily_features
(
    feature_date Date,
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String,
    account_type LowCardinality(String) DEFAULT 'unknown',
    login_count UInt32 DEFAULT 0,
    failed_login_count UInt32 DEFAULT 0,
    success_login_count UInt32 DEFAULT 0,
    distinct_src_ip_count UInt32 DEFAULT 0,
    distinct_host_count UInt32 DEFAULT 0,
    distinct_action_count UInt32 DEFAULT 0,
    first_seen_time DateTime,
    last_seen_time DateTime,
    night_event_count UInt32 DEFAULT 0,
    sensitive_action_count UInt32 DEFAULT 0,
    download_count UInt32 DEFAULT 0,
    permission_change_count UInt32 DEFAULT 0,
    new_source_count UInt32 DEFAULT 0,
    maintenance_window_hit_count UInt32 DEFAULT 0,
    common_src_ips Array(String) DEFAULT [],
    common_ip_prefixes Array(String) DEFAULT [],
    common_hosts Array(String) DEFAULT [],
    common_actions Array(String) DEFAULT [],
    profile_metrics String DEFAULT '{}',
    created_at DateTime DEFAULT now()
)
-- ReplacingMergeTree(created_at) so a re-run for the same (tenant, user, date)
-- collapses to the latest aggregation; the writer also deletes the day before
-- inserting, making daily-feature rebuilds idempotent.
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(feature_date)
ORDER BY (tenant_id, user_id, feature_date);

CREATE TABLE IF NOT EXISTS log_ai.ueba_user_baseline
(
    baseline_date Date,
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String,
    period_type LowCardinality(String) DEFAULT 'global',
    period_key String DEFAULT 'all',
    profile_group LowCardinality(String),
    feature_name LowCardinality(String),
    mean_value Nullable(Float64),
    std_value Nullable(Float64),
    p50_value Nullable(Float64),
    p95_value Nullable(Float64),
    p99_value Nullable(Float64),
    common_values Array(String) DEFAULT [],
    value_histogram String DEFAULT '{}',
    sample_days UInt16 DEFAULT 0,
    sample_count UInt32 DEFAULT 0,
    baseline_confidence Float32 DEFAULT 0,
    trained_from Date,
    trained_to Date,
    fallback_level LowCardinality(String) DEFAULT 'none',
    model_version String DEFAULT '',
    created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(baseline_date)
ORDER BY (tenant_id, user_id, period_type, period_key, profile_group, feature_name, baseline_date);

ALTER TABLE log_ai.ueba_user_baseline
    ADD COLUMN IF NOT EXISTS period_type LowCardinality(String) DEFAULT 'global' AFTER user_id;
ALTER TABLE log_ai.ueba_user_baseline
    ADD COLUMN IF NOT EXISTS period_key String DEFAULT 'all' AFTER period_type;

CREATE TABLE IF NOT EXISTS log_ai.ueba_baseline_overrides
(
    override_id String,
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String DEFAULT '',
    profile_group LowCardinality(String),
    feature_name LowCardinality(String),
    period_type LowCardinality(String),
    period_key String,
    merge_mode LowCardinality(String),
    override_value String DEFAULT '{}',
    source_type LowCardinality(String),
    source_feedback_id String DEFAULT '',
    reason String,
    status LowCardinality(String),
    effective_from DateTime,
    effective_to Nullable(DateTime),
    created_by String,
    reviewed_by String DEFAULT '',
    reviewed_at Nullable(DateTime),
    model_version String,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, user_id, profile_group, feature_name, period_type, period_key, override_id);

CREATE TABLE IF NOT EXISTS log_ai.ai_judgements
(
    judgement_id String,
    event_id String,
    created_at DateTime DEFAULT now(),
    model_name LowCardinality(String),
    model_version String DEFAULT '',
    risk_level LowCardinality(String),
    attack_type LowCardinality(String),
    judgement String,
    key_reasons Array(String) DEFAULT [],
    recommended_actions Array(String) DEFAULT [],
    confidence Float32,
    feedback_suggestions String DEFAULT '{}',
    raw_response String DEFAULT '{}',
    is_mock UInt8 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, event_id, risk_level);

CREATE TABLE IF NOT EXISTS log_ai.ai_feedback
(
    feedback_id String,
    event_id String,
    judgement_id String DEFAULT '',
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String DEFAULT '',
    feedback_type LowCardinality(String),
    suggestion String,
    target_component LowCardinality(String),
    confidence Float32,
    review_status LowCardinality(String),
    reviewed_by String DEFAULT '',
    reviewed_at Nullable(DateTime),
    review_reason String DEFAULT '',
    applied_override_id String DEFAULT '',
    applied_version String DEFAULT '',
    created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, created_at, target_component, review_status);

ALTER TABLE log_ai.ai_feedback
    ADD COLUMN IF NOT EXISTS reviewed_by String DEFAULT '' AFTER review_status;
ALTER TABLE log_ai.ai_feedback
    ADD COLUMN IF NOT EXISTS reviewed_at Nullable(DateTime) AFTER reviewed_by;
ALTER TABLE log_ai.ai_feedback
    ADD COLUMN IF NOT EXISTS review_reason String DEFAULT '' AFTER reviewed_at;
ALTER TABLE log_ai.ai_feedback
    ADD COLUMN IF NOT EXISTS applied_override_id String DEFAULT '' AFTER review_reason;
ALTER TABLE log_ai.ai_feedback
    ADD COLUMN IF NOT EXISTS applied_version String DEFAULT '' AFTER applied_override_id;

CREATE TABLE IF NOT EXISTS log_ai.daily_security_reports
(
    report_date Date,
    tenant_id LowCardinality(String) DEFAULT 'default',
    total_logs UInt64 DEFAULT 0,
    anomaly_count UInt64 DEFAULT 0,
    high_count UInt64 DEFAULT 0,
    critical_count UInt64 DEFAULT 0,
    overall_score Float32 DEFAULT 0,
    top_risk_users Array(String) DEFAULT [],
    top_attack_types Array(String) DEFAULT [],
    key_events Array(String) DEFAULT [],
    ai_summary String DEFAULT '',
    recommended_actions Array(String) DEFAULT [],
    markdown_body String DEFAULT '',
    created_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(report_date)
ORDER BY (tenant_id, report_date);

CREATE TABLE IF NOT EXISTS log_ai.data_quality_metrics
(
    metric_date Date,
    tenant_id LowCardinality(String) DEFAULT 'default',
    source_type LowCardinality(String),
    generated_count UInt64 DEFAULT 0,
    injected_anomaly_count UInt64 DEFAULT 0,
    injected_high_risk_count UInt64 DEFAULT 0,
    raw_logs_count UInt64 DEFAULT 0,
    parsed_logs_count UInt64 DEFAULT 0,
    clickhouse_insert_count UInt64 DEFAULT 0,
    security_logs_count UInt64 DEFAULT 0,
    raw_size_bytes UInt64 DEFAULT 0,
    table_size_bytes UInt64 DEFAULT 0,
    compression_ratio Float32 DEFAULT 0,
    missing_event_time_rate Float32 DEFAULT 0,
    missing_user_id_rate Float32 DEFAULT 0,
    missing_src_ip_rate Float32 DEFAULT 0,
    missing_action_rate Float32 DEFAULT 0,
    missing_result_rate Float32 DEFAULT 0,
    parse_error_rate Float32 DEFAULT 0,
    created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(metric_date)
ORDER BY (tenant_id, metric_date, source_type);

CREATE TABLE IF NOT EXISTS log_ai.system_metrics
(
    metric_time DateTime,
    component LowCardinality(String),
    metric_name LowCardinality(String),
    metric_value Float64,
    labels String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(metric_time)
ORDER BY (component, metric_name, metric_time);
