CREATE TABLE IF NOT EXISTS operations_task_runs
(
    run_id String,
    task_name LowCardinality(String),
    tenant_id LowCardinality(String) DEFAULT 'default',
    target_date Date,
    idempotency_key String,
    scheduled_at DateTime64(3),
    started_at Nullable(DateTime64(3)),
    finished_at Nullable(DateTime64(3)),
    status LowCardinality(String),
    attempt UInt16 DEFAULT 1,
    input_watermark String DEFAULT '{}',
    output_refs String DEFAULT '{}',
    code_version String,
    error_code LowCardinality(String) DEFAULT '',
    error_message String DEFAULT '',
    version UInt64,
    recorded_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(target_date)
ORDER BY (tenant_id, task_name, target_date, idempotency_key, run_id);

CREATE TABLE IF NOT EXISTS acceptance_reports
(
    report_id String,
    tenant_id LowCardinality(String) DEFAULT 'default',
    status LowCardinality(String),
    git_commit String,
    compose_config_digest String,
    scenario_version String,
    policy_version String,
    baseline_model_version String,
    ai_model String,
    ai_is_mock UInt8 DEFAULT 0,
    threshold_version String,
    sample_from Nullable(DateTime64(3)),
    sample_to Nullable(DateTime64(3)),
    normal_scenario_count UInt32 DEFAULT 0,
    attack_scenario_count UInt32 DEFAULT 0,
    created_at DateTime64(3),
    run_id String DEFAULT '',
    summary String DEFAULT '{}'
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, report_id);

CREATE TABLE IF NOT EXISTS acceptance_metrics
(
    report_id String,
    metric_name LowCardinality(String),
    scenario_type LowCardinality(String) DEFAULT 'overall',
    numerator Float64 DEFAULT 0,
    denominator Float64 DEFAULT 0,
    value Float64,
    threshold_operator LowCardinality(String),
    threshold_value Float64,
    passed UInt8,
    unit LowCardinality(String) DEFAULT 'ratio',
    details String DEFAULT '{}',
    created_at DateTime64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(created_at)
ORDER BY (report_id, metric_name, scenario_type);

CREATE TABLE IF NOT EXISTS notification_outbox
(
    outbox_id String,
    idempotency_key String,
    event_id String,
    tenant_id LowCardinality(String) DEFAULT 'default',
    channel LowCardinality(String),
    destination String,
    payload String,
    status LowCardinality(String),
    attempt_count UInt16 DEFAULT 0,
    next_attempt_at DateTime64(3),
    last_error String DEFAULT '',
    created_at DateTime64(3),
    updated_at DateTime64(3),
    delivered_at Nullable(DateTime64(3)),
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, idempotency_key, outbox_id);

CREATE TABLE IF NOT EXISTS notification_attempts
(
    attempt_id String,
    outbox_id String,
    attempt UInt16,
    started_at DateTime64(3),
    finished_at DateTime64(3),
    success UInt8,
    response_status Nullable(UInt16),
    duration_ms UInt32 DEFAULT 0,
    error_code LowCardinality(String) DEFAULT '',
    error_message String DEFAULT '',
    response_body String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(started_at)
ORDER BY (outbox_id, attempt, started_at);

CREATE TABLE IF NOT EXISTS parser_failures
(
    failure_id String,
    occurred_at DateTime64(3),
    source_topic LowCardinality(String),
    partition Int32 DEFAULT 0,
    offset Int64 DEFAULT 0,
    raw_payload String,
    error_code LowCardinality(String),
    error_message String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (source_topic, occurred_at, partition, offset);

ALTER TABLE daily_security_reports
    ADD COLUMN IF NOT EXISTS run_id String DEFAULT '' AFTER markdown_body;
ALTER TABLE daily_security_reports
    ADD COLUMN IF NOT EXISTS input_watermark String DEFAULT '{}' AFTER run_id;
ALTER TABLE daily_security_reports
    ADD COLUMN IF NOT EXISTS quality_status LowCardinality(String) DEFAULT 'unknown' AFTER input_watermark;

ALTER TABLE data_quality_metrics
    ADD COLUMN IF NOT EXISTS event_id_traceability_rate Float32 DEFAULT 1 AFTER parse_error_rate;
