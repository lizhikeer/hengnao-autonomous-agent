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
