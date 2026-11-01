CREATE TABLE IF NOT EXISTS log_ai.reason_code_feedback_stats
(
    tenant_id LowCardinality(String) DEFAULT 'default',
    user_id String,
    reason_codes_combo String,
    fp_count UInt32 DEFAULT 0,
    confirmed_count UInt32 DEFAULT 0,
    last_updated DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(last_updated)
ORDER BY (tenant_id, user_id, reason_codes_combo);
