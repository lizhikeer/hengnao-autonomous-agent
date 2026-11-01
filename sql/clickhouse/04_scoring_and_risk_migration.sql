ALTER TABLE log_ai.anomaly_events
    ADD COLUMN IF NOT EXISTS scoring_version String DEFAULT '' AFTER model_version;
