-- =============================================================================
-- SecLog-Agent / W1 全链路日志统一 Schema 落库脚本
-- 依据：docs/project design/项目分工与前期架构设计.md §5.1
-- 说明：
--   1) 本脚本与 01_init.sql 互补。01_init.sql 保留原项目 security_logs 检测底座；
--      本脚本新增 full_chain_logs 作为「统一 Schema」唯一落库表。
--   2) 脚本幂等，可重复执行。
--   3) 字段名与 JSONL 契约一一对应，仅两处工程化调整（见下方注释）：
--      - JSON 的 `user`  -> 列 `user_name`（`user` 在 ClickHouse 中与内置函数冲突）
--      - JSON 的 `timestamp` -> 列名保持 `timestamp`，与契约完全一致
-- =============================================================================

CREATE DATABASE IF NOT EXISTS log_ai;

-- -----------------------------------------------------------------------------
-- 统一全链路日志表：Web 访问 / 认证 / Zeek 网络日志 三源对齐后的唯一事实表
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_ai.full_chain_logs
(
    -- 契约字段
    log_id            String,
    trace_id          String,
    timestamp         DateTime64(3, 'UTC'),
    log_source        LowCardinality(String),
    src_ip            String,
    src_port          Nullable(UInt16),
    dest_ip           String,
    dest_port         Nullable(UInt16),
    asset_id          LowCardinality(String),
    user_name         String,                                   -- 契约字段 `user`
    session_id        String,
    action_or_method  LowCardinality(String),
    uri_or_target     String,
    payload_summary   String,
    status_code       Nullable(UInt16),
    bytes_out         Nullable(UInt64),
    user_agent        String,
    attack_stage_hint LowCardinality(String),

    -- 工程字段（契约之外，服务于取证与运维）
    ingest_time       DateTime64(3) DEFAULT now64(3),
    source_file       String DEFAULT '',
    raw_log           String DEFAULT '',

    -- 物化辅助列
    event_date        Date MATERIALIZED toDate(timestamp),

    -- 常见检索维度预聚合，避免查询时反复解析
    is_external_src   UInt8 MATERIALIZED if(startsWith(src_ip, '10.') OR startsWith(src_ip, '192.168.') OR startsWith(src_ip, '172.') OR src_ip = '', toUInt8(0), toUInt8(1)),

    INDEX idx_trace_id   trace_id      TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_src_ip     src_ip        TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_uri        uri_or_target TYPE tokenbf_v1(4096, 3, 0) GRANULARITY 1,
    INDEX idx_user_agent user_agent    TYPE tokenbf_v1(4096, 3, 0) GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (log_source, asset_id, timestamp, src_ip)
TTL toDateTime(timestamp) + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

COMMENT ON TABLE  log_ai.full_chain_logs IS 'SecLog-Agent 全链路日志统一事实表（W1 冻结）';
COMMENT ON COLUMN log_ai.full_chain_logs.log_source IS 'nginx_access | auth_log | zeek_conn | zeek_http | zeek_dns';
COMMENT ON COLUMN log_ai.full_chain_logs.attack_stage_hint IS 'recon | brute_force | exploitation | c2_callback | lateral_movement | benign | unknown';
COMMENT ON COLUMN log_ai.full_chain_logs.trace_id IS '攻击故事链/调查链标识，CHAIN-<场景>-<序号>，同一条链上所有日志共享';
COMMENT ON COLUMN log_ai.full_chain_logs.asset_id IS '被访问资产标识，与资产台账对齐，如 web-prod-01';
COMMENT ON COLUMN log_ai.full_chain_logs.payload_summary IS '已脱敏的请求体/参数摘要，敏感字段以 *** 替代，禁止落库明文口令';

-- -----------------------------------------------------------------------------
-- 在原有 security_logs 上补齐全链路字段，保持老检测链路可用
-- trace_id / session_id 原表已有，此处仅补 log_source / asset_id / attack_stage_hint
-- -----------------------------------------------------------------------------
ALTER TABLE log_ai.security_logs
    ADD COLUMN IF NOT EXISTS log_source LowCardinality(String) DEFAULT '' AFTER source_type;

ALTER TABLE log_ai.security_logs
    ADD COLUMN IF NOT EXISTS asset_id LowCardinality(String) DEFAULT '' AFTER dst_ip;

ALTER TABLE log_ai.security_logs
    ADD COLUMN IF NOT EXISTS attack_stage_hint LowCardinality(String) DEFAULT '' AFTER step_index;

-- -----------------------------------------------------------------------------
-- 会话聚合表：把同一 session_id 的 Web/认证行为折叠成一行，供画像与关联查询快速取用
-- 物化视图随 full_chain_logs 写入增量维护
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_ai.session_rollup
(
    session_id     String,
    asset_id       LowCardinality(String),
    src_ip         String,
    user_name      String,
    first_seen     DateTime64(3, 'UTC'),
    last_seen      DateTime64(3, 'UTC'),
    event_count    UInt64,
    error_count    UInt64,
    bytes_out_sum  UInt64,
    stages         Array(String),
    log_sources    Array(String)
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(first_seen)
ORDER BY (session_id, asset_id, src_ip, first_seen);

CREATE MATERIALIZED VIEW IF NOT EXISTS log_ai.mv_session_rollup
TO log_ai.session_rollup
AS
SELECT
    session_id,
    asset_id,
    src_ip,
    any(user_name)                         AS user_name,
    min(timestamp)                         AS first_seen,
    max(timestamp)                         AS last_seen,
    count()                                AS event_count,
    countIf(status_code >= 400)            AS error_count,
    sum(coalesce(bytes_out, 0))            AS bytes_out_sum,
    groupUniqArray(attack_stage_hint)      AS stages,
    groupUniqArray(log_source)             AS log_sources
FROM log_ai.full_chain_logs
WHERE session_id != ''
GROUP BY session_id, asset_id, src_ip;

-- -----------------------------------------------------------------------------
-- 数据接入健康度：按批次记录清洗脚本的产出，便于 W2 起做数据质量对账
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_ai.ingest_batches
(
    batch_id      String,
    log_source    LowCardinality(String),
    source_file   String,
    started_at    DateTime64(3),
    finished_at   Nullable(DateTime64(3)),
    total_lines   UInt64 DEFAULT 0,
    parsed_lines  UInt64 DEFAULT 0,
    dropped_lines UInt64 DEFAULT 0,
    status        LowCardinality(String) DEFAULT 'running',
    error_summary String DEFAULT ''
)
ENGINE = ReplacingMergeTree(finished_at)
PARTITION BY toYYYYMM(started_at)
ORDER BY (started_at, batch_id);

-- -----------------------------------------------------------------------------
-- 常用查询视图：攻击链全景，供 Agent 工具层 get_attack_chain 直接消费
-- -----------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS log_ai.v_attack_chain_timeline
AS
SELECT
    trace_id,
    timestamp,
    log_source,
    attack_stage_hint,
    src_ip,
    asset_id,
    user_name,
    action_or_method,
    uri_or_target,
    status_code,
    bytes_out,
    log_id
FROM log_ai.full_chain_logs
WHERE trace_id != ''
ORDER BY trace_id, timestamp;
