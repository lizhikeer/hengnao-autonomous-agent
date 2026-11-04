-- 用途：定义知识卡、案例记忆及其审核、证据和索引任务的 SQLite 结构。
-- 责任：卡片版本是权威原文，Qdrant 与 FTS5 是可重建索引；发布由后台事务控制。
-- 实施要求：每个数据库连接均启用 foreign_keys；时间由服务规范化为毫秒精度 UTC。
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS kb_cards (
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'withdrawn')),
    published_version INTEGER,
    -- 审核发布意图、撤回时递增；旧索引任务不能覆盖较新的决定。
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, card_id),
    FOREIGN KEY (tenant_id, card_id, published_version)
        REFERENCES kb_card_versions (tenant_id, card_id, version)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (status <> 'withdrawn' OR published_version IS NULL)
);

CREATE TABLE IF NOT EXISTS kb_card_versions (
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    schema_version TEXT NOT NULL CHECK (schema_version IN ('1.0', '1.1')),
    card_type TEXT NOT NULL CHECK (card_type IN (
        'security_knowledge', 'verified_correct_case', 'verified_error_revision'
    )),
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    attack_category TEXT NOT NULL,
    mitre_id TEXT,
    applicable_log_sources_json TEXT NOT NULL
        CHECK (json_valid(applicable_log_sources_json) AND json_type(applicable_log_sources_json) = 'array'),
    keywords_json TEXT NOT NULL
        CHECK (json_valid(keywords_json) AND json_type(keywords_json) = 'array'),
    source_reference TEXT NOT NULL,
    sources_json TEXT NOT NULL
        CHECK (json_valid(sources_json) AND json_type(sources_json) = 'array'),
    -- 正文包括调查目标、触发现象、所需数据、条件判断和步骤；案例再带可核验调查路径。
    -- 不重复 tenant、版本、审核状态等公共列；JSON Schema 负责校验内容对象。
    content_json TEXT NOT NULL CHECK (json_valid(content_json) AND json_type(content_json) = 'object'),
    origin_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(origin_json) AND json_type(origin_json) = 'object'),
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    dataset_split TEXT NOT NULL CHECK (dataset_split IN ('knowledge', 'development', 'production')),
    review_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (review_status IN ('pending', 'approved', 'rejected')),
    reviewed_by TEXT,
    reviewed_at TEXT,
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, card_id, version),
    FOREIGN KEY (tenant_id, card_id) REFERENCES kb_cards (tenant_id, card_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK (review_status = 'pending' OR (
        reviewed_by IS NOT NULL AND length(trim(reviewed_by)) > 0 AND reviewed_at IS NOT NULL
    )),
    CHECK ((card_type = 'security_knowledge' AND dataset_split = 'knowledge') OR
        (card_type <> 'security_knowledge' AND dataset_split IN ('development', 'production')))
);

CREATE INDEX IF NOT EXISTS idx_kb_versions_visibility
    ON kb_card_versions (tenant_id, review_status, dataset_split, card_type, valid_from, valid_until);
-- 不设 UNIQUE：同文可能有不同来源/适用期；服务按哈希返回既有版本或提示合并。
CREATE INDEX IF NOT EXISTS idx_kb_versions_hash
    ON kb_card_versions (tenant_id, card_type, content_hash);

CREATE TABLE IF NOT EXISTS kb_evidence_refs (
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    evidence_id TEXT NOT NULL,
    ref_type TEXT NOT NULL CHECK (ref_type IN ('log', 'anomaly', 'tool_result', 'external_document')),
    source_table TEXT,
    source_id TEXT NOT NULL,
    locator TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    snapshot_summary TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL CHECK (
        length(snapshot_sha256) = 64 AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (tenant_id, card_id, version, evidence_id),
    CHECK ((ref_type = 'log' AND source_table IS 'security_logs') OR
        (ref_type = 'anomaly' AND source_table IS 'anomaly_events') OR
        (ref_type IN ('tool_result', 'external_document') AND source_table IS NULL)),
    FOREIGN KEY (tenant_id, card_id, version)
        REFERENCES kb_card_versions (tenant_id, card_id, version)
);

CREATE TABLE IF NOT EXISTS kb_reviews (
    review_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected', 'withdrawn')),
    review_reason TEXT NOT NULL CHECK (length(trim(review_reason)) > 0),
    reviewed_by TEXT NOT NULL CHECK (length(trim(reviewed_by)) > 0),
    reviewed_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id, card_id, version)
        REFERENCES kb_card_versions (tenant_id, card_id, version)
);

CREATE TABLE IF NOT EXISTS kb_chunks (
    chunk_pk INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    -- 包含模型与 tokenizer revision、分块/分词/正文模板版本；具体值在实施时冻结。
    index_profile TEXT NOT NULL,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    point_id TEXT NOT NULL UNIQUE,
    collection_name TEXT NOT NULL CHECK (collection_name IN ('security_knowledge', 'verified_cases')),
    section_path TEXT NOT NULL,
    text TEXT NOT NULL CHECK (length(trim(text)) > 0),
    search_text TEXT NOT NULL CHECK (length(trim(search_text)) > 0),
    token_count INTEGER NOT NULL CHECK (token_count > 0),
    created_at TEXT NOT NULL,
    UNIQUE (tenant_id, card_id, version, index_profile, chunk_index),
    FOREIGN KEY (tenant_id, card_id, version)
        REFERENCES kb_card_versions (tenant_id, card_id, version)
);

-- search_text 已由服务中文分词；FTS5 不负责自动理解连续中文句子。
-- 内容表与虚拟表一同建立。对既有数据补建时需执行 FTS5 rebuild。
CREATE VIRTUAL TABLE IF NOT EXISTS kb_chunk_fts USING fts5(
    search_text, content = 'kb_chunks', content_rowid = 'chunk_pk', tokenize = 'unicode61'
);
CREATE TRIGGER IF NOT EXISTS kb_chunks_ai AFTER INSERT ON kb_chunks BEGIN
    INSERT INTO kb_chunk_fts (rowid, search_text) VALUES (new.chunk_pk, new.search_text);
END;
CREATE TRIGGER IF NOT EXISTS kb_chunks_ad AFTER DELETE ON kb_chunks BEGIN
    INSERT INTO kb_chunk_fts (kb_chunk_fts, rowid, search_text)
        VALUES ('delete', old.chunk_pk, old.search_text);
END;
CREATE TRIGGER IF NOT EXISTS kb_chunks_au AFTER UPDATE ON kb_chunks BEGIN
    INSERT INTO kb_chunk_fts (kb_chunk_fts, rowid, search_text)
        VALUES ('delete', old.chunk_pk, old.search_text);
    INSERT INTO kb_chunk_fts (rowid, search_text) VALUES (new.chunk_pk, new.search_text);
END;

CREATE TABLE IF NOT EXISTS kb_index_jobs (
    job_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    index_profile TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    operation TEXT NOT NULL CHECK (operation IN ('publish', 'delete')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_retry_at TEXT,
    -- 租约过期后可恢复被进程崩溃中断的 running 任务。
    locked_until TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (tenant_id, card_id, version, index_profile, generation, operation),
    FOREIGN KEY (tenant_id, card_id, version)
        REFERENCES kb_card_versions (tenant_id, card_id, version)
);
CREATE INDEX IF NOT EXISTS idx_kb_jobs_retry ON kb_index_jobs (status, next_retry_at, locked_until);

-- 此视图统一发布、审核与有效期检查；租户、index_profile、场景权限仍须参数化过滤。
CREATE VIEW IF NOT EXISTS kb_searchable_versions AS
SELECT v.* FROM kb_card_versions AS v
JOIN kb_cards AS c ON c.tenant_id = v.tenant_id AND c.card_id = v.card_id
    AND c.published_version = v.version
WHERE c.status = 'active' AND v.review_status = 'approved'
    AND v.valid_from <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    AND (v.valid_until IS NULL OR v.valid_until > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- 扩展点：跨字段业务规则、审批身份、来源清单与评测隔离由服务配合 JSON Schema 校验。
-- 不直接向 Agent 暴露表写入；DDL 校验 JSON 形状，不能替代审核与授权。
