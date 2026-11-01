from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_csv(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    kafka_bootstrap_servers: list[str]
    kafka_raw_topic: str
    kafka_parsed_topic: str
    kafka_alert_topic: str
    kafka_ai_topic: str
    kafka_metrics_topic: str

    clickhouse_host: str
    clickhouse_http_port: int
    clickhouse_native_port: int
    clickhouse_database: str
    clickhouse_user: str
    clickhouse_password: str
    clickhouse_full_chain_table: str

    qdrant_url: str
    qdrant_api_key: str
    qdrant_knowledge_collection: str
    qdrant_case_collection: str

    api_bind_host: str
    api_bind_port: int
    api_internal_token: str

    flink_dashboard_url: str

    dashscope_api_key: str
    dashscope_model: str

    backend_cors_origins: list[str]

    generator_script: Path
    generator_jsonl: Path
    generator_syslog: Path

    threshold_ip_fail_5m: int
    threshold_user_fail_5m: int
    threshold_api_call_1m: int
    threshold_sensitive_5m: int
    threshold_multi_user_fail_ip_5m: int

    work_hour_start: int
    work_hour_end: int


settings = Settings(
    kafka_bootstrap_servers=_get_csv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
    kafka_raw_topic=os.getenv("KAFKA_RAW_TOPIC", "raw_logs"),
    kafka_parsed_topic=os.getenv("KAFKA_PARSED_TOPIC", "parsed_logs"),
    kafka_alert_topic=os.getenv("KAFKA_ANOMALY_TOPIC", os.getenv("KAFKA_ALERT_TOPIC", "anomaly_events")),
    kafka_ai_topic=os.getenv("KAFKA_AI_JUDGEMENT_TOPIC", os.getenv("KAFKA_AI_TOPIC", "ai_judgements")),
    kafka_metrics_topic=os.getenv("KAFKA_METRICS_TOPIC", "system_metrics"),
    clickhouse_host=os.getenv("CLICKHOUSE_HOST", "localhost"),
    clickhouse_http_port=_get_int("CLICKHOUSE_HTTP_PORT", 8123),
    clickhouse_native_port=_get_int("CLICKHOUSE_NATIVE_PORT", 9000),
    clickhouse_database=os.getenv("CLICKHOUSE_DATABASE", "log_ai"),
    clickhouse_user=os.getenv("CLICKHOUSE_USER", "default"),
    clickhouse_password=os.getenv("CLICKHOUSE_PASSWORD", ""),
    clickhouse_full_chain_table=os.getenv(
        "CLICKHOUSE_FULL_CHAIN_TABLE", "log_ai.full_chain_logs"
    ),
    qdrant_url=os.getenv("QDRANT_URL", "http://localhost:6333"),
    qdrant_api_key=os.getenv("QDRANT_API_KEY", ""),
    qdrant_knowledge_collection=os.getenv("QDRANT_KNOWLEDGE_COLLECTION", "security_knowledge"),
    qdrant_case_collection=os.getenv("QDRANT_CASE_COLLECTION", "verified_cases"),
    api_bind_host=os.getenv("API_BIND_HOST", "0.0.0.0"),
    api_bind_port=_get_int("API_BIND_PORT", 8000),
    api_internal_token=os.getenv("API_INTERNAL_TOKEN", ""),
    flink_dashboard_url=os.getenv("FLINK_DASHBOARD_URL", "http://localhost:8081"),
    dashscope_api_key=os.getenv("DASHSCOPE_API_KEY", ""),
    dashscope_model=os.getenv("DASHSCOPE_MODEL", "qwen-plus"),
    backend_cors_origins=_get_csv("BACKEND_CORS_ORIGINS", "http://localhost:5173"),
    generator_script=(PROJECT_ROOT / os.getenv("GENERATOR_SCRIPT", "log-generator/gen_vpn_logs.py")).resolve(),
    generator_jsonl=(PROJECT_ROOT / os.getenv("GENERATOR_JSONL", "log-generator/vpn_output/vpn_logs.jsonl")).resolve(),
    generator_syslog=(PROJECT_ROOT / os.getenv("GENERATOR_SYSLOG", "log-generator/vpn_output/vpn_logs.log")).resolve(),
    threshold_ip_fail_5m=_get_int("THRESHOLD_IP_FAIL_5M", 8),
    threshold_user_fail_5m=_get_int("THRESHOLD_USER_FAIL_5M", 5),
    threshold_api_call_1m=_get_int("THRESHOLD_API_CALL_1M", 80),
    threshold_sensitive_5m=_get_int("THRESHOLD_SENSITIVE_5M", 5),
    threshold_multi_user_fail_ip_5m=_get_int("THRESHOLD_MULTI_USER_FAIL_IP_5M", 4),
    work_hour_start=_get_int("WORK_HOUR_START", 9),
    work_hour_end=_get_int("WORK_HOUR_END", 18),
)
