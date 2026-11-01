"""显式 Mock 数据（Week 1 骨架专用）。

每条记录通过 ``mock=True`` 字段自我标识；消费方（恒脑模型节点/评测脚本）
必须把 mock 数据视为演示样例，不得当作真实证据。真实 ClickHouse / Qdrant
接入后此模块整体下线（由 @lizhikeer / @Snowed-night 的后端替换）。

样例数据对齐 docs/project design/项目分工与前期架构设计.md 5.1 的
EVAL-CHAIN-001 场景（SQL 注入 + 暴力破解攻击链）。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# 演示数据的固定回放时刻；真实后端应使用请求的调查时刻或当前 UTC 时间。
MOCK_REFERENCE_TIME = datetime(2026, 10, 27, 14, 26, tzinfo=timezone.utc)

MOCK_LOGS: list[dict] = [
    {
        "log_id": "LOG-20261027-0001",
        "trace_id": "CHAIN-ATTACK-01",
        "timestamp": "2026-10-27T14:18:02Z",
        "log_source": "auth_log",
        "src_ip": "198.51.100.23",
        "dest_ip": "10.0.0.15",
        "asset_id": "web-prod-01",
        "user": "admin",
        "action_or_method": "auth_fail",
        "uri_or_target": "/admin",
        "payload_summary": "password attempt #1 (wrong)",
        "status_code": 401,
        "user_agent": "hydra/9.1",
        "attack_stage_hint": "brute_force",
    },
    {
        "log_id": "LOG-20261027-0008",
        "trace_id": "CHAIN-ATTACK-01",
        "timestamp": "2026-10-27T14:20:05Z",
        "log_source": "nginx_access",
        "src_ip": "198.51.100.23",
        "dest_ip": "10.0.0.15",
        "asset_id": "web-prod-01",
        "user": "admin",
        "action_or_method": "POST",
        "uri_or_target": "/admin/login.php",
        "payload_summary": "username=admin&password=' OR 1=1--",
        "status_code": 200,
        "user_agent": "sqlmap/1.7.2",
        "attack_stage_hint": "exploitation",
    },
    {
        "log_id": "LOG-20261027-0015",
        "trace_id": "CHAIN-ATTACK-01",
        "timestamp": "2026-10-27T14:22:41Z",
        "log_source": "nginx_access",
        "src_ip": "198.51.100.23",
        "dest_ip": "10.0.0.15",
        "asset_id": "web-prod-01",
        "user": None,
        "action_or_method": "GET",
        "uri_or_target": "/admin/export.php?table=users",
        "payload_summary": "table=users (sensitive export attempt)",
        "status_code": 200,
        "user_agent": "sqlmap/1.7.2",
        "attack_stage_hint": "exploitation",
    },
    {
        "log_id": "LOG-20261027-0022",
        "trace_id": "CHAIN-ATTACK-01",
        "timestamp": "2026-10-27T14:25:10Z",
        "log_source": "zeek_conn",
        "src_ip": "10.0.0.15",
        "dest_ip": "203.0.113.66",
        "asset_id": "web-prod-01",
        "user": None,
        "action_or_method": None,
        "uri_or_target": None,
        "payload_summary": "outbound TLS to unknown host",
        "status_code": None,
        "user_agent": None,
        "attack_stage_hint": "c2_callback",
    },
    # 良性背景流量（用于演示"非恶意/零告警"区分）
    {
        "log_id": "LOG-20261027-0100",
        "trace_id": "CHAIN-BENIGN-07",
        "timestamp": "2026-10-27T09:10:33Z",
        "log_source": "nginx_access",
        "src_ip": "203.0.113.7",
        "dest_ip": "10.0.0.15",
        "asset_id": "web-prod-01",
        "user": "ops-wang",
        "action_or_method": "GET",
        "uri_or_target": "/index.html",
        "payload_summary": None,
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "attack_stage_hint": "benign",
    },
]

MOCK_USER_PROFILE: dict = {
    "admin": {
        "user": "admin",
        "active_hours": "09:00-19:00 CST",
        "common_src_ips": ["203.0.113.7"],
        "failed_logins_24h": 0,
        "mock": True,
    },
}

MOCK_ASSET_CONTEXT: dict = {
    "web-prod-01": {
        "asset_id": "web-prod-01",
        "importance": "HIGH",
        "maintenance_window": None,
        "whitelisted": False,
        "mock": True,
    },
}

MOCK_KNOWLEDGE_CARDS: list[dict] = [
    {
        "card_id": "KB-OWASP-SQLI-001",
        "card_type": "security_knowledge",
        "title": "SQL 注入攻击（联合查询与写文件 Webshell）调查与处置指南",
        "attack_category": "SQL_Injection",
        "mitre_id": "T1190",
        "key_indicators": [
            "URI 或请求体包含 UNION SELECT、INTO OUTFILE、sleep()、information_schema",
            "同一源 IP 短时间内触发大量 500/403 后突然出现 200 且响应包体异常增大",
        ],
        "recommended_action": "block_ip_short_term",
        "score": 0.91,
    },
    {
        "card_id": "KB-MITRE-BRUTE-003",
        "card_type": "security_knowledge",
        "title": "账号爆破（Hydra 类工具）识别与处置",
        "attack_category": "Brute_Force",
        "mitre_id": "T1110",
        "key_indicators": [
            "同一源 IP 对 /admin 等登录端点高频 401",
            "User-Agent 含 hydra/medusa等爆破工具特征",
        ],
        "recommended_action": "block_ip_short_term",
        "score": 0.84,
    },
    {
        "card_id": "KB-CASE-CORRECT-005",
        "card_type": "verified_correct_case",
        "title": "已确认正确案例：爆破后 SQL 注入攻击链处置复盘",
        "attack_category": "SQL_Injection",
        "mitre_id": "T1190",
        "key_indicators": ["爆破阶段与注入阶段共享同一 src_ip 与同一 trace_id"],
        "recommended_action": "block_ip",
        "score": 0.78,
    },
    {
        "card_id": "KB-MITRE-C2-007",
        "card_type": "security_knowledge",
        "title": "内网主机异常外连（疑似 C2 回连）研判与处置指南",
        "attack_category": "C2_Callback",
        "mitre_id": "T1071",
        "key_indicators": [
            "受害主机向未登记的外部 IP/域名发起周期性连接",
            "外连端口与业务用途不符，且伴随小包心跳特征",
            "外连时间紧接在漏洞利用阶段之后，提示已获取执行能力",
        ],
        "recommended_action": "block_ip_short_term",
        "score": 0.82,
    },
]


def query_mock_logs(
    *,
    src_ip: str | None,
    dest_ip: str | None,
    trace_id: str | None,
    log_source: str,
    window_minutes: int = 60,
) -> list[dict]:
    """按白名单过滤条件查询 Mock 日志。返回的每条记录自动附加 mock 标识。"""
    results: list[dict] = []
    cutoff = MOCK_REFERENCE_TIME - timedelta(minutes=window_minutes)
    for log in MOCK_LOGS:
        timestamp = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
        if not cutoff <= timestamp <= MOCK_REFERENCE_TIME:
            continue
        if src_ip and log["src_ip"] != src_ip:
            continue
        if dest_ip and log["dest_ip"] != dest_ip:
            continue
        if trace_id and log["trace_id"] != trace_id:
            continue
        if log_source != "all" and log["log_source"] != log_source:
            continue
        results.append({**log, "mock": True})
    return results


def search_mock_knowledge(query: str, attack_category: str | None) -> list[dict]:
    """极简关键词匹配 Mock 检索（真实 BGE 向量检索由 @Snowed-night 实现）。

    只做"演示语义"：命中任一领域关键词即视为相关。
    真实实现是语义向量 + 关键词混合检索，不要用本函数的行为评估检索质量。
    """
    keywords = ["sql", "注入", "sqli", "brute", "爆破", "认证", "外连", "c2", "回连", "横向"]
    results: list[dict] = []
    for card in MOCK_KNOWLEDGE_CARDS:
        if attack_category and card["attack_category"] != attack_category:
            continue
        text = card["title"] + " " + " ".join(card["key_indicators"])
        if any(k in query.lower() for k in keywords) and any(
            k in text.lower() for k in keywords
        ):
            results.append({**card, "mock": True})
    return results
