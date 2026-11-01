"""SecLog 工具服务配置常量（时间窗 / limit 等边界）。

所有查询类工具的过滤参数都在此白名单内，不提供任意 SQL / 命令执行。
"""

from __future__ import annotations

# --- time_window 边界（ISO8601 字符串或相对分钟数场景均受此约束） ---
# 相对时间窗最大回溯 7 天（分钟）
TIME_WINDOW_MAX_MINUTES = 7 * 24 * 60
# 相对时间窗最小 1 分钟
TIME_WINDOW_MIN_MINUTES = 1
# 绝对时间范围：单次查询跨度上限 7 天
TIME_RANGE_MAX_SPAN_SECONDS = 7 * 24 * 60 * 60

# --- limit 边界 ---
LIMIT_MIN = 1
LIMIT_MAX = 200
LIMIT_DEFAULT = 50

# --- log_source 白名单（与全链路日志统一 Schema 对齐，见 docs/project design/项目分工与前期架构设计.md 5.1） ---
ALLOWED_LOG_SOURCES = (
    "nginx_access",
    "auth_log",
    "zeek_conn",
    "zeek_http",
    "all",
)

# --- 响应通用字段 ---
MOCK_FLAG_KEY = "mock"
DATA_SOURCE_MOCK = "mock"

# --- 处置动作白名单（高危动作需人工审批，本周一律不产生真实副作用） ---
ALLOWED_RESPONSE_ACTIONS = (
    "block_ip",            # 封禁 IP（高危，需审批；本周仅登记待审批）
    "block_ip_short_term", # 短时封禁（高危，需审批）
    "rate_limit",          # 限速（低危，可自动执行——但本周权限网关未接入，仍返回待审批状态）
    "none",                # 无需处置
)
HIGH_RISK_ACTIONS = frozenset({"block_ip", "block_ip_short_term"})

# --- 时间窗字符串解析（兼容 Issue #4 的 time_window 语义） ---

_TIME_UNIT_MINUTES = {"m": 1, "h": 60, "d": 60 * 24}


def parse_time_window(raw: str) -> int:
    """把 ``30m`` / ``1h`` / ``7d`` 解析为分钟数。

    非法格式抛 ``ValueError``（由调用方转换为 422 参数错误）。
    解析结果同样受 ``TIME_WINDOW_MIN_MINUTES`` / ``TIME_WINDOW_MAX_MINUTES`` 约束。
    """
    text = (raw or "").strip().lower()
    if len(text) < 2 or not text[:-1].isdigit():
        raise ValueError(f"time_window 格式非法：{raw!r}，应为 <数字><m|h|d>，如 30m、1h、7d")
    unit = text[-1]
    if unit not in _TIME_UNIT_MINUTES:
        raise ValueError(f"time_window 单位非法：{raw!r}，仅支持 m/h/d")
    minutes = int(text[:-1]) * _TIME_UNIT_MINUTES[unit]
    if minutes < TIME_WINDOW_MIN_MINUTES or minutes > TIME_WINDOW_MAX_MINUTES:
        raise ValueError(
            f"time_window 超出范围：{raw!r} = {minutes} 分钟，"
            f"允许 {TIME_WINDOW_MIN_MINUTES} ~ {TIME_WINDOW_MAX_MINUTES} 分钟（7 天）"
        )
    return minutes
