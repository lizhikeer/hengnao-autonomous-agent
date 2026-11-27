"""恒脑自主安全智能体 —— SMTP 邮件通知模块（独立、零第三方依赖）。

职责：
    1. 把结构化告警字典渲染为排版清晰、可直接投递的 HTML 邮件正文（全部使用内联 CSS）；
    2. 通过 SSL（默认 465 端口）发送告警 / 审批邮件，失败时按指数退避重试；
    3. 提供 dry_run 模式，在没有 SMTP 凭证或断网的情况下也能验证 HTML 渲染结果。

安全红线：
    SMTP 服务器地址、发件人邮箱、授权码等敏感配置一律从环境变量读取，
    本文件不包含任何真实邮箱账号或授权码，严禁在此处硬编码口令。

环境变量：
    SMTP_HOST               SMTP 服务器地址，默认 smtp.qq.com
    SMTP_PORT               SMTP SSL 端口，默认 465
    SMTP_USER               发件人邮箱，同时作为登录账号
    SMTP_PASS               发件人邮箱授权码（注意不是网页登录密码）
    ALERT_RECEIVER_EMAIL    默认收件人，多个地址用英文逗号分隔
    EMAIL_DRY_RUN_DIR       dry_run 模式 HTML 落盘目录，默认当前目录下 dry_run_output

命令行用法：
    python src/operations/email_notifier.py                 # 默认 dry_run，仅渲染并保存 HTML
    python src/operations/email_notifier.py --send          # 真实发送，需先配置好上述环境变量
    python src/operations/email_notifier.py --send --to a@b.com
"""

import html
import json
import os
import smtplib
import ssl
import sys
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "SmtpConfigError",
    "render_alert_html",
    "send_security_notification",
    "render_approval_request_html",
    "send_approval_request_email",
    "render_action_revoked_html",
    "send_action_revoked_email",
    "SAMPLE_ALERT_DATA",
]

# ---------------------------------------------------------------------------
# 常量配置：仅保留非敏感默认值，任何账号 / 授权码都必须走环境变量
# ---------------------------------------------------------------------------
DEFAULT_SMTP_HOST = "smtp.qq.com"
DEFAULT_SMTP_PORT = 465
DEFAULT_TIMEOUT_SECONDS = 30      # 连接 + 发信整体超时，避免线程被长时间挂起
DEFAULT_MAX_RETRIES = 2           # 首次发送失败后最多再重试 2 次（共 3 次尝试）
DEFAULT_BACKOFF_SECONDS = 5       # 退避基数，第 n 次重试等待 backoff * 2^(n-1) 秒
DEFAULT_DRY_RUN_DIR = "dry_run_output"

# 风险等级 -> 徽章配色（红 / 橙 / 蓝），保证收件人第一眼能分辨紧急程度
_RISK_BADGE_STYLES: Dict[str, Dict[str, str]] = {
    "CRITICAL": {"label": "CRITICAL · 严重", "bg": "#FCE8E6", "fg": "#7F0000", "border": "#E57373"},
    "HIGH": {"label": "HIGH · 高危", "bg": "#FDECEA", "fg": "#B71C1C", "border": "#F3B4AE"},
    "MEDIUM": {"label": "MEDIUM · 中危", "bg": "#FFF4E5", "fg": "#B25E09", "border": "#F5C67A"},
    "LOW": {"label": "LOW · 低危", "bg": "#E8F0FE", "fg": "#1A56C4", "border": "#B6CBF7"},
    "UNKNOWN": {"label": "UNKNOWN · 未知", "bg": "#F1F3F4", "fg": "#5F6368", "border": "#DADCE0"},
}

# 建议处置动作 -> 中文可读描述；未命中的动作原样透出，方便后续扩展新动作
_ACTION_LABELS: Dict[str, str] = {
    "block_ip": "封禁攻击源 IP（block_ip）",
    "block_ip_short_term": "短时封禁攻击源 IP（block_ip_short_term）",
    "rate_limit": "对攻击源 IP 实施请求限速（rate_limit）",
    "rate_limit_ip": "对攻击源 IP 实施请求限速（rate_limit_ip）",
    "isolate_account": "临时冻结/隔离涉事账号（isolate_account）",
    "isolate_host": "隔离受影响主机（isolate_host）",
    "reset_password": "强制重置相关账号口令（reset_password）",
    "notify_owner": "通知资产负责人人工复核（notify_owner）",
    "monitor_only": "仅持续监控，暂不阻断（monitor_only）",
    "none": "无需执行阻断处置（none）",
}

_MONO_STYLE = "font-family:Consolas,'Courier New',monospace;"

# 高危审批动作使用策略文件中的中文名称，主题仍保留原始动作枚举便于程序处理
_APPROVAL_ACTION_LABELS: Dict[str, str] = {
    "block_ip": "长效封禁（block_ip）",
    "block_ip_short_term": "短时封禁（block_ip_short_term）",
    "isolate_account": "账号隔离（isolate_account）",
}

_POST_CHECK_LABELS: Dict[str, str] = {
    "effect_verification": "攻击停止核验（effect_verification）",
    "business_impact": "正常业务影响核验（business_impact）",
}
_LABEL_STYLE = (
    "padding:10px 16px;width:150px;font-size:13px;color:#5f6368;"
    "border-bottom:1px solid #eef0f3;white-space:nowrap;vertical-align:top;"
)
_VALUE_STYLE = (
    "padding:10px 16px;font-size:13px;color:#202124;"
    "border-bottom:1px solid #eef0f3;word-break:break-all;"
)

# 邮件外壳（骨架）单独抽出来，避免在 f-string 中转义 CSS 花括号
_HTML_HEAD = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>恒脑安全告警通知</title>
</head>
<body style="margin:0;padding:0;background-color:#f5f6f8;font-family:'Microsoft YaHei','PingFang SC',Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f5f6f8;padding:24px 0;">
<tr><td align="center">
<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" style="width:680px;max-width:680px;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
"""

_HTML_TAIL = """</table>
</td></tr>
</table>
</body>
</html>
"""


class SmtpConfigError(RuntimeError):
    """SMTP 配置缺失或非法时抛出，便于调用方区分「没配好」与「发送失败」。"""


# ---------------------------------------------------------------------------
# 内部小工具
# ---------------------------------------------------------------------------
def _escape(value: Any, default: str = "未提供") -> str:
    """把任意值安全地转成 HTML 文本，既做 None 兜底也做 XSS 转义。

    告警字段最终来自日志 / 模型输出，属于不可信输入，
    直接拼接进 HTML 会有注入风险，因此统一走 html.escape。
    """
    if value is None:
        return html.escape(default)
    if isinstance(value, (list, tuple, set)):
        text = ", ".join(str(item) for item in value)
    else:
        text = str(value)
    text = text.strip()
    return html.escape(text if text else default)


def _as_bool(value: Any) -> bool:
    """兼容 bool / 字符串 / 数字三种写法，避免上游给 "false" 时被误判成真值。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on", "是", "需要"}
    return False


def _normalize_log_ids(value: Any) -> List[str]:
    """把证据日志 ID 统一成字符串列表，兼容 list、逗号 / 分号分隔的字符串。"""
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [
        chunk.strip()
        for chunk in str(value).replace(";", ",").split(",")
        if chunk.strip()
    ]


def _slugify(value: str) -> str:
    """把案例编号清洗成安全的文件名片段，防止路径穿越或非法字符。"""
    cleaned = "".join(ch if (ch.isalnum() or ch in "-_") else "_" for ch in str(value))
    cleaned = cleaned.strip("_")
    return cleaned or "unknown_case"


# ---------------------------------------------------------------------------
# HTML 渲染
# ---------------------------------------------------------------------------
def render_alert_html(alert_data: dict) -> str:
    """把告警字典渲染成一份完整的 HTML 邮件正文。

    参数：
        alert_data: 告警 / 评测案例数据字典，字段见 SAMPLE_ALERT_DATA，
                    缺失字段会以「未提供」占位，不影响整体渲染。

    返回：
        可直接作为邮件 HTML 正文使用的字符串（内联 CSS，无外部资源依赖）。
    """
    data = alert_data or {}

    # 基础字段：全部经过转义，避免不可信文本破坏邮件结构
    case_id = _escape(data.get("case_id"))
    attack_type = _escape(data.get("attack_type"))
    attacker_ip = _escape(data.get("attacker_ip"))
    victim_asset = _escape(data.get("victim_asset"))
    summary = _escape(data.get("attack_chain_summary"))

    # 风险等级：兼容大小写与非法值，非法值统一落到 UNKNOWN 灰色徽章
    risk_level = str(data.get("risk_level") or "").strip().upper()
    badge = _RISK_BADGE_STYLES.get(risk_level, _RISK_BADGE_STYLES["UNKNOWN"])
    badge_html = (
        '<span style="display:inline-block;padding:3px 12px;border-radius:12px;'
        'font-size:13px;font-weight:600;background-color:{bg};color:{fg};'
        'border:1px solid {border};">{label}</span>'.format(
            bg=badge["bg"], fg=badge["fg"], border=badge["border"], label=badge["label"]
        )
    )

    # 建议处置动作：命中映射表时给出中文释义，否则原样展示，便于扩展
    action_raw = str(data.get("recommended_action") or "").strip()
    action_text = _ACTION_LABELS.get(action_raw, _escape(action_raw, "未提供建议动作"))

    # 证据日志 ID：渲染成横向排列的小卡片，方便值班同学逐个回查
    log_ids = _normalize_log_ids(data.get("evidence_log_ids"))
    if log_ids:
        evidence_html = "".join(
            '<span style="display:inline-block;margin:0 6px 6px 0;padding:4px 10px;'
            'background-color:#f1f5fd;border:1px solid #d6e2fb;border-radius:4px;'
            'font-size:12px;color:#1a56c4;{}">{}</span>'.format(
                _MONO_STYLE, html.escape(log_id)
            )
            for log_id in log_ids
        )
    else:
        evidence_html = '<span style="font-size:13px;color:#9aa0a6;">未提供证据日志 ID</span>'

    # 先收集「标签 - 值」对，再统一渲染成斑马纹表格，新增字段只需往列表里追加
    rows: List[Tuple[str, str]] = [
        ("告警案例编号", '<span style="{}{}">{}</span>'.format(_MONO_STYLE, "font-weight:600;color:#1a56c4;", case_id)),
        ("风险等级", badge_html),
        ("攻击类型", attack_type),
        ("攻击源 IP", '<span style="{}{}">{}</span>'.format(_MONO_STYLE, "color:#c5221f;font-weight:600;", attacker_ip)),
        ("受影响资产", victim_asset),
        ("建议处置动作", action_text),
    ]

    # 可选字段：只有上游确实提供了「未确认事项」才渲染，避免噪音行
    unknown_items = data.get("unknown_items")
    if unknown_items:
        rows.append(("未确认事项", _escape(unknown_items)))

    rows_html_parts = []
    for index, (label, value) in enumerate(rows):
        row_bg = "#ffffff" if index % 2 == 0 else "#fafbfc"
        rows_html_parts.append(
            '<tr style="background-color:{};">'
            '<td style="{}">{}</td>'
            '<td style="{}">{}</td>'
            "</tr>".format(row_bg, _LABEL_STYLE, label, _VALUE_STYLE, value)
        )

    # 人工审批提示：审批流是「高危处置不自动执行」的最后一道闸门，必须足够醒目
    if _as_bool(data.get("requires_human_approval")):
        approval_html = (
            '<div style="margin:18px 24px 0 24px;padding:12px 14px;background-color:#fff4e5;'
            'border-left:4px solid #f59e0b;border-radius:4px;font-size:13px;color:#7a4a00;">'
            "<strong>需要人工审批</strong><br />"
            "本次处置动作不会自动下发，需安全运营人员复核确认后手动执行。"
            "</div>"
        )
    else:
        approval_html = (
            '<div style="margin:18px 24px 0 24px;padding:12px 14px;background-color:#e6f4ea;'
            'border-left:4px solid #34a853;border-radius:4px;font-size:13px;color:#1e6b3a;">'
            "<strong>无需人工审批</strong><br />"
            "按建议处置动作自动下发，处置结果可在审计日志中回溯。"
            "</div>"
        )

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 拼装正文：标题栏 -> 字段表格 -> 攻击过程摘要 -> 证据 -> 审批提示 -> 页脚
    body_html = (
        '<tr><td style="background-color:#12325b;padding:20px 24px;">'
        '<div style="font-size:18px;font-weight:600;color:#ffffff;letter-spacing:0.5px;">'
        "恒脑安全告警通知</div>"
        '<div style="margin-top:6px;font-size:12px;color:#c3d3ea;">'
        "恒脑自主安全智能体 · 自动化研判结果</div>"
        "</td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="border:1px solid #eef0f3;border-radius:6px;">{rows}</table>'
        "</td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="font-size:13px;font-weight:600;color:#3c4043;margin-bottom:8px;">攻击过程摘要</div>'
        '<div style="padding:12px 14px;background-color:#fafbfc;border-left:3px solid #1a73e8;'
        'border-radius:4px;font-size:13px;line-height:1.7;color:#202124;">{summary}</div>'
        "</td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="font-size:13px;font-weight:600;color:#3c4043;margin-bottom:8px;">'
        "核心证据日志 ID</div><div>{evidence}</div>"
        "</td></tr>"
        "<tr><td>{approval}</td></tr>"
        '<tr><td style="padding:20px 24px 24px 24px;">'
        '<div style="border-top:1px solid #eef0f3;padding-top:12px;font-size:12px;'
        'color:#9aa0a6;line-height:1.6;">'
        "生成时间：{generated_at}<br />"
        "本邮件由恒脑自主安全智能体自动发送，请勿直接回复。"
        "</div></td></tr>"
    ).format(
        rows="".join(rows_html_parts),
        summary=summary,
        evidence=evidence_html,
        approval=approval_html,
        generated_at=generated_at,
    )

    return _HTML_HEAD + body_html + _HTML_TAIL


def _render_html_page(title: str, body_html: str) -> str:
    """复用告警邮件外壳，同时给不同通知设置独立的页面标题。"""
    head = _HTML_HEAD.replace(
        "<title>恒脑安全告警通知</title>", "<title>{}</title>".format(_escape(title))
    )
    return head + body_html + _HTML_TAIL


def _render_info_rows(rows: List[Tuple[str, str]]) -> str:
    """把已转义的标签与值渲染成和告警邮件一致的斑马纹表格。"""
    rows_html_parts = []
    for index, (label, value) in enumerate(rows):
        row_bg = "#ffffff" if index % 2 == 0 else "#fafbfc"
        rows_html_parts.append(
            '<tr style="background-color:{};">'
            '<td style="{}">{}</td>'
            '<td style="{}">{}</td>'
            "</tr>".format(row_bg, _LABEL_STYLE, label, _VALUE_STYLE, value)
        )
    return "".join(rows_html_parts)


def render_approval_request_html(approval_data: dict) -> str:
    """把高危处置审批单渲染为待人工审批的 HTML 邮件正文。"""
    data = approval_data or {}
    approval_id = _escape(data.get("approval_id"))
    case_id = _escape(data.get("case_id"))
    action_raw = str(data.get("action") or "").strip()
    action_text = _APPROVAL_ACTION_LABELS.get(action_raw, _escape(action_raw))

    target_ip_raw = data.get("target_ip")
    has_target_ip = target_ip_raw is not None and bool(str(target_ip_raw).strip())
    target_raw = target_ip_raw if has_target_ip else data.get("target_user")
    target_label = "目标 IP" if has_target_ip else "目标账号"
    target_html = '<span style="{}{}">{}</span>'.format(
        _MONO_STYLE, "color:#c5221f;font-weight:600;", _escape(target_raw)
    )

    overview_rows: List[Tuple[str, str]] = [
        (
            "审批单号",
            '<span style="{}{}">{}</span>'.format(
                _MONO_STYLE, "font-size:15px;font-weight:700;color:#b71c1c;", approval_id
            ),
        ),
        ("案例编号", '<span style="{}">{}</span>'.format(_MONO_STYLE, case_id)),
        ("高危动作", action_text),
        (target_label, target_html),
    ]
    if data.get("target_type"):
        overview_rows.append(("目标类型", _escape(data.get("target_type"))))
    if data.get("victim_asset"):
        overview_rows.append(("受影响资产", _escape(data.get("victim_asset"))))
    if data.get("max_duration_minutes") is not None:
        overview_rows.append(
            ("到期自动解除", "{} 分钟".format(_escape(data.get("max_duration_minutes"))))
        )
    if data.get("requested_by"):
        overview_rows.append(("申请人", _escape(data.get("requested_by"))))
    if data.get("expires_at"):
        overview_rows.append(("审批有效期至", _escape(data.get("expires_at"))))

    # 六要素表严格按 response-policy.yaml 的 approval.required_fields 顺序展示
    log_ids = _normalize_log_ids(data.get("evidence_log_ids"))
    if log_ids:
        evidence_html = "".join(
            '<span style="display:inline-block;margin:0 6px 6px 0;padding:4px 10px;'
            'background-color:#f1f5fd;border:1px solid #d6e2fb;border-radius:4px;'
            'font-size:12px;color:#1a56c4;{}">{}</span>'.format(
                _MONO_STYLE, html.escape(log_id)
            )
            for log_id in log_ids
        )
    else:
        evidence_html = '<span style="font-size:13px;color:#9aa0a6;">未提供</span>'

    required_rows: List[Tuple[str, str]] = [
        ("case_id（案例编号）", '<span style="{}">{}</span>'.format(_MONO_STYLE, case_id)),
        ("action（处置动作）", action_text),
        (
            "target_ip（目标 IP）",
            '<span style="{}">{}</span>'.format(_MONO_STYLE, _escape(data.get("target_ip"))),
        ),
        ("evidence_log_ids（证据日志 ID）", evidence_html),
        ("expected_effect（预期效果）", _escape(data.get("expected_effect"))),
        ("rollback_plan（回退方案）", _escape(data.get("rollback_plan"))),
    ]
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    body_html = (
        '<tr><td style="background-color:#12325b;padding:20px 24px;">'
        '<div style="font-size:18px;font-weight:600;color:#ffffff;letter-spacing:0.5px;">'
        "恒脑高危处置审批</div>"
        '<div style="margin-top:6px;font-size:12px;color:#c3d3ea;">'
        "恒脑自主安全智能体 · 人工授权请求</div></td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="padding:14px 16px;background-color:#fdecea;border-left:5px solid #d93025;'
        'border-radius:4px;color:#b71c1c;line-height:1.7;">'
        '<strong style="font-size:17px;">待人工审批</strong><br />'
        '<span style="font-size:13px;">高危动作尚未执行，请核对审批六要素后通过授权渠道处理。</span>'
        "</div></td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="font-size:13px;font-weight:600;color:#3c4043;margin-bottom:8px;">审批单概览</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="border:1px solid #eef0f3;border-radius:6px;">{overview_rows}</table></td></tr>'
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="font-size:13px;font-weight:600;color:#3c4043;margin-bottom:8px;">审批六要素</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="border:1px solid #eef0f3;border-radius:6px;">{required_rows}</table></td></tr>'
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="padding:12px 14px;background-color:#fff4e5;border-left:4px solid #f59e0b;'
        'border-radius:4px;font-size:13px;color:#7a4a00;line-height:1.7;">'
        "审批结论只能来自恒脑交互节点 <span style=\"{mono}\">confirm_block</span> "
        "或权限服务的程序化回执；本邮件不构成授权。</div></td></tr>"
        '<tr><td style="padding:20px 24px 24px 24px;">'
        '<div style="border-top:1px solid #eef0f3;padding-top:12px;font-size:12px;'
        'color:#9aa0a6;line-height:1.6;">生成时间：{generated_at}<br />'
        "本邮件由恒脑自主安全智能体自动发送，请勿直接回复。</div></td></tr>"
    ).format(
        overview_rows=_render_info_rows(overview_rows),
        required_rows=_render_info_rows(required_rows),
        mono=_MONO_STYLE,
        generated_at=generated_at,
    )
    return _render_html_page("恒脑高危处置审批", body_html)


def render_action_revoked_html(revoke_data: dict) -> str:
    """把到期自动解除回执与后置核验结果渲染为 HTML 邮件正文。"""
    data = revoke_data or {}
    action_raw = str(data.get("action") or "").strip()
    action_text = _APPROVAL_ACTION_LABELS.get(action_raw, _escape(action_raw))
    target_raw = data.get("target") or data.get("target_ip") or data.get("target_user")

    rows: List[Tuple[str, str]] = [
        (
            "动作编号",
            '<span style="{}{}">{}</span>'.format(
                _MONO_STYLE, "font-weight:700;color:#1e6b3a;", _escape(data.get("action_id"))
            ),
        ),
        ("审批单号", '<span style="{}">{}</span>'.format(_MONO_STYLE, _escape(data.get("approval_id")))),
        ("案例编号", '<span style="{}">{}</span>'.format(_MONO_STYLE, _escape(data.get("case_id")))),
        ("处置动作", action_text),
        ("处置目标", '<span style="{}">{}</span>'.format(_MONO_STYLE, _escape(target_raw))),
        ("执行时间", _escape(data.get("executed_at"))),
        ("到期时间", _escape(data.get("expires_at"))),
        ("解除时间", _escape(data.get("revoked_at"))),
    ]
    if data.get("operator_note"):
        rows.append(("操作备注", _escape(data.get("operator_note"))))
    if data.get("remaining_risk"):
        rows.append(("剩余风险", _escape(data.get("remaining_risk"))))

    post_checks = data.get("post_checks")
    check_rows = []
    if isinstance(post_checks, dict) and post_checks:
        for check_name, check_value in post_checks.items():
            check_detail = None
            if isinstance(check_value, dict):
                check_status = (
                    check_value.get("status")
                    or check_value.get("result")
                    or check_value.get("state")
                    or "未提供"
                )
                check_detail = (
                    check_value.get("detail")
                    or check_value.get("message")
                    or check_value.get("summary")
                )
            else:
                check_status = check_value

            normalized_status = str(check_status or "").strip().lower()
            if normalized_status in {"pass", "ok", "passed", "success", "通过", "正常"}:
                status_style = "background-color:#e6f4ea;color:#1e6b3a;border:1px solid #b7dfc2;"
            elif (
                normalized_status in {"fail", "failed", "failure", "error", "exception", "失败", "异常"}
                or "fail" in normalized_status
                or "异常" in normalized_status
            ):
                status_style = "background-color:#fce8e6;color:#c5221f;border:1px solid #f3b4ae;"
            else:
                status_style = "background-color:#f1f3f4;color:#5f6368;border:1px solid #dadce0;"

            status_html = (
                '<span style="display:inline-block;padding:3px 10px;border-radius:12px;'
                'font-size:12px;font-weight:600;{}">{}</span>'
            ).format(status_style, _escape(check_status))
            if check_detail:
                status_html += '<div style="margin-top:6px;font-size:12px;color:#5f6368;">{}</div>'.format(
                    _escape(check_detail)
                )
            check_label = _POST_CHECK_LABELS.get(str(check_name), _escape(check_name))
            check_rows.append((check_label, status_html))
        post_checks_html = _render_info_rows(check_rows)
    else:
        post_checks_html = (
            '<tr><td style="padding:12px 16px;font-size:13px;color:#9aa0a6;">'
            "未提供后置核验结果</td></tr>"
        )

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body_html = (
        '<tr><td style="background-color:#12325b;padding:20px 24px;">'
        '<div style="font-size:18px;font-weight:600;color:#ffffff;letter-spacing:0.5px;">'
        "恒脑处置解除回执</div>"
        '<div style="margin-top:6px;font-size:12px;color:#c3d3ea;">'
        "恒脑自主安全智能体 · 生命周期后置核验</div></td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="padding:14px 16px;background-color:#e6f4ea;border-left:5px solid #34a853;'
        'border-radius:4px;color:#1e6b3a;line-height:1.7;">'
        '<strong style="font-size:17px;">已自动解除</strong><br />'
        '<span style="font-size:13px;">处置动作已按生命周期策略到期撤销，请结合后置核验结果确认业务状态。</span>'
        "</div></td></tr>"
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="font-size:13px;font-weight:600;color:#3c4043;margin-bottom:8px;">解除回执</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="border:1px solid #eef0f3;border-radius:6px;">{detail_rows}</table></td></tr>'
        '<tr><td style="padding:18px 24px 0 24px;">'
        '<div style="font-size:13px;font-weight:600;color:#3c4043;margin-bottom:8px;">后置核验摘要</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="border:1px solid #eef0f3;border-radius:6px;">{post_checks}</table></td></tr>'
        '<tr><td style="padding:20px 24px 24px 24px;">'
        '<div style="border-top:1px solid #eef0f3;padding-top:12px;font-size:12px;'
        'color:#9aa0a6;line-height:1.6;">生成时间：{generated_at}<br />'
        "本邮件由恒脑自主安全智能体自动发送，请勿直接回复。</div></td></tr>"
    ).format(
        detail_rows=_render_info_rows(rows),
        post_checks=post_checks_html,
        generated_at=generated_at,
    )
    return _render_html_page("恒脑处置解除回执", body_html)


def _render_plain_text(alert_data: Any) -> str:
    """生成纯文本备用正文，供不支持 HTML 的客户端显示。"""
    data = alert_data or {}
    log_ids = _normalize_log_ids(data.get("evidence_log_ids"))
    return "\n".join(
        [
            "【恒脑安全告警通知】",
            "案例编号：{}".format(data.get("case_id") or "未提供"),
            "风险等级：{}".format(data.get("risk_level") or "未提供"),
            "攻击类型：{}".format(data.get("attack_type") or "未提供"),
            "攻击源 IP：{}".format(data.get("attacker_ip") or "未提供"),
            "受影响资产：{}".format(data.get("victim_asset") or "未提供"),
            "攻击过程摘要：{}".format(data.get("attack_chain_summary") or "未提供"),
            "核心证据日志 ID：{}".format("、".join(log_ids) if log_ids else "无"),
            "建议处置动作：{}".format(data.get("recommended_action") or "未提供"),
            "是否需要人工审批：{}".format("是" if _as_bool(data.get("requires_human_approval")) else "否"),
        ]
    )


def _render_approval_plain_text(approval_data: Any) -> str:
    """生成审批请求纯文本备用正文。"""
    data = approval_data or {}
    log_ids = _normalize_log_ids(data.get("evidence_log_ids"))
    target = data.get("target_ip") or data.get("target_user") or "未提供"
    return "\n".join(
        [
            "【恒脑审批】【待审批】",
            "审批单号：{}".format(data.get("approval_id") or "未提供"),
            "案例编号：{}".format(data.get("case_id") or "未提供"),
            "处置动作：{}".format(data.get("action") or "未提供"),
            "处置目标：{}".format(target),
            "证据日志 ID：{}".format("、".join(log_ids) if log_ids else "未提供"),
            "预期效果：{}".format(data.get("expected_effect") or "未提供"),
            "回退方案：{}".format(data.get("rollback_plan") or "未提供"),
            "审批结论只能来自恒脑交互节点 confirm_block 或权限服务的程序化回执；本邮件不构成授权。",
        ]
    )


def _render_revoked_plain_text(revoke_data: Any) -> str:
    """生成到期解除回执纯文本备用正文。"""
    data = revoke_data or {}
    post_checks = data.get("post_checks")
    check_lines = []
    if isinstance(post_checks, dict):
        for name, value in post_checks.items():
            if isinstance(value, dict):
                value = value.get("status") or value.get("result") or value.get("state") or "未提供"
            check_lines.append("{}：{}".format(name, value))
    return "\n".join(
        [
            "【恒脑处置】【已解除】",
            "动作编号：{}".format(data.get("action_id") or "未提供"),
            "审批单号：{}".format(data.get("approval_id") or "未提供"),
            "案例编号：{}".format(data.get("case_id") or "未提供"),
            "处置动作：{}".format(data.get("action") or "未提供"),
            "处置目标：{}".format(data.get("target") or data.get("target_ip") or data.get("target_user") or "未提供"),
            "执行时间：{}".format(data.get("executed_at") or "未提供"),
            "到期时间：{}".format(data.get("expires_at") or "未提供"),
            "解除时间：{}".format(data.get("revoked_at") or "未提供"),
            "后置核验：{}".format("；".join(check_lines) if check_lines else "未提供"),
        ]
    )


def _build_subject(alert_data: Any) -> str:
    """统一邮件主题，方便收件人按风险等级快速分拣。"""
    data = alert_data or {}
    risk = str(data.get("risk_level") or "UNKNOWN").strip().upper()
    approval_tag = "【待审批】" if _as_bool(data.get("requires_human_approval")) else ""
    return "[恒脑告警][{}]{} {} {}".format(
        risk,
        approval_tag,
        data.get("case_id") or "UNKNOWN-CASE",
        data.get("attack_type") or "",
    ).strip()


# ---------------------------------------------------------------------------
# 配置读取与投递
# ---------------------------------------------------------------------------
def _load_smtp_config() -> Dict[str, Any]:
    """从环境变量装配 SMTP 配置；缺任何一项都直接报错，绝不回退到硬编码值。"""
    missing = [key for key in ("SMTP_USER", "SMTP_PASS") if not os.getenv(key)]
    if missing:
        raise SmtpConfigError(
            "缺少 SMTP 环境变量：{}。请先设置对应环境变量或使用 .env（授权码不是登录密码）。".format(
                "、".join(missing)
            )
        )

    port_raw = (os.getenv("SMTP_PORT") or str(DEFAULT_SMTP_PORT)).strip()
    try:
        port = int(port_raw)
    except ValueError:
        raise SmtpConfigError("SMTP_PORT 必须是整数，当前值为：{}".format(port_raw))

    return {
        "host": (os.getenv("SMTP_HOST") or DEFAULT_SMTP_HOST).strip(),
        "port": port,
        "user": os.getenv("SMTP_USER", "").strip(),
        "password": os.getenv("SMTP_PASS", "").strip(),
        "receiver": (os.getenv("ALERT_RECEIVER_EMAIL") or "").strip(),
    }


def _save_dry_run_html(html_body: str, case_id: str, prefix: str = "alert") -> Path:
    """dry_run 落盘：把渲染结果写到本地，便于离线核对排版。"""
    output_dir = Path(os.getenv("EMAIL_DRY_RUN_DIR") or DEFAULT_DRY_RUN_DIR).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = "{}_{}_{}.html".format(
        _slugify(prefix), _slugify(case_id), datetime.now().strftime("%Y%m%d-%H%M%S")
    )
    target = output_dir / filename
    target.write_text(html_body, encoding="utf-8")
    return target


def _append_notification_outbox(event: str, title: str, payload: Dict[str, Any],
                                html_path: Path, reason: str) -> Optional[str]:
    """追加通知 outbox；任何写盘错误都只返回给调用方，不反噬处置流程。"""
    project_root = Path(__file__).resolve().parents[2]
    state_dir = Path(
        os.getenv("SECLOG_STATE_DIR") or str(project_root / "data" / "state")
    ).expanduser()
    record = {
        "event": event,
        "title": title,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "payload": payload,
        "html_path": str(html_path),
        "reason": reason,
    }
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        outbox_path = state_dir / "notification_outbox.jsonl"
        with outbox_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception as exc:  # 序列化 / 权限 / 磁盘异常均不得中断通知调用方
        return "{}: {}".format(type(exc).__name__, exc)
    return None


def _deliver(config: Dict[str, Any], recipient: str, subject: str,
             html_body: str, plain_text: str) -> Dict[str, Any]:
    """真正执行一次 SMTP_SSL 投递，单次调用不带重试逻辑。"""
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    # 发件人展示名做一层包装，收件人侧更易识别为系统告警而非垃圾邮件
    message["From"] = formataddr(("恒脑安全告警", config["user"]))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=config["user"].split("@")[-1] or "localhost")
    message.attach(MIMEText(plain_text, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    # 收件人允许逗号分隔多人，逐个 trim 后交给 sendmail
    recipients = [
        item.strip() for item in recipient.replace(";", ",").split(",") if item.strip()
    ]
    if not recipients:
        raise SmtpConfigError("收件人列表为空，请检查 to_email 或 ALERT_RECEIVER_EMAIL。")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        config["host"], config["port"], timeout=DEFAULT_TIMEOUT_SECONDS, context=context
    ) as server:
        server.login(config["user"], config["password"])
        refused = server.sendmail(config["user"], recipients, message.as_string())

    return {"recipients": recipients, "refused_recipients": refused or {}}


def _deliver_with_retries(config: Dict[str, Any], recipient: str, subject: str,
                          html_body: str, plain_text: str) -> Dict[str, Any]:
    """按现有默认参数执行 SMTP_SSL 投递与指数退避重试。"""
    attempts_allowed = DEFAULT_MAX_RETRIES + 1
    last_error = ""
    for attempt in range(1, attempts_allowed + 1):
        try:
            delivered = _deliver(config, recipient, subject, html_body, plain_text)
            return {
                "status": "sent",
                "attempts": attempt,
                "subject": subject,
                "html": html_body,
                "recipients": delivered["recipients"],
                "refused_recipients": delivered["refused_recipients"],
            }
        except Exception as exc:  # 网络 / 认证 / 超时统一记录后重试
            last_error = "{}: {}".format(type(exc).__name__, exc)
            if attempt < attempts_allowed:
                time.sleep(DEFAULT_BACKOFF_SECONDS * (2 ** (attempt - 1)))

    return {
        "status": "failed",
        "attempts": attempts_allowed,
        "error": last_error,
        "subject": subject,
        "html": html_body,
    }


def send_security_notification(alert_data: dict, to_email: str = None,
                               dry_run: bool = False, max_retries: int = DEFAULT_MAX_RETRIES,
                               backoff_seconds: float = DEFAULT_BACKOFF_SECONDS) -> dict:
    """发送安全告警 / 审批邮件。

    参数：
        alert_data:      告警数据字典（字段见 SAMPLE_ALERT_DATA）。
        to_email:        收件人；为空时回退到环境变量 ALERT_RECEIVER_EMAIL。
        dry_run:         True 时不连接 SMTP，只把 HTML 落盘并返回内容，用于离线自测。
        max_retries:     发送失败后的最大重试次数，默认 2（即总共最多 3 次尝试）。
        backoff_seconds: 退避基数，第 n 次重试等待 backoff_seconds * 2^(n-1) 秒。

    返回：
        状态字典，一定包含 status / subject / html 三个字段：
        - {"status": "dry_run_saved", ...}  仅渲染未发送
        - {"status": "sent", "attempts": n, ...}  发送成功
        - {"status": "failed", "attempts": n, "error": "...", ...}  重试后仍失败
    """
    html_body = render_alert_html(alert_data)
    subject = _build_subject(alert_data)

    # dry_run 分支：完全不触碰网络与凭证，保证无 SMTP 环境也能验收
    if dry_run:
        saved_path = _save_dry_run_html(html_body, str((alert_data or {}).get("case_id") or ""))
        return {
            "status": "dry_run_saved",
            "html": html_body,
            "subject": subject,
            "saved_path": str(saved_path),
        }

    config = _load_smtp_config()
    recipient = (to_email or config["receiver"]).strip()
    if not recipient:
        raise SmtpConfigError("未指定收件人：请传入 to_email 或设置环境变量 ALERT_RECEIVER_EMAIL。")

    plain_text = _render_plain_text(alert_data)
    attempts_allowed = max(1, max_retries) + 1
    last_error = ""

    # 逐次尝试 + 指数退避：应对 SMTP 侧限流或瞬时网络抖动
    for attempt in range(1, attempts_allowed + 1):
        try:
            delivered = _deliver(config, recipient, subject, html_body, plain_text)
            return {
                "status": "sent",
                "attempts": attempt,
                "subject": subject,
                "html": html_body,
                "recipients": delivered["recipients"],
                "refused_recipients": delivered["refused_recipients"],
            }
        except Exception as exc:  # 网络 / 认证 / 超时统一记录后重试
            last_error = "{}: {}".format(type(exc).__name__, exc)
            if attempt < attempts_allowed:
                # 第一次失败等 backoff，第二次翻倍，尽量错开服务端限流窗口
                time.sleep(backoff_seconds * (2 ** (attempt - 1)))

    return {
        "status": "failed",
        "attempts": attempts_allowed,
        "error": last_error,
        "subject": subject,
        "html": html_body,
    }


def send_approval_request_email(approval_data: dict, to_email: Optional[str] = None,
                                dry_run: bool = False) -> dict:
    """发送高危动作审批请求；无 SMTP 凭据时自动保存 HTML 并写入 outbox。"""
    data = approval_data or {}
    html_body = render_approval_request_html(data)
    subject = "[恒脑审批][待审批] {} · {} · {}".format(
        data.get("action") or "UNKNOWN-ACTION",
        data.get("case_id") or "UNKNOWN-CASE",
        data.get("approval_id") or "UNKNOWN-APPROVAL",
    )
    file_key = str(data.get("case_id") or data.get("approval_id") or "")

    if dry_run:
        saved_path = _save_dry_run_html(html_body, file_key, prefix="approval_request")
        return {
            "status": "dry_run_saved",
            "html": html_body,
            "subject": subject,
            "saved_path": str(saved_path),
        }

    has_credentials = bool(
        os.getenv("SMTP_USER", "").strip() and os.getenv("SMTP_PASS", "").strip()
    )
    if not has_credentials:
        # 在读取配置和建立连接之前降级，开发机 / CI 不产生 SMTP 网络等待
        saved_path = _save_dry_run_html(html_body, file_key, prefix="approval_request")
        queue_error = _append_notification_outbox(
            event="approval_required",
            title="处置待审批",
            payload=data,
            html_path=saved_path,
            reason="smtp_not_configured",
        )
        result = {
            "status": "dry_run_saved",
            "reason": "smtp_not_configured",
            "html": html_body,
            "subject": subject,
            "saved_path": str(saved_path),
        }
        if queue_error:
            result["queue_error"] = queue_error
        return result

    config = _load_smtp_config()
    recipient = (to_email or config["receiver"]).strip()
    if not recipient:
        raise SmtpConfigError("未指定收件人：请传入 to_email 或设置环境变量 ALERT_RECEIVER_EMAIL。")
    return _deliver_with_retries(
        config, recipient, subject, html_body, _render_approval_plain_text(data)
    )


def send_action_revoked_email(revoke_data: dict, to_email: Optional[str] = None,
                              dry_run: bool = False) -> dict:
    """发送动作到期解除回执；无 SMTP 凭据时自动保存 HTML 并写入 outbox。"""
    data = revoke_data or {}
    html_body = render_action_revoked_html(data)
    subject = "[恒脑处置][已解除] {} · {} · {}".format(
        data.get("action") or "UNKNOWN-ACTION",
        data.get("case_id") or "UNKNOWN-CASE",
        data.get("action_id") or "UNKNOWN-ACTION-ID",
    )
    file_key = str(data.get("case_id") or data.get("action_id") or "")

    if dry_run:
        saved_path = _save_dry_run_html(html_body, file_key, prefix="action_revoked")
        return {
            "status": "dry_run_saved",
            "html": html_body,
            "subject": subject,
            "saved_path": str(saved_path),
        }

    has_credentials = bool(
        os.getenv("SMTP_USER", "").strip() and os.getenv("SMTP_PASS", "").strip()
    )
    if not has_credentials:
        saved_path = _save_dry_run_html(html_body, file_key, prefix="action_revoked")
        queue_error = _append_notification_outbox(
            event="revoked",
            title="处置到期自动解除",
            payload=data,
            html_path=saved_path,
            reason="smtp_not_configured",
        )
        result = {
            "status": "dry_run_saved",
            "reason": "smtp_not_configured",
            "html": html_body,
            "subject": subject,
            "saved_path": str(saved_path),
        }
        if queue_error:
            result["queue_error"] = queue_error
        return result

    config = _load_smtp_config()
    recipient = (to_email or config["receiver"]).strip()
    if not recipient:
        raise SmtpConfigError("未指定收件人：请传入 to_email 或设置环境变量 ALERT_RECEIVER_EMAIL。")
    return _deliver_with_retries(
        config, recipient, subject, html_body, _render_revoked_plain_text(data)
    )


# ---------------------------------------------------------------------------
# 样例数据与本地自测入口
# ---------------------------------------------------------------------------
SAMPLE_ALERT_DATA = {
    "case_id": "EVAL-CHAIN-001",
    "is_malicious": True,
    "attack_type": "SQL_Injection_After_Brute_Force",
    "risk_level": "HIGH",
    "attacker_ip": "198.51.100.23",
    "victim_asset": "web-prod-01",
    "evidence_log_ids": [
        "LOG-20261027-0001",
        "LOG-20261027-0008",
        "LOG-20261027-0015",
    ],
    "attack_chain_summary": (
        "攻击源 198.51.100.23 先对 /admin 执行账号爆破失败，"
        "随后针对登录接口发起 SQL 注入绕过认证并尝试导出敏感表数据。"
    ),
    "recommended_action": "block_ip",
    "requires_human_approval": True,
    "unknown_items": "暂未获取到数据库内部审计日志，需进一步确认敏感表具体泄露行数。",
}


SAMPLE_APPROVAL_DATA = {
    "approval_id": "APR-CHAIN-CASE-01-001",
    "case_id": "CHAIN-CASE-01",
    "action": "block_ip",
    "target_ip": "198.51.100.23",
    "target_type": "web",
    "victim_asset": "web-prod-01",
    "evidence_log_ids": [
        "LOG-CHAIN-01-0001",
        "LOG-CHAIN-01-0008",
        "LOG-CHAIN-01-0015",
    ],
    "expected_effect": "阻断攻击源 IP 对 web-prod-01 的后续请求，遏制 SQL 注入与数据导出尝试。",
    "rollback_plan": "审批到期或人工撤销时删除对应封禁规则，并复核关键接口成功率与同源请求日志。",
    "max_duration_minutes": 1440,
    "requested_by": "恒脑自主安全智能体",
    "expires_at": "2026-11-28T12:00:00+00:00",
}

SAMPLE_REVOKED_DATA = {
    "action_id": "ACT-CHAIN-CASE-01-001",
    "approval_id": "APR-CHAIN-CASE-01-001",
    "case_id": "CHAIN-CASE-01",
    "action": "block_ip",
    "target": "198.51.100.23",
    "executed_at": "2026-11-26T12:00:00+00:00",
    "expires_at": "2026-11-27T12:00:00+00:00",
    "revoked_at": "2026-11-27T12:00:03+00:00",
    "post_checks": {
        "effect_verification": "pass",
        "business_impact": "pass",
    },
    "operator_note": "封禁规则已按生命周期策略自动删除。",
    "remaining_risk": "暂无新增同源攻击请求，继续监测 30 分钟。",
}


if __name__ == "__main__":
    # 默认走 dry_run：只需标准库 + 本地文件写入，无任何网络与凭证依赖
    args = sys.argv[1:]
    dry_run = "--send" not in args
    to_email = None
    if "--to" in args:
        to_index = args.index("--to")
        if to_index + 1 < len(args):
            to_email = args[to_index + 1]

    try:
        result = send_security_notification(
            SAMPLE_ALERT_DATA, to_email=to_email, dry_run=dry_run
        )
        approval_result = send_approval_request_email(
            SAMPLE_APPROVAL_DATA, to_email=to_email, dry_run=dry_run
        )
        revoked_result = send_action_revoked_email(
            SAMPLE_REVOKED_DATA, to_email=to_email, dry_run=dry_run
        )
    except SmtpConfigError as exc:
        print("[配置错误] {}".format(exc))
        sys.exit(1)

    # 打印渲染后的 HTML，便于在命令行直接确认排版与字段是否齐全
    print(result["html"])
    print("-" * 72)
    print("邮件主题：{}".format(result.get("subject")))
    print(
        "发送结果：{}".format(
            {key: value for key, value in result.items() if key != "html"}
        )
    )

    for label, extra_result in (
        ("审批请求邮件", approval_result),
        ("到期解除邮件", revoked_result),
    ):
        print("-" * 72)
        print("{}主题：{}".format(label, extra_result.get("subject")))
        print("{}返回状态：{}".format(label, extra_result.get("status")))
        print("{}HTML 保存路径：{}".format(label, extra_result.get("saved_path", "未落盘")))

    all_results = (result, approval_result, revoked_result)
    succeeded = all(item["status"] in {"sent", "dry_run_saved"} for item in all_results)
    sys.exit(0 if succeeded else 1)
