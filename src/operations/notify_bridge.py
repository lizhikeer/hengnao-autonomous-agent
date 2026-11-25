"""处置事件通知桥：把状态机事件转成可投递的告警，并在无凭据时降级落队列。

设计原则（与 ``email_notifier`` 的分工）：

* 本模块只做**事件 → 告警载荷**的映射和**降级策略**，不碰 SMTP 协议细节；
* 通知是**旁路**：任何异常都不得让处置主流程失败。发不出去就进 outbox，
  由运维稍后补发，而不是把已经执行的封禁回滚掉；
* 无 ``SMTP_USER`` / ``SMTP_PASS`` 时不去试探网络，直接落 outbox——
  在开发机与 CI 上不该因为没配邮箱就制造连接超时。

outbox 文件：``data/state/notification_outbox.jsonl``（可用 ``SECLOG_STATE_DIR`` 改目录）。
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import email_notifier

#: outbox 文件名，与 ``executed_enforcements.jsonl`` 同目录
OUTBOX_FILENAME = "notification_outbox.jsonl"

#: 事件类型 → 中文标题（进入邮件主题与 outbox 的 ``title`` 字段）
EVENT_TITLES = {
    "approval_required": "处置待审批",
    "executed": "处置已执行",
    "revoked": "处置到期自动解除",
    "rejected": "处置已拒批",
    "blocked": "处置被策略拦截",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def state_dir() -> Path:
    """与执行器共用 ``SECLOG_STATE_DIR``，保证审计与通知落在同一处。"""
    return Path(os.getenv("SECLOG_STATE_DIR", str(_project_root() / "data" / "state")))


def outbox_path() -> Path:
    return state_dir() / OUTBOX_FILENAME


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def has_smtp_credentials() -> bool:
    """凭据齐备才允许真发；缺一项都按"未配置"处理。"""
    return bool(os.getenv("SMTP_USER", "").strip() and os.getenv("SMTP_PASS", "").strip())


def append_outbox(record: Dict[str, Any]) -> Dict[str, Any]:
    """追加一条待投递记录（append-only）。写盘失败也吞掉，不允许影响处置。"""
    try:
        path = outbox_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        record["queued"] = True
    except OSError as exc:  # 磁盘满 / 只读挂载：记录在返回值里，不抛
        record["queued"] = False
        record["queue_error"] = f"{type(exc).__name__}: {exc}"
    return record


def build_alert(event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """把状态机事件映射成 ``email_notifier`` 认识的告警字段。"""
    payload = dict(payload or {})
    return {
        "case_id": payload.get("case_id") or "UNKNOWN-CASE",
        "is_malicious": True,
        "attack_type": payload.get("attack_type") or payload.get("action") or "unknown",
        "risk_level": str(payload.get("risk_level") or "HIGH").upper(),
        "attacker_ip": payload.get("target") or payload.get("target_ip") or "",
        "victim_asset": payload.get("target_type") or payload.get("asset_id") or "",
        "evidence_log_ids": list(payload.get("evidence_log_ids") or []),
        "attack_chain_summary": payload.get("detail")
        or EVENT_TITLES.get(event, event),
        "recommended_action": payload.get("action") or "none",
        "requires_human_approval": event == "approval_required",
        "unknown_items": payload.get("unknown_items")
        or f"事件类型：{EVENT_TITLES.get(event, event)}；审批单：{payload.get('approval_id') or '无'}",
    }


def notify_response_event(
    event: str,
    payload: Dict[str, Any],
    *,
    to_email: Optional[str] = None,
) -> Dict[str, Any]:
    """发送处置事件通知；无凭据或发送失败时降级写入 outbox。

    返回字典一定包含 ``status``：

    * ``sent``     —— 已通过 SMTP 投递；
    * ``queued``   —— 无凭据或投递失败，已进 outbox 待补发；
    * ``skipped``  —— 事件本身不需要通知（例如 no_action）。

    永不抛异常：调用方是处置主流程，不能让通知故障反噬。
    """
    if event in {"no_action", "none"}:
        return {"status": "skipped", "event": event, "reason": "该事件无需通知"}

    alert = build_alert(event, payload)
    base = {
        "event": event,
        "title": EVENT_TITLES.get(event, event),
        "created_at": _now_iso(),
        "alert": alert,
    }

    if not has_smtp_credentials():
        return {"status": "queued", **append_outbox({**base, "reason": "smtp_not_configured"})}

    try:
        result = email_notifier.send_security_notification(alert, to_email=to_email)
    except Exception as exc:  # 配置错误 / 网络异常一律降级，不冒泡
        return {
            "status": "queued",
            **append_outbox({**base, "reason": f"{type(exc).__name__}: {exc}"}),
        }

    if result.get("status") == "sent":
        return {
            "status": "sent",
            "event": event,
            "subject": result.get("subject"),
            "recipients": result.get("recipients"),
        }
    return {
        "status": "queued",
        **append_outbox(
            {
                **base,
                "reason": result.get("error") or result.get("status") or "send_failed",
            }
        ),
    }
