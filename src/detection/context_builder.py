"""从 `config/` 加载资产台账、维护窗口与白名单，为每条日志构造 `DetectionContext`。

## 为什么需要

`RuleEngine.evaluate_log(log, context)` 早就支持两个降权开关：

    context.maintenance_window   # 处于维护窗口
    context.allowlisted_context  # 命中白名单

但默认调用 `detect_batch(logs)` 时 context 是空的，等于这两个开关永久关闭。
结果就是「正常运维场景」被误判成攻击——实测 CASE-03 的 22 条正常运维日志
被报出 9 条线索（含 2 条 critical）。

本模块把 `config/*.yaml` 里的声明式配置翻译成 context，让配置真正生效。

## 时区

维护窗口按 `Asia/Shanghai` 声明（如 02:00-03:30），而日志时间是 UTC。
必须先把 `event_time` 转成本地时间再比对，否则窗口判断会整体偏移 8 小时。

## 匹配规则

- 资产：按 `asset_id` 精确匹配
- IP 白名单：精确匹配
- 账号白名单：支持 `fnmatch` 通配（如 `ops_*` 覆盖 `ops_zhang`、`ops_li`）
"""

from __future__ import annotations

import fnmatch
from datetime import time as dtime
from pathlib import Path
from typing import Any

import yaml

from src.detection.rules import DetectionContext
from src.schemas import NormalizedLog

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


class ContextRegistry:
    """加载一次，反复复用。无配置文件时退化为「无窗口、无白名单」。"""

    def __init__(self, config_dir: Path | str | None = None) -> None:
        base = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
        self._assets = {a["asset_id"]: a for a in _load(base / "assets.yaml").get("assets", [])}
        self._windows = _load(base / "maintenance-windows.yaml").get("windows", [])
        allow = _load(base / "response-policy.yaml").get("allowlist", {})
        self._allow_ips = allow.get("ips", [])
        self._allow_users = allow.get("users", [])
        self._allow_assets = {a.get("asset_id") for a in allow.get("assets", [])}
        tz_name = _load(base / "maintenance-windows.yaml").get("timezone", "Asia/Shanghai")
        try:
            from zoneinfo import ZoneInfo
            self._tz = ZoneInfo(tz_name)
        except Exception:  # noqa: BLE001 - 缺 tzdata 时退化为 UTC，不阻断检测
            from datetime import timezone
            self._tz = timezone.utc

    # --- 判定 -------------------------------------------------------

    def in_maintenance_window(self, log: NormalizedLog) -> bool:
        asset_id = getattr(log, "asset_id", None)
        if not asset_id:
            return False
        local = log.event_time.astimezone(self._tz)
        weekday = local.strftime("%a").lower()[:3]
        for w in self._windows:
            if w.get("asset_id") != asset_id:
                continue
            if weekday not in [d.lower()[:3] for d in w.get("days", [])]:
                continue
            try:
                start = dtime.fromisoformat(str(w["start"]))
                end = dtime.fromisoformat(str(w["end"]))
            except (KeyError, ValueError):
                continue
            if start <= local.time() <= end:
                return True
        return False

    def is_allowlisted(self, log: NormalizedLog) -> bool:
        src = log.src_ip or ""
        if src and any(item.get("ip") == src for item in self._allow_ips):
            return True
        user = log.user_id or ""
        if user and any(fnmatch.fnmatch(user, item.get("user", "")) for item in self._allow_users):
            return True
        return False

    def asset_of(self, log: NormalizedLog) -> dict[str, Any] | None:
        return self._assets.get(getattr(log, "asset_id", None) or "")

    # --- 对外接口 ---------------------------------------------------

    def build(self, log: NormalizedLog) -> DetectionContext:
        return DetectionContext(
            maintenance_window=self.in_maintenance_window(log),
            allowlisted_context=self.is_allowlisted(log),
            baseline_deviations=[],
        )

    def is_critical_asset(self, log: NormalizedLog) -> bool:
        meta = self.asset_of(log) or {}
        return str(meta.get("criticality", "")).lower() == "critical"
