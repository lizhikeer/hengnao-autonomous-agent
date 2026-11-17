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

## UEBA 基线偏离

`--from-files` 离线模式下没有 ClickHouse，也就没有持久化的用户基线。
`UEBABaselineProvider` 用「同一批日志」的会话统计构造内存基线，再复用
`src/ueba/deviation.py` 的 `load_user_context` / `evaluate_deviations` 产出
偏离证据，注入 `DetectionContext.baseline_deviations`。

它只实现 `DeviationStorage` 协议的两个方法，因此和 ClickHouse 实现可以互换；
`ContextRegistry(baseline_provider=...)` 是显式开关，默认行为保持不变。
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, time as dtime
from pathlib import Path
from typing import Any, Iterable

import yaml

from src.detection.rules import DetectionContext
from src.schemas import NormalizedLog

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def _log_doc(log: NormalizedLog | dict[str, Any]) -> dict[str, Any]:
    if isinstance(log, dict):
        return dict(log)
    return log.model_dump()


class UEBABaselineProvider:
    """内存版 `DeviationStorage`：基线来自本批日志，不依赖 ClickHouse。

    语义说明（离线场景的取舍）：

    - 基线＝「同组会话统计」，即把本批日志当作该用户的历史样本；
      样本少时 `evaluate_deviations` 会给出 `insufficient_history` /
      `low_baseline_confidence`，而不是假装「没有偏离」。
    - `seen_source` 用时间序判断：只有在本条日志**之前**出现过的源 IP 才算
      「已见」。这样攻击首次落地的那条日志仍会命中 `new_source_ip`，
      而同一会话内的后续访问不会被重复报成新来源。
    """

    def __init__(self, logs: Iterable[NormalizedLog | dict[str, Any]]) -> None:
        docs = [_log_doc(log) for log in logs]
        self._baselines: dict[tuple[str, str], dict[str, Any]] = {}
        self._first_seen: dict[tuple[str, str], dict[str, datetime]] = {}
        self._cache: dict[str, list[dict[str, Any]]] = {}

        for doc in docs:
            tenant = str(doc.get("tenant_id") or "default")
            user_id = doc.get("user_id")
            src_ip = doc.get("src_ip")
            if not user_id or not src_ip:
                continue
            when = doc.get("event_time")
            if not isinstance(when, datetime):
                continue
            per_user = self._first_seen.setdefault((tenant, str(user_id)), {})
            current = per_user.get(str(src_ip))
            if current is None or when < current:
                per_user[str(src_ip)] = when

        # 延迟导入：基线模块会间接拉起 storage 依赖，ClickHouse 路径不需要它
        from src.ueba.baseline import build_baselines_from_logs

        for baseline in build_baselines_from_logs(docs):
            doc = baseline.model_dump()
            key = (str(doc.get("tenant_id") or "default"), str(doc.get("user_id") or ""))
            self._baselines[key] = doc

    # --- DeviationStorage 协议 --------------------------------------

    def get_user_baseline(
        self,
        user_id: str,
        *,
        tenant_id: str | None = None,
        baseline_date: Any = None,
    ) -> dict[str, Any] | None:
        if not user_id:
            return None
        user = str(user_id)
        if tenant_id:
            return self._baselines.get((str(tenant_id), user))
        for (_, candidate), doc in self._baselines.items():
            if candidate == user:
                return doc
        return None

    def query_user_seen_sources(
        self,
        *,
        tenant_id: str = "default",
        user_id: str | None = None,
        source_type: str | None = None,
        source_key: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        if source_type and source_type != "ip":
            return []
        rows: list[dict[str, Any]] = []
        for (tenant, user), seen in self._first_seen.items():
            if tenant_id and tenant != str(tenant_id):
                continue
            if user_id and user != str(user_id):
                continue
            for ip in seen:
                if source_key and ip != str(source_key):
                    continue
                rows.append(
                    {
                        "tenant_id": tenant,
                        "user_id": user,
                        "source_type": "ip",
                        "source_key": ip,
                    }
                )
                if len(rows) >= limit:
                    return rows
        return rows

    # --- 供 ContextRegistry 使用 ------------------------------------

    @property
    def user_count(self) -> int:
        return len(self._baselines)

    def has_baseline(self, log: NormalizedLog) -> bool:
        user_id = getattr(log, "user_id", None)
        if not user_id:
            return False
        tenant = str(getattr(log, "tenant_id", None) or "default")
        return (tenant, str(user_id)) in self._baselines

    def seen_source(self, log: NormalizedLog) -> bool | None:
        """本条日志之前是否已见过该源 IP；无用户或无 IP 时返回 None。"""
        user_id = getattr(log, "user_id", None)
        src_ip = getattr(log, "src_ip", None)
        if not user_id or not src_ip:
            return None
        tenant = str(getattr(log, "tenant_id", None) or "default")
        first = self._first_seen.get((tenant, str(user_id)), {}).get(str(src_ip))
        if first is None:
            return False
        return first < log.event_time

    def deviations_for(self, log: NormalizedLog) -> list[dict[str, Any]]:
        """单条日志的基线偏离证据（9 字段契约）。"""
        cache_key = str(getattr(log, "event_id", "") or "")
        if cache_key and cache_key in self._cache:
            return list(self._cache[cache_key])

        from src.ueba.deviation import evaluate_deviations, load_user_context

        user_context = load_user_context(
            self,
            log.tenant_id,
            log.user_id,
            log.event_time,
        )
        deviations = [item.to_dict() for item in evaluate_deviations(log, user_context)]
        if cache_key:
            if len(self._cache) > 20000:
                self._cache.clear()
            self._cache[cache_key] = deviations
        return list(deviations)


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


class ContextRegistry:
    """加载一次，反复复用。无配置文件时退化为「无窗口、无白名单」。"""

    def __init__(
        self,
        config_dir: Path | str | None = None,
        baseline_provider: UEBABaselineProvider | None = None,
    ) -> None:
        base = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
        self._provider = baseline_provider
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
        deviations: list[dict[str, Any]] = []
        baseline_available = False
        seen_source: bool | None = None
        if self._provider is not None:
            deviations = self._provider.deviations_for(log)
            baseline_available = self._provider.has_baseline(log)
            seen_source = self._provider.seen_source(log)
        return DetectionContext(
            maintenance_window=self.in_maintenance_window(log),
            allowlisted_context=self.is_allowlisted(log),
            baseline_deviations=deviations,
            baseline_available=baseline_available,
            seen_source=seen_source,
        )

    def is_critical_asset(self, log: NormalizedLog) -> bool:
        meta = self.asset_of(log) or {}
        return str(meta.get("criticality", "")).lower() == "critical"
