"""资产与账号上下文：**只读 `config/` 这一份配置**。

配置来源（PR #23 合入后为唯一权威，见 ``config/README.md``）：

* ``config/assets.yaml`` —— 资产台账（``asset_id``、IP、``criticality``、暴露面、日志来源）
* ``config/maintenance-windows.yaml`` —— 维护窗口（``days``/``start``/``end``/``never_exempt``）
* ``config/response-policy.yaml`` —— 白名单（IP / 账号通配 / 资产）

设计约束：

* **不再自带一份 JSON 台账**。第二周曾用 ``data/asset_context/asset_context.json``，
  与组长的 YAML 是两套配置（连 ``backup-01`` 的 IP 都不同），会各自生效；
  PR #23 之后统一到 ``config/``，旧 JSON 已删除。
* 只做**事实查询**，不给"该场景是否正常"的结论。
* 维护窗口按**日志时间**判断（``at_time``），时区取 YAML 声明的 ``Asia/Shanghai``。
* 资产查不到不再编造：返回 ``None``，由调用方判"未登记"。
* ``never_exempt`` 的语义由调查层保证：攻击事实优先于授权判断，
  窗口内的注入/上传照常告警（见 ``investigation._behavior_facts`` 的判定顺序）。

环境变量：``SECLOG_CONFIG_DIR`` 可指向另一份配置目录（默认项目根 ``config/``）。
"""

from __future__ import annotations

import fnmatch
import os
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"
CST = timezone(timedelta(hours=8), "Asia/Shanghai")


class AssetContextUnavailable(RuntimeError):
    def __init__(self, reason: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"资产上下文不可用：{reason}")
        self.reason = reason
        self.details = details or {}


_cache: dict[str, Any] = {"dir": None, "mtime": None, "data": None}


def config_path() -> Path:
    return Path(os.getenv("SECLOG_CONFIG_DIR", DEFAULT_CONFIG_DIR))


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import yaml  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - 依赖缺失属环境问题
        raise AssetContextUnavailable(
            "缺少 PyYAML，无法解析 config/*.yaml", details={"hint": "pip install pyyaml"}
        ) from exc
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise AssetContextUnavailable(
            f"{path.name} 解析失败：{type(exc).__name__}: {exc}", details={"path": str(path)}
        ) from exc
    if not isinstance(data, dict):
        raise AssetContextUnavailable(f"{path.name} 根节点必须是对象", details={"path": str(path)})
    return data


def _load() -> dict[str, Any]:
    base = config_path()
    assets_file = base / "assets.yaml"
    if not assets_file.exists():
        raise AssetContextUnavailable(
            f"资产台账不存在：{assets_file}",
            details={"config_dir": str(base), "hint": "SECLOG_CONFIG_DIR"},
        )
    mtime = assets_file.stat().st_mtime
    if _cache["data"] is not None and _cache["dir"] == str(base) and _cache["mtime"] == mtime:
        return _cache["data"]

    assets_doc = _load_yaml(assets_file)
    windows_doc = _load_yaml(base / "maintenance-windows.yaml")
    policy_doc = _load_yaml(base / "response-policy.yaml")

    data = {
        "assets": {a["asset_id"]: a for a in assets_doc.get("assets", []) if a.get("asset_id")},
        "windows": windows_doc.get("windows", []),
        "timezone": windows_doc.get("timezone", "Asia/Shanghai"),
        "allow_ips": (policy_doc.get("allowlist") or {}).get("ips", []),
        "allow_users": (policy_doc.get("allowlist") or {}).get("users", []),
        "allow_assets": (policy_doc.get("allowlist") or {}).get("assets", []),
        "actions": list((policy_doc.get("actions") or {}).keys()),
        "version": assets_doc.get("version"),
        "updated": assets_doc.get("updated"),
    }
    _cache.update({"dir": str(base), "mtime": mtime, "data": data})
    return data


def reset_cache() -> None:
    _cache.update({"dir": None, "mtime": None, "data": None})


# ---------------------------------------------------------------------------
# 时间与窗口
# ---------------------------------------------------------------------------


def _tz():
    try:
        from zoneinfo import ZoneInfo  # noqa: PLC0415

        return ZoneInfo(_load()["timezone"])
    except Exception:  # 缺 tzdata 时退化为固定 UTC+8（中国无夏令时）
        return CST


def _parse_at(at_time: Optional[str]) -> Optional[datetime]:
    if not at_time:
        return None
    text = str(at_time).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _match_window(
    windows: list[dict[str, Any]], at_time: Optional[str]
) -> tuple[Optional[bool], Optional[dict[str, Any]]]:
    """返回 (是否在窗口内, 命中的窗口)。未给时间时返回 (None, None)。"""
    dt = _parse_at(at_time)
    if dt is None:
        return None, None
    local = dt.astimezone(_tz())
    weekday = local.strftime("%a").lower()[:3]
    for window in windows or []:
        days = [str(d).lower()[:3] for d in (window.get("days") or [])]
        if days and weekday not in days:
            continue
        try:
            start = dtime.fromisoformat(str(window.get("start", "00:00")))
            end = dtime.fromisoformat(str(window.get("end", "00:00")))
        except ValueError:
            continue
        if start <= local.time() <= end:
            return True, window
    return False, None


# ---------------------------------------------------------------------------
# 对外查询
# ---------------------------------------------------------------------------


def _find_asset(data: dict[str, Any], target: str) -> Optional[dict[str, Any]]:
    for asset in data["assets"].values():
        if target in (asset.get("asset_id"), asset.get("ip")):
            return asset
    return None


def get_asset_context(target: str, *, at_time: Optional[str] = None) -> Optional[dict[str, Any]]:
    """按 ``asset_id`` 或 IP 查资产；查不到返回 ``None``。"""
    data = _load()
    asset = _find_asset(data, target)
    if asset is None:
        return None

    asset_id = asset.get("asset_id")
    windows = [w for w in data["windows"] if w.get("asset_id") == asset_id]
    in_window, matched = _match_window(windows, at_time)

    allow_asset = next((a for a in data["allow_assets"] if a.get("asset_id") == asset_id), None)
    return {
        "asset_id": asset_id,
        "hostname": asset.get("name") or asset_id,
        "ip": asset.get("ip"),
        "role": asset.get("type"),
        # 配置里叫 criticality，对外沿用 importance（API 契约历史字段）
        "importance": str(asset.get("criticality", "")).upper() or None,
        "criticality": asset.get("criticality"),
        "exposed_to_internet": asset.get("exposed_to_internet"),
        "owner": asset.get("owner"),
        "department": asset.get("department"),
        "services": asset.get("services") or [],
        "log_sources": asset.get("log_sources") or [],
        "blast_radius": asset.get("blast_radius"),
        "whitelisted": allow_asset is not None,
        "whitelist_reason": (allow_asset or {}).get("reason"),
        "whitelisted_ips": [i.get("ip") for i in data["allow_ips"] if i.get("ip")],
        "maintenance_windows": windows,
        # 时区在 YAML 顶层声明，窗口时间按它解释；单独返回便于核验
        "timezone": data["timezone"],
        "in_maintenance_window": in_window,
        "matched_window": matched,
        "evaluated_at": at_time,
        "config_source": "config/assets.yaml + maintenance-windows.yaml + response-policy.yaml",
    }


def get_user_profile(user: str) -> Optional[dict[str, Any]]:
    """按账号查授权信息。命中 ``allowlist.users`` 的通配规则才算已登记。

    配置里没有账号台账，只有白名单；因此这里只回答"这个账号是否被授权"，
    不编造活跃时段等画像字段（缺就留空，不猜）。
    """
    data = _load()
    if not user:
        return None
    for rule in data["allow_users"]:
        pattern = rule.get("user", "")
        if pattern and fnmatch.fnmatch(user, pattern):
            # 这里要区分两件事，混用会得出错误结论：
            # * **处置豁免**（allowlist）：表示"不自动隔离/不自动封禁"，是执行侧的豁免；
            # * **行为授权范围**：账号能从哪些来源、对哪些资产做什么，是判断"是否正常运维"
            #   的依据。当前 config/ 只有前者，没有后者。
            return {
                "user": user,
                "account_type": "legit_operator",
                "allowlisted": True,
                "disposition_exempt": True,
                "matched_rule": pattern,
                "allowlist_reason": rule.get("reason"),
                "allowlist_scope": rule.get("scope"),
                # 行为授权范围是否由配置提供：目前没有，必须如实标 false，
                # 否则调用方会把"豁免名单"当成"授权清单"。
                "source_scope_provided": False,
                "asset_scope_provided": False,
                "authorization_source": (
                    "config/response-policy.yaml#allowlist.users（仅处置豁免；"
                    "未提供账号-来源/账号-资产授权范围）"
                ),
                "config_source": "config/response-policy.yaml#allowlist.users",
            }
    return None


def list_entities() -> dict[str, Any]:
    data = _load()
    return {
        "assets": sorted(data["assets"].keys()),
        "users": [r.get("user") for r in data["allow_users"]],
        "hosts": sorted({a.get("ip") for a in data["assets"].values() if a.get("ip")}),
    }


def health() -> dict[str, Any]:
    try:
        data = _load()
    except AssetContextUnavailable as exc:
        return {"available": False, "reason": exc.reason, "config_dir": str(config_path())}
    return {
        "available": True,
        "config_dir": str(config_path()),
        "version": data.get("version"),
        "updated": data.get("updated"),
        "assets": len(data["assets"]),
        "windows": len(data["windows"]),
        "allowlist_ips": len(data["allow_ips"]),
        "allowlist_users": len(data["allow_users"]),
        "actions": data["actions"],
    }
