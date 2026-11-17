"""恒脑自主安全智能体 —— 受控处置执行器：策略加载 + Pre-flight ABAC 网关。

职责边界（W3 分层，本文件当前**只实现网关层，不含状态机**）：
    1. 加载 ``config/response-policy.yaml`` 作为**唯一权威动作枚举**（config/README.md 硬规则 1），
       受理前先做别名归一化（``rate_limit_ip`` / ``throttle_ip`` → ``rate_limit``）；
    2. ``check_action(action, target_type, target_ip, target_user, evidence_log_ids)``
       在处置受理前做 ABAC 预检，返回 ``(allowed, policy_reason)``；
    3. 拦截四类越权：
       - ``forbidden_actions`` 命中（永远不执行，只能转人工）；
       - ``allowlist`` 命中（ips / assets / users，按条目 ``scope`` 精确匹配动作）；
       - ``target_types`` 越界（如 ``block_ip`` 仅允许 web 资产）；
       - 缺证据（动作 ``requires_evidence: true`` 而 ``evidence_log_ids`` 为空）。

**不在本层做的事**：状态流转（NO_ACTION / EXECUTED / PENDING_APPROVAL）、审批单校验、
执行下发与到期自动解除。``allowed=True`` 仅表示"策略预检通过、可以受理"，
``auto_execute: false`` 的高危动作仍须由下游审批层放行，本网关不代替审批。

配置来源：
    * ``config/response-policy.yaml`` —— 动作枚举 / 禁止动作 / 白名单（唯一权威，必需）；
    * ``config/assets.yaml`` —— 资产台账（必需，辅助）：``check_action`` 只拿到 ``target_ip``，
      而白名单 ``assets`` 条目按 ``asset_id`` 登记（如 ``db-core-01``），
      因此用台账把 IP 解析成资产再匹配，不自造第二份资产映射（config/README.md 硬规则 2）。

失败语义（fail-closed）：
    策略文件缺失 / 解析失败 / 结构非法时，``check_action`` 不抛异常、不放行，
    返回 ``(False, "BLOCKED_BY_POLICY:policy_unavailable:...")``；
    直接调用 ``load_policy`` 则抛 ``PolicyLoadError``。

``policy_reason`` 约定：
    * 放行：``ALLOWED``；
    * 拦截：``BLOCKED_BY_POLICY:<code>:<细节>``，code 取值：
      ``policy_unavailable`` / ``forbidden_action`` / ``unknown_action`` /
      ``allowlist_ip`` / ``allowlist_asset`` / ``allowlist_user`` /
      ``target_type_not_allowed`` / ``missing_evidence``。

环境变量：``SECLOG_CONFIG_DIR`` 可指向另一份配置目录（默认项目根 ``config/``，
与 ``src/api/asset_context.py`` 同一约定）。策略按文件 mtime 缓存，改配置即生效。
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "PolicyLoadError",
    "load_policy",
    "check_action",
    "reset_cache",
    "BLOCKED_BY_POLICY",
    "ALLOWED",
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"
POLICY_FILENAME = "response-policy.yaml"
ASSETS_FILENAME = "assets.yaml"

#: 拦截原因的统一前缀；放行时为 ``ALLOWED``
BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
ALLOWED = "ALLOWED"

#: 白名单条目 scope 的"全部动作"写法（YAML 中的中文常量）
_ALL_ACTIONS_SCOPE = "全部动作"


class PolicyLoadError(RuntimeError):
    """策略配置缺失或非法。网关层捕获后 fail-closed 拒绝，绝不带病放行。"""


def config_path() -> Path:
    """配置目录：默认项目根 ``config/``，可用 ``SECLOG_CONFIG_DIR`` 覆盖。"""
    return Path(os.getenv("SECLOG_CONFIG_DIR", DEFAULT_CONFIG_DIR))


# ---------------------------------------------------------------------------
# 策略加载（唯一权威枚举）
# ---------------------------------------------------------------------------
def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise PolicyLoadError(f"配置文件不存在：{path}")
    try:
        import yaml  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - 依赖缺失属环境问题
        raise PolicyLoadError(
            f"缺少 PyYAML，无法解析 {path.name}（pip install pyyaml）"
        ) from exc
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise PolicyLoadError(f"{path.name} 解析失败：{type(exc).__name__}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyLoadError(f"{path.name} 根节点必须是对象")
    return data


def _allowlist_entries(raw: Any, key: str, section: str) -> List[Dict[str, Any]]:
    """校验白名单某一节（ips/users/assets）：必须是对象列表且每条带主键。"""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PolicyLoadError(f"allowlist.{section} 必须是列表")
    entries: List[Dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict) or not entry.get(key):
            raise PolicyLoadError(f"allowlist.{section} 条目缺少 {key}：{entry!r}")
        entries.append(entry)
    return entries


def load_policy(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """解析并校验策略，返回归一化后的只读视图（每次调用都重新读盘，不走缓存）。

    返回结构：
        ``actions``      权威动作枚举 {动作名: 规则}（规则含 target_types / requires_evidence 等）
        ``aliases``      别名 → 权威动作名
        ``forbidden``    禁止动作 → 原因
        ``allowlist``    {"ips": [...], "users": [...], "assets": [...]}（保留 YAML 原条目）
        ``assets_by_ip`` IP → 资产台账条目（用于把 target_ip 解析成 asset_id）

    任何结构非法都抛 ``PolicyLoadError``：宁可拒绝受理，也不按猜测执行。
    """
    base = Path(config_dir) if config_dir is not None else config_path()
    policy_doc = _load_yaml(base / POLICY_FILENAME)
    assets_doc = _load_yaml(base / ASSETS_FILENAME)

    # --- 动作枚举：唯一权威，缺省值一律往"更严"的方向取 ---
    actions_raw = policy_doc.get("actions")
    if not isinstance(actions_raw, dict) or not actions_raw:
        raise PolicyLoadError("response-policy.yaml 缺少非空的 actions 枚举")
    actions: Dict[str, Dict[str, Any]] = {}
    aliases: Dict[str, str] = {}
    for name, rule in actions_raw.items():
        name = str(name)
        if not isinstance(rule, dict):
            raise PolicyLoadError(f"actions.{name} 必须是对象")
        target_types = rule.get("target_types") or []
        if not isinstance(target_types, list):
            raise PolicyLoadError(f"actions.{name}.target_types 必须是列表")
        actions[name] = {
            "risk": str(rule.get("risk") or "unknown"),
            "auto_execute": bool(rule.get("auto_execute", False)),
            # 未声明 requires_evidence 时按"需要证据"处理（fail-closed）
            "requires_evidence": bool(rule.get("requires_evidence", True)),
            "max_duration_minutes": rule.get("max_duration_minutes", 0),
            "target_types": [str(t) for t in target_types],
        }
        for alias in rule.get("aliases") or []:
            alias = str(alias).strip()
            if not alias:
                continue
            if alias in aliases and aliases[alias] != name:
                raise PolicyLoadError(f"别名 {alias} 同时指向 {aliases[alias]} 与 {name}")
            aliases[alias] = name
    for alias in aliases:
        if alias in actions:
            raise PolicyLoadError(f"别名 {alias} 与权威动作名冲突")

    # --- 禁止动作：Agent 可以提出，但永远不执行 ---
    forbidden_raw = policy_doc.get("forbidden_actions") or []
    if not isinstance(forbidden_raw, list):
        raise PolicyLoadError("forbidden_actions 必须是列表")
    forbidden: Dict[str, str] = {}
    for entry in forbidden_raw:
        if not isinstance(entry, dict) or not entry.get("action"):
            raise PolicyLoadError(f"forbidden_actions 条目缺少 action：{entry!r}")
        forbidden[str(entry["action"])] = str(entry.get("reason") or "")

    # --- 白名单：命中即不进入自动处置（保护性拦截），scope 决定覆盖哪些动作 ---
    allow_raw = policy_doc.get("allowlist") or {}
    if not isinstance(allow_raw, dict):
        raise PolicyLoadError("allowlist 必须是对象")
    allowlist = {
        "ips": _allowlist_entries(allow_raw.get("ips"), "ip", "ips"),
        "users": _allowlist_entries(allow_raw.get("users"), "user", "users"),
        "assets": _allowlist_entries(allow_raw.get("assets"), "asset_id", "assets"),
    }

    # --- 资产台账：IP → 资产，仅用于白名单 assets 匹配，不做第二份枚举 ---
    assets_raw = assets_doc.get("assets") or []
    if not isinstance(assets_raw, list):
        raise PolicyLoadError("assets.yaml 的 assets 必须是列表")
    assets_by_ip: Dict[str, Dict[str, Any]] = {}
    for asset in assets_raw:
        if isinstance(asset, dict) and asset.get("ip"):
            assets_by_ip[str(asset["ip"]).strip()] = asset

    return {
        "version": policy_doc.get("version"),
        "config_dir": str(base),
        "actions": actions,
        "aliases": aliases,
        "forbidden": forbidden,
        "allowlist": allowlist,
        "assets_by_ip": assets_by_ip,
    }


# --- 按 mtime 缓存：改配置即生效，测试可用 reset_cache() 强制重读 ---
_cache: Dict[str, Any] = {"key": None, "data": None}


def reset_cache() -> None:
    _cache.update({"key": None, "data": None})


def _load_cached() -> Dict[str, Any]:
    base = config_path()
    try:
        key = (
            str(base),
            (base / POLICY_FILENAME).stat().st_mtime_ns,
            (base / ASSETS_FILENAME).stat().st_mtime_ns,
        )
    except OSError:
        key = (str(base), None, None)
    if _cache["data"] is not None and _cache["key"] == key:
        return _cache["data"]
    data = load_policy(base)
    _cache.update({"key": key, "data": data})
    return data


# ---------------------------------------------------------------------------
# Pre-flight ABAC 网关
# ---------------------------------------------------------------------------
def _normalize_evidence_ids(value: Any) -> List[str]:
    """证据 ID 归一化：兼容 list/tuple/set 与逗号/分号分隔字符串，空白项一律丢弃。"""
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [
        chunk.strip()
        for chunk in str(value).replace(";", ",").split(",")
        if chunk.strip()
    ]


def _scope_covers(scope: Any, action: str) -> bool:
    """白名单条目的 scope 是否覆盖当前动作。

    ``全部动作``（或未写 scope）覆盖所有动作；列表只覆盖列出的动作；
    单个动作名字符串只覆盖该动作。scope 之外的动作不享受该条豁免。
    """
    if scope is None or scope == "" or scope == _ALL_ACTIONS_SCOPE:
        return True
    if isinstance(scope, (list, tuple, set)):
        return action in scope
    return str(scope) == action


def _match_allowlist(
    policy: Dict[str, Any], action: str, target_ip: str, target_user: str
) -> Optional[Tuple[str, str]]:
    """按 ips → assets → users 顺序匹配白名单，返回 (原因码, 细节) 或 None。

    assets 匹配先把 target_ip 经台账解析成 asset_id，再与白名单条目比对；
    users 支持通配（``ops_*``），用 fnmatchcase 保证大小写敏感的确定性匹配。
    """
    allow = policy["allowlist"]
    ip = str(target_ip or "").strip()

    for entry in allow["ips"]:
        if ip and str(entry.get("ip", "")).strip() == ip and _scope_covers(entry.get("scope"), action):
            detail = f"{ip}: {entry.get('reason') or ''}".rstrip(": ")
            return "allowlist_ip", detail

    if ip:
        asset = policy["assets_by_ip"].get(ip)
        asset_id = (asset or {}).get("asset_id")
        if asset_id:
            for entry in allow["assets"]:
                if entry.get("asset_id") == asset_id and _scope_covers(entry.get("scope"), action):
                    detail = f"{asset_id}({ip}): {entry.get('reason') or ''}".rstrip(": ")
                    return "allowlist_asset", detail

    user = str(target_user or "").strip()
    if user:
        for entry in allow["users"]:
            pattern = str(entry.get("user") or "")
            if pattern and fnmatch.fnmatchcase(user, pattern) and _scope_covers(entry.get("scope"), action):
                detail = f"{user}(规则 {pattern}): {entry.get('reason') or ''}".rstrip(": ")
                return "allowlist_user", detail

    return None


def check_action(
    action: str,
    target_type: str = "",
    target_ip: str = "",
    target_user: str = "",
    evidence_log_ids: Any = None,
) -> Tuple[bool, str]:
    """处置受理前的 Pre-flight ABAC 预检，返回 ``(allowed, policy_reason)``。

    参数：
        action:           处置动作名（支持 YAML 登记的别名，受理前归一化）；
        target_type:      目标资产类型（web / host / database / ...，见 assets.yaml）；
        target_ip:        目标 IP（白名单 ips 直接比对；assets 经台账解析成 asset_id）；
        target_user:      涉事账号（白名单 users 通配匹配，如 ops_*）；
        evidence_log_ids: 证据日志 ID 列表（也兼容逗号分隔字符串）。

    判定顺序（先命中先返回，保证原因可解释）：
        策略可用性 → 别名归一化 → forbidden_actions → 权威枚举 →
        allowlist(ips/assets/users，按 scope) → target_types → requires_evidence。

    语义说明：
        * ``target_types`` 为空的动作（如 ``none``）不产生资产副作用，跳过类型校验；
          其余动作缺 target_type 一律拒绝（无法核验目标就谈不上授权）。
        * 证据要求按 YAML 的 ``requires_evidence`` 逐动作执行：为 true 而证据为空
          （含 None / 全空白项）时拒绝，原因含 ``missing_evidence``。
        * ``allowed=True`` 只代表策略预检通过；高危动作的人工审批由下游层负责。
    """
    try:
        policy = _load_cached()
    except PolicyLoadError as exc:
        return False, f"{BLOCKED_BY_POLICY}:policy_unavailable:{exc}"

    raw = str(action or "").strip()
    canonical = policy["aliases"].get(raw, raw)
    if not canonical:
        return False, f"{BLOCKED_BY_POLICY}:unknown_action:动作名为空"

    # 1) 禁止动作硬拦截：不在枚举里也要先按"禁止"定性，而不是"未知"
    if canonical in policy["forbidden"] or raw in policy["forbidden"]:
        reason = policy["forbidden"].get(canonical) or policy["forbidden"].get(raw) or ""
        return False, f"{BLOCKED_BY_POLICY}:forbidden_action:{raw}: {reason}".rstrip()

    # 2) 唯一权威枚举：未登记的动作一律拒绝
    rule = policy["actions"].get(canonical)
    if rule is None:
        return False, f"{BLOCKED_BY_POLICY}:unknown_action:{raw}"

    # 3) 白名单：命中的源不进入自动处置（仍由上游生成线索供人判断）
    hit = _match_allowlist(policy, canonical, target_ip, target_user)
    if hit is not None:
        code, detail = hit
        return False, f"{BLOCKED_BY_POLICY}:{code}:{detail}"

    # 4) target_types 越界：防止误伤数据库/备份机等非授权类型资产
    allowed_types = rule["target_types"]
    if allowed_types:
        ttype = str(target_type or "").strip()
        if ttype not in allowed_types:
            shown = ttype or "<空>"
            return False, (
                f"{BLOCKED_BY_POLICY}:target_type_not_allowed:"
                f"{canonical} 仅允许 {'/'.join(allowed_types)}，实际 {shown}"
            )

    # 5) 证据门槛：缺证据一律拒绝
    if rule["requires_evidence"] and not _normalize_evidence_ids(evidence_log_ids):
        return False, f"{BLOCKED_BY_POLICY}:missing_evidence:{canonical} 必须携带 evidence_log_ids"

    return True, ALLOWED