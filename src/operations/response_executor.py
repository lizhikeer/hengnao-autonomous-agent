"""恒脑自主安全智能体 —— 受控处置执行器：策略加载 + Pre-flight ABAC 网关 + 处置状态机。

分层（W3）：
    网关层（``load_policy`` / ``check_action``）—— 只回答"这个动作能不能受理"，
    ``allowed=True`` 仅表示策略预检通过，不产生任何副作用。

    状态机层（``evaluate_action`` / ``approve`` / ``reject``）—— 在网关之上决定处置去向：
        * 决策 ``none``                                   → ``NO_ACTION``（不落盘、无副作用）；
        * 低危（``risk: low``）且 ``auto_execute: true``   → ``EXECUTED``，
          并追加一行执行审计到 ``data/state/executed_enforcements.jsonl``；
        * 其余（高危 / 不允许自动执行 / 未知风险）         → ``PENDING_APPROVAL``，
          生成审批单，等待 ``approve`` / ``reject``；
        * 网关拦截（``allowed=False``）                    → ``BLOCKED``（fail-closed，不落盘）。

    审批单必须带齐 ``response-policy.yaml`` 的 ``approval.required_fields``（6 项），
    缺任何一项 ``approve`` 直接拒绝；``on_timeout: reject`` 时超时未审批自动按拒绝处理。

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
``SECLOG_STATE_DIR`` 可指向另一份审计落盘目录（默认项目根 ``data/state/``）。
"""

from __future__ import annotations

import fnmatch
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "PolicyLoadError",
    "ApprovalError",
    "load_policy",
    "check_action",
    "reset_cache",
    "BLOCKED_BY_POLICY",
    "ALLOWED",
    "NO_ACTION",
    "EXECUTED",
    "PENDING_APPROVAL",
    "REJECTED",
    "BLOCKED",
    "APPROVED",
    "append_enforcement_record",
    "evaluate_action",
    "approve",
    "reject",
    "expire_pending",
    "reset_pending",
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_STATE_DIR = PROJECT_ROOT / "data" / "state"
POLICY_FILENAME = "response-policy.yaml"
ASSETS_FILENAME = "assets.yaml"
ENFORCEMENTS_FILENAME = "executed_enforcements.jsonl"

#: 拦截原因的统一前缀；放行时为 ``ALLOWED``
BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
ALLOWED = "ALLOWED"

# --- 状态机状态（终态：NO_ACTION / REVOKED / REJECTED / BLOCKED）---
NO_ACTION = "NO_ACTION"
EXECUTED = "EXECUTED"
PENDING_APPROVAL = "PENDING_APPROVAL"
REJECTED = "REJECTED"
BLOCKED = "BLOCKED"
#: 生效期已满、由 ``sweep_expired_actions`` 自动解除。EXECUTED 不是终态，REVOKED 才是。
REVOKED = "REVOKED"

#: 审计事件的两种类型。``executed_enforcements.jsonl`` 是 append-only 的事件流，
#: 每条有效动作由「executed + revoked」两行表达，读侧按 ``action_id`` 折叠出当前生命周期。
EVENT_EXECUTED = "executed"
EVENT_REVOKED = "revoked"

#: 审批事件（审批单的审批结果，非处置终态）
APPROVED = "APPROVED"

#: 允许自动执行的风险等级：只有显式 low 才走自动执行，未登记风险一律降级为人工审批
_AUTO_EXECUTE_RISK = "low"

#: 审批单必填字段的兜底值——仅在策略缺 ``approval.required_fields`` 时使用，
#: 保证"校验 6 项必填"不会因为配置缺失而退化成"零校验"（fail-closed）。
_DEFAULT_REQUIRED_FIELDS = (
    "case_id",
    "action",
    "target_ip",
    "evidence_log_ids",
    "expected_effect",
    "rollback_plan",
)

#: 白名单条目 scope 的"全部动作"写法（YAML 中的中文常量）
_ALL_ACTIONS_SCOPE = "全部动作"


class PolicyLoadError(RuntimeError):
    """策略配置缺失或非法。网关层捕获后 fail-closed 拒绝，绝不带病放行。"""


class ApprovalError(ValueError):
    """审批单非法（缺必填字段 / 状态不允许审批 / 审批人缺失）。"""


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

    # --- 审批要求：状态机在 PENDING_APPROVAL 时按本节校验审批单 ---
    approval_raw = policy_doc.get("approval") or {}
    if not isinstance(approval_raw, dict):
        raise PolicyLoadError("approval 必须是对象")
    required_raw = approval_raw.get("required_fields") or list(_DEFAULT_REQUIRED_FIELDS)
    if not isinstance(required_raw, list) or not required_raw:
        raise PolicyLoadError("approval.required_fields 必须是非空列表")
    required_fields = []
    for field in required_raw:
        field = str(field).strip()
        if field:
            required_fields.append(field)
    if not required_fields:
        raise PolicyLoadError("approval.required_fields 不能全为空白")
    timeout_raw = str(approval_raw.get("on_timeout") or "reject").strip().lower()
    # 超时只允许"拒绝"：自动放行等于让"无人处理"变成"默认同意"，必须有审批人身份
    if timeout_raw != "reject":
        raise PolicyLoadError(
            f"approval.on_timeout 目前只支持 reject，实际 {timeout_raw}（自动放行不可接受）"
        )
    approval = {
        "channel": str(approval_raw.get("channel") or ""),
        "required_fields": required_fields,
        "on_timeout": timeout_raw,
    }

    return {
        "version": policy_doc.get("version"),
        "config_dir": str(base),
        "actions": actions,
        "aliases": aliases,
        "forbidden": forbidden,
        "allowlist": allowlist,
        "assets_by_ip": assets_by_ip,
        "approval": approval,
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


# ---------------------------------------------------------------------------
# 审计落盘：执行记录（JSONL，append-only）
# ---------------------------------------------------------------------------
def state_dir() -> Path:
    """审计落盘目录：默认项目根 ``data/state/``，可用 ``SECLOG_STATE_DIR`` 覆盖。"""
    return Path(os.getenv("SECLOG_STATE_DIR", DEFAULT_STATE_DIR))


def enforcement_log_path() -> Path:
    """执行审计文件。

    路径优先级：

    1. ``SECLOG_RESPONSE_DB``：与需求文档的环境变量名对齐，用于把状态文件
       指到显式位置（容器里通常指向持久化卷）；
    2. ``SECLOG_STATE_DIR`` + ``executed_enforcements.jsonl``：默认布局。

    本项目用 **append-only JSONL** 而不是 SQLite 承载状态机：事件流天然可审计、
    可 diff、可手工核对，且不需要额外的事务与迁移。``SECLOG_RESPONSE_DB``
    只是路径覆盖，不会把内容变成数据库文件。
    """
    override = os.getenv("SECLOG_RESPONSE_DB", "").strip()
    if override:
        return Path(override)
    return state_dir() / ENFORCEMENTS_FILENAME


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _canonical_action(action: Any) -> str:
    """把动作名归一化到权威键（只读已加载策略，不触发二次校验）。"""
    raw = str(action or "").strip()
    try:
        policy = _load_cached()
    except PolicyLoadError:
        return raw
    return policy["aliases"].get(raw, raw)


def _target_of(target_ip: Any, target_user: Any) -> str:
    """审计里的 ``target``：优先 IP，其次账号；两者皆空表示无具体目标。"""
    ip = str(target_ip or "").strip()
    if ip:
        return ip
    return str(target_user or "").strip()


def append_enforcement_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """向 ``executed_enforcements.jsonl`` 追加一行 JSON，返回实际落盘的记录。

    append-only：不重写历史，不做去重，任何失败都向上抛——审计写不进去就不能算执行成功。
    """
    path = enforcement_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return record


def _build_record(
    *,
    action: str,
    target_type: str,
    target: str,
    evidence_log_ids: List[str],
    policy_reason: str,
    approved_by: Optional[str] = None,
    case_id: str = "",
    approval_id: str = "",
    ts: Optional[str] = None,
    action_id: str = "",
    executed_at: str = "",
    expires_at: str = "",
    max_duration_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    """执行审计记录：6 个必备字段 + 审批留痕 + 生命周期字段。

    生命周期三件套（``action_id`` / ``executed_at`` / ``expires_at``）是到期自动解除的依据：
    没有 ``expires_at`` 的记录不可被 sweep 命中，等价于"永久生效"，因此执行路径必须写全。
    """
    record: Dict[str, Any] = {
        "event": EVENT_EXECUTED,
        "ts": ts or _iso(_now()),
        "action": action,
        "target_type": target_type,
        "target": target,
        "evidence_log_ids": list(evidence_log_ids),
        "policy_reason": policy_reason,
    }
    if case_id:
        record["case_id"] = str(case_id)
    if approval_id:
        record["approval_id"] = str(approval_id)
    if approved_by:
        record["approved_by"] = str(approved_by)
    if action_id:
        record["action_id"] = str(action_id)
    if executed_at:
        record["executed_at"] = str(executed_at)
    if expires_at:
        record["expires_at"] = str(expires_at)
    if max_duration_minutes is not None:
        record["max_duration_minutes"] = int(max_duration_minutes)
    return record


# ---------------------------------------------------------------------------
# 状态机：NO_ACTION / EXECUTED / PENDING_APPROVAL / REJECTED / BLOCKED
# ---------------------------------------------------------------------------
#: 审批单有效期（分钟）：统一 30 分钟，不写死其他值；到期按 ``approval.on_timeout`` 处理
DEFAULT_APPROVAL_TIMEOUT_MINUTES = 30

#: 进程内待审批表 {approval_id: 审批单}。审批单本身是运行时状态，不落 jsonl；
#: 审计只记最终结果（执行记录含 approval_id / approved_by），避免出现两份真相。
_pending: Dict[str, Dict[str, Any]] = {}
_approval_seq = {"n": 0}
_action_seq = {"n": 0}


def reset_pending() -> None:
    """清空待审批表（测试隔离用；生产进程内不应调用）。"""
    _pending.clear()
    _approval_seq["n"] = 0
    _action_seq["n"] = 0


def _new_approval_id(now: datetime) -> str:
    _approval_seq["n"] += 1
    return f"APR-{now.strftime('%Y%m%d%H%M%S')}-{_approval_seq['n']:04d}"


def _new_action_id(now: datetime) -> str:
    """生效动作编号：sweep 与后置核验都靠它定位一条具体处置。"""
    _action_seq["n"] += 1
    return f"ACT-{now.strftime('%Y%m%d%H%M%S')}-{_action_seq['n']:04d}"


def _max_duration_minutes(action: str) -> int:
    """动作的最长生效时间（分钟）；策略缺失时返回 0 表示不自动解除。"""
    try:
        raw = _load_cached()["actions"][action].get("max_duration_minutes")
    except (PolicyLoadError, KeyError):
        return 0
    try:
        return max(0, int(raw or 0))
    except (TypeError, ValueError):
        return 0


def _required_fields() -> List[str]:
    """审批单必填字段：以策略 ``approval.required_fields`` 为准，策略不可用时用兜底 6 项。"""
    try:
        return list(_load_cached()["approval"]["required_fields"])
    except (PolicyLoadError, KeyError):
        return list(_DEFAULT_REQUIRED_FIELDS)


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _validate_approval_fields(order: Dict[str, Any]) -> List[str]:
    """校验必填字段，返回缺失/空白字段名列表（空列表表示通过）。"""
    missing: List[str] = []
    for field in _required_fields():
        if _is_blank(order.get(field)):
            missing.append(field)
    return missing


def evaluate_action(
    action: str,
    target_type: str = "",
    target_ip: str = "",
    target_user: str = "",
    evidence_log_ids: Any = None,
    *,
    case_id: str = "",
    timeout_minutes: float = DEFAULT_APPROVAL_TIMEOUT_MINUTES,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """处置决策入口：先过 ABAC 网关，再按风险/自动执行标记流转状态。

    返回 dict（状态见模块常量）：
        ``status``          NO_ACTION / EXECUTED / PENDING_APPROVAL / BLOCKED
        ``action``          归一化后的权威动作名（none 决策也是 ``none``）
        ``target_type`` / ``target`` / ``evidence_log_ids``  决策上下文
        ``policy_reason``   网关给出的原因（EXECUTED 时即 ``ALLOWED``）
        ``approval_id``     仅 PENDING_APPROVAL 提供，后续 approve/reject 的凭据
        ``deadline``        仅 PENDING_APPROVAL 提供（ISO8601 UTC）
        ``record``          仅 EXECUTED 提供，即已落盘的审计记录

    流转规则：
        * 网关拦截 → ``BLOCKED``：策略原因原样返回，**不落盘**（未执行就没有执行记录）；
        * ``none``  → ``NO_ACTION``：仅记录结论，不落盘；
        * ``risk: low`` 且 ``auto_execute: true`` → ``EXECUTED``：追加审计并返回；
        * 其余（high / auto_execute=false / 未知风险）→ ``PENDING_APPROVAL``。
          只有显式 low 才自动执行，任何"风险不明"都降级到人工，符合 fail-closed。
    """
    allowed, policy_reason = check_action(
        action, target_type, target_ip, target_user, evidence_log_ids
    )
    canonical = _canonical_action(action)
    evidence = _normalize_evidence_ids(evidence_log_ids)
    target = _target_of(target_ip, target_user)
    context = {
        "action": canonical,
        "target_type": str(target_type or "").strip(),
        "target": target,
        "evidence_log_ids": evidence,
        "policy_reason": policy_reason,
    }

    if not allowed:
        return {"status": BLOCKED, **context}

    if canonical == "none":
        return {"status": NO_ACTION, **context}

    try:
        rule = _load_cached()["actions"][canonical]
    except (PolicyLoadError, KeyError):
        # 网关已放行却取不到规则，说明策略在两次读盘之间变更；以"未知风险"转人工
        rule = {"risk": "unknown", "auto_execute": False}

    if rule["risk"] == _AUTO_EXECUTE_RISK and rule["auto_execute"]:
        moment = now or _now()
        duration = _max_duration_minutes(canonical)
        action_id = _new_action_id(moment)
        expires_at = _iso(moment + timedelta(minutes=duration)) if duration > 0 else ""
        record = _build_record(
            action=canonical,
            target_type=context["target_type"],
            target=target,
            evidence_log_ids=evidence,
            policy_reason=policy_reason,
            case_id=str(case_id or ""),
            ts=_iso(moment),
            action_id=action_id,
            executed_at=_iso(moment),
            expires_at=expires_at,
            max_duration_minutes=duration,
        )
        append_enforcement_record(record)
        return {
            "status": EXECUTED,
            **context,
            "record": record,
            "action_id": action_id,
            "expires_at": expires_at,
        }

    moment = now or _now()
    approval_id = _new_approval_id(moment)
    deadline = moment + timedelta(minutes=float(timeout_minutes))
    _pending[approval_id] = {
        "approval_id": approval_id,
        "status": PENDING_APPROVAL,
        "action": canonical,
        "target_type": context["target_type"],
        "target": target,
        "target_ip": str(target_ip or "").strip(),
        "target_user": str(target_user or "").strip(),
        "evidence_log_ids": evidence,
        "policy_reason": policy_reason,
        "risk": rule["risk"],
        "case_id": str(case_id or ""),
        "created_at": _iso(moment),
        "deadline": _iso(deadline),
        "deadline_at": deadline,
        "required_fields": _required_fields(),
    }
    return {
        "status": PENDING_APPROVAL,
        **context,
        "approval_id": approval_id,
        "deadline": _pending[approval_id]["deadline"],
    }


def _pending_or_raise(approval_id: str, now: Optional[datetime]) -> Dict[str, Any]:
    """取出待审批单；已超时则先按 ``on_timeout`` 结算，再拒绝本次审批操作。"""
    order = _pending.get(str(approval_id or "").strip())
    if order is None:
        raise ApprovalError(f"审批单不存在：{approval_id}")
    if order["status"] == PENDING_APPROVAL and (now or _now()) >= order["deadline_at"]:
        expire_pending(now=now)  # 先按 on_timeout=reject 结算，再拒绝本次审批操作
    if order["status"] != PENDING_APPROVAL:
        raise ApprovalError(f"审批单状态为 {order['status']}，不能重复审批：{order['approval_id']}")
    return order


def approve(
    approval_id: str,
    order: Dict[str, Any],
    approved_by: str,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """人工审批放行：校验 6 项必填字段 → 与待审批单比对 → 落盘执行审计。

    ``order`` 是审批人提交的审批单（对应 ``approval.required_fields``）：
        case_id / action / target_ip / evidence_log_ids / expected_effect / rollback_plan

    拒绝情形（抛 ``ApprovalError``，不产生任何执行记录）：
        * 必填字段缺失或全空白；
        * ``approved_by`` 为空（谁批的必须可追溯到人）；
        * 审批单不存在 / 已结算 / 已超时；
        * 审批单的 action 或 target_ip 与待审批单不一致（防止批 A 执行 B）。
    """
    if _is_blank(approved_by):
        raise ApprovalError("approve 必须提供 approved_by（审批人）")

    missing = _validate_approval_fields(order or {})
    if missing:
        raise ApprovalError(f"审批单缺少必填字段：{', '.join(missing)}")

    record_order = _pending_or_raise(approval_id, now)

    submitted_action = _canonical_action(order.get("action"))
    if submitted_action != record_order["action"]:
        raise ApprovalError(
            f"审批单动作 {submitted_action} 与待审批动作 {record_order['action']} 不一致"
        )
    submitted_ip = str(order.get("target_ip") or "").strip()
    if submitted_ip != record_order["target_ip"]:
        raise ApprovalError(
            f"审批单目标 {submitted_ip or '<空>'} 与待审批目标 "
            f"{record_order['target_ip'] or '<空>'} 不一致"
        )

    moment = now or _now()
    duration = _max_duration_minutes(record_order["action"])
    action_id = _new_action_id(moment)
    expires_at = _iso(moment + timedelta(minutes=duration)) if duration > 0 else ""
    record = _build_record(
        action=record_order["action"],
        target_type=record_order["target_type"],
        target=record_order["target"],
        evidence_log_ids=record_order["evidence_log_ids"],
        policy_reason=record_order["policy_reason"],
        approved_by=str(approved_by).strip(),
        case_id=str(order.get("case_id") or record_order.get("case_id") or ""),
        approval_id=record_order["approval_id"],
        ts=_iso(moment),
        action_id=action_id,
        executed_at=_iso(moment),
        expires_at=expires_at,
        max_duration_minutes=duration,
    )
    append_enforcement_record(record)

    record_order.update(
        {"status": APPROVED, "approved_by": record["approved_by"], "resolved_at": record["ts"]}
    )
    return {
        "status": EXECUTED,
        "approval_id": record_order["approval_id"],
        "record": record,
        "action_id": action_id,
        "expires_at": expires_at,
    }


def reject(
    approval_id: str,
    rejected_by: str,
    *,
    reason: str = "",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """人工拒批：审批单转 ``REJECTED``，不执行、不写执行审计（拒绝本身不是处置动作）。"""
    if _is_blank(rejected_by):
        raise ApprovalError("reject 必须提供 rejected_by（审批人）")
    order = _pending_or_raise(approval_id, now)
    moment = _iso(now or _now())
    order.update(
        {
            "status": REJECTED,
            "rejected_by": str(rejected_by).strip(),
            "reject_reason": str(reason or "").strip(),
            "resolved_at": moment,
        }
    )
    return {
        "status": REJECTED,
        "approval_id": order["approval_id"],
        "action": order["action"],
        "target": order["target"],
        "rejected_by": order["rejected_by"],
        "reason": order["reject_reason"],
        "resolved_at": moment,
    }


def expire_pending(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """结算所有到期审批单，按 ``approval.on_timeout`` 处理，返回本次结算的单据。

    只处理 ``status == PENDING_APPROVAL`` 且 ``deadline_at <= now`` 的单子，
    统一转 ``REJECTED``（``rejected_by=SYSTEM_TIMEOUT``，``reject_reason`` 以 timeout 开头）：
    绝不因为"没人处理"就默认放行，也不伪造审批人。
    """
    moment = now or _now()
    settled: List[Dict[str, Any]] = []
    for order in _pending.values():
        if order["status"] != PENDING_APPROVAL or moment < order["deadline_at"]:
            continue
        order.update(
            {
                "status": REJECTED,
                "rejected_by": "SYSTEM_TIMEOUT",
                "reject_reason": "timeout: 审批超时，按 approval.on_timeout=reject 自动拒绝",
                "resolved_at": _iso(moment),
            }
        )
        settled.append(order)
    return settled


# ---------------------------------------------------------------------------
# 到期自动解除：EXECUTED -> REVOKED
# ---------------------------------------------------------------------------
def read_enforcement_records() -> List[Dict[str, Any]]:
    """读取全部审计事件（append-only 文件，按写入顺序）。

    坏行（手工编辑、磁盘截断）直接跳过而不是整份报错——审计是旁路证据，
    不能因为一行损坏就让整个回滚引擎停摆；跳过数由调用方通过长度差自行核对。
    """
    path = enforcement_log_path()
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _fold_lifecycle(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """把事件流按 ``action_id`` 折叠成「当前生命周期快照」。

    没有 ``action_id`` 的历史记录（W3 之前的旧格式）无法被可靠地关联到撤销事件，
    因此不参与折叠——宁可少回滚，也不能把两条不同处置混成一条。
    """
    folded: Dict[str, Dict[str, Any]] = {}
    for record in records:
        action_id = str(record.get("action_id") or "").strip()
        if not action_id:
            continue
        if record.get("event") == EVENT_REVOKED:
            current = folded.get(action_id)
            if current is not None:
                current.update(
                    {
                        "lifecycle": REVOKED,
                        "revoked_at": record.get("ts"),
                        "revoke_reason": record.get("revoke_reason", ""),
                    }
                )
            continue
        folded[action_id] = {**record, "lifecycle": EXECUTED}
    return folded


def _parse_iso(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def list_actions(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """返回全部处置动作的当前视图，附带 ``expired`` 判定（只读，不落盘）。"""
    moment = now or _now()
    folded = _fold_lifecycle(read_enforcement_records())
    view: List[Dict[str, Any]] = []
    for action_id, record in folded.items():
        expires_at = _parse_iso(record.get("expires_at"))
        view.append(
            {
                **record,
                "action_id": action_id,
                "expired": bool(
                    record["lifecycle"] == EXECUTED and expires_at and moment >= expires_at
                ),
            }
        )
    view.sort(key=lambda item: (str(item.get("executed_at") or item.get("ts") or ""), item["action_id"]))
    return view


def sweep_expired_actions(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """扫描已到期且仍生效的处置，自动解除并流转为 ``REVOKED``。

    只处理 ``lifecycle == EXECUTED`` 且 ``now >= expires_at`` 的动作：
    没有 ``expires_at`` 的动作不在此列——「没写到期的」应当被当成配置缺陷去修，
    而不是被悄悄解除（那会让一次本该持续的封禁提前失效）。

    解除动作本身也写一条 ``event=revoked`` 的审计，保持 append-only：
    历史上"曾经封过"和"何时解除"都可追溯。
    """
    moment = now or _now()
    swept: List[Dict[str, Any]] = []
    for action_id, record in _fold_lifecycle(read_enforcement_records()).items():
        if record["lifecycle"] != EXECUTED:
            continue
        expires_at = _parse_iso(record.get("expires_at"))
        if expires_at is None or moment < expires_at:
            continue
        event = {
            "event": EVENT_REVOKED,
            "ts": _iso(moment),
            "action_id": action_id,
            "action": record.get("action", ""),
            "target": record.get("target", ""),
            "target_type": record.get("target_type", ""),
            "policy_reason": "AUTO_REVOKE: 到达 expires_at 自动解除",
            "revoke_reason": "expired",
            "expires_at": record.get("expires_at", ""),
        }
        for key in ("case_id", "approval_id"):
            if record.get(key):
                event[key] = record[key]
        append_enforcement_record(event)
        swept.append(
            {
                **record,
                "action_id": action_id,
                "lifecycle": REVOKED,
                "revoked_at": event["ts"],
                "revoke_reason": "expired",
            }
        )
    return swept


# ---------------------------------------------------------------------------
# 后置核验
# ---------------------------------------------------------------------------
#: 视为"仍然在被攻击"的状态码：4xx 说明探测被拒但攻击者仍在尝试，5xx 说明已打穿。
_MALICIOUS_STATUS = frozenset({400, 401, 403, 404, 405, 500, 502, 503})


def _request_status(log: Dict[str, Any]) -> int:
    try:
        return int(log.get("status_code") or 0)
    except (TypeError, ValueError):
        return 0


def run_post_check(
    action_id: str,
    recent_logs: Optional[List[Dict[str, Any]]] = None,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """对一条已执行处置做后置核验，输出两类结论。

    * ``effect_verification``：目标是否还被恶意请求打——目标是封禁/限速对象，
      它的请求量归零或被拒（4xx/5xx）即视为"攻击未继续成功"；
    * ``business_impact``：非目标流量是否出现异常 5xx——误伤非目标才是真事故。

    ``recent_logs`` 由调用方提供（处置后的观测窗口）。**不在这里访问 ClickHouse**：
    执行器保持纯函数式，便于离线复现与单测。
    """
    folded = _fold_lifecycle(read_enforcement_records())
    record = folded.get(str(action_id or "").strip())
    if record is None:
        raise ApprovalError(f"找不到处置动作：{action_id}")

    target = str(record.get("target") or "").strip()
    logs = [item for item in (recent_logs or []) if isinstance(item, dict)]
    target_logs = [
        item for item in logs if target and target in (item.get("src_ip"), item.get("dest_ip"))
    ]
    other_logs = [item for item in logs if item not in target_logs]
    target_errors = [item for item in target_logs if _request_status(item) in _MALICIOUS_STATUS]
    other_errors = [item for item in other_logs if _request_status(item) >= 500]

    effect_ok = len(target_errors) == 0
    impact_ok = len(other_errors) == 0
    return {
        "action_id": record.get("action_id"),
        "action": record.get("action", ""),
        "target": target,
        "target_type": record.get("target_type", ""),
        "lifecycle": record["lifecycle"],
        "checked_at": _iso(now or _now()),
        "effect_verification": {
            "post_check": "effect_verification",
            "target_requests": len(target_logs),
            "malicious_requests": len(target_errors),
            "passed": effect_ok,
            "detail": (
                f"目标 {target or '<未指定>'} 在观测窗口内无异常请求，攻击已停止"
                if effect_ok
                else f"目标 {target} 仍有 {len(target_errors)} 条异常请求，处置未完全生效"
            ),
        },
        "business_impact": {
            "post_check": "business_impact",
            "non_target_requests": len(other_logs),
            "server_errors": len(other_errors),
            "passed": impact_ok,
            "detail": (
                "非目标业务未出现 5xx，未观察到误伤"
                if impact_ok
                else f"非目标业务出现 {len(other_errors)} 条 5xx，疑似误伤，需人工复核"
            ),
        },
    }


# ---------------------------------------------------------------------------
# 只读查询（供 API 拼审批单与台账，均不改变状态）
# ---------------------------------------------------------------------------
def get_pending(approval_id: str) -> Optional[Dict[str, Any]]:
    """按编号取待审批单的副本；不存在返回 ``None``。

    返回副本而不是引用：调用方拼审批单时不应意外改到状态机内部记录。
    """
    order = _pending.get(str(approval_id or "").strip())
    if order is None:
        return None
    return {key: value for key, value in order.items() if key != "deadline_at"}


def list_pending(now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """全部仍处于 PENDING_APPROVAL 的审批单，附带 ``expired`` 只读判定。

    这里**不结算**超时单——结算由 ``expire_pending`` 显式触发，
    避免"查一下台账"这种只读操作产生状态副作用。
    """
    moment = now or _now()
    items: List[Dict[str, Any]] = []
    for order in _pending.values():
        if order["status"] != PENDING_APPROVAL:
            continue
        items.append(
            {
                **{key: value for key, value in order.items() if key != "deadline_at"},
                "expired": moment >= order["deadline_at"],
            }
        )
    items.sort(key=lambda item: str(item.get("created_at") or ""))
    return items
