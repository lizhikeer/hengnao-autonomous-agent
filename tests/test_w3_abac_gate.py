"""W3：Pre-flight ABAC 网关（策略加载 + check_action）拦截回归。

覆盖任务要求的四类拦截：forbidden_actions、allowlist（ips/assets/users）、
target_types 越界、缺失证据；另含别名归一化、none 放行、策略缺失 fail-closed
与"枚举以 YAML 为唯一权威"的守卫用例。

全部用例直接读真实 ``config/``（response-policy.yaml 是唯一权威枚举），不 mock 策略；
fail-closed 用例通过 ``SECLOG_CONFIG_DIR`` 指向临时目录构造缺失场景。
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
import yaml

from operations.response_executor import (
    ALLOWED,
    BLOCKED_BY_POLICY,
    check_action,
    load_policy,
    reset_cache,
)

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config"

EVIDENCE = ["LOG-20261117-0001"]
ATTACKER_IP = "198.51.100.23"  # 台账外的攻击源，不命中任何白名单


@pytest.fixture(autouse=True)
def _fresh_policy_cache():
    """策略缓存是进程内单例，用例之间必须隔离（尤其改 SECLOG_CONFIG_DIR 的用例）。"""
    reset_cache()
    yield
    reset_cache()


def _assert_blocked(result, code: str) -> str:
    allowed, reason = result
    assert allowed is False
    assert reason.startswith(BLOCKED_BY_POLICY)
    assert code in reason
    return reason


# ---------------------------------------------------------------------------
# 1. forbidden_actions 硬拦截
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("action", ["delete_data", "shutdown_host", "modify_firewall_rule"])
def test_forbidden_actions_blocked(action):
    """禁止动作即使带齐证据、目标合法也必须拦截，且定性为 forbidden 而非 unknown。"""
    reason = _assert_blocked(
        check_action(action, "web", ATTACKER_IP, "", EVIDENCE), "forbidden_action"
    )
    assert action in reason


# ---------------------------------------------------------------------------
# 2. 唯一权威枚举
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("action", ["reboot_server", "isolate_host", ""])
def test_unknown_action_blocked(action):
    """未在 response-policy.yaml 登记的动作一律拒绝。"""
    _assert_blocked(check_action(action, "web", ATTACKER_IP, "", EVIDENCE), "unknown_action")


def test_action_enum_comes_from_yaml():
    """枚举必须与 YAML 完全一致，防止代码里私藏第二份动作清单。"""
    doc = yaml.safe_load((CONFIG / "response-policy.yaml").read_text(encoding="utf-8"))
    policy = load_policy()
    assert set(policy["actions"]) == set(doc["actions"])
    assert policy["aliases"]["rate_limit_ip"] == "rate_limit"
    assert policy["aliases"]["throttle_ip"] == "rate_limit"


@pytest.mark.parametrize("alias", ["rate_limit_ip", "throttle_ip"])
def test_alias_normalized_before_check(alias):
    """知识卡别名受理前归一化到权威键（config/README.md 硬规则 1）。"""
    allowed, reason = check_action(alias, "web", ATTACKER_IP, "", EVIDENCE)
    assert allowed is True
    assert reason == ALLOWED


# ---------------------------------------------------------------------------
# 3. allowlist：ips / assets / users（按 scope 精确匹配）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "target_ip,action",
    [
        ("10.0.0.40", "rate_limit"),          # 备份主机，scope=全部动作
        ("127.0.0.1", "block_ip"),            # 本机回环，scope=全部动作
        ("10.0.0.77", "block_ip_short_term"), # 授权扫描器，scope 含短时封禁
        ("10.0.0.77", "rate_limit"),
    ],
)
def test_allowlist_ip_blocked(target_ip, action):
    _assert_blocked(
        check_action(action, "web", target_ip, "", EVIDENCE), "allowlist_ip"
    )


def test_allowlist_ip_scope_respected():
    """10.0.0.77 的豁免 scope 不含 isolate_account：该动作不因此 IP 被拦。"""
    allowed, reason = check_action("isolate_account", "web", "10.0.0.77", "scanner_svc", EVIDENCE)
    assert allowed is True
    assert reason == ALLOWED


@pytest.mark.parametrize("action", ["block_ip", "block_ip_short_term"])
def test_allowlist_asset_db_core_blocked(action):
    """db-core-01（10.0.0.30）命中资产白名单；allowlist 先于 target_types 定性。"""
    reason = _assert_blocked(check_action(action, "database", "10.0.0.30", "", EVIDENCE), "allowlist_asset")
    assert "db-core-01" in reason


@pytest.mark.parametrize("user", ["ops_zhang", "ops_li", "ops"])
def test_allowlist_user_ops_blocked(user):
    """ops_* 通配与精确 ops 都命中账号白名单，isolate_account 在其 scope 内。"""
    reason = _assert_blocked(
        check_action("isolate_account", "web", ATTACKER_IP, user, EVIDENCE), "allowlist_user"
    )
    assert user in reason


def test_allowlist_user_scope_respected():
    """ops_* 的豁免 scope 只有 isolate_account：封禁运维账号来源 IP 不受该条保护。"""
    allowed, reason = check_action("block_ip", "web", ATTACKER_IP, "ops_zhang", EVIDENCE)
    assert allowed is True
    assert reason == ALLOWED


# ---------------------------------------------------------------------------
# 4. target_types 越界
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("target_type", ["host", "database", "unknown", ""])
def test_block_ip_only_allows_web(target_type):
    """block_ip 仅允许 web 资产；缺失 target_type 也拒绝（无法核验目标）。"""
    _assert_blocked(
        check_action("block_ip", target_type, ATTACKER_IP, "", EVIDENCE),
        "target_type_not_allowed",
    )


def test_target_type_within_policy_allowed():
    """block_ip_short_term / rate_limit 允许 web+host，按 YAML 放行。"""
    for action in ("block_ip_short_term", "rate_limit"):
        for target_type in ("web", "host"):
            allowed, reason = check_action(action, target_type, ATTACKER_IP, "", EVIDENCE)
            assert allowed is True, (action, target_type, reason)
            assert reason == ALLOWED


# ---------------------------------------------------------------------------
# 5. 缺失证据
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("action", ["block_ip", "block_ip_short_term", "rate_limit", "isolate_account"])
@pytest.mark.parametrize("evidence", [[], None, ["", "   "]])
def test_missing_evidence_blocked(action, evidence):
    """requires_evidence=true 的动作缺证据：BLOCKED_BY_POLICY 且原因含 missing_evidence。"""
    reason = _assert_blocked(
        check_action(action, "web", ATTACKER_IP, "", evidence), "missing_evidence"
    )
    assert "missing_evidence" in reason


def test_evidence_string_form_accepted():
    """兼容逗号分隔字符串形式的证据 ID。"""
    allowed, reason = check_action("rate_limit", "web", ATTACKER_IP, "", "LOG-1, LOG-2")
    assert allowed is True
    assert reason == ALLOWED


# ---------------------------------------------------------------------------
# 6. 放行路径与 none
# ---------------------------------------------------------------------------
def test_none_requires_no_evidence_or_target():
    """none 无副作用：不要求证据与目标类型（YAML requires_evidence=false）。"""
    allowed, reason = check_action("none")
    assert allowed is True
    assert reason == ALLOWED


def test_high_risk_action_passes_gate_pending_approval():
    """网关只做策略预检：block_ip 带证据、web 目标即放行，审批是下游层职责。"""
    allowed, reason = check_action("block_ip", "web", ATTACKER_IP, "", EVIDENCE)
    assert allowed is True
    assert reason == ALLOWED


# ---------------------------------------------------------------------------
# 7. fail-closed 与配置热加载
# ---------------------------------------------------------------------------
def test_missing_policy_fail_closed(tmp_path, monkeypatch):
    """策略目录为空：不放行、不抛异常，返回 policy_unavailable。"""
    monkeypatch.setenv("SECLOG_CONFIG_DIR", str(tmp_path))
    _assert_blocked(
        check_action("rate_limit", "web", ATTACKER_IP, "", EVIDENCE), "policy_unavailable"
    )


def test_missing_assets_registry_fail_closed(tmp_path, monkeypatch):
    """只有策略没有台账：资产白名单无法核验，同样 fail-closed。"""
    shutil.copy(CONFIG / "response-policy.yaml", tmp_path / "response-policy.yaml")
    monkeypatch.setenv("SECLOG_CONFIG_DIR", str(tmp_path))
    _assert_blocked(
        check_action("rate_limit", "web", ATTACKER_IP, "", EVIDENCE), "policy_unavailable"
    )


def test_policy_reload_on_change(tmp_path, monkeypatch):
    """改 YAML 即生效：新增禁止动作后无需重启进程即可拦截。"""
    for name in ("response-policy.yaml", "assets.yaml"):
        shutil.copy(CONFIG / name, tmp_path / name)
    monkeypatch.setenv("SECLOG_CONFIG_DIR", str(tmp_path))

    allowed, _ = check_action("wipe_disk", "web", ATTACKER_IP, "", EVIDENCE)
    assert allowed is False  # 未登记动作先按 unknown 拒绝

    policy_file = tmp_path / "response-policy.yaml"
    doc = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
    doc["forbidden_actions"].append({"action": "wipe_disk", "reason": "测试新增禁止动作"})
    policy_file.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    # 显式推进 mtime，避免同一纳秒内写回导致缓存键不变
    stat = policy_file.stat()
    os.utime(policy_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))

    _assert_blocked(
        check_action("wipe_disk", "web", ATTACKER_IP, "", EVIDENCE), "forbidden_action"
    )