"""第二周：上下文是否真的参与判定（授权匹配 / 窗口外 / 来源不符 / 上下文缺失）。

这组用例直接针对审查意见：
「get_context 虽被调用，但维护窗口、账号和白名单不参与最终判定，调用时也未传 at_time」
「不把有维护窗口或账号在白名单当作整个场景无条件正常的依据」
「上下文缺失时保留不确定性」「不能单凭 benign 标签判正常」。
"""

from __future__ import annotations

from typing import Any

from ai_engine.investigation import InvestigationSession

BASE_LOG = {
    "trace_id": "SCENE-1",
    "timestamp": "2026-10-29T18:10:00Z",
    "log_source": "auth_log",
    "src_ip": "10.0.0.66",
    "dest_ip": "10.0.0.15",
    "asset_id": "web-prod-01",
    "user": "ops_zhang",
    "action_or_method": "ssh_login",
    "uri_or_target": "/admin",
    "payload_summary": "login success",
    "status_code": 200,
    "user_agent": "OpenSSH_9.4",
}


def _log(log_id: str, **overrides: Any) -> dict[str, Any]:
    record = dict(BASE_LOG)
    record.update(overrides)
    record["log_id"] = log_id
    return record


def _profile(**overrides: Any) -> dict[str, Any]:
    data = {
        "user": "ops_zhang",
        "account_type": "legit_operator",
        "common_src_ips": ["10.0.0.66"],
        "allowed_assets": ["web-prod-01"],
    }
    data.update(overrides)
    return data


def _asset(**overrides: Any) -> dict[str, Any]:
    data = {
        "asset_id": "web-prod-01",
        "importance": "HIGH",
        "maintenance_windows": [
            {"kind": "weekly", "weekdays": ["Fri"], "start": "02:00", "end": "03:30", "timezone": "Asia/Shanghai"}
        ],
        "in_maintenance_window": True,
    }
    data.update(overrides)
    return data


def _session(logs: list[dict[str, Any]], *, profile=None, asset=None, total=None) -> InvestigationSession:
    """构造一个只返回给定日志与上下文的会话。"""

    def query_logs(_args: dict[str, Any]) -> dict[str, Any]:
        return {"meta": {"total": len(logs), "data_source": "fake"}, "items": logs}

    def get_context(_args: dict[str, Any]) -> dict[str, Any]:
        found = total if total is not None else (2 if (profile or asset) else 0)
        return {"meta": {"total": found}, "user_profile": profile, "asset_context": asset}

    def search_knowledge(_args: dict[str, Any]) -> dict[str, Any]:
        return {"meta": {"total": 0}, "items": []}

    def request_response(_args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "approval_required", "approval_id": "APPR-X", "executed": False}

    return InvestigationSession(
        case_id="CASE-CTX",
        seed_trace_id="SCENE-1",
        tools={
            "query_logs": query_logs,
            "get_context": get_context,
            "search_knowledge": search_knowledge,
            "request_response": request_response,
        },
    )


# ---------------------------------------------------------------------------
# 授权匹配：这是唯一可以判"正常"的情形
# ---------------------------------------------------------------------------


def test_authorized_operation_is_judged_normal_with_basis():
    session = _session([_log("L-1", attack_stage_hint="benign")], profile=_profile(), asset=_asset())
    final = session.run()

    assert final.attack_type == "none"
    assert final.is_malicious is False
    assert final.risk_level == "LOW"
    # 结论必须说明依据，而不是只写"未见异常"
    assert "维护窗口" in final.attack_chain_summary or "来源" in final.attack_chain_summary


def test_get_context_called_with_behavior_time():
    """必须把被调查行为的时间传下去，否则服务端无法判断维护窗口。"""
    session = _session([_log("L-1", attack_stage_hint="benign")], profile=_profile(), asset=_asset())
    session.run()

    calls = [c for c in session.calls if c.tool == "get_context"]
    assert calls, "应当调用过 get_context"
    assert calls[0].args.get("at_time"), "get_context 必须带 at_time"
    assert calls[0].args["at_time"].startswith("2026-10-29")


# ---------------------------------------------------------------------------
# 不匹配：允许弃权，但不能判"正常"
# ---------------------------------------------------------------------------


def test_outside_maintenance_window_is_not_normal():
    session = _session(
        [_log("L-1", attack_stage_hint="benign")],
        profile=_profile(),
        asset=_asset(
            maintenance_windows=[{"kind": "weekly", "weekdays": ["Mon"], "start": "02:00", "end": "03:30", "timezone": "Asia/Shanghai"}],
            in_maintenance_window=False,
        ),
    )
    final = session.run()

    assert final.attack_type != "none", "窗口外的运维行为不能直接判正常"
    assert final.attack_type == "insufficient_evidence"
    assert "维护窗口" in final.unknown_items
    assert final.requires_human_approval is True


def test_source_not_in_account_baseline_is_not_normal():
    session = _session(
        [_log("L-1", attack_stage_hint="benign", src_ip="203.0.113.200")],
        profile=_profile(),
        asset=_asset(),
    )
    final = session.run()

    assert final.attack_type == "insufficient_evidence"
    assert "来源 IP" in final.unknown_items


def test_unknown_account_is_not_normal():
    session = _session(
        [_log("L-1", attack_stage_hint="benign", user="intruder")],
        profile=None,
        asset=_asset(),
        total=1,
    )
    final = session.run()

    assert final.attack_type == "insufficient_evidence"
    assert "intruder" in final.unknown_items


def test_missing_context_keeps_uncertainty():
    """上下文整体不可用时，不能继续宣称"已完成防误报判断"。"""
    session = _session([_log("L-1", attack_stage_hint="benign")], profile=None, asset=None, total=0)
    final = session.run()

    assert final.attack_type == "insufficient_evidence"
    assert "上下文不可用" in final.unknown_items
    assert final.requires_human_approval is True


def test_window_not_evaluated_without_time_is_not_normal():
    """服务端没拿到行为时间（in_maintenance_window=None）时不能默认在窗口内。"""
    session = _session(
        [_log("L-1", attack_stage_hint="benign")],
        profile=_profile(),
        asset=_asset(
            maintenance_windows=[{"kind": "weekly", "weekdays": ["Mon"], "start": "02:00", "end": "03:30", "timezone": "Asia/Shanghai"}],
            in_maintenance_window=None,
        ),
    )
    final = session.run()

    assert final.attack_type == "insufficient_evidence"
    assert "维护窗口" in final.unknown_items


# ---------------------------------------------------------------------------
# 人工阶段标签不能被当成事实
# ---------------------------------------------------------------------------


def test_missing_stage_tags_are_not_treated_as_benign():
    """去掉 attack_stage_hint 后应视为"未知"，而不是"正常"。"""
    log = _log("L-1")
    log.pop("attack_stage_hint", None)
    session = _session([log], profile=_profile(), asset=_asset())
    final = session.run()

    assert final.attack_type == "insufficient_evidence", "无标签不能直接判正常"
    # 语义变化：现在统一表述为"未解释的行为"，并点出阶段标注值
    assert "未解释的行为" in final.unknown_items and "unknown" in final.unknown_items


def test_stage_label_alone_does_not_confirm_attack():
    """只有 exploitation 标签、但没有任何行为痕迹时，不确认攻击成立。"""
    logs = [
        _log(
            "L-1",
            attack_stage_hint="exploitation",
            src_ip="10.0.0.66",
            user=None,
            uri_or_target="/index.html",
            payload_summary=None,
            user_agent="Mozilla/5.0",
            status_code=200,
        )
    ]
    session = _session(logs, profile=_profile(), asset=_asset())
    final = session.run()

    assert final.is_malicious is False, "单凭阶段标签不能确认攻击"
    assert final.attack_type in {"insufficient_evidence", "none"}


def test_exploitation_with_external_source_is_confirmed():
    """阶段标签 + 外部攻击源 + 注入特征，才确认攻击成立。"""
    logs = [
        _log(
            "L-1",
            attack_stage_hint="exploitation",
            src_ip="198.51.100.23",
            user=None,
            uri_or_target="/admin/login.php",
            payload_summary="UNION SELECT sleep(5)",
            user_agent="sqlmap/1.7.2",
            status_code=200,
        )
    ]
    session = _session(logs, profile=_profile(), asset=_asset())
    final = session.run()

    assert final.is_malicious is True
    assert "SQL_Injection" in final.attack_type


# ---------------------------------------------------------------------------
# 反例回归（独立验收提出，修复前均判错）
# ---------------------------------------------------------------------------


def test_external_ip_without_attack_feature_is_not_confirmed():
    """反例 1：外部 IP + exploitation 标签 + 普通访问，不得确认攻击或建议封禁。

    修复前：is_malicious=true / Unknown_Attack / block_ip。
    外部地址只是来源属性，不是攻击成立的证据。
    """
    logs = [
        _log(
            "L-1",
            attack_stage_hint="exploitation",
            src_ip="198.51.100.23",
            user=None,
            uri_or_target="/index.html",
            payload_summary=None,
            user_agent="Mozilla/5.0",
            status_code=200,
        )
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.is_malicious is False
    assert final.attack_type != "Unknown_Attack"
    assert final.recommended_action != "block_ip"
    assert final.attack_type == "insufficient_evidence"
    assert "无攻击载荷特征" in final.unknown_items


def test_empty_authorization_scope_is_not_treated_as_unrestricted():
    """反例 2A：来源/资产/窗口配置为空，不能当作"不限范围"而判正常。

    修复前：attack_type=none。
    """
    profile = _profile(common_src_ips=[], allowed_assets=[])
    asset = _asset(maintenance_windows=[], in_maintenance_window=None)
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=profile, asset=asset).run()

    assert final.attack_type == "insufficient_evidence"
    assert "来源授权范围" in final.unknown_items or "资产授权范围" in final.unknown_items


def test_multiple_accounts_cannot_share_one_profile():
    """反例 2B：同一批日志混入未登记账号，不能用 ops_zhang 的画像批准整批。

    修复前：attack_type=none。
    """
    logs = [
        _log("L-1", attack_stage_hint="benign"),
        _log("L-2", attack_stage_hint="benign", user="intruder"),
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.attack_type == "insufficient_evidence"
    assert "多个账号" in final.unknown_items
    assert "intruder" in final.unknown_items


def test_partial_window_coverage_cannot_approve_whole_sequence():
    """行为序列里有窗口外操作时，不能凭另一条窗口内日志批准整体。"""
    logs = [
        _log("L-1", attack_stage_hint="benign"),  # 周五 02:10 CST，窗口内
        _log("L-2", attack_stage_hint="benign", timestamp="2026-10-30T02:00:00Z"),  # 周五 10:00 CST，窗外
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.attack_type == "insufficient_evidence"
    assert "维护窗口外" in final.unknown_items


def test_benign_label_cannot_mask_injection_payload():
    """反例 3：benign 标签 + 注入载荷，不能判正常。

    修复前：attack_type=none / recommended_action=none。
    """
    logs = [
        _log(
            "L-1",
            attack_stage_hint="benign",
            payload_summary="UNION SELECT sleep(5)",
            user_agent="sqlmap/1.7.2",
        )
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.is_malicious is True
    assert final.attack_type == "SQL_Injection"
    assert final.requires_human_approval is True


def test_authorized_normal_operation_still_concludes_normally():
    """对照：授权匹配且确无异常行为时，仍应正常收束（防止"一律弃权"式通过）。"""
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=_profile(), asset=_asset()).run()

    assert final.attack_type == "none"
    assert final.is_malicious is False
    assert final.requires_human_approval is False
    assert "授权" in final.attack_chain_summary


# ---------------------------------------------------------------------------
# 第三轮反例：弱关键词误判、证据错配、缺窗口配置
# ---------------------------------------------------------------------------


def test_robots_txt_is_not_an_attack():
    """反例：普通 /robots.txt 访问曾被判 Scan/HIGH/block_ip。"""
    logs = [
        _log(
            "L-1",
            attack_stage_hint="benign",
            uri_or_target="/robots.txt",
            payload_summary="",
            user_agent="Mozilla/5.0",
            status_code=200,
        )
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.is_malicious is False
    assert final.attack_type != "Scan"
    assert final.recommended_action != "block_ip"


def test_avatar_upload_is_not_malicious_upload():
    """反例：普通头像上传曾被判 Malicious_Upload/HIGH/block_ip。"""
    logs = [
        _log(
            "L-1",
            attack_stage_hint="benign",
            uri_or_target="/upload/avatar",
            payload_summary="multipart/form-data; filename=avatar.png",
            user_agent="Mozilla/5.0",
            status_code=200,
        )
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.is_malicious is False
    assert final.attack_type != "Malicious_Upload"
    assert final.recommended_action != "block_ip"


def test_http_2xx_alone_does_not_confirm_success():
    """2xx 只是请求被处理，不单独构成"利用成功"；被拒的攻击尝试风险更低。"""
    rejected = _session(
        [
            _log(
                "L-1",
                attack_stage_hint="exploitation",
                user=None,
                payload_summary="UNION SELECT sleep(5)",
                user_agent="sqlmap/1.7.2",
                status_code=403,
            )
        ],
        profile=_profile(),
        asset=_asset(),
    ).run()
    accepted = _session(
        [
            _log(
                "L-1",
                attack_stage_hint="exploitation",
                user=None,
                payload_summary="UNION SELECT sleep(5)",
                user_agent="sqlmap/1.7.2",
                status_code=200,
            )
        ],
        profile=_profile(),
        asset=_asset(),
    ).run()

    assert rejected.is_malicious is True  # 有强特征，仍然是攻击
    assert rejected.risk_level == "MEDIUM"  # 但被拒，不抬到 HIGH
    assert accepted.risk_level == "HIGH"


def test_real_attack_still_detected_even_with_benign_label():
    """正例不能因修复误判而丢失：benign 标签 + 真实 webshell 访问仍判攻击。"""
    logs = [
        _log(
            "L-1",
            attack_stage_hint="benign",
            user=None,
            uri_or_target="/uploads/shell.php?cmd=whoami",
            payload_summary="cmd=whoami",
            user_agent="Mozilla/5.0",
            status_code=200,
        )
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.is_malicious is True
    assert "Malicious_Upload" in final.attack_type
    assert final.requires_human_approval is True


def test_evidence_points_to_triggering_log_not_background():
    """反例：结论来自 L2 的注入载荷，证据却只引用 L1 的普通访问。"""
    logs = [
        _log(
            "L1",
            attack_stage_hint="unknown",
            uri_or_target="/index.html",
            payload_summary="",
            user_agent="Mozilla/5.0",
            status_code=200,
        ),
        _log(
            "L2",
            attack_stage_hint="benign",
            uri_or_target="/admin/login.php",
            payload_summary="UNION SELECT sleep(5)",
            user_agent="sqlmap",
            status_code=200,
        ),
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.attack_type == "SQL_Injection"
    assert "L2" in final.evidence_log_ids, "触发结论的日志必须进证据"
    assert final.evidence_log_ids == ["L2"], "不应把无关背景日志塞进证据"


def test_missing_window_config_blocks_authorization():
    """反例：仅缺维护窗口配置时，不能宣称授权核对通过。

    来源与资产都匹配，只有 maintenance_windows=[] —— 之前会被跳过核验。
    """
    asset = _asset(maintenance_windows=[], in_maintenance_window=None)
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=_profile(), asset=asset).run()

    assert final.attack_type == "insufficient_evidence"
    assert "维护窗口" in final.unknown_items


def test_business_account_does_not_need_maintenance_window():
    """普通业务账号不要求维护窗口：缺窗口配置也不能因此弃权。"""
    profile = _profile(account_type="application_admin")
    asset = _asset(maintenance_windows=[], in_maintenance_window=None)
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=profile, asset=asset).run()

    assert final.attack_type == "none"
    assert final.recommended_action == "none"


# ---------------------------------------------------------------------------
# 第四轮反例：判定与下游结论必须同源
# ---------------------------------------------------------------------------

_INJECT = dict(
    attack_stage_hint="benign",
    src_ip="198.51.100.23",
    payload_summary="UNION SELECT sleep(5)",
    user_agent="sqlmap",
    status_code=403,
)
_NORMAL_VISIT = dict(
    uri_or_target="/index.html",
    payload_summary="",
    user_agent="Mozilla/5.0",
    status_code=200,
)


def test_attacker_ip_resolved_from_behavior_not_label():
    """反例一：L1 带注入特征也有源 IP，但曾被 benign 标签排除 → attacker_ip=unknown。"""
    final = _session([_log("L1", **_INJECT)], profile=_profile(), asset=_asset()).run()

    assert final.attacker_ip == "198.51.100.23", "攻击源应来自攻击行为日志，而非标签"
    assert final.attack_type == "SQL_Injection"


def test_recon_label_cannot_add_scan_stage():
    """反例二之一：一条只有 recon 标签的普通访问，不能给结论加 Scan。"""
    logs = [_log("L1", **_INJECT), _log("L2", attack_stage_hint="recon", **_NORMAL_VISIT)]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.attack_type == "SQL_Injection"
    assert "Scan" not in final.attack_type
    assert final.evidence_log_ids == ["L1"], "无行为证据的日志不该进证据"


def test_c2_label_cannot_add_c2_stage():
    """反例二之二：一条只有 c2_callback 标签的普通访问，不能加 C2 分类。"""
    logs = [_log("L1", **_INJECT), _log("L2", attack_stage_hint="c2_callback", **_NORMAL_VISIT)]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.attack_type == "SQL_Injection"
    assert "C2_Exfiltration" not in final.attack_type
    assert "可疑外连" not in final.attack_chain_summary


def test_unrelated_bytes_cannot_escalate_to_exfiltration():
    """反例三：无关日志的 2MB 流量不能把注入结果升级为确认外传。"""
    inject_ok = dict(_INJECT)
    inject_ok["status_code"] = 200
    logs = [
        _log("L1", **inject_ok),
        _log("L2", attack_stage_hint="c2_callback", bytes_out=2097152, **_NORMAL_VISIT),
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert final.risk_level != "CRITICAL", "不能把无关流量拼成确认外传"
    assert "C2_Exfiltration" not in final.attack_type
    assert "已建立对外连接" not in final.attack_chain_summary
    assert "未确认利用成功" in final.attack_chain_summary


def test_unlinked_callback_does_not_prove_c2_by_volume():
    """明确回连且连接成功可判高风险，但字节量不证明外传。"""
    inject_ok = dict(_INJECT)
    inject_ok["status_code"] = 200
    logs = [
        _log("L1", **inject_ok),
        _log(
            "L2",
            attack_stage_hint="c2_callback",
            uri_or_target="/beacon",
            payload_summary="beacon;conn_state=SF",
            user_agent="Mozilla/5.0",
            dest_port=4444,
            bytes_out=2097152,
        ),
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert "C2_Exfiltration" not in final.attack_type
    assert final.risk_level == "HIGH"
    assert "L2" not in final.evidence_log_ids


def test_summary_stages_trace_back_to_logs():
    """摘要里声称的阶段必须有对应日志；数字与证据对得上。"""
    logs = [
        _log("L1", **{**_INJECT, "user_agent": "hydra/9.5", "payload_summary": "auth_fail", "status_code": 401}),
        _log("L2", **_INJECT),
    ]
    final = _session(logs, profile=_profile(), asset=_asset()).run()

    assert "账号爆破" in final.attack_chain_summary
    assert "SQL 注入" in final.attack_chain_summary
    assert set(final.evidence_log_ids) == {"L1", "L2"}


def test_label_change_does_not_change_fact_based_conclusion():
    """同一批日志只改标签，事实结论不变；标签疑点单独记录。"""
    base = _log(
        "L1",
        attack_stage_hint="benign",
        uri_or_target="/index.html",
        payload_summary="",
        user_agent="Mozilla/5.0",
        status_code=200,
    )
    for stage in ("benign", "recon", "c2_callback", None):
        log = dict(base)
        if stage is None:
            log.pop("attack_stage_hint", None)
        else:
            log["attack_stage_hint"] = stage
        final = _session([log], profile=_profile(), asset=_asset()).run()
        # 无攻击行为：无论标签怎么改，都不能判攻击
        assert final.is_malicious is False, f"stage={stage} 不应判攻击"
        assert final.attack_type in {"none", "insufficient_evidence"}


def test_single_password_typo_and_retry_are_not_brute_force():
    failed = _log("FAIL", attack_stage_hint="benign", payload_summary="reason=invalid_password", user_agent="Mozilla", status_code=401)
    success = _log("OK", attack_stage_hint="benign", payload_summary="login success", user_agent="Mozilla", status_code=200)
    for logs in ([failed], [failed, success]):
        result = _session(logs, profile=_profile(), asset=_asset()).run()
        assert not result.is_malicious
        assert result.recommended_action == "none"


def test_port_and_label_do_not_prove_c2():
    for stage in ("benign", "c2_callback", None):
        log = _log("PORT", attack_stage_hint=stage, dest_port=8888, payload_summary="conn_state=S0", uri_or_target="/", user_agent="Mozilla", status_code=None, bytes_out=0)
        result = _session([log], profile=_profile(), asset=_asset()).run()
        assert not result.is_malicious


def test_repeated_failures_require_same_source_and_time_window():
    logs = [_log(f"F{i}", timestamp=f"2026-10-29T18:10:0{i}Z", attack_stage_hint="benign", payload_summary="reason=invalid_password", status_code=401, user_agent="Mozilla") for i in range(5)]
    assert _session(logs, profile=_profile(), asset=_asset()).run().attack_type == "Brute_Force"
    scattered = [dict(log, src_ip=f"10.0.0.{i+1}") for i, log in enumerate(logs)]
    assert not _session(scattered, profile=_profile(), asset=_asset()).run().is_malicious


# ---------------------------------------------------------------------------
# 第五轮：授权范围必须来自配置，豁免名单不能当授权
# ---------------------------------------------------------------------------


def test_authorized_when_scope_configured():
    """配置齐全（来源 + 资产 + 窗口）时，才判授权运维。"""
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=_profile(), asset=_asset()).run()
    assert final.attack_type == "none"


def test_cidr_source_scope_authorizes_member_address():
    """账号授权范围中的 CIDR 应按网段匹配，而非当作单个 IP 字符串。"""
    profile = _profile(common_src_ips=["10.0.0.0/24"])
    log = _log("L-CIDR", src_ip="10.0.0.67", attack_stage_hint="benign")
    final = _session([log], profile=profile, asset=_asset()).run()
    assert final.attack_type == "none"


def test_cidr_source_scope_rejects_address_outside_network():
    profile = _profile(common_src_ips=["10.0.0.0/24"])
    log = _log("L-CIDR-OUT", src_ip="10.0.1.67", attack_stage_hint="benign")
    final = _session([log], profile=profile, asset=_asset()).run()
    assert final.attack_type == "insufficient_evidence"
    assert "不在授权范围" in final.unknown_items


def test_missing_source_scope_is_uncertain():
    """缺来源授权范围（只有处置豁免名单）时不能判正常。"""
    profile = {
        "user": "ops_zhang",
        "account_type": "legit_operator",
        "disposition_exempt": True,
        "source_scope_provided": False,
        "asset_scope_provided": True,
        "allowed_assets": ["web-prod-01"],
    }
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=profile, asset=_asset()).run()
    assert final.attack_type == "insufficient_evidence"
    assert "来源授权范围" in final.unknown_items


def test_asset_out_of_scope_is_uncertain():
    """行为落在账号授权资产之外时不能判正常。"""
    profile = _profile(allowed_assets=["backup-01"])
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=profile, asset=_asset()).run()
    assert final.attack_type == "insufficient_evidence"
    assert "不在授权范围" in final.unknown_items


def test_db_core_outside_sunday_window_is_uncertain():
    """db-core-01 只在周日 01:00-04:00 开窗，周四访问应判不确定。"""
    asset = _asset(
        asset_id="db-core-01",
        maintenance_windows=[
            {
                "asset_id": "db-core-01",
                "days": ["sun"],
                "start": "01:00",
                "end": "04:00",
                "allowed_actions": ["backup", "index_rebuild"],
            }
        ],
        in_maintenance_window=False,
    )
    profile = _profile(allowed_assets=["db-core-01"])
    logs = [
        _log(
            "L-1",
            attack_stage_hint="benign",
            asset="db-core-01",
            timestamp="2026-10-29T02:10:00Z",  # 周四 10:10 CST
        )
    ]
    final = _session(logs, profile=profile, asset=asset).run()
    assert final.attack_type == "insufficient_evidence"
    assert "维护窗口" in final.unknown_items


def test_disposition_allowlist_alone_is_not_authorization():
    """仅命中 allowlist（处置豁免）不构成行为授权。"""
    profile = {
        "user": "ops_zhang",
        "account_type": "legit_operator",
        "allowlisted": True,
        "disposition_exempt": True,
        "source_scope_provided": False,
        "asset_scope_provided": False,
    }
    final = _session([_log("L-1", attack_stage_hint="benign")], profile=profile, asset=_asset()).run()
    assert final.attack_type == "insufficient_evidence"


# ---------------------------------------------------------------------------
# isolate_account 契约：与 config/response-policy.yaml 对齐
# ---------------------------------------------------------------------------


def test_isolate_account_requires_target_user(client):
    """账号隔离必须带 target_user，缺了应被请求模型拒绝。"""
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as c:
        client.post("/tools/query_logs", json={"case_id": "CASE-ISO", "trace_id": "CHAIN-ATTACK-01"})
        r = c.post(
            "/tools/request_response",
            json={
                "case_id": "CASE-ISO",
                "action": "isolate_account",
                "evidence_log_ids": [],
                "reason": "账号已被用于爆破",
            },
        )
    assert r.status_code == 422


def test_isolate_account_goes_to_approval_and_never_executes(client):
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as c:
        q = c.post("/tools/query_logs", json={"case_id": "CASE-ISO2", "trace_id": "CHAIN-ATTACK-01"})
        ids = [i["log_id"] for i in q.json()["items"]][:2]
        r = c.post(
            "/tools/request_response",
            json={
                "case_id": "CASE-ISO2",
                "action": "isolate_account",
                "target_user": "admin",
                "evidence_log_ids": ids,
                "reason": "admin 账号遭爆破后疑似被登录，申请隔离",
            },
        )
    body = r.json()
    assert body["status"] == "approval_required"
    assert body["executed"] is False, "账号隔离只能登记待审批，不得实际执行"
    assert "admin" in body["detail"]


def test_block_ip_rejects_target_user(client):
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as c:
        q = c.post("/tools/query_logs", json={"case_id": "CASE-ISO3", "trace_id": "CHAIN-ATTACK-01"})
        ids = [i["log_id"] for i in q.json()["items"]][:1]
        r = c.post(
            "/tools/request_response",
            json={
                "case_id": "CASE-ISO3",
                "action": "block_ip",
                "target_ip": "198.51.100.23",
                "target_user": "admin",
                "evidence_log_ids": ids,
                "reason": "混用字段应被拒绝",
            },
        )
    assert r.status_code == 422
