"""第二周：七类分类口径、契约校验、知识检索适配的回归测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_engine import attack_types
from ai_engine.results_schema import load_example, validate_results
from ai_engine.verify import VALID_ATTACK_SEGMENTS, verify_triage

REPO = Path(__file__).resolve().parents[1]
TRACES = REPO / "data" / "agent_traces" / "v1"


# ---------------------------------------------------------------------------
# 分类口径
# ---------------------------------------------------------------------------


def test_seven_categories_declared():
    catalog = attack_types.catalog()
    codes = [c["code"] for c in catalog]
    assert codes == [
        "Scan",
        "Brute_Force",
        "SQL_Injection",
        "XSS",
        "Path_Traversal_Privilege",
        "Malicious_Upload",
        "C2_Exfiltration",
    ]
    # 七类必须是七个独立取值：「恶意上传」「遍历与越权」不合并，XSS 与 RCE 不合并
    assert len(codes) == 7
    assert {"Path_Traversal_Privilege", "Malicious_Upload"} <= set(codes)
    missing_cards = [c["code"] for c in catalog if not c["knowledge_card_ready"]]
    assert missing_cards == ["Scan"]


def test_verify_segments_in_sync_with_attack_types():
    """verify.py 为保持"可整段粘贴"内联了枚举，必须与 attack_types 同步。"""
    expected = set(attack_types.VALID_CODES) | set(attack_types.COMPAT_SEGMENTS)
    assert set(VALID_ATTACK_SEGMENTS) == expected


def test_normalize_aliases():
    assert attack_types.normalize("C2_Callback_After_SQL_Injection") == "C2_Exfiltration_After_SQL_Injection"
    assert attack_types.normalize("Webshell") == "Malicious_Upload"
    assert attack_types.normalize("SQLi") == "SQL_Injection"
    assert attack_types.normalize("密码爆破") == "Brute_Force"
    assert attack_types.normalize("Recon") == "Scan"
    assert attack_types.normalize("insufficient_evidence") == "insufficient_evidence"
    assert attack_types.normalize("") == "none"


def test_segments_order_is_chronological():
    assert attack_types.segments("C2_Exfiltration_After_SQL_Injection_After_Brute_Force") == [
        "Brute_Force",
        "SQL_Injection",
        "C2_Exfiltration",
    ]


def test_invalid_segment_detected():
    assert attack_types.invalid_segments("SQL_Injection_After_Brute_Force") == []
    assert attack_types.invalid_segments("SQL_Injection_After_Whatever") == ["Whatever"]
    assert attack_types.is_valid("none") is True
    assert attack_types.is_valid("Webshell_Upload_And_C2_Callback") is False


def test_zh_name_and_knowledge_category():
    assert attack_types.zh_name("SQL_Injection_After_Brute_Force") == "密码爆破 → SQL 注入"
    assert attack_types.knowledge_category("C2_Exfiltration_After_SQL_Injection") == "C2_Exfiltration"
    assert attack_types.knowledge_category("Scan") is None


def test_infer_from_text():
    assert attack_types.infer_from_text("sqlmap 1.7 UNION SELECT sleep(5)") == "SQL_Injection"
    assert attack_types.infer_from_text("hydra 爆破 auth_fail") == "Brute_Force"
    assert attack_types.infer_from_text("upload shell.php 到 /uploads") == "Malicious_Upload"
    assert attack_types.infer_from_text("GET /index.html") is None


def test_verify_rejects_unknown_attack_type():
    payload = load_example()
    payload["attack_type"] = "SQL_Injection_After_Whatever"
    result = verify_triage(payload)
    assert not result.ok
    assert any("未定义的攻击类别" in p for p in result.problems)


def test_verify_accepts_canonical_chain():
    payload = load_example()
    payload["attack_type"] = "SQL_Injection_After_Brute_Force_After_Scan"
    assert verify_triage(payload).ok is True


# ---------------------------------------------------------------------------
# V1 产物
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not TRACES.exists(), reason="尚未运行 tests/run_v1_traces.py")
def test_v1_results_are_strict_contract_and_trace_is_complete():
    files = sorted(p for p in TRACES.glob("*.json") if ".trace." not in p.name)
    assert files, "data/agent_traces/v1 下没有结果文件"
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        # 严格 11 字段：多余字段会被 validate_results 拒绝
        validated = validate_results(payload)
        assert validated.case_id
        trace = json.loads((TRACES / f"{path.stem}.trace.json").read_text(encoding="utf-8"))
        assert trace["run"]["data_source"] in {"dataset_replay", "clickhouse", "mock"}
        assert trace["trace"]["steps"], "轨迹不能为空"
        for step in trace["trace"]["steps"]:
            assert step["tool"] and step["why"]
        assert trace["checks"]["evidence_all_registered"] is True
        assert trace["checks"]["verify_ok"] is True


@pytest.mark.skipif(not TRACES.exists(), reason="尚未运行 tests/run_v1_traces.py")
def test_v1_trace_never_reads_ground_truth_into_result():
    """标准答案只用于评测对照：结果对象里不能出现 truth 独有字段。"""
    for path in TRACES.glob("*.trace.json"):
        trace = json.loads(path.read_text(encoding="utf-8"))
        assert set(trace["result"]) == set(load_example().keys())
        if trace["evaluation"]:
            assert trace["evaluation"]["note"].startswith("仅作独立评测对照")


# ---------------------------------------------------------------------------
# 知识检索适配
# ---------------------------------------------------------------------------


def test_knowledge_adapter_mock_mode_maps_fields():
    from api import knowledge_adapter

    cards, meta = knowledge_adapter.search("SQL 注入如何处置", top_k=3, mode="mock")
    assert meta["retrieval_mode"] == "mock" and meta["mock"] is True
    assert cards
    required = {
        "card_id",
        "card_type",
        "title",
        "attack_category",
        "mitre_id",
        "key_indicators",
        "recommended_action",
        "score",
    }
    for card in cards:
        # 允许携带 mock 等附加标识，但契约字段必须齐备
        assert required <= set(card)


def test_knowledge_adapter_map_card_tolerates_unknown_type():
    from api import knowledge_adapter

    mapped = knowledge_adapter.map_card(
        {"card_id": "K1", "card_type": "weird", "title": "t", "key_indicators": "单条字符串"}
    )
    assert mapped["card_type"] == "security_knowledge"
    assert mapped["key_indicators"] == ["单条字符串"]
    assert mapped["score"] == 0.0


def test_knowledge_adapter_reports_unavailable_when_deps_missing():
    """真实模式缺 BGE/Qdrant 时必须抛 KnowledgeUnavailable，而不是返回固定答案。"""
    from api import knowledge_adapter

    try:
        cards, meta = knowledge_adapter.search("SQL 注入如何处置", top_k=3, mode="auto")
    except knowledge_adapter.KnowledgeUnavailable as exc:
        assert exc.details.get("stage") in {"import", "search"}
        assert exc.reason
    else:  # 依赖齐备时应当真的检索到卡片
        assert meta["retrieval_mode"] == "hybrid"
        assert isinstance(cards, list)


def test_search_endpoint_never_returns_fake_success(monkeypatch, client):
    """缺依赖时接口必须 503，并且响应里不能出现卡片。"""
    monkeypatch.setenv("SECLOG_SEARCH_MODE", "auto")
    r = client.post("/tools/search_knowledge", json={"query": "SQL 注入如何处置", "limit": 3})
    if r.status_code == 200:
        assert r.json()["meta"]["data_source"] == "hybrid_search"
    else:
        assert r.status_code == 503
        assert r.json()["code"] == "backend_unavailable"
        assert r.json()["details"]["backend"] == "knowledge"


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# 七类必须可区分；结果分类与知识卡分类是两套口径
# ---------------------------------------------------------------------------


def test_seven_categories_are_distinguishable():
    """每一类都要能从日志特征里被单独识别出来，否则"七类"只是名义上的。"""
    samples = {
        "Scan": "dirsearch 探测 /.git/config 与 robots.txt",
        "Brute_Force": "hydra auth_fail 多次登录失败",
        "SQL_Injection": "sqlmap UNION SELECT sleep(5)",
        "XSS": "<script>alert(1)</script> onerror=",
        "Path_Traversal_Privilege": "GET /../../etc/passwd 未授权访问",
        "Malicious_Upload": "multipart/form-data filename=shell.php upload",
        "C2_Exfiltration": "外连 45.77.128.203:4444 beacon",
    }
    for expected, text in samples.items():
        got = attack_types.infer_from_text(text)
        assert got == expected, f"{expected} 未被识别，实际 {got}"


def test_result_category_maps_to_knowledge_category():
    """结果分类七个，知识卡分类五个：多对一是允许的，但不能反过来合并结果类。"""
    mapping = {t.code: t.knowledge_category for t in attack_types.ATTACK_TYPES}
    assert mapping["XSS"] == "XSS_RCE"
    assert mapping["Malicious_Upload"] == "File_Upload_Traversal"
    assert mapping["Path_Traversal_Privilege"] == "File_Upload_Traversal"
    assert mapping["Scan"] is None
    assert attack_types.knowledge_category("XSS") == "XSS_RCE"
    assert attack_types.knowledge_category("Path_Traversal_Privilege") == "File_Upload_Traversal"
    # 结果类本身仍然是两个
    assert attack_types.BY_CODE["Malicious_Upload"] is not attack_types.BY_CODE["Path_Traversal_Privilege"]


def test_combined_type_uses_seven_class_segments():
    combo = "C2_Exfiltration_After_Malicious_Upload_After_Scan"
    assert attack_types.is_valid(combo) is True
    assert attack_types.segments(combo) == ["Scan", "Malicious_Upload", "C2_Exfiltration"]


def test_illegal_category_is_rejected():
    assert attack_types.is_valid("Malicious_Upload_And_Traversal") is False
    assert attack_types.invalid_segments("XSS_After_Nope") == ["Nope"]

    payload = load_example()
    payload["attack_type"] = "Malicious_Upload_And_Traversal"
    assert verify_triage(payload).ok is False


def test_legacy_merged_codes_still_normalize():
    """历史合并类要能收敛到七类，但不能因此让新产出继续使用旧码。"""
    assert attack_types.normalize("XSS_RCE") == "XSS"
    assert attack_types.normalize("File_Upload_Traversal") == "Malicious_Upload"
    assert attack_types.normalize("C2_Callback") == "C2_Exfiltration"
    # 旧码仍在兼容集合里（供校验放行历史产物），但不属于七类清单
    assert "XSS_RCE" in attack_types.COMPAT_SEGMENTS
    assert "XSS_RCE" not in {t.code for t in attack_types.ATTACK_TYPES}


@pytest.mark.skipif(not TRACES.exists(), reason="尚未运行 tests/run_v1_traces.py")
def test_trace_keeps_decision_evidence_not_ellipsis():
    """轨迹必须留下可核验的判定依据：维护窗口细节不能被脱敏成省略号。"""
    path = TRACES / "CHAIN-CASE-03.trace.json"
    if not path.exists():
        pytest.skip("缺少 CHAIN-CASE-03 轨迹")
    trace = json.loads(path.read_text(encoding="utf-8"))
    decision = trace.get("context_decision") or {}
    assert decision.get("available") is True
    assert decision.get("checks"), "授权核对项不能为空"

    evidence = decision.get("evidence") or {}
    windows = evidence.get("maintenance_windows") or []
    assert windows, "必须保留维护窗口配置"
    first = windows[0]
    # PR #23 的 config/maintenance-windows.yaml 用 days，时区在配置顶层
    assert first.get("days") or first.get("weekdays"), "窗口缺少星期声明"
    for key in ("start", "end"):
        assert first.get(key) not in (None, "", "…"), f"{key} 被脱敏掉了"
    assert evidence.get("evaluated_at"), "必须保留窗口判断所用时间"
    assert isinstance(evidence.get("per_log_in_window"), dict) and evidence["per_log_in_window"]
    # 最新 main 已为 ops_* 配置明确的来源与资产行为授权范围。
    assert evidence.get("observed_src_ips")
    assert evidence.get("source_scope_provided") is True
    assert evidence.get("asset_scope_provided") is True
    assert "10.0.0.0/24" in evidence.get("allowed_src_ips", [])
    assert "web-prod-01" in evidence.get("allowed_assets", [])

    # 成功 / 零命中 / 失败仍可区分
    statuses = {s["status"] for s in trace["trace"]["steps"]}
    assert statuses <= {"ok", "empty", "error"}
    assert statuses


@pytest.mark.skipif(not TRACES.exists(), reason="尚未运行 tests/run_v1_traces.py")
def test_trace_records_what_each_conclusion_rests_on():
    """轨迹要能核对：分类的每一段、风险、攻击源分别由哪些日志支撑。"""
    checked = 0
    for path in sorted(TRACES.glob("*.trace.json")):
        trace = json.loads(path.read_text(encoding="utf-8"))
        basis = trace.get("conclusion_basis")
        assert basis, f"{path.name} 缺少 conclusion_basis"

        result = trace["result"]
        evidence = set(result["evidence_log_ids"])

        # 分类：每个已确认阶段都要有依据日志
        at = basis["attack_type"]
        assert at["value"] == result["attack_type"]
        for seg in at["segments"]:
            assert seg["log_ids"], f"{path.name} 的 {seg['code']} 段没有依据日志"
            assert set(seg["log_ids"]) <= evidence, f"{path.name} 的 {seg['code']} 依据不在证据内"

        # 风险：有规则名和依据
        risk = basis["risk_level"]
        assert risk["value"] == result["risk_level"]
        assert risk["rule"]
        if result["is_malicious"]:
            assert risk["log_ids"], f"{path.name} 的恶意结论缺少风险依据日志"
            assert set(risk["log_ids"]) <= evidence

        # 攻击源：确定为具体地址时必须有来源日志
        src = basis["attacker_ip"]
        assert src["value"] == result["attacker_ip"]
        if result["attacker_ip"] != "unknown":
            assert src["log_ids"], f"{path.name} 的攻击源缺少来源日志"

        # 摘要：阶段计数与分类段一致
        summary = basis["summary"]
        assert summary["text"] == result["attack_chain_summary"]
        for code, count in summary["stage_counts"].items():
            assert count >= 1

        checked += 1
    assert checked >= 3
