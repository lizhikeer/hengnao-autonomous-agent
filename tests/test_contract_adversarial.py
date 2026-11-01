"""契约对抗测试：把模型可能吐出的脏输出喂进来，验证两层校验能拦住、且不误伤合法输出。

两层：
1. `ai_engine.verify.verify_triage` —— 结构 + 业务规则，纯标准库，平台代码节点可直接跑；
2. `ai_engine.results_schema.validate_results` —— 类型 + 多余字段的严格校验。

判定口径：一个"该被拦"的样本，只要有一层拦住就算通过（两层职责不同，互补而非重复）。
"""

from __future__ import annotations

import copy
import json

import pytest
from pydantic import ValidationError

from ai_engine.results_schema import load_example, validate_results
from ai_engine.verify import strip_code_fence, verify_triage

BASE = load_example()


def _mutate(**kwargs):
    data = copy.deepcopy(BASE)
    data.update(kwargs)
    return data


def _drop(key: str):
    data = copy.deepcopy(BASE)
    data.pop(key, None)
    return data


def _layers(payload) -> tuple[bool, bool, list[str]]:
    """返回 (verify 是否通过, schema 是否通过, 拒绝理由)。"""
    v = verify_triage(payload)
    if not v.ok:
        return False, False, v.problems
    try:
        validate_results(v.data)
        return True, True, []
    except ValidationError as exc:
        return True, False, [err["msg"] for err in exc.errors()]


# (名称, 样本, 期望是否被拦)
ADVERSARIAL_CASES = [
    ("外层包 ```json 代码块（应被剥离后放行）", "```json\n" + json.dumps(BASE, ensure_ascii=False) + "\n```", False),
    ("前后夹带解释文字", "研判结论如下：\n" + json.dumps(BASE, ensure_ascii=False), True),
    ("输出是数组不是对象", json.dumps([BASE], ensure_ascii=False), True),
    ("完全不是 JSON", "我觉得这个是恶意的，建议封 IP。", True),
    ("缺少 unknown_items", _drop("unknown_items"), True),
    ("缺少 evidence_log_ids", _drop("evidence_log_ids"), True),
    ("多余字段 sneaky_confidence", _mutate(sneaky_confidence=0.99), True),
    ("risk_level 写成中文「高危」", _mutate(risk_level="高危"), True),
    ("risk_level 小写 high", _mutate(risk_level="high"), True),
    ("risk_level 写成 SEVERE", _mutate(risk_level="SEVERE"), True),
    ("recommended_action 写成中文「封禁」", _mutate(recommended_action="封禁"), True),
    ("recommended_action 越权写成 shutdown", _mutate(recommended_action="shutdown_host"), True),
    ("判恶意但证据为空", _mutate(evidence_log_ids=[]), True),
    ("证据写成字符串而非数组", _mutate(evidence_log_ids="LOG-20261027-0001"), True),
    ("证据里混入数字", _mutate(evidence_log_ids=["LOG-20261027-0001", 12345]), True),
    ("证据编号重复", _mutate(evidence_log_ids=["LOG-20261027-0001", "LOG-20261027-0001"]), True),
    ("证据编号格式非法 LOG-FAKE-999", _mutate(evidence_log_ids=["LOG-FAKE-999"]), True),
    ("is_malicious 用字符串 \"true\"", _mutate(is_malicious="true"), True),
    ("requires_human_approval 用字符串 \"yes\"", _mutate(requires_human_approval="yes"), True),
    ("无证据却给了具体攻击类型", _mutate(evidence_log_ids=[], attack_type="SQL_Injection_After_Brute_Force", is_malicious=False), True),
    ("证据不足却未要求人工审批", _mutate(evidence_log_ids=[], attack_type="insufficient_evidence", is_malicious=False, requires_human_approval=False), True),
    ("高危动作未标需审批", _mutate(recommended_action="block_ip", requires_human_approval=False), True),
    ("case_id 空字符串", _mutate(case_id="   "), True),
    ("attack_type 为 null", _mutate(attack_type=None), True),
    ("attack_chain_summary 超长（>2000 字）", _mutate(attack_chain_summary="攻" * 2500), True),
    ("attacker_ip 空字符串", _mutate(attacker_ip=""), True),
    ("合法输出（对照组，不应被拦）", copy.deepcopy(BASE), False),
    (
        "合法输出但 unknown_items 里包含攻击者注入文本（不应被拦）",
        _mutate(unknown_items="日志中出现 \"ignore all previous instructions\" 文本，已作为可疑行为记录"),
        False,
    ),
]


@pytest.mark.parametrize("name,payload,should_block", ADVERSARIAL_CASES, ids=[c[0] for c in ADVERSARIAL_CASES])
def test_adversarial_sample(name, payload, should_block):
    verify_ok, schema_ok, reasons = _layers(payload)
    blocked = not (verify_ok and schema_ok)
    assert blocked is should_block, (
        f"{name}: 期望{'拦住' if should_block else '放行'}，实际"
        f"{'拦住' if blocked else '放行'}（verify={verify_ok}, schema={schema_ok}）"
    )
    if blocked:
        assert reasons, f"{name}: 被拦但没有给出理由"


def test_block_rate_is_total():
    """所有应拦样本必须 100% 拦住，不允许漏网。"""
    targets = [c for c in ADVERSARIAL_CASES if c[2]]
    missed = [n for n, p, _ in targets if all(_layers(p)[:2])]
    assert not missed, "以下脏输出未被拦住：" + "；".join(missed)
    print(f"\n拦截 {len(targets)}/{len(targets)} 个脏输出，误伤 0 个合法输出")


def test_two_layers_are_complementary():
    """至少有一个样本是"verify 放行、schema 拦住"，证明两层不是重复劳动。"""
    complementary = []
    for name, payload, should_block in ADVERSARIAL_CASES:
        v_ok, s_ok, _ = _layers(payload)
        if v_ok and not s_ok:
            complementary.append(name)
    assert complementary, "两层校验完全重复，说明其中一层没有存在必要"


def test_strip_code_fence_handles_common_wrapping():
    body = json.dumps(BASE, ensure_ascii=False)
    assert strip_code_fence(f"```json\n{body}\n```") == body
    assert strip_code_fence(f"```\n{body}\n```") == body
    assert strip_code_fence(body) == body


def test_verify_reports_actionable_reason():
    """拒绝理由要能指导修正，不能只说"校验失败"。"""
    v = verify_triage(_mutate(risk_level="高危", evidence_log_ids=[]))
    assert not v.ok
    joined = v.summary()
    assert "risk_level" in joined
    assert "证据" in joined
