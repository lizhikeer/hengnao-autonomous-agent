"""端到端链路模拟：在没有恒脑平台账号的情况下，把整条工作流在本地跑通一遍。

它替代不了"平台真的能调通"这件事，但能回答另外三个问题：
1. 节点拓扑与边条件在逻辑上闭合吗（白名单旁路 / 字段残缺反问 / 主链路调查）；
2. 高危动作的审批门禁真的拦得住吗（批准 / 驳回两条路都跑）；
3. 结束节点输出的 Markdown 报告与 results JSON 长什么样，能不能直接拿去演示。

用法：
    .venv/Scripts/python tests/e2e_workflow_sim.py

产物：
    design/hengnao_workflows/e2e_reports/TC-*.md   每条用例一份报告（可直接贴进答辩材料）
    design/hengnao_workflows/e2e_reports/SUMMARY.md 汇总
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ai_engine.investigation import InvestigationSession  # noqa: E402
from ai_engine.preprocess import ask_back_message, clean_log  # noqa: E402
from ai_engine.results_schema import validate_results  # noqa: E402
from api import app as api_app  # noqa: E402
from api.evidence_check import registry  # noqa: E402
from api.schemas import RequestResponseRequest  # noqa: E402

OUT_DIR = REPO / "design" / "hengnao_workflows" / "e2e_reports"


@dataclass
class Trace:
    """节点执行轨迹，用于在报告里还原"工作流到底走了哪些节点"。"""

    steps: list[tuple[str, str]] = field(default_factory=list)

    def add(self, node: str, detail: str) -> None:
        self.steps.append((node, detail))

    def as_table(self) -> str:
        rows = ["| # | 节点 | 实际行为 |", "| --: | :--- | :--- |"]
        for i, (node, detail) in enumerate(self.steps, 1):
            rows.append(f"| {i} | `{node}` | {detail} |")
        return "\n".join(rows)


@dataclass
class CaseResult:
    case_id: str
    title: str
    raw_log: str
    trace: Trace
    branch: str
    results: Optional[dict[str, Any]] = None
    report_md: str = ""
    approval: Optional[str] = None
    response: Optional[dict[str, Any]] = None
    assertions: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(ok for _n, ok, _d in self.assertions)


def _render_report_markdown(results: dict[str, Any], response: Optional[dict[str, Any]]) -> str:
    """模拟结束节点"回答内容"的 Markdown 模板（与设计文档 §3.7 一致）。"""
    resp_line = "未进入处置环节"
    if response:
        resp_line = f"{response['status']}（executed={response['executed']}，审批单 {response.get('approval_id')}）"
    evidence = "\n".join(f"- `{i}`" for i in results["evidence_log_ids"]) or "- （本次未取得可引用证据）"
    return f"""## 调查结论：{results["attack_type"]}

- 判定：{"恶意" if results["is_malicious"] else "未判定为恶意"} ｜ 风险等级：{results["risk_level"]}
- 攻击源：{results["attacker_ip"]} → 受害资产：{results["victim_asset"]}
- 建议动作：{results["recommended_action"]}（需人工审批：{results["requires_human_approval"]}）
- 处置状态：{resp_line}

### 攻击链还原
{results["attack_chain_summary"]}

### 证据
{evidence}

### 未确认事项
{results["unknown_items"] or "无"}
"""


def run_main_chain(
    case: CaseResult,
    *,
    seed_src_ip: str,
    seed_asset_id: str,
    approve: bool,
) -> CaseResult:
    """主链路：清洗 → 调查 → 校验 → 审批 → 处置 → 结束。"""
    registry.clear()

    cleaned = clean_log(case.raw_log)
    case.branch = cleaned.branch
    case.trace.add("code_clean", f"抽出 src_ip={cleaned.clean['src_ip']}，uri={cleaned.clean['uri']}，"
                                 f"UA={cleaned.clean['user_agent']}，字段完整={cleaned.is_complete}")

    session = InvestigationSession(
        case_id=case.case_id,
        seed_src_ip=seed_src_ip,
        seed_asset_id=seed_asset_id,
    )
    results_model = session.run()
    for call in session.calls:
        case.trace.add(f"llm_investigate → {call.tool}", call.why)
    results = results_model.to_results()

    # code_verify：契约校验（与平台代码节点同源规则）
    validate_results(results)
    from api.schemas import VerifyResultsRequest
    verification = api_app.verify_results(VerifyResultsRequest(case_id=case.case_id, results=results))
    assert verification["verified"], verification["verify_msg"]
    case.trace.add("code_verify", f"契约校验通过，证据 {len(results['evidence_log_ids'])} 条，无伪造编号")

    case.results = results

    # 审批门禁
    if results["requires_human_approval"]:
        case.approval = "批准" if approve else "驳回"
        case.trace.add("interactive_confirm", f"confirm_block → 人工选择「{case.approval}」")
        if approve:
            resp = api_app.request_response(
                RequestResponseRequest(
                    case_id=case.case_id,
                    action=results["recommended_action"],
                    target_ip=results["attacker_ip"],
                    evidence_log_ids=results["evidence_log_ids"],
                    reason=results["attack_chain_summary"][:200],
                )
            )
            case.response = resp.model_dump()
            case.trace.add(
                "plugin_response",
                f"调用 /tools/request_response → {resp.status}，executed={resp.executed}",
            )
        else:
            case.trace.add("plugin_response", "审批驳回，不调用处置接口（这是门禁生效的证据）")
    else:
        case.trace.add("interactive_confirm", "无需审批，跳过")

    case.report_md = _render_report_markdown(results, case.response)
    return case


def run_bypass_chain(case: CaseResult, expect_branch: str) -> CaseResult:
    """旁路链路：白名单放行 / 字段残缺反问，均不调用模型与工具。"""
    registry.clear()
    cleaned = clean_log(case.raw_log)
    case.branch = cleaned.branch
    if cleaned.branch == "whitelist":
        case.trace.add("code_clean", f"命中健康检查白名单（uri={cleaned.clean['uri']}，UA={cleaned.clean['user_agent']}）")
        case.trace.add("end", "白名单旁路直接结束，不进模型、不调工具、不消耗 token")
        case.report_md = (
            "## 研判结论：白名单流量，无需研判\n\n"
            f"- 请求：`{cleaned.clean['method']} {cleaned.clean['uri']}`\n"
            f"- User-Agent：`{cleaned.clean['user_agent']}`\n"
            "- 处置：旁路放行（此类探针流量不进入调查链路，避免误报与 token 浪费）"
        )
    else:
        case.trace.add("code_clean", f"字段残缺，缺失：{','.join(cleaned.missing_fields)}")
        case.trace.add("code_ask", "生成反问文案，等待补充日志")
        case.report_md = "## 需要补充信息\n\n" + ask_back_message(cleaned)

    case.assertions.append(
        (f"分支判定为 {expect_branch}", case.branch == expect_branch, f"实际 {case.branch}")
    )
    return case


def render_case(case: CaseResult) -> str:
    lines = [f"# 端到端链路模拟 · {case.case_id} · {case.title}", ""]
    lines.append("> 本报告由 `tests/e2e_workflow_sim.py` 在本地生成。它验证的是**链路逻辑**，")
    lines.append("> 不代表恒脑平台侧已调通（平台侧状态见 `week1_acceptance.md` §4.4）。")
    lines.append("")
    lines.append("## 输入")
    lines.append("")
    lines.append("```text")
    lines.append(case.raw_log)
    lines.append("```")
    lines.append("")
    lines.append("## 节点轨迹")
    lines.append("")
    lines.append(case.trace.as_table())
    lines.append("")
    if case.results:
        lines.append("## 结构化输出（结束节点 results，11 字段）")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(case.results, ensure_ascii=False, indent=2))
        lines.append("```")
        lines.append("")
    lines.append("## 结束节点渲染（对话界面可见的 Markdown）")
    lines.append("")
    lines.append(case.report_md.rstrip())
    lines.append("")
    if case.approval:
        lines.append(f"## 人工审批结果：{case.approval}")
        lines.append("")
    lines.append("## 断言")
    lines.append("")
    for name, ok, detail in case.assertions:
        lines.append(f"- [{'x' if ok else ' '}] {name} — {detail}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[CaseResult] = []

    # --- TC-01：主链路，审批通过 ---
    c1 = CaseResult(
        case_id="TC-01",
        title="SQL 注入 + 前置爆破（主链路，审批通过）",
        raw_log='198.51.100.23 - - [27/Oct/2026:14:20:05 +0800] "POST /admin/login.php HTTP/1.1" 200 4520 "-" "sqlmap/1.7.2"',
        trace=Trace(),
        branch="",
    )
    run_main_chain(c1, seed_src_ip="198.51.100.23", seed_asset_id="web-prod-01", approve=True)
    r1 = c1.results or {}
    c1.assertions += [
        ("判定为恶意", r1.get("is_malicious") is True, f"is_malicious={r1.get('is_malicious')}"),
        ("风险等级 HIGH 及以上", r1.get("risk_level") in {"HIGH", "CRITICAL"}, f"risk_level={r1.get('risk_level')}"),
        ("攻击类型含注入与爆破", "SQL_Injection" in str(r1.get("attack_type")) and "Brute_Force" in str(r1.get("attack_type")), str(r1.get("attack_type"))),
        ("证据非空且格式合法", len(r1.get("evidence_log_ids") or []) >= 1, f"{len(r1.get('evidence_log_ids') or [])} 条"),
        ("处置未真实执行", (c1.response or {}).get("executed") is False, f"executed={(c1.response or {}).get('executed')}"),
        ("处置进入待审批", (c1.response or {}).get("status") == "approval_required", str((c1.response or {}).get("status"))),
    ]
    results.append(c1)

    # --- TC-02：同一案例，人工驳回 ---
    c2 = CaseResult(
        case_id="TC-02",
        title="同一攻击链，人工审批驳回（门禁生效验证）",
        raw_log=c1.raw_log,
        trace=Trace(),
        branch="",
    )
    run_main_chain(c2, seed_src_ip="198.51.100.23", seed_asset_id="web-prod-01", approve=False)
    c2.assertions += [
        ("审批驳回后未调用处置接口", c2.response is None, "response=None" if c2.response is None else "误调用"),
        ("结论仍判恶意", (c2.results or {}).get("is_malicious") is True, "结论不因驳回而改变，只是不执行"),
    ]
    results.append(c2)

    # --- TC-03：白名单健康检查（旁路） ---
    c3 = CaseResult(
        case_id="TC-03",
        title="健康检查探针流量（白名单旁路，不调模型）",
        raw_log='203.0.113.7 - - [27/Oct/2026:09:10:33 +0800] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.27"',
        trace=Trace(),
        branch="",
    )
    run_bypass_chain(c3, "whitelist")
    c3.assertions.append(("未调用任何调查工具", len(c3.trace.steps) == 2, f"{len(c3.trace.steps)} 步"))
    results.append(c3)

    # --- TC-04：字段残缺（反问） ---
    c4 = CaseResult(
        case_id="TC-04",
        title="缺少源 IP 的截断日志（反问补字段，不编造攻击源）",
        raw_log='- - [27/Oct/2026:14:20:05 +0800] "GET /admin HTTP/1.1" 408 0 "-" "-"',
        trace=Trace(),
        branch="",
    )
    run_bypass_chain(c4, "ask")
    c4.assertions += [
        ("不调用模型/工具", len(c4.trace.steps) == 2, f"{len(c4.trace.steps)} 步"),
        ("反问文案指出缺失字段", "src_ip" in c4.report_md, "报告含 src_ip 缺失说明"),
    ]
    results.append(c4)

    # --- 落盘 ---
    summary = ["# 端到端链路模拟汇总", "", "| 用例 | 分支 | 结论 | 断言 | 报告 |", "| :--- | :--- | :--- | :--- | :--- |"]
    for c in results:
        (OUT_DIR / f"{c.case_id}.md").write_text(render_case(c), encoding="utf-8")
        verdict = "—"
        if c.results:
            verdict = f"{c.results['attack_type']} / {c.results['risk_level']}"
        status = "通过" if c.passed else "失败"
        summary.append(f"| {c.case_id} {c.title} | `{c.branch}` | {verdict} | {status}（{sum(1 for _n, ok, _d in c.assertions if ok)}/{len(c.assertions)}） | [{c.case_id}.md](./{c.case_id}.md) |")
    summary.append("")
    summary.append("> 全部用例均使用显式 Mock 数据（`meta.mock=true`），仅验证链路逻辑，不代表真实检出效果。")
    (OUT_DIR / "SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")

    # --- 控制台输出 ---
    for c in results:
        print(f"[{ 'PASS' if c.passed else 'FAIL' }] {c.case_id} {c.title} → 分支={c.branch}")
        for name, ok, detail in c.assertions:
            print(f"        {'✓' if ok else '✗'} {name}：{detail}")
    print(f"\n报告已写入：{OUT_DIR}")
    return 0 if all(c.passed for c in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
