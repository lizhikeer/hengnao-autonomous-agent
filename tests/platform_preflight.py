"""平台调试等价预检：在没有平台账号的情况下，先把"点调试时会发生什么"全部算出来。

恒脑平台的 API 工具调试本质上就是：云端发一次 HTTP 请求（固定方法/参数位置/样例值），
看到 HTTP 200 + 可解析 JSON 就算"成功"，否则该能力项在工作流里置灰。

所以只要在本地按平台的行为方式发一遍请求并逐项检查，就能把"调试能不能过"提前算清楚。
隧道打通后照本脚本的样例值点一遍即可，不需要现场试错。

检查项：
1. 状态码 200；2. Content-Type=application/json；3. UTF-8 无 BOM 且可解析；
4. 响应体积 ≤ 256KB；5. 时延 ≤ 5s；6. 仅 GET/POST；
7. OpenAPI 中每个参数都有 description 与 examples（平台"必须填样例值"的前置）；
8. request_response 的可用调试路径（action=none）。

用法：
    .venv/Scripts/python tests/platform_preflight.py
产物：
    design/hengnao_workflows/platform_preflight.md
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient  # noqa: E402

from api.app import app  # noqa: E402
from api.evidence_check import registry  # noqa: E402

OUT = REPO / "design" / "hengnao_workflows" / "platform_preflight.md"

MAX_BODY_KB = 256
MAX_LATENCY_S = 5.0


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class ActionPlan:
    """一个平台能力项的调试配方 —— 与 week1_workflow_design.md §2 的注册表一一对应。"""

    key: str
    name: str
    method: str
    path: str
    sample: Optional[dict[str, Any]] = None
    note: str = ""
    checks: list[Check] = field(default_factory=list)
    status_code: int = 0
    latency_ms: float = 0.0
    body_kb: float = 0.0
    sample_response: str = ""

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks)


def _check_json_utf8(raw: bytes, payload: Any) -> list[Check]:
    checks: list[Check] = []
    bom = raw.startswith(b"\xef\xbb\xbf")
    checks.append(Check("UTF-8 无 BOM", not bom, "带 BOM 时部分解析器会报错" if bom else "无 BOM"))
    try:
        raw.decode("utf-8")
        checks.append(Check("可按 UTF-8 解码", True, "ok"))
    except UnicodeDecodeError as exc:
        checks.append(Check("可按 UTF-8 解码", False, str(exc)))
    checks.append(Check("响应体为可解析 JSON", payload is not None, "ok" if payload is not None else "解析失败"))
    return checks


def probe(client: TestClient, plan: ActionPlan) -> ActionPlan:
    registry.clear()
    started = time.perf_counter()
    if plan.method == "GET":
        resp = client.get(plan.path)
    else:
        resp = client.post(plan.path, json=plan.sample or {})
    plan.latency_ms = (time.perf_counter() - started) * 1000
    raw = resp.content
    plan.status_code = resp.status_code
    plan.body_kb = len(raw) / 1024

    try:
        payload = resp.json()
    except Exception:
        payload = None

    plan.checks.append(Check("HTTP 200", resp.status_code == 200, f"实际 {resp.status_code}"))
    ctype = resp.headers.get("content-type", "")
    plan.checks.append(Check("Content-Type 为 application/json", "application/json" in ctype, ctype or "缺失"))
    plan.checks.extend(_check_json_utf8(raw, payload))
    plan.checks.append(
        Check(f"响应体积 ≤ {MAX_BODY_KB}KB", plan.body_kb <= MAX_BODY_KB, f"{plan.body_kb:.1f}KB")
    )
    plan.checks.append(
        Check(f"时延 ≤ {MAX_LATENCY_S}s", plan.latency_ms / 1000 <= MAX_LATENCY_S, f"{plan.latency_ms:.0f}ms")
    )
    if payload is not None:
        plan.sample_response = json.dumps(payload, ensure_ascii=False)
        if len(plan.sample_response) > 600:
            plan.sample_response = plan.sample_response[:600] + " ...（截断）"
    return plan


def check_openapi_param_docs(client: TestClient) -> list[Check]:
    """平台要求每个参数都能填样例值，否则调试页填不出来。这里检查 description/examples 是否齐全。"""
    spec = client.get("/openapi.json").json()
    checks: list[Check] = []
    missing: list[str] = []
    total = 0
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method.lower() not in {"get", "post"}:
                continue
            body_schema = (
                op.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            ref = body_schema.get("$ref")
            if ref:
                model = spec["components"]["schemas"].get(ref.split("/")[-1], {})
                for pname, prop in (model.get("properties") or {}).items():
                    total += 1
                    if not prop.get("description"):
                        missing.append(f"{path} → {pname} 缺 description")
                    if not prop.get("examples") and "example" not in prop:
                        missing.append(f"{path} → {pname} 缺 examples")
            for prm in op.get("parameters", []) or []:
                total += 1
                if not prm.get("description"):
                    missing.append(f"{path} → {prm.get('name')} 缺 description")
    checks.append(
        Check(
            f"参数文档完整（共 {total} 个参数）",
            not missing,
            "全部具备 description 与 examples" if not missing else "；".join(missing[:8]),
        )
    )

    methods = set()
    for methods_map in spec.get("paths", {}).values():
        methods |= {m.upper() for m in methods_map}
    checks.append(
        Check("仅使用 GET / POST", methods <= {"GET", "POST"}, "、".join(sorted(methods)))
    )
    return checks


def main() -> int:
    client = TestClient(app)
    plans = [
        ActionPlan("health", "服务健康检查", "GET", "/health"),
        ActionPlan(
            "query_logs",
            "全链路关联日志查询",
            "POST",
            "/tools/query_logs",
            {"case_id": "EVAL-CHAIN-001", "trace_id": "CHAIN-ATTACK-01", "limit": 50},
        ),
        ActionPlan(
            "get_context",
            "账号行为基线与资产上下文查询",
            "POST",
            "/tools/get_context",
            {"user": "admin", "asset_id": "web-prod-01"},
        ),
        ActionPlan(
            "search_knowledge",
            "安全知识卡与案例卡检索",
            "POST",
            "/tools/search_knowledge",
            {"query": "SQL 注入绕过认证后如何处置", "limit": 5},
        ),
        ActionPlan(
            "request_response",
            "处置动作提交（封禁/限速，需审批）",
            "POST",
            "/tools/request_response",
            {"case_id": "PREFLIGHT-001", "action": "none", "evidence_log_ids": [], "reason": "调试连通性，无需处置"},
            note="证据表在内存，平台单次调试无法预热；用 action=none 取得一次 200 使节点可选，真实证据校验仍在服务端生效",
        ),
    ]

    for plan in plans:
        probe(client, plan)

    openapi_checks = check_openapi_param_docs(client)

    # --- 报告 ---
    lines = [
        "# 平台调试等价预检报告（Platform Preflight）",
        "",
        "> 生成脚本：`tests/platform_preflight.py`。",
        "> 作用：在没有恒脑平台账号/公网隧道的情况下，按平台调试的行为方式把五个能力项各发一次请求，",
        "> 逐项检查状态码、Content-Type、编码、体积、时延与参数文档完整性，",
        "> 从而把「调试能否通过」提前算出来。**本报告不能替代平台上的实际调试**，",
        "> 但隧道与账号到位后，照下面「调试配方」逐条点一遍即可，无需现场试错。",
        "",
        "## 一、结论",
        "",
        "| 能力项 | 方法 | 路径 | 状态码 | 时延 | 体积 | 结果 |",
        "| :--- | :--- | :--- | ---: | ---: | ---: | :--- |",
    ]
    for p in plans:
        lines.append(
            f"| {p.name} | {p.method} | `{p.path}` | {p.status_code} | {p.latency_ms:.0f}ms | "
            f"{p.body_kb:.1f}KB | {'通过' if p.passed else '**未通过**'} |"
        )
    lines += [
        "",
        f"全局检查：{'全部通过' if all(c.ok for c in openapi_checks) else '**存在未通过项**'}",
        "",
        "## 二、逐项检查明细",
        "",
    ]
    for p in plans:
        lines.append(f"### {p.name}（`{p.method} {p.path}`）")
        lines.append("")
        if p.sample is not None:
            lines.append("调试样例值（平台调试页照填）：")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(p.sample, ensure_ascii=False, indent=2))
            lines.append("```")
            lines.append("")
        lines.append("| 检查项 | 结果 | 说明 |")
        lines.append("| :--- | :--- | :--- |")
        for c in p.checks:
            lines.append(f"| {c.name} | {'通过' if c.ok else '未通过'} | {c.detail} |")
        if p.note:
            lines.append("")
            lines.append(f"> 注意：{p.note}")
        if p.sample_response:
            lines.append("")
            lines.append("实测响应（截断）：")
            lines.append("")
            lines.append("```json")
            lines.append(p.sample_response)
            lines.append("```")
        lines.append("")

    lines += ["## 三、全局兼容性检查", "", "| 检查项 | 结果 | 说明 |", "| :--- | :--- | :--- |"]
    for c in openapi_checks:
        lines.append(f"| {c.name} | {'通过' if c.ok else '未通过'} | {c.detail} |")
    lines += [
        "",
        "## 四、隧道打通后的操作顺序（照做即可）",
        "",
        "1. 起服务：`./.venv/Scripts/python -m uvicorn api.app:app --app-dir src --host 127.0.0.1 --port 8000`",
        "2. 开隧道（任选）：`cloudflared tunnel --url http://127.0.0.1:8000` 或 `npx localtunnel --port 8000`",
        "3. 先在公网地址上自测一次：`curl https://<隧道域名>/health` 必须返回 200 且 body 为 JSON",
        "4. 平台侧：新建 API 工具集，Base URL 填隧道域名（不带路径、不带尾斜杠）",
        "5. 按本报告 §2 的「调试样例值」逐个创建能力项并点调试；`request_response` 用 `action=none`",
        "6. 五个能力项全部显示「成功」后，再进入工作流编排（`week1_workflow_design.md` §3）",
        "",
        "## 五、本报告证明不了什么",
        "",
        "- 平台云端到本机的**真实网络可达性**（取决于隧道，不是本机能力）；",
        "- 平台自己的超时/体积/重试策略（本报告用的是保守阈值，不是平台真实限制）；",
        "- 平台对返回体字段的解析行为（如它是否只取部分字段）。",
        "",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")

    ok = all(p.passed for p in plans) and all(c.ok for c in openapi_checks)
    for p in plans:
        print(f"[{'PASS' if p.passed else 'FAIL'}] {p.method:4s} {p.path:26s} {p.status_code} "
              f"{p.latency_ms:6.1f}ms {p.body_kb:5.1f}KB")
    for c in openapi_checks:
        print(f"[{'PASS' if c.ok else 'FAIL'}] {c.name} — {c.detail}")
    print(f"\n报告：{OUT}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
