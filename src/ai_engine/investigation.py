"""多轮自主调查会话骨架（Week 1）。

它解决的是"Agent 到底怎么决定下一步查什么"这个问题：
**不是把工具固定串行跑一遍**，而是每拿到一次工具返回就重新判断，
例如——
* 查日志零结果 → 换更宽的检索条件重试，而不是立刻宣布"没有攻击"；
* 查到认证爆破 → 去查账号基线与资产重要性，判断是广域扫描还是定向打点；
* 查到利用阶段 → 去检索处置知识卡，而不是凭模型记忆给建议；
* 出现外连行为或证据链成型 → 提交处置（高危动作只登记待审批）；
* 连续两轮没有新证据 / 达到轮次上限 → 收束，且结论必须标"证据不足"而不是"安全"。

在恒脑平台上，这套判断逻辑由【模型节点】承担（模型自主决定调用哪个工具）；
本模块是同一套判断的可执行参照实现，用途有三：
1. 本地可复现地验证"决策依赖返回结果"这一性质（见 tests/test_investigation.py）；
2. 给【模型节点】的系统提示词提供决策清单（见 design/hengnao_workflows/week1_workflow_design.md）；
3. 将来若改用【自规划节点】+ MCP，可直接作为规划器骨架。

注意：本模块**不做**任何真实网络/数据库调用，默认执行器走的是 Mock 工具服务。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# 允许以 `python src/ai_engine/investigation.py` 单独运行
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from ai_engine.results_schema import AgentResults, build_insufficient_evidence  # noqa: E402

#: 内部/保留地址段，不当作攻击源
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.")
_PRIVATE_172 = tuple(f"172.{i}." for i in range(16, 32))

MAX_ROUNDS_DEFAULT = 8
MAX_EMPTY_STREAK = 2  # 连续两轮零新增证据即收束


@dataclass
class ToolCall:
    """一次待执行的工具调用，``why`` 记录决策理由（可解释性）。"""

    tool: str
    args: dict[str, Any]
    why: str


@dataclass
class InvestigationSession:
    """一次调查会话的状态机。"""

    case_id: str
    seed_src_ip: Optional[str] = None
    seed_trace_id: Optional[str] = None
    seed_asset_id: Optional[str] = None
    max_rounds: int = MAX_ROUNDS_DEFAULT
    tools: Optional[dict[str, Callable[[dict[str, Any]], dict[str, Any]]]] = None

    # -- 运行期状态 --
    round: int = 0
    calls: list[ToolCall] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    logs: list[dict[str, Any]] = field(default_factory=list)
    empty_streak: int = 0
    no_new_evidence_streak: int = 0
    seen: dict[str, bool] = field(default_factory=dict)  # 已执行过的工具/查询形态
    findings: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.seen.setdefault("query_logs", False)
        self.seen.setdefault("query_logs_broadened", False)
        self.seen.setdefault("get_context", False)
        self.seen.setdefault("search_knowledge", False)
        self.seen.setdefault("request_response", False)

    # ------------------------------------------------------------------
    # 决策
    # ------------------------------------------------------------------

    def decide(self) -> Optional[ToolCall]:
        """返回下一步该做什么；返回 ``None`` 表示调查应当收束。"""
        if self.round >= self.max_rounds:
            return None
        if self.no_new_evidence_streak >= MAX_EMPTY_STREAK:
            return None

        # 1) 还没查过日志：先取全链路日志
        if not self.seen["query_logs"]:
            if self.seed_trace_id:
                args = {"case_id": self.case_id, "trace_id": self.seed_trace_id, "limit": 50}
                why = "以线索 trace_id 拉取同一攻击故事链的全阶段日志"
            elif self.seed_src_ip:
                args = {"case_id": self.case_id, "src_ip": self.seed_src_ip, "time_window": "1h", "limit": 50}
                why = "以可疑源 IP 拉取近 1 小时关联日志"
            elif self.seed_asset_id:
                args = {"case_id": self.case_id, "dest_ip": self.seed_asset_id, "limit": 50}
                why = "缺少源侧线索，先从受害资产侧反查日志"
            else:
                return None  # 连线索都没有，交人工提供
            return ToolCall("query_logs", args, why)

        # 2) 上一轮零结果：放宽条件重试一次（不要立刻判"无攻击"）
        if self.empty_streak == 1 and not self.seen["query_logs_broadened"]:
            args = {"case_id": self.case_id, "limit": 100}
            if self.seed_src_ip:
                args["src_ip"] = self.seed_src_ip
                args["time_window"] = "24h"
            elif self.seed_asset_id:
                args["dest_ip"] = self.seed_asset_id
                args["time_window"] = "24h"
            else:
                args["log_source"] = "nginx_access"
            return ToolCall(
                "query_logs",
                args,
                "上一轮零结果，把时间窗放宽到 24h 再查一次：零结果既可能是没有攻击，也可能是线索时间窗不对",
            )

        stages = self._stage_counts()

        # 3) 有日志但还没有账号/资产上下文：判断"广域扫描"还是"定向打点"必须靠基线
        if not self.seen["get_context"] and (stages.get("brute_force") or self._first_user()):
            args: dict[str, Any] = {}
            if self._first_user():
                args["user"] = self._first_user()
            if self.seed_asset_id or self._first_asset():
                args["asset_id"] = self.seed_asset_id or self._first_asset()
            if args:
                return ToolCall(
                    "get_context",
                    args,
                    "已见到认证/账号相关行为，需用行为基线与资产重要性区分定向打点与正常运维",
                )

        # 4) 已见到利用或外连：检索处置知识卡，别凭记忆给建议
        if not self.seen["search_knowledge"] and (
            stages.get("exploitation") or stages.get("c2_callback")
        ):
            return ToolCall(
                "search_knowledge",
                {"query": self._knowledge_query(), "limit": 5},
                "已出现利用/外连阶段，检索知识卡与已确认案例作为处置依据",
            )

        # 调查只生成建议；处置申请由人工审批后的独立步骤调用。
        return None  # 收束

    # ------------------------------------------------------------------
    # 观察（工具返回 → 状态更新）
    # ------------------------------------------------------------------

    def observe(self, call: ToolCall, result: dict[str, Any]) -> None:
        """记录一次工具返回并更新会话状态。"""
        self.round += 1
        self.calls.append(call)
        self.results.append(result)
        self.seen[call.tool] = True
        if call.tool == "query_logs" and call.args.get("time_window") == "24h":
            self.seen["query_logs_broadened"] = True

        new_evidence = 0
        if call.tool == "query_logs":
            items = result.get("items") or []
            if not items:
                self.empty_streak += 1
            else:
                self.empty_streak = 0
            for item in items:
                log_id = item.get("log_id")
                if log_id and log_id not in self.evidence_ids:
                    self.evidence_ids.append(log_id)
                    new_evidence += 1
                self.logs.append(item)
        elif call.tool == "get_context":
            self.findings["context"] = {
                "user_profile": result.get("user_profile"),
                "asset_context": result.get("asset_context"),
                "total": (result.get("meta") or {}).get("total", 0),
            }
        elif call.tool == "search_knowledge":
            self.findings["knowledge"] = result.get("items") or []
        elif call.tool == "request_response":
            self.findings["response"] = result

        if call.tool == "query_logs":
            self.no_new_evidence_streak = self.no_new_evidence_streak + 1 if new_evidence == 0 else 0

    # ------------------------------------------------------------------
    # 执行（默认走 Mock 工具服务）
    # ------------------------------------------------------------------

    def _execute(self, call: ToolCall) -> dict[str, Any]:
        executor = self.tools or default_tools()
        fn = executor.get(call.tool)
        if fn is None:
            raise KeyError(f"未注册的工具：{call.tool}")
        return fn(call.args)

    def run(self) -> AgentResults:
        """按决策循环执行直到收束，返回结构化结论。"""
        while True:
            call = self.decide()
            if call is None:
                break
            self.observe(call, self._execute(call))
        return self.build_results()

    # ------------------------------------------------------------------
    # 结论
    # ------------------------------------------------------------------

    def build_results(self) -> AgentResults:
        stages = self._stage_counts()
        attacker_ip = self._guess_attacker_ip()
        victim_asset = self.seed_asset_id or self._first_asset() or "unknown"

        if not self.evidence_ids:
            return build_insufficient_evidence(
                case_id=self.case_id,
                attacker_ip=attacker_ip or "unknown",
                victim_asset=victim_asset,
                evidence_log_ids=[],
                missing=[
                    "本次调查未取得任何可引用日志（query_logs 两轮均为零结果）",
                    "无法确认攻击源与受害资产，需人工核对日志采集链路与时间窗",
                ],
                summary="两轮放宽条件后仍无日志命中，无法判断是否存在攻击，未作恶意结论。",
            )

        malicious = bool(stages.get("exploitation") or stages.get("c2_callback")) or (
            stages.get("brute_force", 0) >= 3
        )
        if not malicious:
            missing = []
            if self.round >= self.max_rounds:
                missing.append("调查达到轮次上限，尚不能确认不存在攻击")
            if self.no_new_evidence_streak >= MAX_EMPTY_STREAK:
                missing.append("连续查询无新增证据，尚不能排除攻击")
            if any(log.get("attack_stage_hint") != "benign" for log in self.logs):
                missing.append("现有日志包含可疑行为或阶段不明，证据不足以判定攻击是否成立")
            if missing:
                return build_insufficient_evidence(
                    case_id=self.case_id,
                    attacker_ip=attacker_ip or "unknown",
                    victim_asset=victim_asset,
                    evidence_log_ids=list(self.evidence_ids),
                    missing=missing,
                )
            return AgentResults(
                case_id=self.case_id,
                is_malicious=False,
                attack_type="none",
                risk_level="LOW",
                attacker_ip=attacker_ip or "unknown",
                victim_asset=victim_asset,
                evidence_log_ids=list(self.evidence_ids),
                attack_chain_summary="已查日志中未发现利用或外连行为，仅见正常访问，判定为无恶意行为。",
                recommended_action="none",
                requires_human_approval=False,
                unknown_items=self._unknown_items(),
            )

        risk = "HIGH"
        if stages.get("c2_callback"):
            risk = "CRITICAL" if stages.get("exploitation") else "HIGH"
        elif stages.get("exploitation", 0) == 0:
            risk = "MEDIUM"

        action = "block_ip" if risk in {"HIGH", "CRITICAL"} else "block_ip_short_term"
        return AgentResults(
            case_id=self.case_id,
            is_malicious=True,
            attack_type=self._attack_type(stages),
            risk_level=risk,  # type: ignore[arg-type]
            attacker_ip=attacker_ip or "unknown",
            victim_asset=victim_asset,
            evidence_log_ids=list(self.evidence_ids),
            attack_chain_summary=self._chain_summary(stages, attacker_ip, victim_asset),
            recommended_action=action,  # type: ignore[arg-type]
            requires_human_approval=True,  # 封禁类动作一律需人工审批
            unknown_items=self._unknown_items(),
        )

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _stage_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for log in self.logs:
            stage = log.get("attack_stage_hint") or "benign"
            counts[stage] = counts.get(stage, 0) + 1
        return counts

    def _first_user(self) -> Optional[str]:
        return next((log.get("user") for log in self.logs if log.get("user")), None)

    def _first_asset(self) -> Optional[str]:
        return next((log.get("asset_id") for log in self.logs if log.get("asset_id")), None)

    def _is_external(self, ip: str | None) -> bool:
        if not ip:
            return False
        if ip.startswith(_PRIVATE_PREFIXES) or ip.startswith(_PRIVATE_172):
            return False
        return True

    def _guess_attacker_ip(self) -> Optional[str]:
        """取出现次数最多的外部源 IP（排除内网/保留地址）。"""
        counter: dict[str, int] = {}
        for log in self.logs:
            if (log.get("attack_stage_hint") or "benign") == "benign":
                continue
            ip = log.get("src_ip")
            if self._is_external(ip):
                counter[ip] = counter.get(ip, 0) + 1
        if not counter:
            return None
        return max(counter.items(), key=lambda kv: kv[1])[0]

    def _knowledge_query(self) -> str:
        stages = self._stage_counts()
        if stages.get("c2_callback"):
            return "主机向境外可疑地址外连（疑似 C2 回连）如何研判与处置"
        if stages.get("exploitation"):
            return "SQL 注入绕过认证成功后如何处置，是否需要短时封禁 IP"
        return "账号爆破攻击如何研判与处置"

    def _attack_type(self, stages: dict[str, int]) -> str:
        """按时间顺序组装攻击类型名，最新阶段写最前。

        例：爆破 → 注入 生成 ``SQL_Injection_After_Brute_Force``；
        再加外连则生成 ``C2_Callback_After_SQL_Injection_After_Brute_Force``。
        """
        parts: list[str] = []
        if stages.get("brute_force"):
            parts.append("Brute_Force")
        if stages.get("exploitation"):
            parts.append("SQL_Injection")
        if stages.get("c2_callback"):
            parts.append("C2_Callback")
        return "_After_".join(reversed(parts)) if parts else "Unknown_Attack"

    def _chain_summary(self, stages: dict[str, int], attacker: str | None, asset: str) -> str:
        seg: list[str] = []
        if stages.get("brute_force"):
            seg.append(f"对 {asset} 的登录端点发起 {stages['brute_force']} 次账号爆破")
        if stages.get("exploitation"):
            seg.append(f"随后以注入类载荷发起 {stages['exploitation']} 次利用尝试")
        if stages.get("c2_callback"):
            seg.append(f"并从 {asset} 向外部地址发起 {stages['c2_callback']} 次可疑外连")
        if not seg:
            seg.append("观察到可疑行为但阶段不明")
        return f"攻击源 {attacker or 'unknown'} " + "，".join(seg) + "。"

    def _unknown_items(self) -> str:
        missing: list[str] = []
        if self._stage_counts().get("exploitation") or self._stage_counts().get("c2_callback"):
            missing.append("处置建议尚未经过人工审批，未提交处置申请")
        if not self.findings.get("context") or not (self.findings["context"].get("total") or 0):
            missing.append("未取得账号行为基线与资产重要性上下文")
        if not self.findings.get("knowledge"):
            missing.append("未检索到匹配的处置知识卡，处置建议缺少标准依据")
        resp = self.findings.get("response") or {}
        if resp.get("status") == "approval_required":
            missing.append(f"处置单 {resp.get('approval_id')} 仍在待审批，处置尚未生效")
        if not missing:
            return ""
        return "；".join(missing) + "。"


# ---------------------------------------------------------------------------
# 默认执行器：转发到 Mock 工具服务（与 HTTP / MCP 同一份实现）
# ---------------------------------------------------------------------------


def default_tools() -> dict[str, Callable[[dict[str, Any]], dict[str, Any]]]:
    from api import app as api_app  # 延迟导入，避免测试注入时被强依赖
    from api.schemas import (
        GetContextRequest,
        QueryLogsRequest,
        RequestResponseRequest,
        SearchKnowledgeRequest,
    )

    def _unwrap(result: Any) -> dict[str, Any]:
        if hasattr(result, "model_dump"):
            return result.model_dump()
        # JSONResponse（错误分支）
        import json

        return json.loads(result.body.decode("utf-8"))

    return {
        "query_logs": lambda a: _unwrap(api_app.query_logs(QueryLogsRequest(**a))),
        "get_context": lambda a: _unwrap(api_app.get_context(GetContextRequest(**a))),
        "search_knowledge": lambda a: _unwrap(api_app.search_knowledge(SearchKnowledgeRequest(**a))),
        "request_response": lambda a: _unwrap(
            api_app.request_response(RequestResponseRequest(**a))
        ),
    }


if __name__ == "__main__":  # pragma: no cover - 手动演示
    from api.evidence_check import registry

    registry.clear()
    session = InvestigationSession(
        case_id="EVAL-CHAIN-001",
        seed_trace_id="CHAIN-ATTACK-01",
        seed_asset_id="web-prod-01",
    )
    final = session.run()
    print(f"轮次：{session.round}，证据：{len(session.evidence_ids)} 条")
    for c in session.calls:
        print(f"  - {c.tool}: {c.why}")
    print(final.model_dump_json(indent=2))
