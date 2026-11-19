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
import ipaddress
from dataclasses import dataclass, field
import datetime as _dt
from typing import Any, Callable, Optional

# 允许以 `python src/ai_engine/investigation.py` 单独运行
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from ai_engine.redaction import redact_text
from ai_engine import attack_types  # noqa: E402
from ai_engine import behavior_rules  # noqa: E402
from ai_engine.results_schema import AgentResults, build_insufficient_evidence  # noqa: E402

#: 内部/保留地址段，不当作攻击源
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.")
_PRIVATE_172 = tuple(f"172.{i}." for i in range(16, 32))

MAX_ROUNDS_DEFAULT = 8

#: 需要维护窗口佐证的账号类型：运维/服务账号在受管资产上的操作必须有窗口依据。
#: 普通业务账号（application_admin 等）不在此列，避免给正常访问强加运维约束。
WINDOW_REQUIRED_ACCOUNT_TYPES = {"legit_operator", "service"}
MAX_EMPTY_STREAK = 2  # 连续两轮零新增证据即收束
VULNERABILITY_SCANNER_MARKERS = (
    "acunetix", "nuclei/", "nikto", "dirsearch", "masscan", "nmap", "nessus",
    "openvas", "burp", "owasp zap", "qualys", "arachni", "w3af",
)


def _ip_matches_scope(address: str, scopes: list[str]) -> bool:
    """按 IP 或 CIDR 检查来源地址；无效配置项不匹配。"""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for scope in scopes:
        try:
            if ip in ipaddress.ip_network(scope, strict=False):
                return True
        except ValueError:
            continue
    return False


#: 知识卡调查步骤里出现的日志源说法 → 契约 log_source。
#: 用于把 ``investigation_steps`` 变成**可执行的补查动作**，而不是只做展示。
_LOG_SOURCE_HINTS: dict[str, tuple[str, ...]] = {
    "nginx_access": ("nginx", "web 访问", "web访问", "访问日志", "request_uri"),
    "auth_log": ("auth", "认证日志", "认证事件", "登录日志", "失败登录"),
    "zeek_conn": ("zeek_conn", "连接记录", "连接日志", "网络连接", "外连"),
    "zeek_http": ("zeek_http", "http 请求", "http请求", "请求方法", "响应状态"),
    "zeek_dns": ("zeek_dns", "dns"),
}

#: 错题卡 ``error_revision_note`` → 复查项。关键词命中即执行对应复查，
#: 复查结果写进轨迹（哪张卡、因为哪句话、改了什么判断）。
#: 这里只做"路由"，具体判断仍由日志事实决定，避免把提示词当结论。
_REVISION_RULES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (
        ("输错", "失败次数", "请求频率", "后续登录"),
        "login_retry_pattern",
        "按错题提示复查：失败次数/间隔节奏/后续是否登录成功，避免仅凭失败次数定性",
    ),
    (
        ("周期", "单一目的", "连接频率", "payload"),
        "outbound_needs_corroboration",
        "按错题提示复查：外连须由目的地址、周期性、连接模式共同支撑，不以端口或流量单独定性",
    ),
    (
        ("账户数量", "多账号", "撞库", "多个账户"),
        "multi_account_bruteforce",
        "按错题提示复查：多账号连续失败同样可能是爆破，需结合来源与成功登录判断",
    ),
    (
        ("正常业务", "备份", "合法", "白名单"),
        "benign_context_check",
        "按错题提示复查：先排除备份/合法运维/授权扫描等正常业务，再定性",
    ),
)


@dataclass
class ToolCall:
    """一次待执行的工具调用，``why`` 记录决策理由（可解释性）。

    ``triggered_by`` 记录"这次调用是谁要求的"：知识卡的哪一步、或哪条错题提示。
    轨迹据此回答"哪张卡触发了哪次补查"，而不是事后推测。
    """

    tool: str
    args: dict[str, Any]
    why: str
    triggered_by: Optional[dict[str, Any]] = None


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
    #: 已按 log_source 补查过的来源（知识卡驱动补查时避免重复）
    queried_sources: set[str] = field(default_factory=set)
    #: 知识检索状态：not_called / ok / zero_hit / failed / degraded
    retrieval_state: str = "not_called"
    #: 检索流程：降级模式、后端、原因（区分"失败"与"降级"）
    retrieval_meta: dict[str, Any] = field(default_factory=dict)
    #: 已执行的知识卡补查（供轨迹展示"哪张卡触发了哪次补查"）
    card_triggered_queries: list[dict[str, Any]] = field(default_factory=list)
    #: 错题卡复查记录
    revision_checks: list[dict[str, Any]] = field(default_factory=list)

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
            if self.seed_trace_id:
                return None  # 精确场景不存在，不能转为全库扫描
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
        if not self.seen["get_context"] and (stages.get("brute_force") or self._first_user() or self._first_asset()):
            args: dict[str, Any] = {}
            if self._first_user():
                args["user"] = self._first_user()
            if self.seed_asset_id or self._first_asset():
                args["asset_id"] = self.seed_asset_id or self._first_asset()
            # 带上被调查行为的时间，服务端才能判断是否落在维护窗口内
            focus = self._focus_time()
            if focus:
                args["at_time"] = focus
            if args:
                return ToolCall(
                    "get_context",
                    args,
                    "已见到认证/账号相关行为，需用行为基线与资产重要性区分定向打点与正常运维",
                )

        # 4) 结论前必须取知识依据：有可疑迹象、或已经查过账号/资产上下文时都要检索一次
        if not self.seen["search_knowledge"] and (self._suspicion() or self.seen["get_context"]):
            kind = self._leading_kind()
            args: dict[str, Any] = {
                "query": self._knowledge_query(kind),
                "limit": 5,
                # 带上当前 case_id：检索端据此排除同案案例，避免把答案带进调查
                "case_id": self.case_id,
            }
            category = attack_types.knowledge_category(kind) if kind else None
            if category:
                args["attack_category"] = category
            return ToolCall(
                "search_knowledge",
                args,
                "已出现可疑行为，先取安全知识卡与已确认案例：用卡里的调查步骤决定补查哪个日志源，"
                "用错题修订提示复查易误判点",
            )

        # 5) 按知识卡的 investigation_steps 定向补查尚未核对的日志源
        supplement = self._card_driven_query()
        if supplement is not None:
            return supplement

        # 调查只生成建议；处置申请由人工审批后的独立步骤调用。
        return None  # 收束

    # ------------------------------------------------------------------
    # 决策辅助
    # ------------------------------------------------------------------

    def _suspicion(self) -> bool:
        """是否已有"值得查知识"的迹象。

        只看日志事实（强特征、认证失败、对外连接、异常状态码、非 benign 标注），
        不看结论——此时还没到下结论的时候。
        """
        facts = self._behavior_facts()
        if facts["has_attack"] or facts["impact"]:
            return True
        if facts["auth"].failure_logs:
            return True
        if any(group.signals.get("connections", 0) >= 2 for group in facts["outbound"]):
            return True
        return any(
            (log.get("attack_stage_hint") or "unknown") != "benign"
            or int(log.get("status_code") or 0) >= 400
            for log in self.logs
        )

    def _leading_kind(self) -> Optional[str]:
        """当前最值得检索的攻击类别（用于收窄知识卡范围）。"""
        facts = self._behavior_facts()
        codes = set(facts.get("kinds") or [])
        for code in reversed(self._TYPE_ORDER):
            if code in codes:
                return code
        if facts["auth"].failure_logs:
            return "Brute_Force"
        if any(group.corroborated for group in facts["outbound"]):
            return "C2_Exfiltration"
        if facts.get("authorized_scans"):
            return "Scan"
        # 行为事实还没成形时，退一步用人工阶段标注决定"先查哪类知识"。
        # 这里只影响**检索方向**（收窄卡片范围），标注值不会进入结论或 attack_type；
        # 且只对语义无歧义的阶段生效（exploitation 可能是任意一类，不做收窄）。
        stages = self._stage_counts()
        if stages.get("c2_callback"):
            return "C2_Exfiltration"
        if stages.get("brute_force"):
            return "Brute_Force"
        return None

    def _card_driven_query(self) -> Optional[ToolCall]:
        """把知识卡的调查步骤翻译成一次定向补查。

        每张卡都会声明 ``applicable_log_sources`` 并在 ``investigation_steps`` 里说清
        "去哪个日志源看什么"。本方法按卡得分顺序找第一条"尚未定向查过"的日志源，
        发出的查询把 ``triggered_by`` 写成卡片编号与步骤序号，轨迹据此可追溯。
        预算最多 2 次，避免把轮次耗在重复查询上。
        """
        if len(self.card_triggered_queries) >= 2:
            return None
        for card in self.findings.get("knowledge") or []:
            steps = card.get("investigation_steps") or []
            declared = [str(item) for item in (card.get("applicable_log_sources") or [])]
            for index, step in enumerate(steps):
                text = str(step)
                for source, hints in _LOG_SOURCE_HINTS.items():
                    if source in self.queried_sources:
                        continue
                    if not any(hint.lower() in text.lower() for hint in hints):
                        continue
                    args: dict[str, Any] = {
                        "case_id": self.case_id,
                        "log_source": source,
                        "limit": 50,
                    }
                    if self.seed_trace_id:
                        args["trace_id"] = self.seed_trace_id
                        args["time_window"] = "2h"
                    elif self.seed_src_ip:
                        args["src_ip"] = self.seed_src_ip
                        args["time_window"] = "24h"
                    elif self.seed_asset_id:
                        args["dest_ip"] = self.seed_asset_id
                        args["time_window"] = "24h"
                    why = (
                        f"知识卡 {card.get('card_id')} 调查步骤 {index + 1}「{text[:60]}」"
                        f"要求补查 {source}；定向复核比首轮 trace 级查询更细，"
                        "可暴露被截断或缺失的日志源"
                    )
                    return ToolCall(
                        "query_logs",
                        args,
                        why,
                        triggered_by={
                            "card_id": card.get("card_id"),
                            "card_type": card.get("card_type"),
                            "step_index": index + 1,
                            "step": text,
                            "declared_log_sources": declared,
                            "log_source": source,
                        },
                    )
        return None

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
                    # 同一场景会被多次查询（首轮 trace 级 + 知识卡驱动的定向补查），
                    # 重复条目会让"失败次数/连接次数"这类计数翻倍，必须按 log_id 去重
                    self.logs.append(item)
                    new_evidence += 1
            source = str(call.args.get("log_source") or "all")
            if source != "all":
                self.queried_sources.add(source)
            if call.triggered_by:
                # 记录"哪张卡的第几步触发了这次补查"，并如实标注是否补到新日志
                self.card_triggered_queries.append(
                    {
                        "round": self.round,
                        **call.triggered_by,
                        "returned_total": len(items),
                        "new_log_ids": new_evidence,
                        "status": "ok" if items else "empty",
                    }
                )
                self.findings["card_triggered_queries"] = self.card_triggered_queries
        elif call.tool == "get_context":
            self.findings["context"] = {
                "user_profile": result.get("user_profile"),
                "asset_context": result.get("asset_context"),
                "total": (result.get("meta") or {}).get("total", 0),
            }
        elif call.tool == "search_knowledge":
            self.findings["knowledge_status"] = result
            self.findings["knowledge"] = result.get("items") or []
            self._record_retrieval_state(result)
        elif call.tool == "request_response":
            self.findings["response"] = result

        if call.tool == "query_logs":
            self.no_new_evidence_streak = self.no_new_evidence_streak + 1 if new_evidence == 0 else 0

    def _record_retrieval_state(self, result: dict[str, Any]) -> None:
        """把检索结果分成四态：成功 / 零命中 / 降级 / 失败。

        这三类必须分开，否则"检索挂了"会被读成"知识库没有这条知识"，
        进而把无依据的结论当成有依据。
        """
        items = result.get("items") or []
        meta = result.get("meta") or {}
        degraded = bool(meta.get("degraded"))
        if result.get("code"):
            state = "failed"
        elif degraded:
            state = "degraded" if items else "degraded_zero_hit"
        elif not items:
            state = "zero_hit"
        else:
            state = "ok"
        self.retrieval_state = state
        self.retrieval_meta = {
            "state": state,
            "retrieval_mode": meta.get("retrieval_mode"),
            "backend": meta.get("dataset"),
            "degraded": degraded,
            "hits": len(items),
            "error_code": result.get("code"),
            "error_message": redact_text(str(result.get("message") or "")) if result.get("code") else None,
            "notes": meta.get("notes") or [],
        }
        self.findings["retrieval"] = self.retrieval_meta

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

    # ------------------------------------------------------------------
    # 行为事实（与人工标签无关）
    # ------------------------------------------------------------------

    #: 常见 C2 回连端口；仅作为"外连可疑"的辅助信号，不单独定性
    _C2_PORTS = {4444, 5555, 1337, 6667, 8888, 9001}

    @staticmethod
    def _event_time(log: dict[str, Any]) -> _dt.datetime:
        from api.datasource import _parse_ts
        return _parse_ts(log.get("timestamp")) or _dt.datetime.min.replace(tzinfo=_dt.timezone.utc)

    @staticmethod
    def _interactive_login(log: dict[str, Any]) -> bool:
        action = str(log.get("action_or_method") or "").lower()
        target = str(log.get("uri_or_target") or "").lower()
        return ("ssh" in action or "interactive" in action or
                (log.get("log_source") == "auth_log" and target == "sshd"
                 and action in {"login_success", "session_opened"}))

    def _c2_signal(self, log: dict[str, Any]) -> bool:
        """只把明确的回连行为描述作为线索，端口与人工标签不证明 C2。"""
        payload = str(log.get("payload_summary") or "").lower()
        fields = dict(part.strip().split("=", 1) for part in payload.split(";") if "=" in part)
        if fields.get("conn_state") != "sf" or "beacon" not in payload or any(word in payload for word in ("disabled", "health", "backup", "approved")):
            return False
        if not self._is_external(log.get("dest_ip")) or log.get("log_source") not in {"zeek_conn", "zeek_http"}:
            return False
        # 回连必须关联同一主机此前的明确 Webshell 行为，单独心跳不定性。
        from urllib.parse import urlsplit
        from ipaddress import ip_address
        import re
        try:
            destination = ip_address(str(log.get("dest_ip")))
        except ValueError:
            return False
        for prior in self.logs:
            if not (prior.get("dest_ip") == log.get("src_ip")
                    and self._event_time(prior) < self._event_time(log)
                    and prior.get("log_source") in {"nginx_access", "zeek_http"}
                    and 200 <= (prior.get("status_code") or 0) < 300):
                continue
            text = str(prior.get("payload_summary") or "")
            # URL 与括号地址先整体消费，不能再从 IPv6 内提取 IPv4 尾部。
            tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>;]+|\[[0-9a-fA-F:.]+\](?::[0-9]+)?|(?<![\w:.])[0-9a-fA-F:.]+(?![\w:.])", text)
            addresses = set()
            for token in tokens:
                try:
                    if "://" in token or token.startswith("["):
                        host = urlsplit(token if "://" in token else "//" + token).hostname
                        addresses.add(ip_address(host))
                    else:
                        try:
                            addresses.add(ip_address(token))
                        except ValueError:
                            # 裸 IPv4:port；完整裸 IPv6 已由上一步解析。
                            addresses.add(ip_address(urlsplit("//" + token).hostname))
                except ValueError:
                    continue
            if destination not in addresses:
                continue
            try:
                path = urlsplit(str(prior.get("uri_or_target") or "")).path
            except ValueError:
                errors = self.findings.setdefault("request_target_errors", {})
                errors[str(prior.get("log_id") or "unknown")] = "请求目标解析失败，未用于 C2 关联"
                continue
            if path.lower().rsplit("/", 1)[-1] in {"shell.php", "c99.php"}:
                return True
        return False

    def _behavior_facts(self) -> dict[str, Any]:
        """从日志事实提取攻击证据，**不以人工阶段标签为依据**。

        分层（V2）：

        * ``attack``：命中**强特征**（注入语法、攻击工具 UA、webshell 路径、
          参数枚举、多账号爆破、被多信号确认的可疑外连）。只有这些才支撑"攻击成立"；
        * ``impact``：攻击成立后的影响迹象——会话被异地复用、失陷主机外连、
          攻击源批量导出数据。它们不新增攻击类别，但决定风险与证据；
        * ``leads``：弱特征或已被解释的行为（低频输错口令后正常登录）；
        * ``unexplained``：带可疑标记却无法用任何模式解释的行为，是弃权的依据。

        HTTP 2xx 只表示请求被处理过，**不能单独**证明利用成功；外部 IP 只是来源属性，
        不参与定性。``auth`` / ``outbound`` 分别是认证与外连的结构化事实，供结论复用。
        """
        auth = behavior_rules.assess_authentication(self.logs)
        outbound = behavior_rules.assess_outbound(self.logs)
        corroborated = [group for group in outbound if group.corroborated]
        c2_group_ids = {
            str(log.get("log_id"))
            for group in corroborated
            for log in group.logs
            if log.get("log_id")
        }
        sessions = behavior_rules.detect_session_reuse(self.logs)
        takeover_ids = {
            str(log.get("log_id")) for item in sessions for log in item["logs"] if log.get("log_id")
        }
        pivot_ids = {
            str(log.get("log_id")) for item in sessions for log in item["pivot_logs"] if log.get("log_id")
        }
        enumerations = [
            item
            for item in behavior_rules.detect_parameter_enumeration(self.logs)
            if behavior_rules.is_external_ip(item["src_ip"])
        ]
        enum_ids = {str(log.get("log_id")) for item in enumerations for log in item["logs"]}

        failure_ids = {str(log.get("log_id")) for log in auth.failure_logs if log.get("log_id")}
        brute_sources = auth.brute_sources
        brute_failure_ids = {
            str(log["log_id"]) for log in auth.failure_logs
            if log.get("log_id") and log.get("src_ip") in brute_sources
        }
        success_ids = {str(log.get("log_id")) for log in auth.success_logs if log.get("log_id")}
        retry_ids = (failure_ids | success_ids) if auth.benign_retry else set()

        attack: list[dict[str, Any]] = []
        c2_logs: list[dict[str, Any]] = []
        responded: list[dict[str, Any]] = []
        impact: list[dict[str, Any]] = []
        leads: list[dict[str, Any]] = []
        unexplained: list[dict[str, Any]] = []
        authorized_scans: list[dict[str, Any]] = []
        kinds: list[str] = []
        #: 每条日志各自命中的类别，供分类/摘要/证据回溯
        log_kinds: dict[str, list[str]] = {}
        impact_ids: set[str] = set()

        for log in self.logs:
            log_id = str(log.get("log_id") or "")
            text = " ".join(
                str(log.get(k) or "")
                for k in ("uri_or_target", "payload_summary", "user_agent")
            )
            signals = attack_types.classify_signals(text)
            stage = self._stage_of(log)
            status = log.get("status_code") or 0
            c2 = self._c2_signal(log)

            strong = [k for k in signals["strong"] if k not in {"Brute_Force", "C2_Exfiltration"}]
            # ``cmd=cat /etc/passwd`` 是 webshell 执行命令的参数，不是文件读取路径；
            # 把它算成"目录遍历"会把上传与遍历混为一类（V1 CASE-02 的分类偏差来源）。
            if "cmd=" in text.lower() and "Path_Traversal_Privilege" in strong:
                strong = [kind for kind in strong if kind != "Path_Traversal_Privilege"]

            scanner = self._is_authorized_scan_candidate(log)
            if scanner and not strong:
                strong.append("Scan")
            if auth.brute_force and (log_id in brute_failure_ids or log_id in success_ids):
                # 只有达到爆破门槛的失败才算攻击；低频人工输错走下面的"已解释"分支
                strong.append("Brute_Force")
            if c2 or log_id in c2_group_ids:
                strong.append("C2_Exfiltration")
            if log_id in enum_ids:
                strong.append("Path_Traversal_Privilege")

            policy_window = self._authorized_scan_window(log, strong) if scanner else None
            if policy_window:
                authorized_scans.append({"log": log, "window": policy_window})
                leads.append(log)
                continue
            # 扫描器收到明确拒绝/未命中响应时，只能证明发生了探测；不能把被拒绝的
            # 利用载荷当成已成立的 XSS、遍历或上传攻击。
            if scanner and isinstance(status, int) and 400 <= status < 500:
                strong = ["Scan"]

            strong = list(dict.fromkeys(strong))
            if strong:
                attack.append(log)
                kinds.extend(strong)
                if log_id:
                    log_kinds[log_id] = strong
                established = "conn_state=sf" in [
                    part.strip() for part in str(log.get("payload_summary") or "").lower().split(";")
                ]
                if "C2_Exfiltration" in strong and (established or self._is_external(log.get("dest_ip"))):
                    c2_logs.append(log)
                elif 200 <= status < 300 and any(
                    kind in strong
                    for kind in {"SQL_Injection", "XSS", "Path_Traversal_Privilege", "Malicious_Upload"}
                ):
                    # 强特征 + 2xx：说明攻击请求得到了响应，**不等于利用成功**
                    responded.append(log)
            elif log_id in takeover_ids or log_id in pivot_ids:
                impact.append(log)
                impact_ids.add(log_id)
            elif log_id in retry_ids:
                # 已被"低频输错→成功登录→正常业务"模式解释，不再作为待解释行为
                leads.append(log)
            elif signals["weak"]:
                # 弱特征：只是线索。只有当日志本身还带可疑标记（非 benign 阶段 / 5xx）才需解释
                if stage != "benign" or status >= 500:
                    unexplained.append(log)
                else:
                    leads.append(log)
            elif stage != "benign" or status >= 500:
                unexplained.append(log)

        # 攻击源在利用后批量导出数据：只对该来源生效，避免把正常报表算成外泄
        attackers = {
            str(log.get("src_ip"))
            for log in attack
            if behavior_rules.is_external_ip(log.get("src_ip"))
        }
        for log in behavior_rules.detect_bulk_export(self.logs, attackers):
            log_id = str(log.get("log_id") or "")
            if log_id and log_id not in log_kinds and log_id not in impact_ids:
                impact.append(log)
                impact_ids.add(log_id)

        benign_pattern = self._benign_retry_pattern(auth, bool(attack), bool(corroborated), sessions)

        return {
            "attack": attack,
            "c2": c2_logs,
            "responded": responded,
            "impact": impact,
            "leads": leads,
            "unexplained": unexplained,
            "authorized_scans": authorized_scans,
            "kinds": kinds,
            "log_kinds": log_kinds,
            "has_attack": bool(attack),
            # 确认影响：外连建立、会话被复用、失陷后对外通信或批量导出
            "has_confirmed_impact": bool(c2_logs) or bool(impact),
            "auth": auth,
            "outbound": outbound,
            "sessions": sessions,
            "enumerations": enumerations,
            "benign_pattern": benign_pattern,
        }

    def _benign_retry_pattern(
        self,
        auth: behavior_rules.AuthAssessment,
        has_attack: bool,
        has_corroborated_outbound: bool,
        sessions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """低频输错口令 → 同源登录成功 → 后续正常业务，是否构成"正常登录重试"。

        这三件事必须同时成立才算解释清楚，缺一条就只能保留不确定性：
        次数少且节奏像人只说明"不像脚本"，不说明"就是本人"；
        真正把行为归因为正常的是"同一来源随后登录成功，并在会话内做常规业务"。
        """
        if has_attack or has_corroborated_outbound or sessions or not auth.benign_retry:
            return {"established": False}
        successes = [log for log in auth.success_logs if log.get("log_id")]
        if not successes:
            return {"established": False}
        subject_src = str(successes[0].get("src_ip") or "")
        subject_user = str(successes[0].get("user") or "")
        last_success = max(
            (behavior_rules.parse_ts(log.get("timestamp")) for log in successes
             if behavior_rules.parse_ts(log.get("timestamp"))),
            default=None,
        )
        activity: list[dict[str, Any]] = []
        for log in self.logs:
            if str(log.get("src_ip") or "") != subject_src:
                continue
            if str(log.get("log_id")) in {str(item.get("log_id")) for item in auth.failure_logs + successes}:
                continue
            stamp = behavior_rules.parse_ts(log.get("timestamp"))
            if last_success is None or stamp is None or (stamp - last_success).total_seconds() < 0:
                continue
            if 200 <= int(log.get("status_code") or 0) < 300:
                activity.append(log)
        if not activity:
            return {"established": False}
        anchors = [log for log in auth.failure_logs + successes if log.get("log_id")]
        return {
            "established": True,
            "subject_src": subject_src,
            "subject_user": subject_user,
            "attempts": auth.attempts,
            "median_interval": auth.median_interval,
            "reasons": auth.benign_reasons,
            "anchors": anchors,
            "activity": activity,
        }

    # ------------------------------------------------------------------
    # 授权核对
    # ------------------------------------------------------------------

    @staticmethod
    def _window_matches(window: dict[str, Any], timestamp: Optional[str]) -> bool:
        """按日志时间检查单个窗口（配置时区为 Asia/Shanghai，即 UTC+8）。"""
        if not timestamp:
            return False
        try:
            text = str(timestamp).replace("Z", "+00:00")
            dt = _dt.datetime.fromisoformat(text)
        except ValueError:
            return False
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        local = dt.astimezone(_dt.timezone(_dt.timedelta(hours=8)))
        weekday = local.strftime("%a").lower()[:3]
        days = [
            str(d).lower()[:3]
            for d in (window.get("days") or window.get("weekdays") or [])
        ]
        if days and weekday not in days:
            return False
        try:
            sh, sm = (int(x) for x in str(window.get("start", "00:00")).split(":"))
            eh, em = (int(x) for x in str(window.get("end", "00:00")).split(":"))
        except ValueError:
            return False
        start = local.replace(hour=sh, minute=sm, second=0, microsecond=0)
        end = local.replace(hour=eh, minute=em, second=0, microsecond=0)
        if end <= start:
            end += _dt.timedelta(days=1)
        return start <= local <= end

    @classmethod
    def _in_window(cls, asset: dict[str, Any], timestamp: Optional[str]) -> bool:
        """按日志时间判断是否落在资产的任一维护窗口内。"""
        return any(
            cls._window_matches(window, timestamp)
            for window in (asset.get("maintenance_windows") or [])
        )

    @staticmethod
    def _is_vulnerability_scanner(log: dict[str, Any]) -> bool:
        user_agent = str(log.get("user_agent") or "").lower()
        return any(marker in user_agent for marker in VULNERABILITY_SCANNER_MARKERS)

    def _is_authorized_scan_candidate(self, log: dict[str, Any]) -> bool:
        if self._is_vulnerability_scanner(log):
            return True
        return log.get("log_source") == "zeek_conn" and any(
            self._is_vulnerability_scanner(other)
            and other.get("src_ip") == log.get("src_ip")
            for other in self.logs
        )

    def _authorized_scan_window(
        self, log: dict[str, Any], signal_codes: list[str]
    ) -> Optional[dict[str, Any]]:
        """只有资产、扫描源、时间窗和扫描动作同时匹配，才认可授权扫描。"""
        asset = ((self.findings.get("context") or {}).get("asset_context") or {})
        if not asset or log.get("asset_id") != asset.get("asset_id"):
            return None
        never_exempt_codes = {
            "sql_injection": "SQL_Injection",
            "malicious_upload": "Malicious_Upload",
            "webshell_access": "Malicious_Upload",
            "suspicious_outbound": "C2_Exfiltration",
            "failed_login_spike": "Brute_Force",
            "brute_force": "Brute_Force",
            "lateral_movement": "Lateral_Movement",
        }
        signals = set(signal_codes)
        for window in asset.get("maintenance_windows") or []:
            actions = set(window.get("allowed_actions") or [])
            if not actions.intersection({"vuln_scan", "probe"}):
                continue
            if window.get("asset_id") != log.get("asset_id"):
                continue
            if not _ip_matches_scope(
                str(log.get("src_ip") or ""),
                list(window.get("authorized_src_ips") or []),
            ):
                continue
            if not self._window_matches(window, log.get("timestamp")):
                continue
            blocked = {
                never_exempt_codes[item]
                for item in (window.get("never_exempt") or [])
                if item in never_exempt_codes
            }
            if signals.intersection(blocked):
                continue
            return window
        return None

    def _scan_authorization_decisions(self) -> list[dict[str, Any]]:
        decisions = []
        for log in self.logs:
            if not self._is_authorized_scan_candidate(log):
                continue
            text = " ".join(
                str(log.get(key) or "")
                for key in ("uri_or_target", "payload_summary", "user_agent")
            )
            signals = attack_types.classify_signals(text)["strong"]
            if not signals:
                signals = ["Scan"]
            decisions.append({
                "log_id": log.get("log_id"),
                "src_ip": log.get("src_ip"),
                "asset_id": log.get("asset_id"),
                "timestamp": log.get("timestamp"),
                "window": self._authorized_scan_window(
                    log,
                    [kind for kind in signals if kind not in {"Brute_Force", "C2_Exfiltration"}],
                ),
            })
        return decisions

    def _authorization(self) -> dict[str, Any]:
        """核对账号、来源、目标资产与维护窗口。

        三条硬要求：
        1. **画像必须与被判断的账号一一对应**，不能拿一个账号的画像批准整批日志；
        2. **空配置不等于不限范围**：缺来源/资产依据时保留不确定性，而不是跳过检查；
        3. **按行为类型取必要条件**：只有运维/服务类账号才要求落在维护窗口内，
           普通业务访问不强行套窗口。
        """
        ctx = self.findings.get("context") or {}
        profile = ctx.get("user_profile")
        asset = ctx.get("asset_context")
        checks: dict[str, bool] = {}
        notes: list[str] = []

        if not ctx.get("total"):
            return {
                "available": False,
                "authorized": False,
                "checks": {},
                "failed": [],
                "notes": ["未取得账号与资产上下文，无法核对授权"],
                "subjects": [],
                "evidence": {},
            }

        account_logs = [log for log in self.logs if log.get("user")]
        if any(not log.get("src_ip") or not log.get("asset_id") for log in account_logs):
            notes.append("行为缺少来源或实际资产，无法核对授权")
        if any(log.get("asset_id") != (asset or {}).get("asset_id") for log in account_logs):
            notes.append("实际资产与上下文不匹配，不能复用其他资产窗口")
        if profile and profile.get("is_service_account") and any(self._interactive_login(log) for log in account_logs):
            notes.append("服务账号交互式登录不在授权范围")
        scan_decisions = self._scan_authorization_decisions()
        # never_exempt 与"有没有账号"无关：纯扫描场景同样要核对窗口禁止豁免项
        never_exempt_hits = self._never_exempt_hits(asset or {})
        if not account_logs:
            if scan_decisions and all(item["window"] for item in scan_decisions) and not never_exempt_hits:
                return {
                    "available": True,
                    "authorized": True,
                    "checks": {
                        "扫描源匹配授权范围": True,
                        "扫描资产与配置一致": True,
                        "扫描时间处于授权窗口": True,
                        "扫描行为未命中禁止豁免类别": True,
                    },
                    "failed": [],
                    "notes": [],
                    "subjects": [],
                    "evidence": {
                        "authorized_scan_logs": scan_decisions,
                        "maintenance_windows": (asset or {}).get("maintenance_windows") or [],
                        "never_exempt_hits": never_exempt_hits,
                    },
                }
            return {
                "available": True,
                "authorized": False,
                "checks": {"账号已登记": False},
                "failed": ["账号已登记"],
                "notes": (
                    ["日志中未出现账号信息，无法核对授权"]
                    + (
                        [
                            "维护窗口 never_exempt 命中（窗口不构成豁免）："
                            + "、".join(
                                f"{item['code']}@{item['log_id']}" for item in never_exempt_hits[:5]
                            )
                        ]
                        if never_exempt_hits
                        else []
                    )
                ),
                "subjects": [],
                "evidence": {
                    "authorized_scan_logs": scan_decisions,
                    "maintenance_windows": (asset or {}).get("maintenance_windows") or [],
                    "never_exempt_hits": never_exempt_hits,
                },
            }

        users = sorted({log["user"] for log in account_logs})
        if len(users) > 1:
            raise_multi = f"同一批日志出现多个账号：{', '.join(users)}，无法用单一画像批准"
            checks["账号唯一"] = False
            notes.append(raise_multi)
        elif profile is None or profile.get("user") != users[0]:
            checks["账号已登记"] = False
            notes.append(
                f"画像与日志账号不匹配（画像 {profile.get('user') if profile else None}，日志 {users[0]}）"
            )
        else:
            checks["账号已登记"] = True
            checks["账号类型可执行该操作"] = profile.get("account_type") in {
                "legit_operator",
                "service",
                "application_admin",
            }

            # 来源：必须有**行为授权范围**才能判断"这个来源是否被允许"。
            # 注意 config/response-policy.yaml#allowlist.ips 是"处置豁免名单"
            # （不自动封禁），不是"账号只能从这些 IP 登录"，不能拿来当授权依据。
            srcs = {log.get("src_ip") for log in account_logs if log.get("src_ip")}
            source_scope = "common_src_ips" in profile or profile.get("source_scope_provided") is True
            if not source_scope:
                checks["来源授权范围"] = False
                notes.append(
                    "配置未提供该账号的来源授权范围（allowlist 只是处置豁免），"
                    f"无法确认来源 {sorted(srcs)} 是否被允许"
                )
            else:
                allowed_src = list(profile.get("common_src_ips") or [])
                if not allowed_src:
                    checks["来源授权范围"] = False
                    notes.append("账号画像的来源授权范围为空，不能视为不限范围")
                else:
                    outside = sorted(src for src in srcs if not _ip_matches_scope(src, allowed_src))
                    checks["来源 IP 符合授权范围"] = not outside
                    if outside:
                        notes.append(f"来源 IP {outside} 不在授权范围")

            # 资产：同理，必须来自配置的账号-资产范围；未提供就不能判"未越权"。
            targets = {log.get("asset_id") for log in account_logs if log.get("asset_id")}
            asset_scope = "allowed_assets" in profile or profile.get("asset_scope_provided") is True
            if targets and not asset_scope:
                checks["资产授权范围"] = False
                notes.append(
                    f"配置未提供该账号的资产授权范围，无法确认 {sorted(targets)} 是否属于授权资产"
                )
            elif targets:
                allowed_assets = list(profile.get("allowed_assets") or [])
                if not allowed_assets:
                    checks["资产授权范围"] = False
                    notes.append("账号画像的资产授权范围为空")
                else:
                    checks["目标资产在授权范围"] = targets <= set(allowed_assets)
                    if not checks["目标资产在授权范围"]:
                        notes.append(f"资产 {sorted(targets - set(allowed_assets))} 不在授权范围")

            # 是否需要维护窗口佐证，由**账号类型**这条规则决定，而不是"配置里有没有窗口"。
            # 否则"没配置"会被读成"不需要检查"，把缺失当成合规。
            needs_window = profile.get("account_type") in WINDOW_REQUIRED_ACCOUNT_TYPES
            if needs_window:
                windows = (asset or {}).get("maintenance_windows") or []
                if not windows:
                    checks["维护窗口配置"] = False
                    notes.append(
                        f"账号类型 {profile.get('account_type')} 要求维护窗口佐证，"
                        "但资产未配置任何 maintenance_windows，无法核验"
                    )
                else:
                    outside = [
                        log
                        for log in account_logs
                        if not self._in_window(asset or {}, log.get("timestamp"))
                    ]
                    checks["全部行为在维护窗口内"] = not outside
                    if outside:
                        notes.append(
                            f"{len(outside)} 条账号行为落在维护窗口外（"
                            + ", ".join(sorted({str(log.get('timestamp')) for log in outside})[:3])
                            + "）"
                        )

        if asset is not None:
            checks["资产已登记"] = True
        else:
            notes.append("未取得目标资产上下文")

        if scan_decisions:
            scans_authorized = all(item["window"] for item in scan_decisions)
            checks["所有扫描源、资产、时间窗和行为均在扫描授权范围"] = scans_authorized
            if not scans_authorized:
                denied = [str(item.get("log_id") or "unknown") for item in scan_decisions if not item["window"]]
                notes.append("扫描日志未匹配授权扫描范围：" + ", ".join(denied))

        # never_exempt：维护窗口只是降权因子，明确禁止豁免的行为一旦命中，
        # 窗口不能把整批行为洗成"正常运维"。这里按**具体窗口配置**逐条比对，
        # 而不是写死一个全局黑名单。
        if never_exempt_hits:
            checks["未命中窗口禁止豁免行为"] = False
            notes.append(
                "维护窗口 never_exempt 命中（窗口不构成豁免）："
                + "、".join(
                    f"{item['code']}@{item['log_id']}" for item in never_exempt_hits[:5]
                )
            )

        authorized = bool(checks) and all(checks.values()) and not notes
        return {
            "available": True,
            "authorized": authorized,
            "checks": checks,
            "failed": [k for k, v in checks.items() if not v],
            "notes": notes,
            "subjects": users,
            "evidence": {
                "account_type": (profile or {}).get("account_type"),
                "allowed_src_ips": (profile or {}).get("common_src_ips") or [],
                "allowed_assets": (profile or {}).get("allowed_assets") or [],
                "source_scope_provided": "common_src_ips" in (profile or {})
                or (profile or {}).get("source_scope_provided") is True,
                "asset_scope_provided": "allowed_assets" in (profile or {})
                or (profile or {}).get("asset_scope_provided") is True,
                "disposition_exempt": (profile or {}).get("disposition_exempt"),
                "observed_src_ips": sorted({log.get("src_ip") for log in account_logs if log.get("src_ip")}),
                "observed_assets": sorted({log.get("asset_id") for log in account_logs if log.get("asset_id")}),
                "evaluated_at": self._focus_time(),
                "maintenance_windows": (asset or {}).get("maintenance_windows") or [],
                "authorized_scan_logs": scan_decisions,
                "never_exempt_hits": never_exempt_hits,
                "per_log_in_window": (
                    {
                        str(log.get("timestamp")): self._in_window(asset or {}, log.get("timestamp"))
                        for log in account_logs
                    }
                    if (asset or {}).get("maintenance_windows")
                    else {}
                ),
            },
        }

    #: 配置里的 never_exempt 代码 → 七类结果分类（与 ``_authorized_scan_window`` 同源）
    _NEVER_EXEMPT_TO_KIND = {
        "sql_injection": "SQL_Injection",
        "malicious_upload": "Malicious_Upload",
        "webshell_access": "Malicious_Upload",
        "suspicious_outbound": "C2_Exfiltration",
        "failed_login_spike": "Brute_Force",
        "brute_force": "Brute_Force",
        "lateral_movement": "Lateral_Movement",
    }

    def _never_exempt_hits(self, asset: dict[str, Any]) -> list[dict[str, Any]]:
        """逐窗口核对：窗口内是否出现了配置声明"即便在窗口内也要告警"的行为。

        只用日志事实判断（强特征 + 认证失败），不看人工阶段标签；
        命中项会保留告警与证据，窗口不再作为豁免依据。
        """
        windows = asset.get("maintenance_windows") or []
        if not windows:
            return []
        asset_id = asset.get("asset_id")
        hits: list[dict[str, Any]] = []
        for window in windows:
            codes = set(window.get("never_exempt") or [])
            if not codes:
                continue
            blocked = {
                self._NEVER_EXEMPT_TO_KIND[code] for code in codes if code in self._NEVER_EXEMPT_TO_KIND
            }
            if not blocked:
                continue
            for log in self.logs:
                if asset_id and log.get("asset_id") != asset_id:
                    continue
                if not self._window_matches(window, log.get("timestamp")):
                    continue
                text = " ".join(
                    str(log.get(key) or "")
                    for key in ("uri_or_target", "payload_summary", "user_agent")
                )
                kinds = set(attack_types.classify_signals(text)["strong"])
                if behavior_rules.is_auth_failure(log):
                    kinds.add("Brute_Force")
                matched = kinds & blocked
                if not matched:
                    continue
                hits.append(
                    {
                        "log_id": log.get("log_id"),
                        "code": sorted(codes)[0],
                        "kinds": sorted(matched),
                        "window": {
                            "start": window.get("start"),
                            "end": window.get("end"),
                            "days": window.get("days") or window.get("weekdays"),
                        },
                        "timestamp": log.get("timestamp"),
                    }
                )
        return hits

    def _focus_time(self) -> Optional[str]:
        """被调查行为的代表时间：最后一条非 benign 日志，否则最后一条日志。"""
        suspicious = [l for l in self.logs if self._stage_of(l) != "benign" and l.get("timestamp")]
        pool = suspicious or [l for l in self.logs if l.get("timestamp")]
        return pool[-1]["timestamp"] if pool else None

    def _build_non_attack(
        self, *, attacker_ip: Optional[str], victim_asset: str, facts: dict[str, Any]
    ) -> AgentResults:
        """没有确认的攻击：授权核对通过、或行为已被正常模式解释，才判"正常"。

        V2 新增的第二条正常路径：**低频输错口令 → 同源登录成功 → 会话内正常业务**。
        它不依赖账号画像（画像只回答"是否登记"，回答不了"这次失败是不是手抖"），
        而是要求三件事同时成立，缺一条就只能保持不确定。
        """
        auth = self.findings.get("authorization") or self._authorization()
        # 存下来供轨迹核验"为什么这么判"
        self.findings["authorization"] = auth
        evidence = self._evidence_ids(facts)
        unresolved = facts["unexplained"]
        pattern = facts.get("benign_pattern") or {}

        if pattern.get("established") and not unresolved:
            basis = "；".join(pattern.get("reasons") or []) or "低频失败后同源登录成功"
            summary = (
                f"来源 {pattern.get('subject_src')} 的账号 {pattern.get('subject_user')} "
                f"共失败 {pattern.get('attempts')} 次（{basis}），随后同源登录成功，"
                f"并在会话内完成 {len(pattern.get('activity') or [])} 次常规业务请求，"
                "未出现攻击载荷、越权参数或异常外连；判定为正常登录重试，不作恶意处置。"
            )
            self._record_conclusion_basis(
                facts, attack_type="none", risk="LOW", summary=summary, attacker_ip=attacker_ip
            )
            return AgentResults(
                case_id=self.case_id,
                is_malicious=False,
                attack_type="none",
                risk_level="LOW",
                attacker_ip=attacker_ip or "unknown",
                victim_asset=victim_asset,
                evidence_log_ids=evidence,
                attack_chain_summary=summary,
                recommended_action="none",
                requires_human_approval=False,
                unknown_items=self._pattern_unknown_items(auth, str(pattern.get("subject_user") or "")),
            )

        if auth["authorized"] and not unresolved:
            basis = "、".join(k for k, v in auth["checks"].items() if v) or "账号/来源/资产/窗口"
            authorized_scan_logs = (auth.get("evidence") or {}).get("authorized_scan_logs") or []
            if authorized_scan_logs:
                scanner_sources = sorted({str(item.get("src_ip")) for item in authorized_scan_logs})
                summary = (
                    f"漏洞扫描源 {', '.join(scanner_sources)} 对已登记资产进行探测；"
                    f"逐条核对来源、目标、授权时间窗及禁止行为（{basis}），"
                    "未发现需告警的利用或禁止行为，判定为授权安全测试。"
                )
            else:
                summary = (
                    f"未发现攻击载荷或外连迹象；账号 {', '.join(auth.get('subjects') or []) or '-'} "
                    f"经上下文核对（{basis}）与授权范围一致，判定为授权运维/业务行为。"
                )
            self._record_conclusion_basis(
                facts, attack_type="none", risk="LOW", summary=summary, attacker_ip=attacker_ip
            )
            return AgentResults(
                case_id=self.case_id,
                is_malicious=False,
                attack_type="none",
                risk_level="LOW",
                attacker_ip=attacker_ip or "unknown",
                victim_asset=victim_asset,
                evidence_log_ids=evidence,
                attack_chain_summary=summary,
                recommended_action="none",
                requires_human_approval=False,
                unknown_items=self._unknown_items(),
            )

        missing: list[str] = []
        if not auth["available"]:
            missing.append("上下文不可用，无法判断该行为是否属授权范围")
        else:
            if auth["failed"]:
                missing.append("授权核对未通过：" + "、".join(auth["failed"]))
            if auth["notes"]:
                missing.append("；".join(auth["notes"]))
        for log_id, reason in self.findings.get("request_target_errors", {}).items():
            missing.append(f"{log_id}：{reason}，保留待查")
        if unresolved:
            stages = sorted({self._stage_of(log) for log in unresolved})
            missing.append(
                f"{len(unresolved)} 条日志存在未解释的行为（阶段标注 {', '.join(stages)}，"
                "但无攻击载荷特征），不能据此确认攻击成立，也不能判为正常"
            )
        if self.round >= self.max_rounds:
            missing.append("调查达到轮次上限，尚不能确认不存在攻击")
        if not missing:
            missing.append("证据不足以判定该行为是否恶意")

        abstain_summary = "未确认攻击成立，也未取得充分的授权依据，不判定为正常，交人工复核。"
        self._record_conclusion_basis(
            facts,
            attack_type="insufficient_evidence",
            risk="LOW",
            summary=abstain_summary,
            attacker_ip=attacker_ip,
        )
        return build_insufficient_evidence(
            case_id=self.case_id,
            attacker_ip=attacker_ip or "unknown",
            victim_asset=victim_asset,
            evidence_log_ids=evidence,
            missing=missing,
            summary=abstain_summary,
        )

    @staticmethod
    def _ordered_ids(logs: list[dict[str, Any]]) -> list[str]:
        """按发生时间排序列出日志编号（去重）。证据顺序应与攻击链顺序一致。"""
        seen: set[str] = set()
        out: list[str] = []
        for log in sorted(logs, key=lambda item: (InvestigationSession._event_time(item), str(item.get("log_id") or ""))):
            log_id = log.get("log_id")
            if not log_id or str(log_id) in seen:
                continue
            seen.add(str(log_id))
            out.append(str(log_id))
        return out

    def _correlated_attempt_logs(self, facts: dict[str, Any]) -> list[dict[str, Any]]:
        """与认证失败同一秒、同一来源、同一账号的 Web 侧请求。

        同一次口令尝试会在 nginx 与 auth_log 两侧各留一条记录：auth_log 记"失败"，
        nginx 记"这次请求"。只引用其中一侧会让人以为证据不全，因此把成对的另一侧补上。
        """
        if not any(kind == "Brute_Force" for kind in facts.get("kinds") or []):
            return []
        attack_ids = {str(log.get("log_id")) for log in facts["attack"]}
        buckets: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
        for log in self.logs:
            stamp = behavior_rules.parse_ts(log.get("timestamp"))
            if stamp is None:
                continue
            key = (str(log.get("src_ip") or ""), str(log.get("user") or ""), int(stamp.timestamp()))
            buckets.setdefault(key, []).append(log)
        extra: list[dict[str, Any]] = []
        for log in facts["attack"]:
            stamp = behavior_rules.parse_ts(log.get("timestamp"))
            if stamp is None:
                continue
            key = (str(log.get("src_ip") or ""), str(log.get("user") or ""), int(stamp.timestamp()))
            for peer in buckets.get(key, []):
                if str(peer.get("log_id")) in attack_ids:
                    continue
                extra.append(peer)
        return extra

    def _post_compromise_logs(self, facts: dict[str, Any]) -> list[dict[str, Any]]:
        """口令被猜中之后的行为：失陷主机外连，以及攻击源维持的长会话。

        这些日志本身可能没有任何"攻击载荷"字样，但它们是"爆破成功"这一结论的
        必要佐证，必须进证据；否则结论说"失陷"，证据却只到登录失败为止。
        """
        auth = facts["auth"]
        if not auth.compromise or not auth.success_logs:
            return []
        last_success = max(
            (behavior_rules.parse_ts(log.get("timestamp")) for log in auth.success_logs
             if behavior_rules.parse_ts(log.get("timestamp"))),
            default=None,
        )
        if last_success is None:
            return []
        attacker_sources = {log["src_ip"] for log in auth.success_logs if log.get("src_ip")}
        victim_ips = {log["dest_ip"] for log in auth.success_logs if log.get("dest_ip")}
        attack_ids = {str(log.get("log_id")) for log in facts["attack"]}
        out: list[dict[str, Any]] = []
        for log in self.logs:
            stamp = behavior_rules.parse_ts(log.get("timestamp"))
            if stamp is None or stamp < last_success or log.get("log_source") not in {"zeek_conn", "zeek_http"}:
                continue
            if str(log.get("log_id")) in attack_ids:
                continue
            src = str(log.get("src_ip") or "")
            # 失陷主机主动向外部地址发起非常规/长时连接
            if (
                src in victim_ips
                and not behavior_rules.is_external_ip(src)
                and behavior_rules.is_external_ip(log.get("dest_ip"))
                and (
                    behavior_rules.is_unusual_egress_port(log)
                    or (behavior_rules.connection_duration(log) or 0) >= 240
                )
            ):
                out.append(log)
                continue
            # 攻击源在登录成功后维持的远程会话连接
            if (
                src in attacker_sources
                and log.get("dest_ip") in victim_ips
                and behavior_rules.dest_port(log) in {22, 3389, 445, 5985}
                and (behavior_rules.connection_duration(log) or 0) >= 30
            ):
                out.append(log)
        return out

    def _evidence_plan(self, facts: dict[str, Any]) -> list[tuple[str, list[str]]]:
        """证据计划：每一组证据回答结论中的哪一部分。

        与 V1 的差别是**分组**而不是"取一批编号"：攻击、影响、配对请求、
        失陷后行为各自成组，轨迹里能看到每组为什么进证据。
        """
        if facts["has_attack"]:
            plan: list[tuple[str, list[str]]] = [("attack", self._ordered_ids(facts["attack"]))]
            if facts["impact"]:
                plan.append(("impact", self._ordered_ids(facts["impact"])))
            correlated = self._correlated_attempt_logs(facts)
            if correlated:
                plan.append(("correlated_attempt", self._ordered_ids(correlated)))
            post = self._post_compromise_logs(facts)
            if post:
                plan.append(("post_compromise", self._ordered_ids(post)))
            return plan

        scans = [item["log"] for item in facts.get("authorized_scans") or []]
        if scans:
            return [("authorized_scan", self._ordered_ids(scans))]

        pattern = facts.get("benign_pattern") or {}
        if pattern.get("established"):
            return [
                (
                    "benign_retry_pattern",
                    self._ordered_ids(list(pattern.get("anchors") or []) + list(pattern.get("activity") or [])),
                )
            ]

        unresolved = facts["unexplained"]
        if unresolved:
            return [("unexplained", self._ordered_ids(unresolved))]

        # 判正常：用账号行为 + 大流量传输（正常批量备份/导出的可核验依据）
        plan = []
        account = [log for log in self.logs if log.get("user") and log.get("log_id")]
        if account:
            plan.append(("account_activity", self._ordered_ids(account)[:8]))
        bulk = [
            log
            for log in self.logs
            if isinstance(log.get("bytes_out"), (int, float)) and log.get("bytes_out") >= 1_000_000
        ]
        if bulk:
            plan.append(("bulk_transfer", self._ordered_ids(bulk)))
        if plan:
            return plan
        ids = [str(log.get("log_id")) for log in self.logs if log.get("log_id")]
        return [("fallback", ids[:1] + ids[-1:] if len(ids) > 1 else ids)]

    def _pattern_unknown_items(self, auth: dict[str, Any], subject_user: str = "") -> str:
        """正常登录重试结论下的未确认事项：说清边界，不留"无"。

        这条结论不依赖账号画像（画像是"是否登记"，解释不了"这次输错"），
        所以要把"画像未覆盖"和"同批其他账号未纳入模式"如实写出来。
        """
        notes: list[str] = []
        if not auth.get("authorized"):
            notes.append("该结论依据行为模式（低频失败+同源成功+后续业务），未依赖账号画像授权")
        others = [user for user in (auth.get("subjects") or []) if user and user != subject_user]
        if others:
            notes.append(
                f"同批日志另含账号 {', '.join(others)}，其活动未纳入本次重试模式判定，需按各自画像另行核对"
            )
        retrieval = self.retrieval_state
        if retrieval in {"degraded", "degraded_zero_hit", "failed", "zero_hit"}:
            notes.append(f"知识检索状态为 {retrieval}，处置建议缺少标准知识卡佐证")
        return "；".join(notes) + "。" if notes else ""

    def _evidence_ids(self, facts: Optional[dict[str, Any]] = None) -> list[str]:
        """挑出支撑结论的证据编号，**依据与判定同一套行为事实**。

        结论由哪些日志推出，证据就引用哪些日志，并按组记录理由（见 ``_evidence_plan``）。
        刻意不按 ``attack_stage_hint`` 挑证据：标签是人工标注，
        用它挑证据会出现"结论来自载荷、证据却引用普通访问"的错配。
        """
        facts = facts if facts is not None else self._behavior_facts()
        plan = self._evidence_plan(facts)
        self.findings["evidence_plan"] = [
            {"group": group, "log_ids": ids, "count": len(ids)} for group, ids in plan
        ]
        merged: list[str] = []
        for _, ids in plan:
            for log_id in ids:
                if log_id not in merged:
                    merged.append(log_id)
        return merged

    def build_results(self) -> AgentResults:
        # 先算行为事实：攻击源、分类、风险、摘要、证据**全部**从这一份事实派生，
        # 避免"结论来自 A、证据引用 B、风险来自 C"的不同源问题。
        facts = self._behavior_facts()
        # 授权核对在**所有**结论路径上都要记录：判恶意时它回答"行为有没有被窗口/白名单豁免"，
        # 判正常时它回答"凭什么批准"，两条路径都需要可核验的依据。
        self.findings["authorization"] = self._authorization()
        # 错题卡复查对"判恶意"和"判正常"都要做：漏在正常路径上做，
        # 就正好漏掉了错题卡最想纠正的那类误判（把人工输错判成爆破）
        self.findings["revision_checks"] = self._evaluate_revisions(facts)
        attacker_ip = self._guess_attacker_ip(facts)
        if not facts["has_attack"] and not attacker_ip:
            # 判正常时字段填"被核查的来源"，而不是 unknown——否则下游无法追问核查对象
            attacker_ip = self._benign_subject(facts)
        victim_asset = self.seed_asset_id or self._first_asset() or "unknown"

        errors = [r for r in self.results if r.get("code")]
        if errors and not self.evidence_ids:
            return build_insufficient_evidence(case_id=self.case_id, attacker_ip="unknown", victim_asset=victim_asset, evidence_log_ids=[], missing=[redact_text(str(r.get("message") or r.get("code"))) for r in errors], summary="日志工具调用失败，未取得可核验证据；不能视为零命中。")
        if not self.evidence_ids:
            return build_insufficient_evidence(
                case_id=self.case_id,
                attacker_ip=attacker_ip or "unknown",
                victim_asset=victim_asset,
                evidence_log_ids=[],
                missing=[
                    "本次调查未取得任何可引用日志",
                    "无法确认攻击源与受害资产，需人工核对日志采集链路与时间窗",
                ],
                summary="当前关联条件下未取得日志，无法判断是否存在攻击。",
            )

        if not facts["has_attack"]:
            return self._build_non_attack(
                attacker_ip=attacker_ip, victim_asset=victim_asset, facts=facts
            )

        # 字节量只能说明传输规模，不能证明数据外泄。
        scan_only = set(facts.get("kinds") or []) == {"Scan"}
        compromise = bool((facts.get("auth") or behavior_rules.AuthAssessment()).compromise)
        if scan_only:
            risk = "MEDIUM"
        elif facts["c2"] or facts["responded"] or facts["impact"] or compromise:
            # 外连建立、会话被异地复用、口令被猜中、批量导出都属已确认影响
            risk = "HIGH"
        else:
            risk = "MEDIUM"

        action = self._recommended_action(risk=risk, scan_only=scan_only, attacker_ip=attacker_ip)
        attack_type = self._attack_type(facts)
        summary = self._chain_summary(facts, attacker_ip, victim_asset)
        self._record_conclusion_basis(
            facts,
            attack_type=attack_type,
            risk=risk,
            summary=summary,
            attacker_ip=attacker_ip,
        )
        return AgentResults(
            case_id=self.case_id,
            is_malicious=True,
            attack_type=attack_type,
            risk_level=risk,  # type: ignore[arg-type]
            attacker_ip=attacker_ip or "unknown",
            victim_asset=victim_asset,
            evidence_log_ids=self._evidence_ids(facts),
            attack_chain_summary=summary,
            recommended_action=action,  # type: ignore[arg-type]
            requires_human_approval=action != "rate_limit",
            unknown_items=self._unknown_items(facts=facts, action=action),
        )

    def _recommended_action(self, *, risk: str, scan_only: bool, attacker_ip: Optional[str]) -> str:
        """处置建议必须落在 ``config/response-policy.yaml`` 的授权范围内。

        ``block_ip`` 只允许 Web。短时封禁和限速只允许 Web 与主机。
        """
        role = str(
            ((self.findings.get("context") or {}).get("asset_context") or {}).get("role") or ""
        ).lower()
        if not attacker_ip or (role and role not in {"web", "host"}):
            return "none"
        if scan_only:
            return "rate_limit"
        if risk not in {"HIGH", "CRITICAL"}:
            return "block_ip_short_term"
        return "block_ip" if role == "web" else "block_ip_short_term"

    def _evaluate_revisions(self, facts: dict[str, Any]) -> list[dict[str, Any]]:
        """把错题卡的 ``error_revision_note`` 变成一次可核验的复查。

        本地控制器没有自然语言推理能力，因此按关键词把提示路由到确定的复查项，
        并把"哪张卡、因为哪句话、复查结论是什么"原样写进轨迹。
        复查只影响**记录与解释**，不直接改写结论——结论必须由日志事实支撑。
        """
        checks: list[dict[str, Any]] = []
        for card in (self.findings.get("knowledge") or [])[:3]:
            note = str(card.get("error_revision_note") or "")
            if not note:
                continue
            for keywords, check_id, description in _REVISION_RULES:
                if not any(word in note for word in keywords):
                    continue
                outcome = self._run_revision_check(check_id, facts)
                checks.append(
                    {
                        "card_id": card.get("card_id"),
                        "note": note[:220],
                        "check": check_id,
                        "check_description": description,
                        "outcome": outcome["result"],
                        "detail": outcome["detail"],
                    }
                )
                break
        self.findings["revision_checks"] = checks
        return checks

    def _run_revision_check(self, check_id: str, facts: dict[str, Any]) -> dict[str, Any]:
        if check_id == "login_retry_pattern":
            pattern = facts.get("benign_pattern") or {}
            if pattern.get("established"):
                return {"result": "pattern_confirmed_benign", "detail": "；".join(pattern.get("reasons") or [])}
            if facts.get("auth").brute_force:
                return {"result": "brute_force_confirmed", "detail": "失败次数与节奏已超过人工输入范围"}
            return {"result": "no_match", "detail": "未同时满足低频、同源、后续成功登录"}
        if check_id == "outbound_needs_corroboration":
            groups = [group for group in facts.get("outbound") or [] if group.corroborated]
            if groups:
                return {
                    "result": "corroborated",
                    "detail": "；".join(reason for group in groups for reason in group.reasons[:2]),
                }
            return {"result": "no_match", "detail": "外连未达到多信号确认门槛，不作 C2 定性"}
        if check_id == "multi_account_bruteforce":
            auth = facts.get("auth")
            if auth.brute_force:
                return {"result": "confirmed", "detail": "多账号连续失败已达爆破门槛"}
            return {"result": "no_match", "detail": "多账号失败未达门槛"}
        if check_id == "benign_context_check":
            scans = facts.get("authorized_scans") or []
            if scans:
                return {"result": "authorized_context", "detail": f"{len(scans)} 条日志命中授权扫描范围"}
            return {"result": "no_match", "detail": "未命中授权扫描/维护窗口范围"}
        return {"result": "not_implemented", "detail": "未登记的复查项"}

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _stage_counts(self) -> dict[str, int]:
        """按阶段计数。**缺失标签归为 unknown，而不是 benign**。

        ``attack_stage_hint`` 是队友做日志清洗时的人工标注，属于线索而非判据：
        缺失时必须保留"未知"，否则去掉标签后所有日志都会被当成正常流量，
        等于把"没标注"读成"没问题"。
        """
        counts: dict[str, int] = {}
        for log in self.logs:
            stage = log.get("attack_stage_hint") or "unknown"
            counts[stage] = counts.get(stage, 0) + 1
        return counts

    @staticmethod
    def _stage_of(log: dict[str, Any]) -> str:
        return log.get("attack_stage_hint") or "unknown"

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

    def _guess_attacker_ip(self, facts: Optional[dict[str, Any]] = None) -> Optional[str]:
        """从**攻击行为日志**定位攻击源。

        不再按 ``benign`` 标签排除：标签是人工标注，而"这条日志带注入载荷"是日志事实。
        优先取攻击日志的外部来源地址；当攻击全部表现为"受害主机主动外连"时
        （无 HTTP payload 的 C2），攻击方就是外连的目的地址。
        两者都没有时返回 ``None``（判正常的场景由 :meth:`_benign_subject` 决定填谁）。
        """
        facts = facts if facts is not None else self._behavior_facts()
        pool = facts["attack"] or facts["unexplained"] or facts["impact"]
        counter: dict[str, int] = {}
        for log in pool:
            ip = log.get("src_ip")
            if self._is_external(ip):
                counter[ip] = counter.get(ip, 0) + 1
        if counter:
            return max(counter.items(), key=lambda kv: kv[1])[0]
        # C2 场景：攻击方是外连的目的地址（日志里它只出现在 dest_ip 上）
        for group in facts.get("outbound") or []:
            if group.corroborated and self._is_external(group.dest_ip):
                return str(group.dest_ip)
        return None

    def _benign_subject(self, facts: dict[str, Any]) -> Optional[str]:
        """判正常时 ``attacker_ip`` 该填谁：本次被调查行为的来源地址。

        结论是"没有攻击"，但字段仍需给出**被核查的对象**，否则下游无法追问
        "你到底核查了谁"。优先级：授权扫描源 → 账号行为来源 → 异常状态码来源 → 出现最多的来源。
        """
        scans = facts.get("authorized_scans") or []
        if scans:
            sources = [str(item["log"].get("src_ip")) for item in scans if item["log"].get("src_ip")]
            if sources:
                return sources[0]
        account = [log.get("src_ip") for log in self.logs if log.get("user") and log.get("src_ip")]
        if account:
            return max(set(account), key=account.count)
        noisy = [
            log.get("src_ip")
            for log in self.logs
            if log.get("src_ip") and int(log.get("status_code") or 0) >= 400
        ]
        if noisy:
            return max(set(noisy), key=noisy.count)
        every = [log.get("src_ip") for log in self.logs if log.get("src_ip")]
        return max(set(every), key=every.count) if every else None

    _KIND_QUERY = {
        "C2_Exfiltration": "内网主机向境外可疑地址持续外连、周期心跳与数据外传如何研判与处置",
        "Malicious_Upload": "Web 上传点被写入 webshell 后如何研判与处置，是否需要封禁来源 IP",
        "SQL_Injection": "Web 登录接口出现 SQL 注入载荷并成功响应后如何研判与处置",
        "XSS": "站内被投放脚本并出现会话复用（会话劫持）时如何研判与处置",
        "Path_Traversal_Privilege": "目录遍历与编号越权批量读取数据如何研判与处置",
        "Brute_Force": "多账号/单账号口令爆破后是否成功登录，如何研判与处置",
        "Scan": "可疑漏洞扫描探测如何研判，是否需要限速",
    }

    def _knowledge_query(self, kind: Optional[str] = None) -> str:
        """按已观察到的行为类构造检索问题（不依赖人工阶段标签）。"""
        kind = kind or self._leading_kind()
        if kind in self._KIND_QUERY:
            return self._KIND_QUERY[kind]
        return "可疑安全事件：如何结合多源日志研判并给出受控处置建议"

    #: 七类的阶段顺序，用于把分类按时间排列
    _TYPE_ORDER = (
        "Scan",
        "Brute_Force",
        "SQL_Injection",
        "XSS",
        "Path_Traversal_Privilege",
        "Malicious_Upload",
        "C2_Exfiltration",
    )
    _EXPLOIT_KINDS = {"SQL_Injection", "XSS", "Path_Traversal_Privilege", "Malicious_Upload"}

    def _attack_type(self, facts: dict[str, Any]) -> str:
        """分类完全由行为事实决定，最新阶段写最前。

        **不再用 ``attack_stage_hint`` 补阶段**：标签是人工标注，
        只用它会让一条"标了 recon 的普通访问"凭空给结论加上 Scan。
        标签带来的疑点改为在 ``unknown_items`` 里单独说明。
        """
        codes = set(facts.get("kinds") or [])
        first_seen = {}
        for log in facts["attack"]:
            for code in facts["log_kinds"].get(str(log.get("log_id")), []):
                stamp = self._event_time(log)
                first_seen[code] = min(first_seen.get(code, stamp), stamp)
        ordered = sorted(codes, key=lambda code: (first_seen.get(code, _dt.datetime.min.replace(tzinfo=_dt.timezone.utc)), code))
        # 同时命中的类别不声称先后；只输出最后时刻的一类，其余在依据中保留。
        if len(set(first_seen.values())) < len(first_seen):
            ordered = ordered[-1:]
        return "_After_".join(reversed(ordered)) if ordered else "Unknown_Attack"

    #: 类别 → 摘要措辞（摘要里声称的每个阶段都必须有对应日志）
    _KIND_PHRASE = {
        "Scan": "扫描探测",
        "Brute_Force": "账号爆破",
        "SQL_Injection": "SQL 注入尝试",
        "XSS": "跨站脚本尝试",
        "Path_Traversal_Privilege": "目录遍历/越权访问",
        "Malicious_Upload": "恶意上传或 webshell 访问",
        "C2_Exfiltration": "可疑外连",
    }

    def _chain_summary(
        self, facts: dict[str, Any], attacker: str | None, asset: str
    ) -> str:
        """摘要只陈述**有日志证据**的行为，不按标签编造阶段。"""
        per_kind: dict[str, int] = {}
        for kinds in (facts.get("log_kinds") or {}).values():
            for kind in kinds:
                per_kind[kind] = per_kind.get(kind, 0) + 1

        seg = [
            f"{self._KIND_PHRASE.get(code, code)} {per_kind[code]} 次"
            for code in self._TYPE_ORDER
            if per_kind.get(code)
        ]
        if not seg:
            seg.append("观察到未解释的行为")

        text = f"攻击源 {attacker or '未确定'} 对 {asset} 实施：" + "，".join(seg)
        if facts.get("c2"):
            text += "；已建立对外连接"
        if facts.get("sessions"):
            text += "；同一会话标识被另一来源复用（会话劫持迹象）"
        if facts.get("impact") and not facts.get("sessions"):
            text += "；攻击源调用了批量导出/下载接口且响应体明显偏大"
        if (facts.get("auth") or behavior_rules.AuthAssessment()).compromise:
            text += "；认证失败后同一来源成功登录，判定已失陷"
        if not facts.get("c2") and facts.get("responded"):
            text += "；攻击请求得到响应（未确认利用成功）"
        return text + "。"

    def _record_conclusion_basis(
        self,
        facts: dict[str, Any],
        *,
        attack_type: str,
        risk: str,
        summary: str,
        attacker_ip: Optional[str],
    ) -> None:
        """记录"分类 / 风险 / 攻击源 / 摘要"分别依据哪些日志，供轨迹核对。

        只写日志编号与规则名，不重复存日志正文。
        """
        kind_logs: dict[str, list[str]] = {}
        for log_id, kinds in (facts.get("log_kinds") or {}).items():
            for kind in kinds:
                kind_logs.setdefault(kind, []).append(str(log_id))

        compromise = bool((facts.get("auth") or behavior_rules.AuthAssessment()).compromise)
        if risk == "HIGH":
            risk_pool = facts["c2"] or facts["impact"] or facts["responded"] or (
                facts["auth"].success_logs if compromise else []
            )
            if facts["c2"]:
                risk_rule = "已建立对外连接"
            elif facts["impact"]:
                risk_rule = "出现会话复用或攻击源批量导出等影响迹象"
            elif compromise:
                risk_rule = "认证失败后同一来源成功登录（已失陷）"
            else:
                risk_rule = "强特征请求得到响应（未确认利用成功）"
        elif risk == "MEDIUM":
            risk_pool = facts["attack"]
            risk_rule = "存在强攻击特征但请求未被受理/无响应"
        else:
            risk_pool = []
            risk_rule = "未确认攻击"

        src_pool = facts["attack"] or facts["unexplained"] or facts["impact"]
        # 攻击源可能来自 src_ip（有载荷的攻击），也可能只出现在 dest_ip（受害主机主动外连）
        attacker_log_ids = sorted(
            str(log["log_id"])
            for log in src_pool
            if log.get("log_id")
            and (log.get("src_ip") == attacker_ip or log.get("dest_ip") == attacker_ip)
        )
        self.findings["conclusion_basis"] = {
            "attack_type": {
                "value": attack_type,
                "segments": [
                    {"code": code, "log_ids": sorted(kind_logs.get(code, []))}
                    for code in self._TYPE_ORDER
                    if code in set(facts.get("kinds") or [])
                ],
            },
            "risk_level": {
                "value": risk,
                "rule": risk_rule,
                "log_ids": sorted(str(l["log_id"]) for l in risk_pool if l.get("log_id")),
            },
            "attacker_ip": {
                # 与 AgentResults 口径一致：定位不到就是 unknown
                "value": attacker_ip or "unknown",
                "log_ids": attacker_log_ids,
            },
            "summary": {
                "text": summary,
                "stage_counts": {code: len(ids) for code, ids in kind_logs.items()},
            },
        }

    def _unknown_items(self, facts: Optional[dict[str, Any]] = None, *, action: str = "none") -> str:
        facts = facts if facts is not None else self._behavior_facts()
        missing: list[str] = []
        for log_id, reason in self.findings.get("request_target_errors", {}).items():
            missing.append(f"{log_id}：{reason}，保留待查")
        if not self._guess_attacker_ip(facts) and facts["has_attack"]:
            missing.append("处置目标未能定位，交人工复核，不建议封禁")
        times = [log.get("timestamp") for log in facts["attack"]]
        if len(facts.get("kinds", [])) > 1 and (len(set(times)) < len(times) or any(len(kinds) > 1 for kinds in facts["log_kinds"].values())):
            missing.append("部分分类同时命中，时序不确定；主分类外的类别保留在 conclusion_basis")
        if facts["has_attack"]:
            if action == "none":
                missing.append("未生成可提交的处置建议，交人工复核")
            elif action == "rate_limit":
                missing.append("仅生成限速建议；本调查器未调用处置工具")
            else:
                missing.append("处置建议尚未经过人工审批，未提交处置申请")
        # 标签带来的、但没有行为证据支撑的疑点，单独列出而不是计入结论
        unbacked = [
            stage
            for stage in ("recon", "brute_force", "exploitation", "c2_callback")
            if self._stage_counts().get(stage)
        ]
        if facts["unexplained"]:
            missing.append(
                "存在标注为 " + "、".join(unbacked) + " 的日志，但缺少对应行为证据，"
                "仅作待查线索，未计入结论"
            )
        if not self.findings.get("context") or not (self.findings["context"].get("total") or 0):
            missing.append("未取得账号行为基线与资产重要性上下文")
        retrieval = self.findings.get("knowledge_status")
        state = self.retrieval_state
        if retrieval is None:
            missing.append("未调用知识检索工具")
        elif state == "failed":
            missing.append("知识检索调用失败：" + redact_text(str(retrieval.get("message") or retrieval.get("code"))))
        elif state in {"degraded", "degraded_zero_hit"}:
            missing.append(
                "知识检索处于降级模式（"
                + str(self.retrieval_meta.get("retrieval_mode") or "未知")
                + "，非混合检索），结论仅作本地验证参考"
                + ("；本次降级检索零命中" if state == "degraded_zero_hit" else "")
            )
        elif state == "zero_hit" or not self.findings.get("knowledge"):
            missing.append("知识检索成功但零命中，处置建议缺少标准依据")
        # 维护窗口 never_exempt 命中：窗口不构成豁免，告警与证据照常保留
        hits = ((self.findings.get("authorization") or {}).get("evidence") or {}).get("never_exempt_hits") or []
        if hits:
            missing.append(
                "维护窗口 never_exempt 命中 "
                + "、".join(str(item.get("log_id")) for item in hits[:5])
                + "，窗口不作为豁免依据"
            )
        pattern = facts.get("benign_pattern") or {}
        if pattern.get("established") and facts.get("unexplained"):
            missing.append("已按低频登录重试模式解释，未见攻击载荷/越权/外连")
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
