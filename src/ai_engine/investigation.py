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
            self.findings["knowledge_status"] = result
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

    def _brute_failure_ids(self) -> set[str]:
        """暂定本地规则：同源、同目标、同账号五分钟内至少五次失败。"""
        groups: dict[tuple, dict[str, tuple]] = {}
        markers = ("invalid_password", "failed password", "authentication failure", "auth_fail", "登录失败", "invalid user")
        for log in self.logs:
            if log.get("log_source") != "auth_log":
                continue
            text = str(log.get("payload_summary") or "").lower()
            if not any(m in text for m in markers):
                continue
            try:
                stamp = _dt.datetime.fromisoformat(str(log.get("timestamp")).replace("Z", "+00:00"))
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=_dt.timezone.utc)
            except ValueError:
                continue
            key = (log.get("src_ip"), log.get("asset_id") or log.get("dest_ip"), log.get("user"))
            if not all(key) or not log.get("log_id"):
                continue
            groups.setdefault(key, {})[log["log_id"]] = (stamp, log["log_id"])
        accepted = set()
        for group in groups.values():
            rows = sorted(group.values())
            for stamp, _ in rows:
                window = [lid for t, lid in rows if 0 <= (t - stamp).total_seconds() <= 300]
                if len(window) >= 5:
                    accepted.update(window)
        return accepted

    def _behavior_facts(self) -> dict[str, Any]:
        """从日志事实提取攻击证据，**不以人工阶段标签为依据**。

        三层区分：

        * ``attack``：命中**强特征**（注入语法、攻击工具 UA、webshell 路径、路径穿越、
          外连信号）。正常业务基本不会出现这些字符串，才可支撑"攻击成立"；
        * ``leads``：只命中**弱特征**（robots.txt、upload、filename=、multipart、.php 等）。
          这些在日常流量里很常见，单独不构成攻击，只作为线索记录；
        * ``impact``：attack 中带影响迹象的（外连已建立，或强特征且请求被受理）。

        HTTP 2xx 只表示请求被处理过，**不能单独**证明利用成功——所以它只在与强特征同时
        出现时才计入 impact，且不因此把风险抬到 CRITICAL。
        外部 IP 只是来源属性，不参与定性。
        """
        attack: list[dict[str, Any]] = []
        c2_logs: list[dict[str, Any]] = []
        responded: list[dict[str, Any]] = []
        leads: list[dict[str, Any]] = []
        unexplained: list[dict[str, Any]] = []
        authorized_scans: list[dict[str, Any]] = []
        kinds: list[str] = []
        #: 每条日志各自命中的类别，供分类/摘要/证据回溯
        log_kinds: dict[str, list[str]] = {}

        brute_ids = self._brute_failure_ids()
        for log in self.logs:
            text = " ".join(
                str(log.get(k) or "")
                for k in ("uri_or_target", "payload_summary", "user_agent")
            )
            signals = attack_types.classify_signals(text)
            stage = self._stage_of(log)
            status = log.get("status_code") or 0
            c2 = self._c2_signal(log)

            strong = [k for k in signals["strong"] if k not in {"Brute_Force", "C2_Exfiltration"}]
            scanner = self._is_authorized_scan_candidate(log)
            if scanner and not strong:
                strong.append("Scan")
            if log.get("log_id") in brute_ids or any(tool in text.lower() for tool in ("hydra", "medusa")):
                strong.append("Brute_Force")
            if c2 and "C2_Exfiltration" not in strong:
                strong.append("C2_Exfiltration")

            policy_window = self._authorized_scan_window(log, strong) if scanner else None
            if policy_window:
                authorized_scans.append({"log": log, "window": policy_window})
                leads.append(log)
                continue
            # 扫描器收到明确拒绝/未命中响应时，只能证明发生了探测；不能把被拒绝的
            # 利用载荷当成已成立的 XSS、遍历或上传攻击。
            if scanner and isinstance(status, int) and 400 <= status < 500:
                strong = ["Scan"]

            if strong:
                attack.append(log)
                kinds.extend(strong)
                log_id = log.get("log_id")
                if log_id:
                    log_kinds[str(log_id)] = strong
                if c2 and "conn_state=sf" in [part.strip() for part in str(log.get("payload_summary") or "").lower().split(";")]:
                    c2_logs.append(log)
                elif 200 <= status < 300 and any(
                    kind in strong
                    for kind in {"SQL_Injection", "XSS", "Path_Traversal_Privilege", "Malicious_Upload"}
                ):
                    # 强特征 + 2xx：说明攻击请求得到了响应，**不等于利用成功**
                    responded.append(log)
            elif signals["weak"]:
                # 弱特征：只是线索。只有当日志本身还带可疑标记（非 benign 阶段 / 5xx）才需解释
                if stage != "benign" or status >= 500:
                    unexplained.append(log)
                else:
                    leads.append(log)
            elif stage != "benign" or status >= 500:
                unexplained.append(log)

        return {
            "attack": attack,
            "c2": c2_logs,
            "responded": responded,
            "leads": leads,
            "unexplained": unexplained,
            "authorized_scans": authorized_scans,
            "kinds": kinds,
            "log_kinds": log_kinds,
            "has_attack": bool(attack),
            # 确认影响：只有外连建立（可延伸到外传判定）；"被响应"不算确认影响
            "has_confirmed_impact": bool(c2_logs),
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
        if not account_logs:
            if scan_decisions and all(item["window"] for item in scan_decisions):
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
                    },
                }
            return {
                "available": True,
                "authorized": False,
                "checks": {"账号已登记": False},
                "failed": ["账号已登记"],
                "notes": ["日志中未出现账号信息，无法核对授权"],
                "subjects": [],
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

    def _focus_time(self) -> Optional[str]:
        """被调查行为的代表时间：最后一条非 benign 日志，否则最后一条日志。"""
        suspicious = [l for l in self.logs if self._stage_of(l) != "benign" and l.get("timestamp")]
        pool = suspicious or [l for l in self.logs if l.get("timestamp")]
        return pool[-1]["timestamp"] if pool else None

    def _build_non_attack(
        self, *, attacker_ip: Optional[str], victim_asset: str, facts: dict[str, Any]
    ) -> AgentResults:
        """没有确认的攻击：授权核对全部通过且无未解释行为才判"正常"，否则弃权。"""
        auth = self._authorization()
        # 存下来供轨迹核验"为什么这么判"
        self.findings["authorization"] = auth
        evidence = self._evidence_ids(facts)
        unresolved = facts["unexplained"]

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

    def _evidence_ids(self, facts: Optional[dict[str, Any]] = None) -> list[str]:
        """挑出支撑结论的证据编号，**依据与判定同一套行为事实**。

        顺序：
        1. 有攻击 → 用命中强特征的那些日志（结论由它们推出，证据就必须是它们）；
        2. 无攻击但有未解释线索 → 用这些线索（弃权也要说清基于哪几条）；
        3. 判正常 → 用带账号的行为日志（授权判断的依据），没有账号则取首尾各一条。

        刻意不再按 ``attack_stage_hint`` 挑证据：标签是人工标注，
        用它挑证据会出现"结论来自载荷、证据却引用普通访问"的错配。
        """
        facts = facts if facts is not None else self._behavior_facts()
        attack_ids = [log["log_id"] for log in facts["attack"] if log.get("log_id")]
        if attack_ids:
            return attack_ids
        authorized_scan_ids = [
            item["log"]["log_id"]
            for item in facts.get("authorized_scans", [])
            if item.get("log", {}).get("log_id")
        ]
        if authorized_scan_ids:
            return authorized_scan_ids
        unexplained_ids = [log["log_id"] for log in facts["unexplained"] if log.get("log_id")]
        if unexplained_ids:
            return unexplained_ids
        account = [log["log_id"] for log in self.logs if log.get("user") and log.get("log_id")]
        if account:
            return account[:8]
        ids = [log["log_id"] for log in self.logs if log.get("log_id")]
        return ids[:1] + ids[-1:] if len(ids) > 1 else ids

    def build_results(self) -> AgentResults:
        # 先算行为事实：攻击源、分类、风险、摘要、证据**全部**从这一份事实派生，
        # 避免"结论来自 A、证据引用 B、风险来自 C"的不同源问题。
        facts = self._behavior_facts()
        attacker_ip = self._guess_attacker_ip(facts)
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
        if scan_only:
            risk = "MEDIUM"
        elif facts["c2"] or facts["responded"]:
            risk = "HIGH"
        else:
            risk = "MEDIUM"

        action = (
            "rate_limit"
            if scan_only
            else "block_ip" if risk in {"HIGH", "CRITICAL"} else "block_ip_short_term"
        )
        attack_type = self._attack_type(facts)
        summary = self._chain_summary(facts, attacker_ip, victim_asset)
        self._record_conclusion_basis(
            facts,
            attack_type=attack_type,
            risk=risk,
            summary=summary,
            attacker_ip=attacker_ip,
        )
        if not attacker_ip:
            action = "none"
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
            unknown_items=self._unknown_items(facts=facts),
        )

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
        优先级：攻击日志 → 未解释线索；两者都没有时返回 ``None``
        （判正常的场景不该把某个访客 IP 当成"攻击源"）。
        """
        facts = facts if facts is not None else self._behavior_facts()
        pool = facts["attack"] or facts["unexplained"]
        counter: dict[str, int] = {}
        for log in pool:
            ip = log.get("src_ip")
            if self._is_external(ip):
                counter[ip] = counter.get(ip, 0) + 1
        if not counter:
            return None
        return max(counter.items(), key=lambda kv: kv[1])[0]

    def _knowledge_query(self) -> str:
        stages = self._stage_counts()
        if stages.get("c2_callback"):
            return "内网主机向境外可疑地址持续外连（疑似 C2 回连与数据外传）如何研判与处置"
        if stages.get("exploitation"):
            kind = self._exploit_type()
            if kind:
                return f"{attack_types.zh_name(kind)}利用成功后如何研判与处置，是否需要短时封禁 IP"
            return "Web 应用出现利用痕迹后如何研判与处置"
        if stages.get("brute_force"):
            return "账号密码爆破攻击如何研判与处置"
        return "可疑扫描探测如何研判与处置"

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

    def _exploit_type(self) -> Optional[str]:
        """按利用阶段日志特征推断具体类别；无特征返回 ``None``。"""
        texts = [
            f"{log.get('uri_or_target') or ''} {log.get('payload_summary') or ''} "
            f"{log.get('user_agent') or ''}"
            for log in self.logs
            if (log.get("attack_stage_hint") or "") == "exploitation"
        ]
        if not texts:
            return None
        return attack_types.infer_from_text(" ".join(texts))

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
        elif facts.get("responded"):
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

        if risk == "HIGH":
            risk_pool = facts["c2"] or facts["responded"]
            risk_rule = "已建立外连" if facts["c2"] else "强特征请求得到响应（未确认利用成功）"
        elif risk == "MEDIUM":
            risk_pool = facts["attack"]
            risk_rule = "存在强攻击特征但请求未被受理/无响应"
        else:
            risk_pool = []
            risk_rule = "未确认攻击"

        src_pool = facts["attack"] or facts["unexplained"]
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
                "log_ids": sorted(
                    str(l["log_id"])
                    for l in src_pool
                    if l.get("log_id") and l.get("src_ip") == attacker_ip
                ),
            },
            "summary": {
                "text": summary,
                "stage_counts": {code: len(ids) for code, ids in kind_logs.items()},
            },
        }

    def _unknown_items(self, facts: Optional[dict[str, Any]] = None) -> str:
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
            if set(facts.get("kinds") or []) == {"Scan"}:
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
        if retrieval is None:
            missing.append("未调用知识检索工具")
        elif retrieval.get("code"):
            missing.append("知识检索调用失败：" + redact_text(str(retrieval.get("message") or retrieval["code"])))
        elif not self.findings.get("knowledge"):
            missing.append("知识检索成功但零命中，处置建议缺少标准依据")
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
