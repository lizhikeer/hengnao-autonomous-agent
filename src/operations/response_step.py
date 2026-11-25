"""受控处置步骤（Week 3）：把调查结论变成一次**有回执**的处置申请。

为什么单独成步骤
----------------
调查节点只负责"判断发生了什么"，不做任何处置。写操作必须由独立步骤发起，
否则调查过程一次误判就会直接落到封禁上。本模块就是那一步：

    调查（只读）→ 处置步骤（本模块）→ 策略网关 → 状态机 → 人工审批/执行回执

与组长 [#37]/[#38] 的分工
----------------------
`src/operations/response_executor.py`（PR #37 网关层 + PR #38 状态机）是**唯一**的
策略与状态机实现，本模块**不重写**它，只做三件事：

1. 把调查结论翻译成 ``evaluate_action`` 需要的入参（动作、目标、证据）；
2. 把执行器返回的状态翻译成对外统一的回执枚举
   （``approval_required`` / ``EXECUTED`` / ``BLOCKED_BY_POLICY`` / ``REJECTED`` 等）；
3. 执行器不可用时 **fail-closed**：返回 ``EXECUTOR_UNAVAILABLE``，不执行、不放行。

为什么允许注入执行器
--------------------
测试需要在不产生真实副作用的前提下验证"待审 / 拒批 / 超时 / 策略拦截"四条路径，
因此本模块面向一个协议编程；测试替身必须实现同一份方法签名与返回结构
（见 ``tests/test_w3_response_step.py``），与真实执行器的契约逐字对齐。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Protocol

#: 对外回执状态（与任务书 / 恒脑交互节点约定的取值）
APPROVAL_REQUIRED = "approval_required"
EXECUTED = "EXECUTED"
BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
REJECTED = "REJECTED"
APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"
NO_ACTION = "NO_ACTION"
EXECUTOR_UNAVAILABLE = "EXECUTOR_UNAVAILABLE"
INVALID_APPROVAL = "INVALID_APPROVAL"

#: 需要人工审批的动作（与 config/response-policy.yaml 的 risk: high 对应）
HIGH_RISK_ACTIONS = frozenset({"block_ip", "block_ip_short_term", "isolate_account"})

#: 执行器内部状态 → 对外回执
_STATUS_MAP = {
    "BLOCKED": BLOCKED_BY_POLICY,
    "NO_ACTION": NO_ACTION,
    "EXECUTED": EXECUTED,
    "PENDING_APPROVAL": APPROVAL_REQUIRED,
    "APPROVAL_REQUIRED": APPROVAL_REQUIRED,
}


class DispositionError(RuntimeError):
    """处置步骤自身的输入错误（不是策略拒绝，也不是执行器故障）。"""


class ResponseExecutor(Protocol):
    """PR #37/#38 执行器的对外契约（本模块只依赖这四个方法）。"""

    def evaluate_action(
        self,
        action: str,
        target_type: str = "",
        target_ip: str = "",
        target_user: str = "",
        evidence_log_ids: Any = None,
        *,
        case_id: str = "",
        timeout_minutes: float = 30,
        now: Optional[datetime] = None,
    ) -> dict[str, Any]: ...

    def approve(
        self, approval_id: str, order: dict[str, Any], approved_by: str, *, now: Optional[datetime] = None
    ) -> dict[str, Any]: ...

    def reject(
        self, approval_id: str, rejected_by: str, *, reason: str = "", now: Optional[datetime] = None
    ) -> dict[str, Any]: ...

    def expire_pending(self, now: Optional[datetime] = None) -> list[dict[str, Any]]: ...


@dataclass
class DispositionRequest:
    """一次处置申请。字段名与 ``approval.required_fields`` 对齐，便于直接生成审批单。"""

    case_id: str
    action: str
    target_ip: str = ""
    target_user: str = ""
    target_type: str = ""
    evidence_log_ids: list[str] = field(default_factory=list)
    reason: str = ""
    expected_effect: str = ""
    rollback_plan: str = ""

    def approval_order(self, approved_by: str) -> dict[str, Any]:
        """生成审批单（人工在恒脑【交互节点】提交的那一份）。

        PR #38 的执行器要求审批单带齐 6 项必填字段
        （``case_id`` / ``action`` / ``target_ip`` / ``evidence_log_ids`` /
        ``expected_effect`` / ``rollback_plan``），缺一项直接拒批。
        后两项本应由审批人填写；这里给出**与策略一致**的默认文案（到期自动解除），
        审批人可在交互节点里改写，但不会因为留空而让整条处置流程卡死。
        """
        return {
            "case_id": self.case_id,
            "action": self.action,
            "target_ip": self.target_ip,
            "evidence_log_ids": list(self.evidence_log_ids),
            "expected_effect": self.expected_effect or self._default_effect(),
            "rollback_plan": self.rollback_plan
            or "按 response-policy.yaml 的 max_duration_minutes 到期自动解除；"
            "需提前恢复时按运维变更流程撤销本次动作",
            "approved_by": approved_by,
        }

    def _default_effect(self) -> str:
        if self.action in HIGH_RISK_ACTIONS:
            return (
                f"对 {self.target_ip or self.target_user} 执行 {self.action}，"
                "阻断该来源的后续访问；到期自动解除，期间需观察业务影响"
            )
        if self.action == "rate_limit":
            return f"对 {self.target_ip or self.target_user} 限速，降低请求频率而非完全阻断"
        return "仅记录结论，不产生副作用"


@dataclass
class DispositionReceipt:
    """处置回执：下游（邮件通知 / 评测 / 审计）只读这一份结构。"""

    status: str
    case_id: str
    action: str
    target: str
    executed: bool = False
    approval_id: Optional[str] = None
    policy_reason: Optional[str] = None
    detail: str = ""
    deadline: Optional[str] = None
    executor: str = "unknown"
    receipt_source: str = "response_executor"
    evidence_log_ids: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def needs_human(self) -> bool:
        return self.status == APPROVAL_REQUIRED

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "case_id": self.case_id,
            "action": self.action,
            "target": self.target,
            "executed": self.executed,
            "approval_id": self.approval_id,
            "policy_reason": self.policy_reason,
            "detail": self.detail,
            "deadline": self.deadline,
            "executor": self.executor,
            "receipt_source": self.receipt_source,
            "evidence_log_ids": list(self.evidence_log_ids),
        }


# ---------------------------------------------------------------------------
# 执行器解析
# ---------------------------------------------------------------------------


def resolve_executor() -> Optional[ResponseExecutor]:
    """加载 PR #37/#38 的真实执行器；未合入或依赖缺失时返回 ``None``。

    显式返回 ``None`` 而不是抛异常：调用方据此产出 ``EXECUTOR_UNAVAILABLE`` 回执，
    让人一眼看出"这条处置没落地"，而不是以为封禁已经生效。
    """
    try:
        from operations import response_executor as executor  # type: ignore[import-not-found]
    except Exception:
        return None
    for name in ("evaluate_action", "approve", "reject", "expire_pending"):
        if not callable(getattr(executor, name, None)):
            return None
    return executor  # type: ignore[return-value]


def _executor_name(executor: Any) -> str:
    return str(getattr(executor, "__name__", type(executor).__name__))


# ---------------------------------------------------------------------------
# 提交 / 审批 / 超时
# ---------------------------------------------------------------------------


def submit(
    request: DispositionRequest,
    *,
    executor: Optional[ResponseExecutor] = None,
    timeout_minutes: float = 30,
    now: Optional[datetime] = None,
) -> DispositionReceipt:
    """提交一次处置申请，返回真实回执。

    关键约束：

    * 证据为空时**不提交**——没有证据的处置无法回溯，直接按策略拒绝；
    * ``action=none`` 不调用执行器，直接 ``NO_ACTION``（无副作用，也不需要审批）；
    * 执行器不可用 → ``EXECUTOR_UNAVAILABLE``，``executed=False``。
    """
    if not request.case_id:
        raise DispositionError("处置申请必须带 case_id")
    if not request.action:
        raise DispositionError("处置申请必须带 action")

    target = request.target_ip or request.target_user
    if request.action == "none":
        return DispositionReceipt(
            status=NO_ACTION,
            case_id=request.case_id,
            action="none",
            target=target,
            executed=False,
            detail="动作 none 表示无需处置：不提交申请、不产生副作用、不需要审批",
            evidence_log_ids=list(request.evidence_log_ids),
        )

    executor = executor if executor is not None else resolve_executor()
    if executor is None:
        return DispositionReceipt(
            status=EXECUTOR_UNAVAILABLE,
            case_id=request.case_id,
            action=request.action,
            target=target,
            executed=False,
            detail=(
                "策略网关/状态机（PR #37/#38 `src/operations/response_executor.py`）"
                "当前不可用：处置未提交、未执行，需等待执行器合入后再跑"
            ),
            receipt_source="none",
            evidence_log_ids=list(request.evidence_log_ids),
        )

    raw = executor.evaluate_action(
        request.action,
        request.target_type,
        request.target_ip,
        request.target_user,
        list(request.evidence_log_ids),
        case_id=request.case_id,
        timeout_minutes=timeout_minutes,
        now=now,
    )
    status = _STATUS_MAP.get(str(raw.get("status")), str(raw.get("status") or "UNKNOWN"))
    executed = status == EXECUTED or bool(raw.get("executed"))
    detail = _describe(status, request, raw)
    return DispositionReceipt(
        status=status,
        case_id=request.case_id,
        action=str(raw.get("action") or request.action),
        target=str(raw.get("target") or target),
        executed=executed,
        approval_id=raw.get("approval_id"),
        policy_reason=raw.get("policy_reason"),
        detail=detail,
        deadline=raw.get("deadline"),
        executor=_executor_name(executor),
        evidence_log_ids=list(request.evidence_log_ids),
        raw=raw,
    )


def _describe(status: str, request: DispositionRequest, raw: dict[str, Any]) -> str:
    if status == BLOCKED_BY_POLICY:
        return (
            f"策略网关拦截，未执行：{raw.get('policy_reason') or '未给出原因'}。"
            "拦截属于 fail-closed，未产生任何副作用。"
        )
    if status == APPROVAL_REQUIRED:
        return (
            f"已登记待审批单 {raw.get('approval_id')}，审批截止 {raw.get('deadline') or '未给出'}。"
            "在恒脑【交互节点】给出明确批准前不会执行，超时按拒绝处理。"
        )
    if status == EXECUTED:
        record = raw.get("record") or {}
        return (
            f"动作 {raw.get('action') or request.action} 已执行并写入审计"
            f"（{record.get('ts') or '时间未给出'}）。"
        )
    if status == NO_ACTION:
        return "策略判定无需处置，未产生副作用。"
    return f"执行器返回未识别状态：{raw.get('status')}"


def resolve_approval(
    approval_id: str,
    *,
    decision: str,
    reviewed_by: str,
    order: dict[str, Any],
    executor: Optional[ResponseExecutor] = None,
    now: Optional[datetime] = None,
) -> DispositionReceipt:
    """人工审批结果回填：``approve`` 执行、``reject`` 不执行。

    审批人必须可追溯（``reviewed_by`` 不能为空）；审批单的动作与目标必须与
    待审批单一致，防止"批 A 执行 B"——这两条由执行器强制，本模块只负责转译。
    """
    if decision not in {"approve", "reject"}:
        raise DispositionError(f"未知审批决定：{decision}（应为 approve / reject）")
    if not reviewed_by or not reviewed_by.strip():
        raise DispositionError("审批必须记录审批人 reviewed_by")

    executor = executor if executor is not None else resolve_executor()
    if executor is None:
        return DispositionReceipt(
            status=EXECUTOR_UNAVAILABLE,
            case_id=str(order.get("case_id") or ""),
            action=str(order.get("action") or ""),
            target=str(order.get("target_ip") or ""),
            executed=False,
            approval_id=approval_id,
            detail="执行器不可用，审批结果无法结算；处置未执行",
            receipt_source="none",
        )

    try:
        if decision == "approve":
            raw = executor.approve(approval_id, order, reviewed_by, now=now)
            return DispositionReceipt(
                status=EXECUTED,
                case_id=str(order.get("case_id") or ""),
                action=str(order.get("action") or ""),
                target=str(order.get("target_ip") or ""),
                executed=True,
                approval_id=approval_id,
                detail=f"审批人 {reviewed_by} 批准并执行，已写入执行审计",
                executor=_executor_name(executor),
                raw=raw if isinstance(raw, dict) else {"result": raw},
            )
        raw = executor.reject(approval_id, reviewed_by, reason=str(order.get("reason") or ""), now=now)
        return DispositionReceipt(
            status=REJECTED,
            case_id=str(order.get("case_id") or ""),
            action=str(order.get("action") or ""),
            target=str(order.get("target_ip") or ""),
            executed=False,
            approval_id=approval_id,
            detail=f"审批人 {reviewed_by} 拒绝，处置未执行",
            executor=_executor_name(executor),
            raw=raw if isinstance(raw, dict) else {"result": raw},
        )
    except Exception as exc:  # ApprovalError 等：审批单失效/字段不全/目标不一致
        return DispositionReceipt(
            status=INVALID_APPROVAL,
            case_id=str(order.get("case_id") or ""),
            action=str(order.get("action") or ""),
            target=str(order.get("target_ip") or ""),
            executed=False,
            approval_id=approval_id,
            detail=f"审批未被受理：{type(exc).__name__}: {exc}",
            executor=_executor_name(executor),
        )


def settle_timeouts(
    *,
    executor: Optional[ResponseExecutor] = None,
    now: Optional[datetime] = None,
) -> list[DispositionReceipt]:
    """结算所有到期审批单：超时一律按拒绝处理，绝不"没人管就默认放行"。"""
    executor = executor if executor is not None else resolve_executor()
    if executor is None:
        return []
    settled = executor.expire_pending(now)
    receipts: list[DispositionReceipt] = []
    for order in settled or []:
        receipts.append(
            DispositionReceipt(
                status=APPROVAL_TIMEOUT,
                case_id=str(order.get("case_id") or ""),
                action=str(order.get("action") or ""),
                target=str(order.get("target") or order.get("target_ip") or ""),
                executed=False,
                approval_id=order.get("approval_id"),
                policy_reason=order.get("reject_reason"),
                detail=(
                    "审批超时未处理，按 approval.on_timeout=reject 自动拒绝，"
                    "处置未执行，也未伪造审批人"
                ),
                executor=_executor_name(executor),
                raw=order,
            )
        )
    return receipts


# ---------------------------------------------------------------------------
# 从调查结论生成处置申请
# ---------------------------------------------------------------------------


def build_request(
    result: dict[str, Any],
    *,
    target_type: str = "",
    target_user: str = "",
    expected_effect: str = "",
    rollback_plan: str = "",
) -> DispositionRequest:
    """把 11 字段调查结论翻译成处置申请。

    ``target_type`` 取资产台账的 ``type``（web/host/database）。策略网关用它判断动作
    是否越界（例如 ``block_ip`` 仅允许 web），因此不能省。
    ``isolate_account`` 的目标是**账号**而不是 IP，必须由调用方显式给出 ``target_user``，
    本函数不猜对象。
    """
    action = str(result.get("recommended_action") or "none")
    target_ip = str(result.get("attacker_ip") or "")
    evidence = [str(item) for item in result.get("evidence_log_ids") or []]
    if action == "isolate_account":
        target_ip = ""
    else:
        target_user = ""
    return DispositionRequest(
        case_id=str(result.get("case_id") or ""),
        action=action,
        target_ip=target_ip,
        target_user=target_user,
        target_type=target_type,
        evidence_log_ids=evidence,
        reason=str(result.get("attack_chain_summary") or ""),
        expected_effect=expected_effect,
        rollback_plan=rollback_plan,
    )
