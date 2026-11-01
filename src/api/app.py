"""SecLog FastAPI 工具服务（Week 1 骨架）。

对外暴露五个能力项，供恒脑平台【API 工具】注册与【插件节点】调用：

===============  ====================================  =========================
方法与路径        能力                                  后端真实状态
===============  ====================================  =========================
GET  /health      健康检查（平台连通性调试准入）        自实现，可直接用
POST /tools/query_logs         全链路关联日志查询        Mock（ClickHouse 未接入）
POST /tools/get_context        用户画像 + 资产上下文     Mock（画像/资产库未接入）
POST /tools/search_knowledge   安全知识卡检索            Mock（Qdrant 未接入）
POST /tools/request_response   处置申请（登录待审批）    未接入权限网关，仅登记
===============  ====================================  =========================

硬约束（来自 Issue #4 与恒脑平台规范）
------------------------------------
* 仅使用 GET / POST —— 平台 API 工具只支持这两种方法。
* 每个参数都有语义 description + examples —— 这是大模型构造请求的唯一依据。
* **Mock 绝不伪装真实**：所有查询响应带 ``meta.mock=true`` /
  ``meta.data_source="mock"`` / ``meta.backend_available=false``；
  需要真实后端时必须显式设置 ``SECLOG_REAL_BACKEND=1``，
  而真实后端尚未接入，此时返回 503 ``backend_unavailable``，不会假装查到了。
* 三类结果严格区分：零结果 200（``total=0``、``items=[]``）、
  参数错误 422（``code=invalid_params``）、后端失败 503（``code=backend_unavailable``）。
* 不提供任意 SQL / 命令执行：过滤字段全部在白名单枚举内。
* 处置接口本周**不产生任何真实副作用**：不封 IP、不改防火墙、不发邮件。

启动：
    .venv/Scripts/python -m uvicorn api.app:app --app-dir src --port 8000
或：
    .venv/Scripts/python src/api/app.py
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
import threading
from typing import Any, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import (
    HIGH_RISK_ACTIONS,
    LIMIT_DEFAULT,
    TIME_WINDOW_MIN_MINUTES,
    parse_time_window,
)
from .evidence_check import registry
from .mock_data import (
    MOCK_REFERENCE_TIME,
    MOCK_ASSET_CONTEXT,
    MOCK_USER_PROFILE,
    query_mock_logs,
    search_mock_knowledge,
)
from .schemas import (
    ErrorBody,
    GetContextRequest,
    GetContextResponse,
    HealthResponse,
    KnowledgeCard,
    LogItem,
    QueryLogsRequest,
    QueryLogsResponse,
    QueryMeta,
    RequestResponseRequest,
    RequestResponseResponse,
    SearchKnowledgeRequest,
    SearchKnowledgeResponse,
    VerifyResultsRequest,
)

SERVICE_NAME = "seclog-tool-service"
SERVICE_VERSION = "0.1.0"
MOCK_MODE = True  # 第一周骨架固定开启：所有查询走显式 Mock

#: 参数错误状态码。Starlette 1.x 已把 HTTP_422_UNPROCESSABLE_ENTITY 标记弃用，
#: 这里直接用字面量，避免依赖具体版本提供的枚举名。
HTTP_422 = 422

#: 置 1 表示"我要真实后端"。真实后端尚未接入，因此该开关打开后查询一律 503。
_REAL_BACKEND_REQUESTED = os.getenv("SECLOG_REAL_BACKEND", "0").strip() in {"1", "true", "True"}

app = FastAPI(
    title="SecLog 工具服务（恒脑 API 工具）",
    version=SERVICE_VERSION,
    description=(
        "面向恒脑平台调用的安全日志调查工具服务。第一周骨架：查询类工具返回显式 Mock 数据"
        "（meta.mock=true），处置类工具只登记待审批、不产生真实副作用。"
        "零结果返回 200 空列表；参数错误返回 422；后端不可用返回 503。"
    ),
)

#: 调试开关：置 1 时把每个 POST 的请求头与请求体打到 stderr，用于排查平台侧调用失败。
#: 默认关闭；只在本地联调时打开，生产环境不要开启（会记录请求内容）。
_DEBUG_REQ = os.getenv("SECLOG_DEBUG_REQ", "0").strip() in {"1", "true", "True"}

#: 空请求体探测的响应体。
#: 恒脑平台的「API 工具调试」实测是一个**只发 URL、不带 Content-Type、body 为空**的连通性探测
#: （见 PENDING_CONFIRMATION.md §2.2 的抓包证据）。此时若按业务规则返回 422，
#: 能力项永远无法通过平台调试、在工作流里被置灰。
#: 因此在"请求体完全为空"时返回一个明确的探测响应：既不执行任何查询/处置，也如实说明情况。
_PROBE_BODY: dict[str, Any] = {
    "probe": True,
    "mock": True,
    "service": SERVICE_NAME,
    "version": SERVICE_VERSION,
    "message": (
        "连通性探测：请求体为空，未执行任何查询或处置动作。"
        "恒脑平台的 API 工具调试即为该形态；真实调用时请携带完整 JSON 参数。"
    ),
}


@app.middleware("http")
async def _probe_and_debug(request: Request, call_next):
    """空请求体探测兜底 + 可选请求日志。"""
    if request.method in {"POST", "PUT", "PATCH"} and request.url.path.startswith("/tools/"):
        raw = await request.body()
        if _DEBUG_REQ:
            sys.stderr.write(
                f"[DEBUG_REQ] {request.method} {request.url.path} "
                f"ct={request.headers.get('content-type')} "
                f"ua={request.headers.get('user-agent')} body={raw[:1500]!r}\n"
            )
            sys.stderr.flush()
        if not raw:
            _audit("probe", {"path": request.url.path, "ua": request.headers.get("user-agent")})
            return JSONResponse(status_code=200, content=_PROBE_BODY)
    return await call_next(request)


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

_audit_lock = threading.Lock()
_audit_log: list[dict[str, Any]] = []
_approval_seq = 0


def _audit(event: str, payload: dict[str, Any]) -> None:
    """进程内审计流水（含时间戳），供验收与排查；不落库。"""
    with _audit_lock:
        _audit_log.append(
            {
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                "event": event,
                **payload,
            }
        )


def _error(
    http_status: int,
    code: str,
    message: str,
    details: Optional[dict[str, Any]] = None,
) -> JSONResponse:
    """统一错误响应体（ErrorBody 直接作为顶层，避免再套一层 detail）。"""
    body = ErrorBody(code=code, message=message, details=details)
    return JSONResponse(status_code=http_status, content=body.model_dump())


def _mock_meta(total: int) -> QueryMeta:
    return QueryMeta(total=total, data_source="mock", mock=True, backend_available=False)


def _next_approval_id() -> str:
    global _approval_seq
    with _audit_lock:
        _approval_seq += 1
        seq = _approval_seq
    return f"APPR-{_dt.datetime.now():%Y%m%d}-{seq:04d}"


def _real_backend_guard() -> Optional[JSONResponse]:
    """真实后端未接入时的统一 503。Mock 模式（默认）不触发。"""
    if not _REAL_BACKEND_REQUESTED:
        return None
    return _error(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "backend_unavailable",
        "已要求使用真实后端，但 ClickHouse / Qdrant / 权限网关本周尚未接入；"
        "为使下游可区分，本次查询不返回任何 Mock 数据冒充结果",
        {"backend_available": False, "requested": "real"},
    )


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """把 FastAPI 默认 422 转成项目统一的 ErrorBody(invalid_params)。"""
    errors = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()) if x not in ("body", "query", "path"))
        errors.append({"field": loc or "<body>", "message": err.get("msg", ""), "type": err.get("type", "")})
    return _error(
        HTTP_422,
        "invalid_params",
        "请求参数校验失败，请按字段说明修正后重试",
        {"errors": errors},
    )


def _resolve_window_minutes(req: QueryLogsRequest) -> int:
    """合并 time_window / time_window_minutes，返回最终回溯分钟数。

    两者都给出且不一致时抛 ``ValueError``（→ 422）。
    """
    from_str = parse_time_window(req.time_window) if req.time_window else None
    from_int = req.time_window_minutes
    if from_str is not None and from_int is not None:
        if from_str != from_int:
            raise ValueError(
                f"time_window={req.time_window!r}({from_str} 分钟) 与 "
                f"time_window_minutes={from_int} 冲突，请只保留一个"
            )
        return from_str
    if from_str is not None:
        return from_str
    if from_int is not None:
        return from_int
    return TIME_WINDOW_MIN_MINUTES * 60  # 默认 1 小时


# ---------------------------------------------------------------------------
# 1. 健康检查
# ---------------------------------------------------------------------------


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="服务健康检查（恒脑平台 API 工具连通性调试用）",
    description=(
        "恒脑平台注册 API 工具时必须先调试通过（HTTP 200）才能在工作流节点中选用。"
        "本接口无参数、无外部依赖，是首周打通公网隧道的验收点。"
    ),
    tags=["基础"],
)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=SERVICE_NAME,
        version=SERVICE_VERSION,
        mock_mode=True,
    )


# ---------------------------------------------------------------------------
# 2. 全链路关联日志查询
# ---------------------------------------------------------------------------


@app.post(
    "/tools/query_logs",
    response_model=QueryLogsResponse,
    summary="按源/目的 IP、trace_id、日志来源与时间窗查询全链路关联日志",
    description=(
        "用于攻击溯源：给定可疑源 IP 或 trace_id，拉取同一攻击故事链的多阶段日志"
        "（认证爆破 → Web 利用 → 网络外连）。返回的每条 log_id 是 Agent 引用证据的唯一合法来源。"
        "当前为 Mock 数据，meta.mock=true；零结果返回 200 且 total=0。"
    ),
    tags=["调查工具"],
)
def query_logs(req: QueryLogsRequest):
    guard = _real_backend_guard()
    if guard is not None:
        return guard

    # 至少一个过滤条件，避免无界全量查询
    filters = [k for k in ("src_ip", "dest_ip", "trace_id") if getattr(req, k)]
    if not filters and req.log_source == "all":
        return _error(
            HTTP_422,
            "invalid_params",
            "至少提供一个过滤条件（src_ip / dest_ip / trace_id / log_source），不接受无条件全量查询",
            {"provided": req.model_dump(exclude_none=True)},
        )

    try:
        window_minutes = _resolve_window_minutes(req)
    except ValueError as exc:
        return _error(
            HTTP_422,
            "invalid_params",
            str(exc),
            {"time_window": req.time_window, "time_window_minutes": req.time_window_minutes},
        )

    rows = query_mock_logs(
        src_ip=req.src_ip,
        dest_ip=req.dest_ip,
        trace_id=req.trace_id,
        log_source=req.log_source,
        window_minutes=window_minutes,
    )
    total_before_limit = len(rows)
    rows = rows[: req.limit]

    # 登记证据：本次查询返回的 log_id 才能被后续处置引用
    registered = registry.register(
        (r["log_id"] for r in rows),
        case_id=req.case_id,
        query_params={
            "src_ip": req.src_ip,
            "dest_ip": req.dest_ip,
            "trace_id": req.trace_id,
            "log_source": req.log_source,
            "window_minutes": window_minutes,
            "limit": req.limit,
        },
    )
    _audit(
        "query_logs",
        {
            "case_id": req.case_id,
            "filters": {k: getattr(req, k) for k in filters},
            "log_source": req.log_source,
            "window_minutes": window_minutes,
            "returned": len(rows),
            "registered_new": registered,
        },
    )

    return QueryLogsResponse(
        meta=_mock_meta(total=total_before_limit).model_copy(
            update={"reference_time": MOCK_REFERENCE_TIME.isoformat()}),
        items=[LogItem(**row) for row in rows],
    )


# ---------------------------------------------------------------------------
# 3. 用户画像 + 资产上下文
# ---------------------------------------------------------------------------


@app.post(
    "/tools/get_context",
    response_model=GetContextResponse,
    summary="查询目标账号行为基线与目标资产重要性/维护窗口/白名单状态",
    description=(
        "整合 get_user_profile 与 get_asset_context 两类上下文："
        "判断一次登录是否偏离该账号的历史行为，以及受害资产的重要等级与是否处于维护窗口。"
        "user 与 asset_id 至少填一项；查不到时返回 200 且 total=0（不是错误）。"
    ),
    tags=["调查工具"],
)
def get_context(req: GetContextRequest):
    guard = _real_backend_guard()
    if guard is not None:
        return guard

    if not req.user and not req.asset_id:
        return _error(
            HTTP_422,
            "invalid_params",
            "user 与 asset_id 至少提供一个",
            {},
        )

    profile = MOCK_USER_PROFILE.get(req.user) if req.user else None
    context = MOCK_ASSET_CONTEXT.get(req.asset_id) if req.asset_id else None
    found = sum(1 for x in (profile, context) if x)

    _audit("get_context", {"user": req.user, "asset_id": req.asset_id, "found": found})
    return GetContextResponse(
        meta=_mock_meta(total=found),
        user_profile=profile,
        asset_context=context,
    )


# ---------------------------------------------------------------------------
# 4. 安全知识 / 已确认案例检索
# ---------------------------------------------------------------------------


@app.post(
    "/tools/search_knowledge",
    response_model=SearchKnowledgeResponse,
    summary="检索安全知识卡与已确认正反案例卡（RAG 混合检索入口）",
    description=(
        "调用知识库检索：返回 OWASP/MITRE 安全知识卡、已确认正确案例卡、错误修订卡。"
        "当前为 Mock 关键词匹配（score 为演示值），真实 BGE 向量 + 关键词混合检索由知识库模块提供。"
        "零命中返回 200 且 items=[]。"
    ),
    tags=["调查工具"],
)
def search_knowledge(req: SearchKnowledgeRequest):
    guard = _real_backend_guard()
    if guard is not None:
        return guard

    cards = search_mock_knowledge(req.query, req.attack_category)
    total_before_limit = len(cards)
    cards = cards[: req.limit]

    _audit(
        "search_knowledge",
        {"query": req.query, "attack_category": req.attack_category, "hits": len(cards)},
    )
    return SearchKnowledgeResponse(
        meta=_mock_meta(total=total_before_limit),
        items=[KnowledgeCard(**c) for c in cards],
    )


# ---------------------------------------------------------------------------
# 5. 处置申请
# ---------------------------------------------------------------------------


@app.post(
    "/tools/request_response",
    response_model=RequestResponseResponse,
    summary="提交处置动作与证据编号（高危动作进入人工审批，本周不执行）",
    description=(
        "Agent 提交处置动作时必须附上支撑证据的 log_id，服务端做程序性校验："
        "证据必须来自本次调查真实查询返回，伪造编号或引用其它调查任务的编号一律拒绝。"
        "高危动作（block_ip / block_ip_short_term）在权限网关与交互节点审批回执缺失时"
        "只登记为待审批，不产生任何真实封禁副作用。模型在理由里自称「已审批」不构成授权。"
    ),
    tags=["处置工具"],
)
def request_response(req: RequestResponseRequest):
    guard = _real_backend_guard()
    if guard is not None:
        return guard

    # action=none：无需处置，不要求证据
    if req.action == "none":
        _audit("request_response:none", {"case_id": req.case_id})
        return RequestResponseResponse(
            status="no_action",
            approval_id=None,
            executed=False,
            detail="action=none 表示本案例无需处置，未提交任何动作，也未产生任何副作用",
            rejected_evidence_ids=[],
            mock=True,
        )

    # --- 程序校验一：证据真实性 ---
    check = registry.check(req.evidence_log_ids, case_id=req.case_id)
    if not check.ok:
        rejected = check.unknown + check.foreign
        parts = []
        if check.unknown:
            parts.append(f"伪造/未经查询返回的证据：{check.unknown}")
        if check.foreign:
            parts.append(f"属于其它调查任务的证据：{check.foreign}")
        detail = (
            "证据校验未通过，处置请求已拒绝（未产生任何副作用）。"
            + "；".join(parts)
            + "。请先用 /tools/query_logs 在本 case 下查询并引用真实返回的 log_id。"
        )
        _audit(
            "request_response:rejected",
            {"case_id": req.case_id, "action": req.action, "unknown": check.unknown, "foreign": check.foreign},
        )
        return RequestResponseResponse(
            status="rejected",
            approval_id=None,
            executed=False,
            detail=detail,
            rejected_evidence_ids=rejected,
            mock=True,
        )

    # --- 程序校验二：高危动作必须有程序化审批回执 ---
    # 本周权限网关未接入，恒脑【交互节点】的审批结果也没有回传通道，
    # 因此任何处置动作都只能登记为待审批。注意：模型自称"已审批"不进入此分支。
    approval_id = _next_approval_id()
    is_high_risk = req.action in HIGH_RISK_ACTIONS
    detail = (
        f"动作 {req.action}（{'高危' if is_high_risk else '低危'}）已登记为待审批单 {approval_id}。"
        "权限网关与执行器本周未接入，**未执行任何真实封禁/限速动作**；"
        "证据真实性校验已通过，审批结论只能来自恒脑【交互节点】confirm_block 或权限服务的程序化回执。"
    )
    _audit(
        "request_response:approval_required",
        {
            "case_id": req.case_id,
            "action": req.action,
            "target_ip": req.target_ip,
            "evidence": req.evidence_log_ids,
            "approval_id": approval_id,
            "executed": False,
        },
    )
    return RequestResponseResponse(
        status="approval_required",
        approval_id=approval_id,
        executed=False,
        detail=detail,
        rejected_evidence_ids=[],
        mock=True,
    )


# ---------------------------------------------------------------------------
# 本地调试入口
# ---------------------------------------------------------------------------


@app.post("/tools/verify_results", tags=["调查校验"])
def verify_results(req: VerifyResultsRequest):
    """工作流校验节点调用；证据取自服务器登记表，不接受模型提供的已知证据列表。"""
    from ai_engine.verify import verify_triage
    from ai_engine.results_schema import AgentResults
    from pydantic import ValidationError

    result = verify_triage(req.results, case_id=req.case_id,
                          evidence_log_ids=sorted(registry.known_log_ids(case_id=req.case_id)))
    try:
        AgentResults.model_validate(req.results)
    except ValidationError as exc:
        result.ok = False
        result.problems.append(str(exc))
    return {"verified": result.ok, "verify_msg": result.summary(), "triage": result.data}


def main() -> None:  # pragma: no cover - 手动启动用
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("SECLOG_PORT", "8000")))


if __name__ == "__main__":  # pragma: no cover
    main()
