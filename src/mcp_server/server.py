"""SecLog MCP 服务（Week 1 骨架）。

概念区分（Issue #4 第 4 条明确要求，勿混为一谈）
------------------------------------------------
* ``src/api/app.py`` 是 **FastAPI 路由**：恒脑平台用【API 工具】+【插件节点】以 HTTP 方式调用。
* 本文件是 **MCP 服务**：用 MCP 官方 Python SDK（``mcp`` 包）暴露工具，供支持 MCP 的客户端
  （恒脑【自规划节点】、Claude Desktop、Codex 等）做 ``tools/list`` 发现与 ``tools/call`` 调用。
* 两者共用同一份业务逻辑与同一份证据登记表（都是 ``src/api`` 下的实现），
  但一个是 REST 接口、一个是 MCP 协议端点。**把 FastAPI 路由称作 MCP 服务是错误的。**

传输方式
--------
* ``stdio``：本地子进程直连（默认）。恒脑 SaaS 云端**无法**直连本地 stdio 进程。
* ``streamable-http``：MCP 的 HTTP 传输。恒脑平台实际支持哪种 MCP 传输方式，
  目前**未在平台上验证**（见 week1_acceptance.md 的"未验证"清单），
  因此第一周对外只承诺 HTTP API 工具这条主线，MCP 作为兼容性预留。

启动：
    .venv/Scripts/python -m mcp_server.server                  # stdio
    .venv/Scripts/python -m mcp_server.server --transport http # streamable-http
需在 ``src`` 目录下运行，或把 ``src`` 加入 ``PYTHONPATH``。
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

# 允许以 `python src/mcp_server/server.py` 直接启动时找到 api 包
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from fastapi.responses import JSONResponse  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

from api import app as api_app  # noqa: E402
from api.schemas import (  # noqa: E402
    GetContextRequest,
    QueryLogsRequest,
    RequestResponseRequest,
    SearchKnowledgeRequest,
)

mcp = FastMCP(
    name="seclog-tool-service",
    instructions=(
        "SecLog 安全日志调查工具集。先用 seclog_query_logs 拉取关联日志并拿到 log_id，"
        "再用 seclog_get_context 查账号基线与资产重要性、seclog_search_knowledge 查处置知识，"
        "最后用 seclog_request_response 提交处置（必须附带真实查询得到的证据编号）。"
        "当前全部为 Mock 数据（meta.mock=true），不得当作真实生产证据。"
    ),
)


def _unwrap(result: Any) -> dict[str, Any]:
    """把 FastAPI 路由函数的返回值统一成 dict。

    - Pydantic 响应模型 → ``model_dump()``
    - 错误场景返回的 ``JSONResponse`` → 解析其 body，保持与 HTTP 调用完全一致的语义
    """
    if isinstance(result, JSONResponse):
        return json.loads(result.body.decode("utf-8"))
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return {"result": result}


# ---------------------------------------------------------------------------
# MCP 工具
# ---------------------------------------------------------------------------


@mcp.tool(
    name="seclog_health",
    description="检查 SecLog 工具服务是否可用，并确认当前是否处于 Mock 模式。用于连通性自检。",
)
def seclog_health() -> dict[str, Any]:
    return _unwrap(api_app.health())


@mcp.tool(
    name="seclog_query_logs",
    description=(
        "查询全链路关联安全日志（认证日志/Web 访问/网络流）。"
        "至少提供 src_ip、dest_ip、trace_id 或 log_source 之一。"
        "返回的 log_id 是后续提交处置时可引用的唯一合法证据编号。"
        "用于处置的查询必须带 case_id；省略时只查询、不登记证据。当前为 Mock 数据。"
    ),
)
def seclog_query_logs(
    case_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    trace_id: Optional[str] = None,
    log_source: str = "all",
    time_window: Optional[str] = None,
    limit: int = 50,
) -> dict[str, Any]:
    req = QueryLogsRequest(
        case_id=case_id,
        src_ip=src_ip,
        dest_ip=dest_ip,
        trace_id=trace_id,
        log_source=log_source,  # type: ignore[arg-type]
        time_window=time_window,
        limit=limit,
    )
    return _unwrap(api_app.query_logs(req))


@mcp.tool(
    name="seclog_get_context",
    description=(
        "查询目标账号的行为基线（活跃时段、常用源 IP、24h 登录失败次数）"
        "与目标资产的上下文（重要性等级、维护窗口、是否白名单）。user 与 asset_id 至少填一项。"
    ),
)
def seclog_get_context(
    user: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> dict[str, Any]:
    return _unwrap(api_app.get_context(GetContextRequest(user=user, asset_id=asset_id)))


@mcp.tool(
    name="seclog_search_knowledge",
    description=(
        "检索安全知识卡与已确认的正/反案例卡（OWASP/MITRE 处置基准、错题修订经验）。"
        "用于给研判结论找处置依据。零命中返回空列表。当前为 Mock 关键词匹配。"
    ),
)
def seclog_search_knowledge(
    query: str,
    attack_category: Optional[str] = None,
    limit: int = 5,
) -> dict[str, Any]:
    req = SearchKnowledgeRequest(query=query, attack_category=attack_category, limit=limit)
    return _unwrap(api_app.search_knowledge(req))


@mcp.tool(
    name="seclog_request_response",
    description=(
        "提交处置动作（block_ip / block_ip_short_term / rate_limit / none）及其证据。"
        "evidence_log_ids 必须来自本次调查经 seclog_query_logs 真实返回的编号，"
        "伪造或跨任务引用会被拒绝。高危动作只登记为待审批单，不产生真实封禁副作用。"
    ),
)
def seclog_request_response(
    case_id: str,
    action: str,
    evidence_log_ids: list[str],
    reason: str,
    target_ip: Optional[str] = None,
) -> dict[str, Any]:
    req = RequestResponseRequest(
        case_id=case_id,
        action=action,  # type: ignore[arg-type]
        target_ip=target_ip,
        evidence_log_ids=evidence_log_ids,
        reason=reason,
    )
    return _unwrap(api_app.request_response(req))


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - 进程入口
    args = list(sys.argv[1:] if argv is None else argv)
    transport = "stdio"
    if "--transport" in args:
        idx = args.index("--transport")
        if idx + 1 < len(args):
            transport = args[idx + 1]
    if transport in {"http", "streamable-http"}:
        mcp.settings.host = os.getenv("SECLOG_MCP_HOST", "127.0.0.1")
        mcp.settings.port = int(os.getenv("SECLOG_MCP_PORT", "8765"))
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
