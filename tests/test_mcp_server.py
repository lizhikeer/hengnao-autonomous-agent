"""MCP 服务测试：用官方 SDK 客户端启动子进程，实测工具发现与工具调用。

注意：这里验证的是 **MCP 协议端点**，与 `test_api.py` 的 HTTP 路由是两条不同的通道。
两者共用同一份业务实现，所以断言的行为应当一致。
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SERVER = REPO / "src" / "mcp_server" / "server.py"

EXPECTED_TOOLS = {
    "seclog_health",
    "seclog_query_logs",
    "seclog_get_context",
    "seclog_search_knowledge",
    "seclog_request_response",
}


async def _with_session(fn):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER), "--transport", "stdio"],
        cwd=str(REPO),
        env={**os.environ},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await fn(session)


def _payload(result) -> dict:
    return json.loads(result.content[0].text)


def test_tools_are_discoverable():
    async def flow(session):
        tools = await session.list_tools()
        return {t.name for t in tools.tools}, {t.name: (t.description or "") for t in tools.tools}

    names, descs = asyncio.run(_with_session(flow))
    assert EXPECTED_TOOLS.issubset(names)
    # 工具描述是大模型选择工具的唯一依据，不能为空
    for name in EXPECTED_TOOLS:
        assert descs[name].strip(), f"{name} 缺少 description"


def test_health_tool_call_matches_http():
    async def flow(session):
        return _payload(await session.call_tool("seclog_health", {}))

    body = asyncio.run(_with_session(flow))
    assert body["status"] == "ok"
    assert body["mock_mode"] is True


def test_query_logs_tool_returns_chain_with_mock_flag():
    async def flow(session):
        return _payload(
            await session.call_tool(
                "seclog_query_logs",
                {"case_id": "CASE-MCP", "trace_id": "CHAIN-ATTACK-01", "limit": 3},
            )
        )

    body = asyncio.run(_with_session(flow))
    assert body["meta"]["mock"] is True
    assert body["meta"]["total"] == 4
    assert len(body["items"]) == 3


def test_query_logs_tool_surfaces_param_error():
    """参数错误在 MCP 通道里应返回同样的 invalid_params 结构，而不是抛协议异常。"""
    async def flow(session):
        return _payload(await session.call_tool("seclog_query_logs", {}))

    body = asyncio.run(_with_session(flow))
    assert body["code"] == "invalid_params"


def test_request_response_tool_rejects_forged_evidence():
    async def flow(session):
        # 先查一次，建立证据；再用伪造编号提交
        await session.call_tool(
            "seclog_query_logs", {"case_id": "CASE-MCP2", "trace_id": "CHAIN-ATTACK-01"}
        )
        return _payload(
            await session.call_tool(
                "seclog_request_response",
                {
                    "case_id": "CASE-MCP2",
                    "action": "block_ip",
                    "target_ip": "198.51.100.23",
                    "evidence_log_ids": ["LOG-20261027-9999"],
                    "reason": "MCP 通道伪造证据测试",
                },
            )
        )

    body = asyncio.run(_with_session(flow))
    assert body["status"] == "rejected"
    assert body["rejected_evidence_ids"] == ["LOG-20261027-9999"]
