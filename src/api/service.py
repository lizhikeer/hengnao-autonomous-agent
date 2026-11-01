"""同一进程提供 REST 与 MCP，保证两种调用方式使用同一案例证据表。"""
from contextlib import asynccontextmanager
import os

from api.app import app as rest_app
from starlette.applications import Starlette
from starlette.routing import Mount
from mcp_server.server import (mcp, seclog_health, seclog_query_logs,
                               seclog_get_context, seclog_search_knowledge)
from mcp.server.fastmcp import FastMCP

# 调查节点只提供读取工具；处置工具由审批后的独立节点调用。
investigation_mcp = FastMCP("seclog-investigation", streamable_http_path="/", stateless_http=True)
for tool in (seclog_health, seclog_query_logs, seclog_get_context, seclog_search_knowledge):
    investigation_mcp.add_tool(tool)

# 公网联调时只放行配置的确切主机名，保留 SDK 的 Host 校验。
public_host = os.getenv("SECLOG_PUBLIC_HOST", "").strip()
if public_host:
    mcp.settings.transport_security.allowed_hosts.append(public_host)
    investigation_mcp.settings.transport_security.allowed_hosts.append(public_host)
mcp.settings.streamable_http_path = "/"
# 工具调用不依赖 MCP 会话；平台持有旧会话 ID 时，重启服务也能继续调用。
mcp.settings.stateless_http = True


@asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():
        async with investigation_mcp.session_manager.run():
            yield


app = Starlette(lifespan=lifespan, routes=[
    Mount("/mcp", app=mcp.streamable_http_app()),
    Mount("/investigation", app=investigation_mcp.streamable_http_app()),
    Mount("/", app=rest_app),
])
