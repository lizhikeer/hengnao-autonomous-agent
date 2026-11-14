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

def register_public_hosts(*apps, env_value: str | None = None) -> list[str]:
    """把配置的公网主机登记进 MCP 的 Host 白名单，返回最终登记的值。

    反代转发给应用的 Host 头可能带端口（``seclog.91666.icu:18443``）也可能被剥掉端口，
    因此对每个配置值同时登记「原值」和「无端口形式」；配置支持逗号分隔多个主机。

    只扩充白名单，**不关闭** SDK 的 Host 校验（DNS rebinding 防护仍生效）。
    """
    raw = env_value if env_value is not None else os.getenv("SECLOG_PUBLIC_HOST", "")
    registered: list[str] = []
    for app in apps:
        allowed = app.settings.transport_security.allowed_hosts
        for host in [h.strip() for h in raw.split(",") if h.strip()]:
            candidates = {host}
            if ":" not in host:
                # 反代可能按 443/80/自定义端口回源
                candidates.update({f"{host}:443", f"{host}:80"})
            else:
                candidates.add(host.split(":")[0])
            for candidate in candidates:
                if candidate not in allowed:
                    allowed.append(candidate)
                registered.append(candidate)
    return sorted(set(registered))


register_public_hosts(mcp, investigation_mcp)
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
