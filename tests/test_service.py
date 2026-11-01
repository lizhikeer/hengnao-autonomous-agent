"""覆盖平台复用服务重启前 MCP 会话 ID 的真实联调回归。"""
from fastapi.testclient import TestClient

from api.service import app


def test_mcp_accepts_stale_session_without_exposing_response_tool_to_planner():
    headers = {
        "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": "session-from-before-server-restart",
        "MCP-Protocol-Version": "2025-03-26",
    }
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        for endpoint, has_response_tool in (("/mcp/", True), ("/investigation/", False)):
            response = client.post(endpoint, headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
            })
            assert response.status_code == 200, response.text
            assert "seclog_query_logs" in response.text
            assert ("seclog_request_response" in response.text) is has_response_tool
