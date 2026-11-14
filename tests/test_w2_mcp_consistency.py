"""第二周：REST 与 MCP 必须复用同一业务逻辑、同一数据源、同一证据校验。

这里直接调用 ``src/mcp_server/server.py`` 里注册给 MCP 的工具函数（进程内），
与 ``/tools/*`` 的 REST 结果逐字段比对，避免两套实现漂移。
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for candidate in (str(REPO / "src"), str(REPO)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


@pytest.fixture()
def mcp_tools(monkeypatch):
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "dataset_replay")
    api_app = importlib.import_module("api.app")
    api_app.reset_source_cache()
    server = importlib.import_module("mcp_server.server")
    yield server, api_app
    api_app.reset_source_cache()


def test_query_logs_matches_rest(mcp_tools):
    server, api_app = mcp_tools
    from api.schemas import QueryLogsRequest

    rest = api_app.query_logs(
        QueryLogsRequest(case_id="MCP-CASE-1", trace_id="CHAIN-CASE-01", limit=10)
    )
    tool = server.seclog_query_logs(case_id="MCP-CASE-1", trace_id="CHAIN-CASE-01", limit=10)

    assert tool["meta"]["data_source"] == rest.meta.data_source == "dataset_replay"
    assert tool["meta"]["total"] == rest.meta.total
    assert [i["log_id"] for i in tool["items"]] == [i.log_id for i in rest.items]


def test_get_context_matches_rest(mcp_tools):
    server, api_app = mcp_tools
    from api.schemas import GetContextRequest

    rest = api_app.get_context(
        GetContextRequest(user="ops_zhang", asset_id="web-prod-01", at_time="2026-10-29T18:10:00Z")
    )
    tool = server.seclog_get_context(
        user="ops_zhang", asset_id="web-prod-01", at_time="2026-10-29T18:10:00Z"
    )

    assert tool["meta"]["data_source"] == rest.meta.data_source == "asset_context"
    assert tool["asset_context"]["in_maintenance_window"] is True
    assert rest.asset_context["in_maintenance_window"] is True
    assert tool["user_profile"]["account_type"] == rest.user_profile["account_type"]


def test_evidence_check_applies_on_mcp_path_too(mcp_tools):
    """MCP 通道同样要拦伪造证据，不能因为是另一条入口就放松。"""
    server, _ = mcp_tools
    server.seclog_query_logs(case_id="MCP-CASE-2", trace_id="CHAIN-CASE-01", limit=5)
    out = server.seclog_request_response(
        case_id="MCP-CASE-2",
        action="block_ip",
        target_ip="198.51.100.23",
        evidence_log_ids=["LOG-19990101-0001"],
        reason="MCP 通道伪造证据测试",
    )
    assert out["status"] == "rejected"
    assert out["rejected_evidence_ids"] == ["LOG-19990101-0001"]


def test_mcp_unavailable_backend_reports_diagnosis(mcp_tools, monkeypatch):
    server, api_app = mcp_tools
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "clickhouse")
    api_app.reset_source_cache()
    out = server.seclog_query_logs(case_id="MCP-CASE-3", trace_id="CHAIN-CASE-01")
    assert out["code"] == "backend_unavailable"
    assert out["details"]["backend"] == "clickhouse"
    api_app.reset_source_cache()


# ---------------------------------------------------------------------------
# MCP 历史时间窗：用独立进程起双通道服务，走真实 tools/call
# ---------------------------------------------------------------------------
# 不用 TestClient：MCP 的 StreamableHTTPSessionManager 一个实例只能 run() 一次，
# 在进程内反复进出 lifespan 会报错。起独立进程最接近部署形态，也没有这个限制。

import json as _json  # noqa: E402
import os as _os  # noqa: E402
import subprocess  # noqa: E402
import sys as _sys  # noqa: E402
import time as _time  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402


def _http_json(url: str, payload: dict, host: str) -> tuple[int, str]:
    data = _json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2024-11-05",
            "Host": host,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _sse_payload(body: str) -> dict:
    for line in body.splitlines():
        if line.startswith("data: "):
            return _json.loads(line[6:])
    return _json.loads(body)


@pytest.fixture(scope="module")
def mcp_service():
    """起一次真实进程，供本模块的 MCP 端到端用例复用。"""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    root = str(REPO)
    env = dict(_os.environ)
    env["PYTHONPATH"] = f"{root}{_os.pathsep}{root}{_os.pathsep}{root + _os.sep + 'src'}"
    env["SECLOG_DATA_SOURCE"] = "dataset_replay"
    env["SECLOG_PUBLIC_HOST"] = "seclog.91666.icu,seclog.91666.icu:18443"
    proc = subprocess.Popen(
        [_sys.executable, "-m", "uvicorn", "src.api.service:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=root,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(40):
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=2) as resp:
                if resp.status == 200:
                    break
        except Exception:
            _time.sleep(0.25)
    else:
        proc.terminate()
        pytest.skip("双通道服务未能启动")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _mcp_call(base: str, path: str, name: str, args: dict) -> dict:
    _http_json(
        f"{base}{path}",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        },
        "seclog.91666.icu",
    )
    status, body = _http_json(
        f"{base}{path}",
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}},
        "seclog.91666.icu",
    )
    assert status == 200, body[:200]
    result = _sse_payload(body)["result"]
    return result.get("structuredContent") or result


def test_mcp_absolute_window_matches_rest(mcp_service):
    """11 月窗口：REST 与 MCP 都应为 0 条（修复前 MCP 忽略 time_start，返回 29 条）。"""
    base = mcp_service
    status, body = _http_json(
        f"{base}/tools/query_logs",
        {"trace_id": "CHAIN-CASE-01", "time_start": "2026-11-01T00:00:00Z", "limit": 200},
        "seclog.91666.icu",
    )
    assert status == 200, body[:200]
    rest = _json.loads(body)

    for path in ("/mcp/", "/investigation/"):
        mcp = _mcp_call(
            base, path, "seclog_query_logs",
            {"trace_id": "CHAIN-CASE-01", "time_start": "2026-11-01T00:00:00Z", "limit": 200},
        )
        assert mcp["meta"]["total"] == rest["meta"]["total"] == 0
        assert mcp["meta"]["time_base"] == rest["meta"]["time_base"] == "absolute"


def test_mcp_historical_window_returns_same_log_ids(mcp_service):
    """10 月窗口：条数、证据 ID、time_base 三者 REST 与 MCP 必须一致。"""
    base = mcp_service
    args = {
        "trace_id": "CHAIN-CASE-01",
        "time_start": "2026-10-27T14:00:00Z",
        "time_end": "2026-10-27T15:00:00Z",
        "limit": 200,
    }
    _, body = _http_json(f"{base}/tools/query_logs", args, "seclog.91666.icu")
    rest = _json.loads(body)
    mcp = _mcp_call(base, "/mcp/", "seclog_query_logs", args)

    assert rest["meta"]["total"] > 0
    assert mcp["meta"]["total"] == rest["meta"]["total"]
    assert mcp["meta"]["time_base"] == rest["meta"]["time_base"]
    assert [i["log_id"] for i in mcp["items"]] == [i["log_id"] for i in rest["items"]]


def test_investigation_entry_exposes_read_only_tools(mcp_service):
    """只读入口在公网 Host 下可列工具，且只有 4 个调查工具。"""
    base = mcp_service
    for path, expected in (
        ("/mcp/", {"seclog_health", "seclog_query_logs", "seclog_get_context", "seclog_search_knowledge", "seclog_request_response"}),
        ("/investigation/", {"seclog_health", "seclog_query_logs", "seclog_get_context", "seclog_search_knowledge"}),
    ):
        _http_json(
            f"{base}{path}",
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "p", "version": "1"}}},
            "seclog.91666.icu",
        )
        status, body = _http_json(
            f"{base}{path}", {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, "seclog.91666.icu"
        )
        assert status == 200, body[:200]
        names = {t["name"] for t in _sse_payload(body)["result"]["tools"]}
        assert names == expected, path


def test_public_host_registration_covers_port_variants():
    """配置单个域名时，带端口的 Host 也要放行；陌生 Host 不进白名单。"""
    from api import service

    registered = service.register_public_hosts(
        service.mcp, env_value="seclog.91666.icu,seclog.91666.icu:18443"
    )
    assert "seclog.91666.icu:18443" in registered
    assert "seclog.91666.icu" in registered
    assert "evil.example.com" not in registered
