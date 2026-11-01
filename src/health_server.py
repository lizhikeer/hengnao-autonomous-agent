"""最小健康检查服务（W1 联调兜底）。

用途：
1. ``@chensz-u`` 的 ``src/api/app.py`` 合入前，先用本模块把公网隧道与 ``/health``
   的连通性跑通，满足 Issue #2 的验收项「平台侧调用 /health 返回 200」。
2. 长期作为容器 liveness 的稳定探针——它只依赖配置与两个外部组件，不依赖业务代码，
   业务代码出问题时仍能准确反映「进程活着、底座是否可达」。

启动：
    uvicorn src.health_server:app --host 0.0.0.0 --port 8000

设计约束：
- ``/health`` 永远返回 HTTP 200，只要进程存活；组件状态放在 body 里。
  这样隧道侧的连通性检查不会被下游组件抖动误判为「隧道断了」。
- ``/health/ready`` 才在组件不可用时返回 503，供编排系统判断是否接流量。
"""

from __future__ import annotations

import socket
import time
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.config import settings

app = FastAPI(
    title="SecLog-Agent Health Probe",
    version="0.1.0",
    description="W1 基础设施联调用的最小健康检查服务",
)

_STARTED_AT = time.time()


def _check_tcp(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    """TCP 连通性探测。比 HTTP 探测更宽容：能连上就说明网络路径通了。"""
    begin = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = round((time.perf_counter() - begin) * 1000, 2)
            return {"ok": True, "latency_ms": latency_ms}
    except OSError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _check_http(url: str, timeout: float = 2.0) -> dict[str, Any]:
    """HTTP 探测，用于 Qdrant 的 /readyz。"""
    import urllib.error
    import urllib.request

    begin = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            latency_ms = round((time.perf_counter() - begin) * 1000, 2)
            return {"ok": 200 <= resp.status < 300, "status": resp.status, "latency_ms": latency_ms}
    except urllib.error.URLError as exc:
        return {"ok": False, "error": str(exc.reason)}
    except OSError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _collect_components() -> dict[str, Any]:
    return {
        "clickhouse": _check_tcp(settings.clickhouse_host, settings.clickhouse_http_port),
        "qdrant": _check_http(settings.qdrant_url.rstrip("/") + "/readyz"),
    }


@app.get("/", include_in_schema=False)
def root() -> dict[str, Any]:
    return {
        "service": "seclog-agent",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", summary="存活探针（始终 200）")
def health() -> dict[str, Any]:
    components = _collect_components()
    return {
        "status": "ok",
        "service": "seclog-agent",
        "version": app.version,
        "uptime_seconds": round(time.time() - _STARTED_AT, 1),
        "components": components,
    }


@app.get("/health/ready", summary="就绪探针（组件不可用返回 503）")
def readiness() -> JSONResponse:
    components = _collect_components()
    ready = all(item.get("ok") for item in components.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "degraded",
            "components": components,
        },
    )
