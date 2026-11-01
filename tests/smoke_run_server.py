"""真实启动 uvicorn 的 smoke test（不走 TestClient，验证进程真能起来并响应）。

用法：
    .venv/Scripts/python tests/smoke_run_server.py

退出码 0 表示通过。会打印实际监听地址与 /health 响应体，便于贴进验收报告。
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    port = _free_port()
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "api.app:app",
        "--app-dir",
        "src",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]
    print(f"[smoke] 启动：{' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        import httpx

        deadline = time.time() + 30
        body = None
        last_err = None
        while time.time() < deadline:
            if proc.poll() is not None:
                out = proc.stdout.read() if proc.stdout else ""
                print("[smoke] 进程提前退出：\n" + out)
                return 1
            try:
                r = httpx.get(f"{base}/health", timeout=2.0)
                if r.status_code == 200:
                    body = r.json()
                    break
            except Exception as exc:  # 还没起来
                last_err = exc
            time.sleep(0.4)

        if body is None:
            print(f"[smoke] /health 未在 30s 内就绪，最后一次错误：{last_err}")
            return 1

        print(f"[smoke] GET {base}/health -> 200")
        print("[smoke] 响应：" + json.dumps(body, ensure_ascii=False))

        r = httpx.post(
            f"{base}/tools/query_logs",
            json={"case_id": "SMOKE-001", "trace_id": "CHAIN-ATTACK-01", "limit": 5},
            timeout=10.0,
        )
        data = r.json()
        print(f"[smoke] POST {base}/tools/query_logs -> {r.status_code}，命中 {data['meta']['total']} 条")
        assert r.status_code == 200
        assert data["meta"]["mock"] is True

        print("[smoke] 通过")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[smoke] 服务已停止")


if __name__ == "__main__":
    raise SystemExit(main())
