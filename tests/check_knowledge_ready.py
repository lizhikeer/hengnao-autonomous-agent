"""逐项确认混合检索是否具备真实集成的条件（不猜、不靠单条报错推断）。

用法：
    .venv/Scripts/python.exe tests/check_knowledge_ready.py

输出每个组件的实际状态，并把结论写进 stdout 供验收报告引用。
只做只读检查，不下载模型、不启动服务、不改配置。
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

CHECKS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str) -> None:
    CHECKS.append((name, ok, detail))


def check_import(module: str, hint: str) -> None:
    try:
        mod = importlib.import_module(module)
        version = getattr(mod, "__version__", "")
        record(f"import {module}", True, f"OK {version}".strip())
    except Exception as exc:
        record(f"import {module}", False, f"{type(exc).__name__}: {exc}（{hint}）")


def main() -> int:
    # 1. 三个运行时依赖
    check_import("sentence_transformers", "pip install sentence-transformers")
    check_import("qdrant_client", "pip install qdrant-client")
    check_import("numpy", "pip install numpy")

    # 2. 检索模块本身能否导入（会连带暴露缺哪个依赖）
    try:
        import src.knowledge.search as ks  # noqa: F401

        record("import src.knowledge.search", True, "OK")
    except Exception as exc:
        record("import src.knowledge.search", False, f"{type(exc).__name__}: {exc}")

    # 3. 配置与模型
    try:
        from src.knowledge.config import KnowledgeConfig

        cfg = KnowledgeConfig.from_env()
        record("KnowledgeConfig", True, f"model={cfg.model_path} qdrant_url={cfg.qdrant_url}")
    except Exception as exc:
        cfg = None
        record("KnowledgeConfig", False, f"{type(exc).__name__}: {exc}")

    model_path = (os.getenv("BGE_MODEL_PATH") or "").strip()
    if model_path and Path(model_path).exists():
        record("BGE 模型文件", True, model_path)
    else:
        hf_cache = Path.home() / ".cache" / "huggingface" / "hub"
        found = []
        if hf_cache.exists():
            found = [p.name for p in hf_cache.iterdir() if "bge" in p.name.lower()]
        record(
            "BGE 模型文件",
            bool(found),
            f"HF 缓存命中 {found}" if found else f"未找到：BGE_MODEL_PATH={model_path or '(未设)'}，HF 缓存 {hf_cache} 无 bge-*",
        )

    # 4. Qdrant：本地目录 or 远端服务
    local_path = (os.getenv("QDRANT_LOCAL_PATH") or "").strip()
    url = os.getenv("QDRANT_URL", "http://localhost:6333")
    if local_path and Path(local_path).exists():
        record("Qdrant 存储", True, f"本地目录 {local_path}")
    else:
        reachable = False
        detail = f"{url} 不可达"
        try:
            import urllib.request

            with urllib.request.urlopen(f"{url.rstrip('/')}/healthz", timeout=3) as resp:
                reachable = resp.status == 200
                detail = f"{url} -> HTTP {resp.status}"
        except Exception as exc:
            detail = f"{url} 不可达（{type(exc).__name__}）"
        record("Qdrant 存储", reachable, detail)

    # 5. SQLite 知识库
    sqlite_rel = getattr(cfg, "sqlite_path", "work/knowledge.sqlite3") if cfg else "work/knowledge.sqlite3"
    sqlite_file = REPO / sqlite_rel
    record(
        "SQLite 知识库",
        sqlite_file.exists(),
        str(sqlite_file) + ("" if sqlite_file.exists() else "（未建库，需先跑入库脚本）"),
    )

    # 6. 知识卡源文件（决定能否建库）
    cards_dir = REPO / "data" / "knowledge_cards"
    cards = sorted(cards_dir.glob("*.json")) if cards_dir.exists() else []
    record("知识卡源文件", bool(cards), f"{len(cards)} 个：{[c.name for c in cards][:6]}")

    # 7. 结论
    blocked = [name for name, ok, _ in CHECKS if not ok]
    print("组件就绪检查")
    print("=" * 78)
    for name, ok, detail in CHECKS:
        print(f"[{'OK   ' if ok else 'MISS '}] {name:<32} {detail}")
    print("=" * 78)
    if blocked:
        print(f"结论：真实混合检索**不具备**集成条件，缺：{', '.join(blocked)}")
        print("说明：这是逐项检查结果，不是从一条导入错误推断出来的。")
    else:
        print("结论：依赖齐备，可以执行真实集成查询（运行 tests/run_v1_traces.py 观察检索步骤）。")
    return 0 if not blocked else 3


if __name__ == "__main__":
    raise SystemExit(main())
