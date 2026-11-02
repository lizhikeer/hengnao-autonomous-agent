"""知识库管理命令：校验和导入卡片、初始化集合、混合检索、审核下架。"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

# 同时支持 python scripts/ingest_knowledge.py 与从其他目录执行的绝对脚本路径。
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.knowledge.config import KnowledgeConfig  # noqa: E402
from src.knowledge.loader import SourceManifest  # noqa: E402
from src.knowledge.schema import CardValidator, normalize_card  # noqa: E402
from src.knowledge.search import KnowledgeService  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """approve-by 是管理员明确审批操作；不将此参数暴露给普通 Agent。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "init", "ingest", "search", "withdraw"])
    parser.add_argument("--input", type=Path, default=ROOT / "data/knowledge_cards")
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "data/knowledge_cards/manifest.json"
    )
    parser.add_argument("--tenant", default=None)
    parser.add_argument("--sqlite", default=None)
    parser.add_argument("--qdrant-path", default=None)
    parser.add_argument("--qdrant-url", default=None)
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--approve-by", default=None)
    parser.add_argument("--reason", default=None)
    parser.add_argument("--query", default=None)
    parser.add_argument("--card-id", default=None)
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args(argv)
    config = KnowledgeConfig.from_env()
    updates = {
        key: value
        for key, value in {
            "tenant_id": args.tenant,
            "sqlite_path": args.sqlite,
            "qdrant_path": args.qdrant_path,
            "qdrant_url": args.qdrant_url,
            "model_path": args.model_path,
        }.items()
        if value is not None
    }
    config = replace(config, **updates)
    service = None
    try:
        if args.command in {"validate", "ingest"}:
            manifest = SourceManifest(args.manifest, ROOT)
            paths = (
                sorted(
                    path
                    for path in args.input.rglob("*")
                    if path.suffix.lower() in {".json", ".md"}
                    and path.resolve() != args.manifest.resolve()
                )
                if args.input.is_dir()
                else [args.input]
            )
            if not paths:
                raise ValueError("输入目录没有卡片文件")
            if args.command == "validate":
                validator, count = CardValidator(), 0
                for path in paths:
                    for raw in manifest.read(path, config.tenant_id):
                        validator.validate(normalize_card(raw, tenant_id=config.tenant_id))
                        count += 1
                output = {"validated": count, "files": len(paths)}
            else:
                service = KnowledgeService(config)
                output = service.ingest_files(paths, manifest=manifest, reviewed_by=args.approve_by)
        else:
            service = KnowledgeService(config)
            if args.command == "init":
                service.vectors.initialize()
                output = {"collections": [config.knowledge_collection, config.case_collection]}
            elif args.command == "search":
                if not args.query:
                    raise ValueError("search 需要 --query")
                service.vectors.initialize()
                output = service.search(args.query, top_k=args.top_k)
            else:
                if not args.card_id or not args.approve_by or not args.reason:
                    raise ValueError("withdraw 需要 --card-id、--approve-by 和 --reason")
                service.withdraw(args.card_id, reviewed_by=args.approve_by, reason=args.reason)
                output = {"card_id": args.card_id, "status": "withdrawn"}
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(
            json.dumps({"error": type(exc).__name__, "message": str(exc)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1
    finally:
        if service:
            service.close()


if __name__ == "__main__":
    raise SystemExit(main())
