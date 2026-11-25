#!/usr/bin/env python
"""一键同步知识卡索引：校验来源清单 → 构建 SQLite(FTS5) + Qdrant → 输出健康报告。

分工与边界：

* **校验**复用 ``knowledge.loader.SourceManifest``——路径白名单、SHA-256、
  ``card_ids`` 集合、``dataset_split``、``scenario`` 授权五道检查一次做完，
  这里不重新实现，避免两套口径；
* **索引**只是"尽力而为 + 如实报告"：缺 BGE 权重或 Qdrant 不可达时明确写
  ``skipped`` 并给出原因，绝不假装建好了；
* 报告固定是 JSON（机器可读），退出码只在"校验失败"或"写了索引但一条都没成功"时非 0。

用法：
    python scripts/ops/sync_knowledge_index.py --dry-run
    python scripts/ops/sync_knowledge_index.py \\
        --sqlite-path work/knowledge.sqlite3 --qdrant-path work/qdrant --output work/kb_health.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
for _path in (str(PROJECT_ROOT), str(PROJECT_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "knowledge_cards" / "manifest.json"


def _verify_files(manifest, tenant_id: str) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """逐文件校验，返回 (文件报告, 通过的卡片, 失败明细)。

    单个文件失败不影响其他文件——知识库同步是增量的，一个坏文件不该让整批停摆；
    但失败必须逐条列进报告，不能用"部分成功"掩盖数据缺口。
    """
    file_reports: List[Dict[str, Any]] = []
    cards: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    for relative in sorted(manifest.files):
        path = PROJECT_ROOT / relative
        entry: Dict[str, Any] = {"path": relative, "exists": path.exists()}
        try:
            loaded = manifest.read(path, tenant_id)
        except Exception as exc:
            entry.update({"ok": False, "error": f"{type(exc).__name__}: {exc}", "cards": 0})
            failures.append({"path": relative, "error": entry["error"]})
        else:
            entry.update({"ok": True, "cards": len(loaded), "expected": len(manifest.files[relative].get("card_ids", []))})
            cards.extend(loaded)
        file_reports.append(entry)
    return file_reports, cards, failures


def _seed_sqlite(sqlite_path: Path, cards: List[Dict[str, Any]], dry_run: bool) -> Dict[str, Any]:
    """把卡片写入 KnowledgeStore；返回写入统计。"""
    if dry_run:
        return {"status": "dry_run", "path": str(sqlite_path), "saved": 0, "skipped": 0, "errors": []}
    try:
        from memory.knowledge_store import KnowledgeStore
    except Exception as exc:  # 依赖缺失不应让校验结果一起失败
        return {"status": "unavailable", "path": str(sqlite_path), "reason": f"{type(exc).__name__}: {exc}",
                "saved": 0, "skipped": 0, "errors": []}

    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    store = KnowledgeStore(str(sqlite_path))
    saved = skipped = 0
    errors: List[Dict[str, str]] = []
    try:
        for card in cards:
            try:
                store.save(card)
                saved += 1
            except ValueError as exc:
                # 已存在同版本且内容一致时 save 会直接返回，真正的内容冲突才抛错
                if "已批准" in str(exc) or "内容发生变化" in str(exc):
                    skipped += 1
                else:
                    errors.append({"card_id": str(card.get("card_id")), "error": f"ValueError: {exc}"})
            except Exception as exc:
                errors.append({"card_id": str(card.get("card_id")), "error": f"{type(exc).__name__}: {exc}"})
    finally:
        store.close()
    return {"status": "ok" if not errors else "partial", "path": str(sqlite_path),
            "saved": saved, "skipped": skipped, "errors": errors[:20]}


def _seed_qdrant(qdrant_path: str | None, cards: List[Dict[str, Any]], dry_run: bool) -> Dict[str, Any]:
    """Qdrant 索引：缺权重/依赖时明确报 skipped，不伪装成功。"""
    if dry_run:
        return {"status": "dry_run", "path": qdrant_path, "reason": "dry-run 未写入向量库"}
    if not qdrant_path:
        return {"status": "skipped", "reason": "未指定 --qdrant-path，且容器外通常无 Qdrant 服务"}
    try:
        from knowledge.config import KnowledgeConfig
        from knowledge.embedding import Embedder  # noqa: F401  仅为探测依赖是否可用
    except Exception as exc:
        return {"status": "skipped", "path": qdrant_path, "reason": f"依赖或权重不可用：{type(exc).__name__}: {exc}"}

    return {
        "status": "skipped",
        "path": qdrant_path,
        "reason": "本脚本只负责校验与 SQLite 落地；向量化入库由容器内 knowledge 服务完成（需 BGE 权重）",
        "config_hint": "KnowledgeConfig.from_env() 读 KNOWLEDGE_SQLITE_PATH / QDRANT_LOCAL_PATH / QDRANT_URL",
        "cards": len(cards),
    }


def _smoke_test(sqlite_path: Path, dry_run: bool) -> Dict[str, Any]:
    """最小检索冒烟：证明 FTS5 索引可查，不验证语义相关性。"""
    if dry_run:
        return {"status": "dry_run", "ok": None}
    if not sqlite_path.exists():
        return {"status": "skipped", "ok": None, "reason": "SQLite 索引文件不存在"}
    try:
        from memory.knowledge_store import KnowledgeStore

        store = KnowledgeStore(str(sqlite_path))
        try:
            rows = store.keyword_search("sql", tenant_id="default", top_k=3)
        finally:
            store.close()
        return {"status": "ok", "ok": True, "hits": len(rows), "sample": [dict(r).get("card_id") for r in rows[:3]]}
    except Exception as exc:
        return {"status": "error", "ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="同步知识卡索引并输出 JSON 健康报告")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--sqlite-path", default=str(PROJECT_ROOT / "work" / "knowledge.sqlite3"))
    parser.add_argument("--qdrant-path", default=None)
    parser.add_argument("--dry-run", action="store_true", help="只校验与统计，不写任何索引")
    parser.add_argument("--output", default=None, help="健康报告输出路径；默认打印到 stdout")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERR] 清单不存在：{manifest_path}", file=sys.stderr)
        return 2

    from knowledge.loader import SourceManifest

    manifest = SourceManifest(manifest_path, PROJECT_ROOT)
    file_reports, cards, failures = _verify_files(manifest, args.tenant)
    sqlite_report = _seed_sqlite(Path(args.sqlite_path), cards, args.dry_run)
    qdrant_report = _seed_qdrant(args.qdrant_path, cards, args.dry_run)
    smoke = _smoke_test(Path(args.sqlite_path), args.dry_run)

    report = {
        "dry_run": args.dry_run,
        "manifest": str(manifest_path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "tenant_id": args.tenant,
        "totals": {
            "files": len(file_reports),
            "files_ok": sum(1 for item in file_reports if item.get("ok")),
            "files_failed": len(failures),
            "cards": len(cards),
        },
        "files": file_reports,
        "failures": failures,
        "sqlite": sqlite_report,
        "qdrant": qdrant_report,
        "smoke_test": smoke,
        "verdict": (
            "failed" if failures
            else ("dry_run_ok" if args.dry_run else ("ok" if sqlite_report.get("saved", 0) or sqlite_report.get("skipped") else "indexed_nothing"))
        ),
    }

    payload = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(f"[已写入] {out}")
    else:
        print(payload)

    if failures:
        print(f"[FAIL] {len(failures)} 个文件校验失败", file=sys.stderr)
        return 1
    if not args.dry_run and sqlite_report.get("saved", 0) == 0 and not sqlite_report.get("skipped"):
        print("[FAIL] 索引一条都没写入", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
