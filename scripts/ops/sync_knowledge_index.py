#!/usr/bin/env python
"""一键同步知识卡索引：校验来源清单 → 构建 SQLite(FTS5) + Qdrant → 输出健康报告。

分工与边界：

* **校验**复用 ``knowledge.loader.SourceManifest``——路径白名单、SHA-256、
  ``card_ids`` 集合、``dataset_split``、``scenario`` 授权五道检查一次做完，
  这里不重新实现，避免两套口径；
* 默认只暂存候选；显式指定审核人后才发布，发布或检索失败返回非零退出码。

用法：
    python scripts/ops/sync_knowledge_index.py --dry-run
    python scripts/ops/sync_knowledge_index.py \\
        --sqlite-path work/knowledge.sqlite3 --qdrant-path work/qdrant --approve-by 审核人 --output work/kb_health.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
for _path in (str(PROJECT_ROOT), str(PROJECT_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "knowledge_cards" / "manifest.json"


def _verify_files(
    manifest, tenant_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """逐文件校验，返回 (文件报告, 通过的卡片, 失败明细)。

    检查所有文件并汇总错误，只有整份清单通过才执行写入。
    """
    file_reports: list[dict[str, Any]] = []
    cards: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    from src.knowledge.schema import CardValidator, normalize_card

    validator = CardValidator()
    for relative in sorted(manifest.files):
        path = PROJECT_ROOT / relative
        entry: dict[str, Any] = {"path": relative, "exists": path.exists()}
        try:
            loaded = manifest.read(path, tenant_id)
            for card in loaded:
                validator.validate(normalize_card(card, tenant_id=tenant_id))
        except Exception as exc:
            entry.update({"ok": False, "error": f"{type(exc).__name__}: {exc}", "cards": 0})
            failures.append({"path": relative, "error": entry["error"]})
        else:
            entry.update(
                {
                    "ok": True,
                    "cards": len(loaded),
                    "expected": len(manifest.files[relative].get("card_ids", [])),
                }
            )
            cards.extend(loaded)
        file_reports.append(entry)
    return file_reports, cards, failures


def _sync(config, manifest, paths, cards, reviewer, dry_run, failures):
    """校验通过后走管理端审核流程，发布后通过实际接口确认可检索。"""
    status = "dry_run" if dry_run else "skipped"
    sqlite = {"status": status, "path": config.sqlite_path, "saved": 0, "skipped": 0, "errors": []}
    qdrant = {"status": status, "cards": []}
    smoke = {"status": status, "ok": None}
    if failures or dry_run:
        return sqlite, qdrant, smoke

    service = None
    try:
        from src.knowledge.search import KnowledgeService

        Path(config.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        service = KnowledgeService(config)
        rows = qdrant["cards"]
        for row in service.iter_ingest_files(
            paths, manifest=manifest, reviewed_by=reviewer, preserve_approved=True
        ):
            rows.append(row)
        published = [row for row in rows if row["status"] == "published"]
        sqlite.update(
            status="ok",
            saved=sum(r["status"] in {"published", "pending", "outside_validity"} for r in rows),
        )
        sqlite["skipped"] = len(rows) - sqlite["saved"]
        if reviewer:
            qdrant.update(status="ok", published=len(published))
            if len(published) != len(cards):
                qdrant["status"] = "incomplete"
                failures.append({"stage": "publish", "error": "部分卡片未发布，详见 qdrant.cards"})
        if published:
            first = published[0]
            card = service.store.get(config.tenant_id, first["card_id"], first["version"])
            hits = service.search(f"{card['title']} {card['card_id']}"[:500], top_k=5)
            batch = {row["card_id"] for row in published}
            matched = any(hit["card_id"] in batch for hit in hits)
            smoke.update(
                status="ok" if matched else "error",
                ok=matched,
                hits=len(hits),
                sample=[hit["card_id"] for hit in hits],
            )
    except Exception as exc:
        failures.append({"stage": "sync", "error": str(exc)})
        sqlite["status"] = "error"
        if reviewer:
            qdrant["status"] = "unverified"
            completed = {(r["card_id"], r["version"]) for r in qdrant["cards"]}
            qdrant["published"] = sum(r["status"] == "published" for r in qdrant["cards"])
            for card in cards:
                version = card.get("version", 1)
                if (card["card_id"], version) not in completed:
                    qdrant["cards"].append(
                        {
                            "card_id": card["card_id"],
                            "version": version,
                            "status": "unverified",
                            "reason": str(exc),
                        }
                    )
    finally:
        if service is not None:
            service.close()
    return sqlite, qdrant, smoke


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="同步知识卡索引并输出 JSON 健康报告")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--tenant", default=None)
    parser.add_argument("--sqlite-path", default=None)
    parser.add_argument("--approve-by", help="将通过核验的清单发布到真实索引，登记审核人")
    parser.add_argument("--qdrant-path", default=None)
    parser.add_argument("--dry-run", action="store_true", help="只校验与统计，不写任何索引")
    parser.add_argument("--output", default=None, help="健康报告输出路径；默认打印到 stdout")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERR] 清单不存在：{manifest_path}", file=sys.stderr)
        return 2

    from src.knowledge.config import KnowledgeConfig
    from src.knowledge.loader import SourceManifest

    manifest = SourceManifest(manifest_path, PROJECT_ROOT)
    config = KnowledgeConfig.from_env()
    config = replace(
        config,
        tenant_id=args.tenant or config.tenant_id,
        sqlite_path=args.sqlite_path or config.sqlite_path,
        qdrant_path=args.qdrant_path or config.qdrant_path,
    )
    file_reports, cards, failures = _verify_files(manifest, config.tenant_id)
    paths = [PROJECT_ROOT / item["path"] for item in file_reports]
    if not cards and not failures:
        failures.append({"stage": "manifest", "error": "清单无卡片"})
    sqlite_report, qdrant_report, smoke = _sync(
        config, manifest, paths, cards, args.approve_by, args.dry_run, failures
    )
    if args.approve_by and not args.dry_run and not failures and not smoke["ok"]:
        failures.append({"stage": "smoke", "error": "未验证已发布内容可检索"})

    verdict = "ok"
    if failures:
        verdict = "partial" if 0 < qdrant_report.get("published", 0) < len(cards) else "failed"
    elif args.dry_run:
        verdict = "dry_run_ok"
    elif not args.approve_by:
        verdict = "staged" if sqlite_report["saved"] else "unchanged"

    report = {
        "dry_run": args.dry_run,
        "manifest": str(manifest_path),
        "tenant_id": config.tenant_id,
        "totals": {
            "files": len(file_reports),
            "files_ok": sum(1 for item in file_reports if item.get("ok")),
            "files_failed": sum(not item["ok"] for item in file_reports),
            "cards": len(cards),
        },
        "files": file_reports,
        "failures": failures,
        "sqlite": sqlite_report,
        "qdrant": qdrant_report,
        "smoke_test": smoke,
        "verdict": verdict,
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
        print(f"[FAIL] 同步报告包含 {len(failures)} 项错误", file=sys.stderr)
        return 1
    if not args.dry_run and sqlite_report.get("saved", 0) == 0 and not sqlite_report.get("skipped"):
        print("[FAIL] 索引一条都没写入", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
