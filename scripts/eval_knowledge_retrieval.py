"""在同一已发布索引上比较 RRF 权重，逐题检查前三条结果与同案隔离。"""

import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.knowledge.config import KnowledgeConfig  # noqa: E402
from src.knowledge.loader import scenario_key  # noqa: E402
from src.knowledge.search import KnowledgeService  # noqa: E402

# 开发回归题只描述观察现象。正例检索使用独立查询，在隔离检查中另行传入来源案件。
QUERIES = [
    ("SSH 登录在多个用户名上失败，之后有一条成功记录", "MEM-DEV-006"),
    ("缺少请求正文，内网机器定期联系相同目的地，随后传输变大", "MEM-DEV-008"),
    ("上传请求、脚本访问和服务器主动连接应怎样排列调查顺序", "MEM-DEV-002"),
    ("扫描告警对应已登记工单，如何核对目标与窗口", "MEM-DEV-009"),
    ("登录服务反复拒绝口令，如何核对 SSH 认证日志", "KB-BF-002"),
    ("数据库查询耗时随请求周期变化，如何排除正常慢查询", "KB-WSTG-015"),
    ("访问其他用户的订单，如何核实对象权限", "KB-WSTG-009"),
    ("DNS 心跳间隔规律，如何结合主机用途确认", "KB-WSTG-019"),
    ("Web 服务连接一直不释放且并发上涨", "KB-FUT-004"),
    ("Web 接口接收文件后如何核验文件是否被发布", "KB-FUT-001"),
]


def main() -> None:
    config = KnowledgeConfig.from_env()
    service = KnowledgeService(config)
    try:
        active = service.store.db.execute(
            "SELECT card_id, origin_json FROM kb_searchable_versions WHERE tenant_id=?",
            (config.tenant_id,),
        ).fetchall()
        ids = {row["card_id"] for row in active}
        missing = {expected for _, expected in QUERIES} - ids
        if missing:
            raise ValueError(f"测试库缺少已发布的目标卡：{sorted(missing)}")
        excluded = json.loads((ROOT / "data/case_memories/manifest.json").read_text("utf-8"))[
            "excluded_scenario_ids"
        ]
        blocked = {scenario_key(s) for s in excluded}
        for row in active:
            origin = json.loads(row["origin_json"] or "{}")
            identifiers = [origin.get("case_id"), *origin.get("scenario_ids", [])]
            if {scenario_key(s) for s in identifiers if s} & blocked:
                raise ValueError(f"发现已发布的盲测来源：{row['card_id']}")
        for weight, grouped in [(0.5, False), (config.semantic_weight, True)]:
            service.config = replace(config, semantic_weight=weight)
            rows = []
            for question, expected in QUERIES:
                hits = service.search(question, top_k=3, baseline=not grouped)
                ids = [hit["card_id"] for hit in hits]
                rows.append({"expected": expected, "top3": ids, "hit": expected in ids})
            print(
                json.dumps(
                    {
                        "semantic_weight": weight,
                        "hits": sum(r["hit"] for r in rows),
                        "queries": len(rows),
                        "rows": rows,
                    },
                    ensure_ascii=False,
                )
            )
        for question, expected in QUERIES:
            if expected.startswith("MEM-DEV-"):
                current = "CASE-" + expected[-2:]
                hits = service.search(
                    question, top_k=20, filters={"exclude_scenario_ids": [current]}
                )
                for hit in hits:
                    source = hit.get("origin", {})
                    identifiers = [source.get("case_id"), *source.get("scenario_ids", [])]
                    if {scenario_key(s) for s in identifiers if s} & (blocked | {current}):
                        raise ValueError(f"检索泄漏：{hit['card_id']}")
        print("同案及盲测来源检查通过")
    finally:
        service.close()


if __name__ == "__main__":
    main()
