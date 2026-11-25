"""在同一已发布索引上比较 RRF 权重，逐题检查前三条结果与同案隔离。"""

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from urllib.request import Request, urlopen
from uuid import uuid4

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

V2_C2_QUERY = "内网主机向境外可疑地址持续外连、周期心跳与数据外传如何研判与处置"


def verify_endpoint(url: str) -> None:
    """按 V2 调用顺序核验部署，检查真实响应、错题正文和同案排除。"""

    def post(tool: str, payload: dict) -> dict:
        request = Request(
            f"{url.rstrip('/')}/tools/{tool}",
            json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=60) as response:
            return json.load(response)

    for scenario in ("CHAIN-CASE-08", "CHAIN-CASE-02"):
        case = f"RETRIEVAL-CHECK-{uuid4().hex}"
        log_result = post("query_logs", {"case_id": case, "trace_id": scenario, "limit": 1})
        result = post(
            "search_knowledge",
            {
                "case_id": case,
                "query": V2_C2_QUERY,
                "attack_category": "C2_Exfiltration",
                "limit": 5,
            },
        )
        meta = result["meta"]
        if meta.get("data_source") != "hybrid_search" or meta.get("mock") is not False:
            raise ValueError(
                f"部署未切换至真实混合检索：{meta.get('data_source')=}, {meta.get('mock')=}"
            )
        if not any(row.get("trace_id") == scenario for row in log_result["items"]):
            raise ValueError(f"日志端未返回场景 {scenario}")
        cards = result["items"]
        target = next((c for c in cards if c["card_id"] == "MEM-DEV-002"), None)
        own = "MEM-DEV-" + scenario[-2:].zfill(3)
        if any(c["card_id"] == own for c in cards):
            raise ValueError(f"{scenario} 返回同案案例")
        if scenario.endswith("08") and not (
            target
            and target.get("corrected_steps")
            and target.get("error_revision_note")
            and any(c["card_type"] == "security_knowledge" for c in cards)
        ):
            raise ValueError("V2 跨阶段检索缺少知识卡或已审核纠错指引")
        print(f"{scenario} {meta['data_source']} Top-5: {[c['card_id'] for c in cards]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="验证已部署的 REST 服务，例如 https://host:port")
    args = parser.parse_args()
    if args.url:
        verify_endpoint(args.url)
        return
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
        # 使用 V2 实际请求的类别、自然语言问题和 limit。检查跨案召回与同案排除。
        question = V2_C2_QUERY
        for trace, allowed in [("CHAIN-CASE-08", True), ("CHAIN-CASE-02", False)]:
            hits = service.search(
                question,
                top_k=5,
                filters={
                    "attack_category": "C2_Exfiltration",
                    "exclude_investigation_id": "V2-REPLAY",
                    "exclude_scenario_ids": [trace],
                },
            )
            result_ids = [card["card_id"] for card in hits]
            if ("MEM-DEV-002" in result_ids) != allowed:
                raise ValueError(f"V2 跨阶段检索或同案隔离失败：{trace} {result_ids}")
            print(f"V2 {trace} Top-5: {result_ids}")
        print("同案及盲测来源检查通过")
    finally:
        service.close()


if __name__ == "__main__":
    main()
