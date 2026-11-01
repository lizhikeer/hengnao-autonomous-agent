import json
from runtime import Args


def handler(args: Args) -> dict:
    data = args.input.input
    if isinstance(data, str):
        data = json.loads(data)
    report = (
        "# 调查报告（模拟数据）\n\n" + data["attack_chain_summary"]
        + "\n\n证据：" + ", ".join(data["evidence_log_ids"])
        + "\n\n建议：" + data["recommended_action"]
        + "\n\n未知事项：" + data["unknown_items"]
        + "\n\n本周没有执行真实封禁。"
    )
    return {"result_key": {"results": data, "report": report}}
