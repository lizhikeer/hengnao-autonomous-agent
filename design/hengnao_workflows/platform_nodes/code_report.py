import json
from runtime import Args


def handler(args: Args) -> dict:
    data = args.input.input
    if isinstance(data, str):
        data = json.loads(data)
    receipt = getattr(args.input, "receipt", None)
    if isinstance(receipt, str):
        receipt = json.loads(receipt) if receipt.strip() else None
    report = (
        "# 调查报告\n\n" + data["attack_chain_summary"]
        + "\n\n证据：" + ", ".join(data["evidence_log_ids"])
        + "\n\n建议：" + data["recommended_action"]
        + "\n\n未知事项：" + data["unknown_items"]
    )
    if isinstance(receipt, dict) and receipt.get("status"):
        report += "\n\n处置回执：" + str(receipt["status"])
        if receipt.get("mock") is True:
            report += "（模拟回执）"
        if receipt.get("approval_id"):
            report += "\n\n审批单号：" + str(receipt["approval_id"])
        if receipt.get("detail"):
            report += "\n\n" + str(receipt["detail"])
    return {"result_key": {"results": data, "report": report}}
