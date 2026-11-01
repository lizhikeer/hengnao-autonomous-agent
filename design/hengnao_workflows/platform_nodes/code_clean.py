import json
from runtime import Args


def handler(args: Args) -> dict:
    data = json.loads(args.input.input)
    if not data.get("case_id") or not (data.get("src_ip") or data.get("trace_id")):
        raise ValueError("需要case_id及src_ip或trace_id")
    return {"result_key": data}
