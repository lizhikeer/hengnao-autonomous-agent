import json
import urllib.request
from runtime import Args


def handler(args: Args) -> dict:
    seed = json.loads(args.input.seed)
    raw = args.input.input
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.splitlines()[1:-1])
        raw = json.loads(raw)
    body = json.dumps({"case_id": seed["case_id"], "results": raw}).encode()
    req = urllib.request.Request(seed["service_url"] + "/tools/verify_results", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        result = json.load(response)
    if result.get("verified") is not True:
        raise ValueError(result.get("verify_msg", "证据校验失败"))
    return {"result_key": result["triage"]}
