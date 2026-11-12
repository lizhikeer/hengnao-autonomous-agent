#!/usr/bin/env python3
"""在全链路日志上跑老项目的规则检测，输出可触发调查的初始线索。

## 定位

Issue #16 任务 3 的运行时入口：把 ClickHouse `log_ai.full_chain_logs` 里的日志
喂给老项目的 `RuleEngine`，产出 `AnomalyEvent` 线索，供 Agent 拿去做多轮调查。

链路：

    ClickHouse full_chain_logs
        → src.detection.from_full_chain.to_normalized   （统一 Schema → NormalizedLog）
        → src.detection.rules.detect_batch              （老规则引擎，不改动）
        → AnomalyEvent 列表（线索）

## 用法

```bash
python3 scripts/detect_clues.py                      # 全部日志
python3 scripts/detect_clues.py --trace-id CHAIN-001 # 只看某条攻击链
python3 scripts/detect_clues.py --window-minutes 60  # 只看最近 1 小时
python3 scripts/detect_clues.py --output clues.json  # 落盘
```

退出码：0 表示执行成功（不代表有线索）；2 表示数据源不可用。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.from_full_chain import to_normalized  # noqa: E402
from src.detection.full_chain_rules import detect_supplementary  # noqa: E402
from src.detection.rules import detect_batch  # noqa: E402

COLUMNS = (
    "log_id", "trace_id", "timestamp", "log_source", "src_ip", "src_port",
    "dest_ip", "dest_port", "asset_id", "user_name", "session_id",
    "action_or_method", "uri_or_target", "payload_summary", "status_code",
    "bytes_out", "user_agent", "attack_stage_hint",
)


def load_env(project_root: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    env_file = project_root / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    import os
    for k in ("CLICKHOUSE_HOST", "CLICKHOUSE_HTTP_PORT", "CLICKHOUSE_DATABASE",
              "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD"):
        if os.getenv(k):
            env[k] = os.environ[k]
    return env


def query(env: dict[str, str], sql: str) -> str:
    url = (
        f"http://{env.get('CLICKHOUSE_HOST', '127.0.0.1')}:"
        f"{env.get('CLICKHOUSE_HTTP_PORT', '8123')}/"
        f"?database={env.get('CLICKHOUSE_DATABASE', 'log_ai')}"
    )
    req = urllib.request.Request(url, data=sql.encode(), method="POST")
    req.add_header("X-ClickHouse-User", env.get("CLICKHOUSE_USER", "seclog"))
    req.add_header("X-ClickHouse-Key", env.get("CLICKHOUSE_PASSWORD", ""))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"[ERR] ClickHouse: {exc.read().decode('utf-8', 'ignore')[:300]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace-id", default=None)
    ap.add_argument("--window-minutes", type=int, default=None)
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--output", default=None)
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()

    env = load_env(Path(args.project_root))

    where = ["1=1"]
    if args.trace_id:
        safe = args.trace_id.replace("'", "''")
        where.append(f"trace_id = '{safe}'")
    if args.window_minutes:
        where.append(f"timestamp >= now() - INTERVAL {int(args.window_minutes)} MINUTE")
    sql = (
        f"SELECT {', '.join(COLUMNS)} FROM full_chain_logs "
        f"WHERE {' AND '.join(where)} ORDER BY timestamp ASC LIMIT {int(args.limit)} "
        f"FORMAT JSONEachRow"
    )

    raw = query(env, sql).strip()
    if not raw:
        print("[WARN] 没有查到日志，规则引擎无输入")
        return 0

    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    print(f"读入 {len(rows)} 条日志")

    logs = [to_normalized(r) for r in rows]
    # 两层规则：老项目 RuleEngine（账号/资源语义）+ 针对统一 Schema 的补充规则
    legacy = detect_batch(logs)
    supplementary = detect_supplementary(logs)
    anomalies = legacy + supplementary

    print(f"命中线索 {len(anomalies)} 条（老规则 {len(legacy)} / 补充规则 {len(supplementary)}）")
    if anomalies:
        dist = Counter(a.risk_level for a in anomalies)
        rules = Counter(a.attack_type for a in anomalies)
        print(f"  风险分布: {dict(dist)}")
        print("  规则分布:")
        for rule, n in rules.most_common():
            print(f"    {rule}: {n}")

    payload = [a.model_dump(mode="json") for a in anomalies]
    if args.output:
        Path(args.output).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"已写入 {args.output}")
    else:
        print(json.dumps(payload[:2], ensure_ascii=False, indent=2)[:1500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
