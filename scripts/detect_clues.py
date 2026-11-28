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
python3 scripts/detect_clues.py                      # 全部日志（ClickHouse）
python3 scripts/detect_clues.py --trace-id CHAIN-001 # 只看某条攻击链
python3 scripts/detect_clues.py --window-minutes 60  # 只看最近 1 小时
python3 scripts/detect_clues.py --output clues.json  # 落盘

# 无 ClickHouse：从本地日志目录离线跑完整流水线
python3 scripts/detect_clues.py --from-files data/full_chain_logs \
    --output data/clues/w3_clues_baseline.json
```

`--from-files` 递归读取目录下的 `*.json` / `*.jsonl`，按 `timestamp` 升序重放；
文件名含 `truth` 的标注文件会被跳过（不进入检测）。离线模式下用本批日志构造
UEBA 基线，把基线偏离注入 `DetectionContext.baseline_deviations`，
`--no-ueba` 可关闭。

退出码：0 表示执行成功（不代表有线索）；2 表示数据源不可用。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.from_full_chain import to_normalized  # noqa: E402
from src.detection.context_builder import ContextRegistry, UEBABaselineProvider  # noqa: E402
from src.detection.full_chain_rules import detect_supplementary  # noqa: E402
from src.detection.rules import RuleEngine  # noqa: E402

# 即使落在维护窗口 + 白名单内，这些攻击类型也不降级——窗口是降噪手段，不是免死金牌
NEVER_EXEMPT_TYPES = {
    "sql_injection", "malicious_upload", "webshell_access",
    "path_traversal", "suspicious_outbound", "xss_attempt",
    # 数据外传与 C2 心跳不做窗口降级：这两类一旦成立就是既遂，不该被"运维时间"稀释
    "data_exfiltration",
}

#: 内网用户输错口令的次数上限：低于它且最终登录成功，视为正常重试而非爆破。
#: 与老规则的爆破阈值（5 次）对齐，避免把 CASE-10 这类"忘密码"误判成 critical。
BENIGN_RETRY_MAX_FAILURES = 5


def _is_private_ip(value: str) -> bool:
    return str(value or "").startswith(("10.", "192.168.", "127."))


def _benign_retry_subjects(logs) -> set[tuple[str, str]]:
    """识别「内网用户输错几次口令后成功登录」的正常重试模式，返回 (src_ip, user_id) 集合。

    CASE-10 的设计意图就是这种情况：用户忘密码重试两次后进入系统，随后访问
    admin 页面。老规则只看"新 IP + 访问敏感资源"就判 critical，属于只看行为
    不看强度的误报。

    边界：失败次数必须严格小于阈值，且源必须是内网。外部 IP 哪怕只失败一次
    也不在此列——那可能是撞库的第一次尝试，不能提前放行。
    """
    fails: dict[tuple[str, str], int] = {}
    succeeded: set[tuple[str, str]] = set()
    for log in logs:
        # 归一化后 action 恒为 "login"，成败落在 result 上（fail / success / error）
        result = str(getattr(log, "result", "") or "").lower()
        key = (str(getattr(log, "src_ip", "") or ""), str(getattr(log, "user_id", "") or ""))
        if result in {"fail", "failure", "denied", "reject", "rejected"}:
            fails[key] = fails.get(key, 0) + 1
        elif result in {"success", "allow", "allowed", "ok"}:
            succeeded.add(key)
    return {
        key
        for key, count in fails.items()
        if count < BENIGN_RETRY_MAX_FAILURES and key in succeeded and _is_private_ip(key[0])
    }


def downgrade_exempt(anomalies, logs, registry) -> int:
    """把「维护窗口 + 白名单」或「良性登录重试」主体触发的运维类线索降到 medium。

    两条降级依据：

    1. **维护窗口 + 白名单**：同一主体在窗口内且命中白名单，其触发的
       非攻击类线索（登录异常、越权、权限变更等）属于正常运维；
    2. **良性登录重试**：内网用户输错少量口令后成功登录（CASE-10），
       后续的账号类/越权类线索属于正常使用，不构成账号接管。

    两条都只降 `high`/`critical` 到 `medium`，且 `NEVER_EXEMPT_TYPES` 里的
    攻击既遂类型（注入/上传/webshell/遍历/外连/外传）永不降级。
    """
    exempt: set[tuple[str, str]] = set()
    for log in logs:
        ctx = registry.build(log)
        if ctx.maintenance_window and ctx.allowlisted_context:
            exempt.add((log.src_ip or "", log.user_id or ""))
    retry_subjects = _benign_retry_subjects(logs)
    if not exempt and not retry_subjects:
        return 0

    changed = 0
    for a in anomalies:
        subject = (a.src_ip or "", a.user_id or "")
        by_window = subject in exempt
        by_retry = subject in retry_subjects
        if not (by_window or by_retry):
            continue
        if (a.attack_type or "").lower() in NEVER_EXEMPT_TYPES:
            continue
        if a.risk_level in ("high", "critical"):
            a.risk_level = "medium"
            a.risk_score = min(float(a.risk_score), 50.0)
            evidence = dict(a.evidence or {})
            evidence["downgraded_by"] = (
                "maintenance_window+allowlist" if by_window else "benign_login_retry"
            )
            a.evidence = evidence
            changed += 1
    return changed


COLUMNS = (
    "log_id", "trace_id", "timestamp", "log_source", "src_ip", "src_port",
    "dest_ip", "dest_port", "asset_id", "user_name", "session_id",
    "action_or_method", "uri_or_target", "payload_summary", "status_code",
    "bytes_out", "user_agent", "attack_stage_hint",
)


def _rows_of(path: Path) -> list[dict[str, Any]]:
    """把一个日志文件解析成行列表，容忍三种落盘格式。

    - `.jsonl`：每行一个 JSON 对象
    - `.json`：顶层数组，或 `{"logs": [...]}` 这类带包装的对象，或单个对象
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        rows: list[dict[str, Any]] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[WARN] 跳过 {path.name}:{lineno} 非法 JSON（{exc.msg}）")
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"[WARN] 跳过文件 {path.name}：JSON 解析失败（{exc.msg}）")
        return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("logs", "records", "data", "rows", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    print(f"[WARN] 跳过文件 {path.name}：顶层不是对象或数组")
    return []


def load_from_files(source: Path) -> list[dict[str, Any]]:
    """递归收集离线日志文件；`*truth*` 是标注，不能喂给检测。"""
    if not source.exists():
        raise SystemExit(f"[ERR] 离线日志目录不存在: {source}")
    if not source.is_dir():
        raise SystemExit(f"[ERR] --from-files 需要目录: {source}")

    paths: list[Path] = []
    for pattern in ("*.json", "*.jsonl"):
        paths.extend(source.rglob(pattern))
    paths = sorted(
        {
            p
            for p in paths
            if p.is_file() and "truth" not in p.name.lower()
        }
    )
    if not paths:
        print(f"[WARN] {source} 下没有 *.json / *.jsonl 日志文件")
        return []

    rows: list[dict[str, Any]] = []
    for path in paths:
        part = _rows_of(path)
        if not part:
            print(f"[WARN] {path.name} 没有解析出日志行")
            continue
        rows.extend(part)
    print(f"读入 {len(rows)} 条日志（{len(paths)} 个文件，已跳过 truth 标注）")
    return rows


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


def select_offline_rows(rows, *, trace_id=None, window_minutes=None, limit=None):
    """离线批次的时间窗口：以批次内最新时间为基准，而不是墙钟 now()。"""
    if trace_id:
        rows = [r for r in rows if str(r.get("trace_id") or "") == str(trace_id)]
    if window_minutes and rows:
        stamps = [ts for ts in (_parse_row_ts(r) for r in rows) if ts is not None]
        if stamps:
            latest = max(stamps)
            rows = [
                r
                for r in rows
                if (ts := _parse_row_ts(r)) is not None
                and (latest - ts).total_seconds() <= window_minutes * 60
            ]
    if limit:
        rows = sorted(
            rows,
            key=lambda r: (_parse_row_ts(r) or _EPOCH, str(r.get("log_id") or "")),
        )[: int(limit)]
    return rows


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _parse_row_ts(row: dict[str, Any]) -> datetime | None:
    raw = row.get("timestamp") or row.get("event_time")
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace-id", default=None)
    ap.add_argument("--window-minutes", type=int, default=None)
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--output", default=None)
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument(
        "--from-files",
        default=None,
        metavar="DIR",
        help="离线批量模式：递归读取 DIR 下的 *.json/*.jsonl，不连 ClickHouse",
    )
    ap.add_argument(
        "--no-ueba",
        action="store_true",
        help="离线模式下不注入 UEBA 基线偏离（默认注入）",
    )
    args = ap.parse_args()

    if args.from_files:
        rows = load_from_files(Path(args.from_files))
        rows = select_offline_rows(
            rows,
            trace_id=args.trace_id,
            window_minutes=args.window_minutes,
            limit=args.limit,
        )
        if not rows:
            print("[WARN] 离线目录里没有可用日志，规则引擎无输入")
            # 下游按落盘文件判断批次结果，空输入也要留下一份合法的空数组。
            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text("[]\n", encoding="utf-8")
                print(f"已写入 {args.output}")
            return 0
    else:
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
    # 规则引擎是有状态的（滑动窗口、已见 IP 记忆），必须按时间顺序重放；
    # 离线目录是多个文件的并集，排序不能省。
    logs.sort(key=lambda log: (log.event_time, log.event_id))

    # UEBA 基线：ClickHouse 场景用持久化基线（本脚本此前未接入），
    # 离线场景没有 ClickHouse，用本批日志的会话统计构造内存基线。
    provider = None
    if args.from_files and not args.no_ueba:
        provider = UEBABaselineProvider(logs)
        print(f"UEBA 基线: {provider.user_count} 个用户（同批会话统计）")

    # 两层规则：老项目 RuleEngine（账号/资源语义）+ 针对统一 Schema 的补充规则。
    # 老规则必须带 context 调用：维护窗口与白名单是降权因子，不带 context 等于永久关闭，
    # 实测会把正常运维场景（CASE-03）误报成 critical。
    engine = RuleEngine()
    registry = ContextRegistry(baseline_provider=provider)
    legacy = []
    for log in logs:
        legacy.extend(engine.evaluate_log(log, registry.build(log)))
    supplementary = detect_supplementary(logs)
    anomalies = legacy + supplementary
    # 补充规则是批量扫描后统一产出，和老规则混在一起会打乱时间序；
    # 落盘结果按 (event_time, 账号, 来源, 攻击类型) 重排，方便按会话回溯。
    # 补充规则的事件 ID 是随机 UUID（共享模块的既有行为），不能拿它当排序键。
    anomalies.sort(
        key=lambda a: (
            a.event_time,
            a.user_id or "",
            a.src_ip or "",
            a.attack_type or "",
            tuple(a.rule_hits),
        )
    )

    downgraded = downgrade_exempt(anomalies, logs, registry)

    print(f"命中线索 {len(anomalies)} 条（老规则 {len(legacy)} / 补充规则 {len(supplementary)}）")
    if provider is not None:
        with_dev = sum(1 for a in anomalies if a.baseline_deviations)
        print(f"  带基线偏离证据: {with_dev} 条")
    if downgraded:
        print(f"  维护窗口+白名单降级: {downgraded} 条")
    if anomalies:
        dist = Counter(a.risk_level for a in anomalies)
        rules = Counter(a.attack_type for a in anomalies)
        print(f"  风险分布: {dict(dist)}")
        print("  规则分布:")
        for rule, n in rules.most_common():
            print(f"    {rule}: {n}")

    payload = [a.model_dump(mode="json") for a in anomalies]
    if args.output:
        out_path = Path(args.output)
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"已写入 {args.output}")
    else:
        print(json.dumps(payload[:2], ensure_ascii=False, indent=2)[:1500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
