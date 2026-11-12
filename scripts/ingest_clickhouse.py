#!/usr/bin/env python3
"""把统一 Schema 的 JSONL 日志灌入 ClickHouse `log_ai.full_chain_logs`。

## 定位

这是 Issue #16 的交付物之一：**只负责「已验证的 JSONL → ClickHouse」这一步**。
上游的原始日志清洗（Nginx/auth/Zeek → 统一 Schema）由 `@ribbonfish-jun` 的
`scripts/log_cleaners/` 负责，本脚本不解析原始日志格式。

## 用法

```bash
# 单文件
python3 scripts/ingest_clickhouse.py --input data/full_chain_logs/normalized/CHAIN-001.jsonl

# 整个目录（递归找 *.jsonl）
python3 scripts/ingest_clickhouse.py --input data/full_chain_logs/normalized/ --batch-note "W2 首批"

# 只校验不写库
python3 scripts/ingest_clickhouse.py --input ... --dry-run
```

连接参数默认从项目根 `.env` 读取（`CLICKHOUSE_*`），也可用环境变量覆盖。

## 设计约束

1. **幂等**：以 `log_id` 为准，同一批重复导入不会产生重复行
   （`ReplacingMergeTree` + 导入前按 `log_id` 集合删除旧行）。
2. **强校验**：18 个契约字段、`log_source` / `attack_stage_hint` 枚举、
   `timestamp` 必须 UTC。不合格的行拒绝入库并计入 `dropped_lines`，**不静默丢弃**。
3. **脱敏兜底**：`payload_summary` 里若出现明文口令特征，直接拒绝该行并报错——
   宁可少一条，也不把口令写进数据库。
4. **批次可追溯**：每次运行写一条 `log_ai.ingest_batches`，记录源文件、行数、状态。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# --- 契约定义（与 docs/project design/全链路日志统一字段规范.md v1.0 对齐）---------

# 必填且不允许为空：缺失即无法定位/无法检索
REQUIRED_NON_EMPTY = (
    "log_id", "timestamp", "log_source", "asset_id",
    "action_or_method", "attack_stage_hint",
)
# 键必须存在，但值允许为空串——规范明确「无链填 ""」「未知 IP 填 ""」
REQUIRED_PRESENT = ("trace_id", "src_ip", "dest_ip")
REQUIRED_FIELDS = REQUIRED_NON_EMPTY + REQUIRED_PRESENT
OPTIONAL_FIELDS = (
    "src_port", "dest_port", "user", "session_id", "uri_or_target",
    "payload_summary", "status_code", "bytes_out", "user_agent",
)
ALLOWED_LOG_SOURCES = {"nginx_access", "auth_log", "zeek_conn", "zeek_http", "zeek_dns"}
ALLOWED_STAGES = {
    "recon", "brute_force", "exploitation", "c2_callback",
    "lateral_movement", "benign", "unknown",
}

# ClickHouse 列名与契约字段的差异：`user` 与内置函数冲突，落库为 `user_name`
COLUMN_MAP = {"user": "user_name"}
INSERT_COLUMNS = (
    "log_id", "trace_id", "timestamp", "log_source", "src_ip", "src_port",
    "dest_ip", "dest_port", "asset_id", "user_name", "session_id",
    "action_or_method", "uri_or_target", "payload_summary", "status_code",
    "bytes_out", "user_agent", "attack_stage_hint", "source_file", "raw_log",
)

# 明文口令兜底检测：清洗脚本应当已脱敏，这里防的是「上游漏了」
PLAINTEXT_SECRET = re.compile(
    r"(?:password|passwd|pwd|token|authorization|cookie)\s*[=:]\s*(?!\*\*\*)([^\s&;'\"]{6,})",
    re.IGNORECASE,
)


def load_env(project_root: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    env_file = project_root / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    # 环境变量优先于 .env
    for k in (
        "CLICKHOUSE_HOST", "CLICKHOUSE_HTTP_PORT", "CLICKHOUSE_DATABASE",
        "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD", "CLICKHOUSE_FULL_CHAIN_TABLE",
    ):
        if os.getenv(k):
            env[k] = os.environ[k]
    return env


def ch_query(env: dict[str, str], sql: str) -> str:
    """执行一条 SQL（HTTP 接口），返回文本结果。"""
    url = (
        f"http://{env.get('CLICKHOUSE_HOST', '127.0.0.1')}:"
        f"{env.get('CLICKHOUSE_HTTP_PORT', '8123')}/"
        f"?database={env.get('CLICKHOUSE_DATABASE', 'log_ai')}"
    )
    req = urllib.request.Request(url, data=sql.encode("utf-8"), method="POST")
    req.add_header("X-ClickHouse-User", env.get("CLICKHOUSE_USER", "seclog"))
    req.add_header("X-ClickHouse-Key", env.get("CLICKHOUSE_PASSWORD", ""))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "ignore")
        raise RuntimeError(f"ClickHouse 返回 {exc.code}: {body[:400]}") from exc


def validate_row(row: dict, line_no: int, source_file: str) -> tuple[dict | None, str | None]:
    """校验单行，返回 (规范化后的行, 错误原因)。"""
    missing = [f for f in REQUIRED_PRESENT if f not in row]
    missing += [f for f in REQUIRED_NON_EMPTY if row.get(f) in (None, "")]
    if missing:
        return None, f"第 {line_no} 行缺少必填字段: {', '.join(sorted(set(missing)))}"

    if row["log_source"] not in ALLOWED_LOG_SOURCES:
        return None, f"第 {line_no} 行 log_source 非法: {row['log_source']!r}"
    if row["attack_stage_hint"] not in ALLOWED_STAGES:
        return None, f"第 {line_no} 行 attack_stage_hint 非法: {row['attack_stage_hint']!r}"

    ts = str(row["timestamp"])
    if not ts.endswith("Z"):
        return None, f"第 {line_no} 行 timestamp 必须为 UTC 且以 Z 结尾: {ts!r}"
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None, f"第 {line_no} 行 timestamp 无法解析: {ts!r}"

    payload = str(row.get("payload_summary") or "")
    hit = PLAINTEXT_SECRET.search(payload)
    if hit:
        return None, f"第 {line_no} 行 payload_summary 疑似含明文口令（{hit.group(0)[:24]}…），拒绝入库"

    out = {col: "" for col in INSERT_COLUMNS}
    for field in REQUIRED_FIELDS + OPTIONAL_FIELDS:
        col = COLUMN_MAP.get(field, field)
        if field in ("src_port", "dest_port", "status_code", "bytes_out"):
            val = row.get(field)
            # Nullable(UInt*) 在 JSONEachRow 里只接受 null，不接受空串
            out[col] = None if val in (None, "") else int(val)
        else:
            out[col] = str(row.get(field) or "").strip()

    # ClickHouse 的 JSONEachRow 对 DateTime64 只接受 "YYYY-MM-DD HH:MM:SS.mmm"，
    # 带 T 与 Z 的 ISO8601 会报 CANNOT_PARSE_INPUT。契约层仍是 UTC + Z，落库前转换。
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    out["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"

    out["source_file"] = source_file
    out["raw_log"] = str(row.get("raw_log") or "")
    return out, None


def iter_records(path: Path):
    """按行读 JSONL，或整体读 JSON 数组——场景包是后者。"""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return
    # 以 [ 开头视为 JSON 数组
    if text[0] == "[":
        try:
            arr = json.loads(text)
        except json.JSONDecodeError as exc:
            yield 1, None, f"JSON 数组解析失败: {exc}"
            return
        for idx, row in enumerate(arr, start=1):
            if isinstance(row, dict):
                yield idx, row, None
            else:
                yield idx, None, f"第 {idx} 个元素不是对象"
        return
    for idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            yield idx, json.loads(line), None
        except json.JSONDecodeError as exc:
            yield idx, None, f"第 {idx} 行 JSON 解析失败: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser(description="统一 Schema JSONL → ClickHouse full_chain_logs")
    ap.add_argument("--input", required=True, help="JSONL 文件或目录")
    ap.add_argument("--batch-note", default="", help="批次备注，写入 ingest_batches.error_summary 之外的日志")
    ap.add_argument("--dry-run", action="store_true", help="只校验不写库")
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()

    project_root = Path(args.project_root)
    env = load_env(project_root)
    table = env.get("CLICKHOUSE_FULL_CHAIN_TABLE", "log_ai.full_chain_logs")

    src = Path(args.input)
    files = sorted(list(src.rglob("*.jsonl")) + list(src.rglob("*.json"))) if src.is_dir() else [src]
    if not files:
        print(f"[ERR] 未找到任何 .jsonl/.json：{src}", file=sys.stderr)
        return 2

    total = parsed = dropped = 0
    errors: list[str] = []
    accepted: list[dict] = []

    for f in files:
        rel = str(f.relative_to(project_root)) if f.is_relative_to(project_root) else str(f)
        for line_no, row, err in iter_records(f):
            total += 1
            if err:
                dropped += 1
                errors.append(f"{rel} {err}")
                continue
            clean, err2 = validate_row(row, line_no, rel)
            if err2:
                dropped += 1
                errors.append(f"{rel} {err2}")
                continue
            accepted.append(clean)
            parsed += 1

    print(f"扫描 {len(files)} 个文件，共 {total} 行；合格 {parsed} 行，拒绝 {dropped} 行")
    for e in errors[:20]:
        print(f"  [DROP] {e}", file=sys.stderr)
    if len(errors) > 20:
        print(f"  …另有 {len(errors) - 20} 条错误未显示", file=sys.stderr)

    if args.dry_run:
        print("--dry-run：未写库")
        return 0 if dropped == 0 else 1
    if not accepted:
        print("[ERR] 没有合格数据，终止", file=sys.stderr)
        return 1

    batch_id = "BATCH-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + \
        hashlib.md5(f"{args.input}{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:6]
    # 写入 ingest_batches 的时间必须是 ClickHouse 的 DateTime64 字面量格式（无 T / Z）
    _now = datetime.now(timezone.utc)
    started = _now.strftime("%Y-%m-%d %H:%M:%S.") + f"{_now.microsecond // 1000:03d}"

    # 幂等：先删同 log_id 的旧行，再插入
    log_ids = sorted({r["log_id"] for r in accepted})
    id_list = ", ".join("'" + i.replace("'", "''") + "'" for i in log_ids)
    try:
        ch_query(env, f"ALTER TABLE {table} DELETE WHERE log_id IN ({id_list}) SETTINGS mutations_sync = 1")
        body = "\n".join(json.dumps(r, ensure_ascii=False) for r in accepted)
        ch_query(env, f"INSERT INTO {table} ({', '.join(INSERT_COLUMNS)}) FORMAT JSONEachRow\n{body}")
    except RuntimeError as exc:
        print(f"[ERR] 写库失败: {exc}", file=sys.stderr)
        # 失败也要留痕，便于排查到底哪一批没进去
        safe_err = str(exc)[:200].replace("'", "''")
        try:
            ch_query(
                env,
                f"INSERT INTO ingest_batches (batch_id, log_source, source_file, started_at, "
                f"finished_at, total_lines, parsed_lines, dropped_lines, status, error_summary) VALUES "
                f"('{batch_id}', 'mixed', '{args.input}', '{started}', now64(3), "
                f"{total}, 0, {dropped}, 'failed', '{safe_err}')",
            )
        except RuntimeError:
            pass
        return 1

    _end = datetime.now(timezone.utc)
    finished = _end.strftime("%Y-%m-%d %H:%M:%S.") + f"{_end.microsecond // 1000:03d}"
    ch_query(
        env,
        f"INSERT INTO ingest_batches (batch_id, log_source, source_file, started_at, finished_at, "
        f"total_lines, parsed_lines, dropped_lines, status, error_summary) VALUES "
        f"('{batch_id}', 'mixed', '{args.input}', '{started}', '{finished}', "
        f"{total}, {parsed}, {dropped}, 'succeeded', '{args.batch_note[:200]}')",
    )

    print(f"批次 {batch_id} 写入完成：{parsed} 行 → {table}")
    return 0 if dropped == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
