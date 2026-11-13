"""日志数据源适配层：ClickHouse 真实库 与 数据集回放 两种后端。

设计约束（来自 Issue #18）：

1. **两种后端都实现，任选其一即可跑通**。ClickHouse 不可用不应阻塞全部工作，
   因此默认 ``auto``：先尝试 ClickHouse，连不上再回落到 ``dataset_replay``；
2. **绝不静默降级到 Mock**。真实数据源失败时抛 :class:`BackendUnavailable`，
   由 API 层转成 503 + 明确原因。Mock 只有在显式设置 ``SECLOG_DATA_SOURCE=mock`` 时才用；
3. **``meta.data_source`` 必须准确**：``clickhouse`` / ``dataset_replay`` / ``mock``；
4. **回放时间基准可复现**：以每个场景自身的**最新日志时间**为基准回溯，
   而不是硬编码某个演示日期，也不是用"当前系统时间"（否则历史数据集永远查不到）。

环境变量：

* ``SECLOG_DATA_SOURCE``：``auto``（默认） | ``clickhouse`` | ``dataset_replay`` | ``mock``
* ``SECLOG_DATASET_DIR``：数据集目录，默认 ``data/full_chain_logs``
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol

from ai_engine.redaction import redact_text

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "full_chain_logs"

#: 统一 Schema 的契约字段（见 docs/project design/全链路日志统一字段规范.md）
CONTRACT_FIELDS = (
    "log_id",
    "trace_id",
    "timestamp",
    "log_source",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "asset_id",
    "user",
    "session_id",
    "action_or_method",
    "uri_or_target",
    "payload_summary",
    "status_code",
    "bytes_out",
    "user_agent",
    "attack_stage_hint",
)

#: 允许的日志来源；``all`` 表示不过滤
LOG_SOURCES = ("nginx_access", "auth_log", "zeek_conn", "zeek_http", "zeek_dns", "all")


class BackendUnavailable(RuntimeError):
    """后端不可用。``reason`` 会原样透出给调用方，便于定位是缺依赖还是缺服务。"""

    def __init__(self, backend: str, reason: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{backend} 不可用：{reason}")
        self.backend = backend
        self.reason = reason
        self.details = details or {}


@dataclass(slots=True)
class LogQuery:
    """一次日志查询的过滤条件。时间窗由 :class:`LogSource` 决定如何落到数据上。"""

    case_id: Optional[str] = None
    trace_id: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    log_source: str = "all"
    window: Optional[timedelta] = None
    #: 绝对时间窗（UTC）。给出时按绝对区间过滤，忽略 ``window``；
    #: 用于复核历史场景——``window`` 是"从基准往回数"，查不到几个月前的数据。
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 50

    @property
    def scenario_key(self) -> Optional[str]:
        """调查 case_id 与日志场景标识的关系。

        * ``trace_id`` 明确给出时以其为准；
        * 否则如果 ``case_id`` 本身就是场景标识（出现在数据集里），用它；
        * 其余情况 ``case_id`` 只用于证据登记隔离，不参与日志过滤。
        """
        return self.trace_id or (self.case_id if self.case_id else None)


@dataclass(slots=True)
class LogQueryResult:
    """查询结果；``data_source`` 等元信息直接进 ``/tools/query_logs`` 的 meta。"""

    items: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    data_source: str = "mock"
    dataset: Optional[str] = None
    reference_time: Optional[str] = None
    time_base: Optional[str] = None
    time_window_applied: Optional[str] = None
    scenarios: list[str] = field(default_factory=list)
    #: 每个命中场景各自的基准时间与窗口边界。
    #: 多场景查询各自独立计时，单靠一个 ``reference_time`` 会误导调用方，故逐场景列出。
    scenario_time_bases: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class LogSource(Protocol):
    """日志数据源协议。REST 与 MCP 都经由同一实现，保证行为一致。"""

    name: str

    def query(self, q: LogQuery) -> LogQueryResult: ...

    def health(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _parse_ts(value: Any) -> Optional[datetime]:
    """解析时间戳；统一成 UTC aware。无法解析返回 ``None``（不猜测）。"""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _normalize_record(raw: dict[str, Any]) -> dict[str, Any]:
    """把一条日志收敛到契约字段；缺失字段补 ``None``，多余字段丢弃。"""
    record = {name: raw.get(name) for name in CONTRACT_FIELDS}
    # ClickHouse 用 user_name 存契约里的 user
    if record.get("user") is None and raw.get("user_name") is not None:
        record["user"] = raw["user_name"]
    ts = _parse_ts(record.get("timestamp"))
    if ts is not None:
        record["timestamp"] = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return record


def _reject_unknown_source(log_source: str) -> None:
    if log_source not in LOG_SOURCES:
        raise ValueError(f"不支持的 log_source：{log_source}，可选 {', '.join(LOG_SOURCES)}")


# ---------------------------------------------------------------------------
# 数据集回放
# ---------------------------------------------------------------------------


class DatasetReplaySource:
    """把 ``data/full_chain_logs/*.json`` 当作只读日志库来查。

    每个 ``*.json``（排除 ``*truth*``）是一个场景的日志数组，自身带 ``trace_id``。
    时间窗以**该场景最新一条日志**为基准回溯，因此同样的查询在任何时候运行结果一致。
    """

    name = "dataset_replay"

    def __init__(self, dataset_dir: Path | str = DEFAULT_DATASET_DIR) -> None:
        self.dataset_dir = Path(dataset_dir)
        self._scenarios: Optional[dict[str, list[dict[str, Any]]]] = None
        self._load_error: Optional[str] = None
        self._warnings: list[str] = []

    # -- 加载 --

    def _ensure_loaded(self) -> dict[str, list[dict[str, Any]]]:
        if self._scenarios is not None:
            return self._scenarios
        if not self.dataset_dir.exists():
            raise BackendUnavailable(
                self.name,
                f"数据集目录不存在：{self.dataset_dir}",
                details={"dataset_dir": str(self.dataset_dir)},
            )
        scenarios: dict[str, list[dict[str, Any]]] = {}
        files = sorted(
            p for p in list(self.dataset_dir.glob("*.json")) + list(self.dataset_dir.glob("*.jsonl")) if "truth" not in p.name.lower()
        )
        if not files:
            raise BackendUnavailable(
                self.name,
                f"数据集目录下没有场景文件：{self.dataset_dir}",
                details={"dataset_dir": str(self.dataset_dir)},
            )
        for path in files:
            try:
                payload = ([json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.suffix == ".jsonl" else json.loads(path.read_text(encoding="utf-8")))
            except Exception as exc:  # 文件损坏要显式记录，不能静默跳过
                self._warnings.append(f"{path.name} 解析失败：{type(exc).__name__}")
                continue
            if not isinstance(payload, list):
                self._warnings.append(f"{path.name} 不是数组，已忽略")
                continue
            for raw in payload:
                if not isinstance(raw, dict):
                    continue
                record = _normalize_record(raw)
                trace = record.get("trace_id")
                if not trace:
                    self._warnings.append(f"{path.name} 存在缺少 trace_id 的记录，已忽略")
                    continue
                scenarios.setdefault(str(trace), []).append(record)
        if not scenarios:
            raise BackendUnavailable(
                self.name, "数据集中没有可用场景（全部解析失败或为空）", details={"warnings": self._warnings}
            )
        for logs in scenarios.values():
            logs.sort(key=lambda r: (_parse_ts(r.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc), r.get("log_id") or ""))
        self._scenarios = scenarios
        return scenarios

    # -- 查询 --

    def query(self, q: LogQuery) -> LogQueryResult:
        _reject_unknown_source(q.log_source)
        scenarios = self._ensure_loaded()

        scenario_key = q.scenario_key
        if scenario_key and scenario_key in scenarios:
            pools = {scenario_key: scenarios[scenario_key]}
        elif q.trace_id or (q.case_id and q.case_id.upper().startswith("CHAIN-")):
            # 明确指定了不存在的场景：如实返回空，而不是回落到全部场景
            return LogQueryResult(
                items=[],
                total=0,
                data_source=self.name,
                dataset=str(self.dataset_dir),
                time_base="scenario_latest",
                time_window_applied=self._fmt_window(q.window),
                scenarios=[],
                notes=[f"数据集中没有 trace_id={q.trace_id} 的场景"] + self._warnings,
            )
        else:
            pools = scenarios

        matched: list[dict[str, Any]] = []
        hits: list[str] = []
        bases: list[dict[str, Any]] = []
        for trace, logs in pools.items():
            # 关键顺序：**先用完整场景确定基准，再套时间窗，最后做字段过滤**。
            # 反过来（先过滤再算窗口）会让窗口锚在"过滤后子集的最后一条"上，
            # 于是响应里的 reference_time 与真正生效的边界对不上。
            stamps = [t for t in (_parse_ts(r.get("timestamp")) for r in logs) if t]
            base = max(stamps) if stamps else None
            windowed = logs
            if q.window is not None and base is not None:
                start = base - q.window
                windowed = [
                    r
                    for r in logs
                    if (t := _parse_ts(r.get("timestamp"))) is not None and start <= t <= base
                ]
            # 绝对时间窗优先：用于复核历史场景（相对窗口查不到几个月前的数据）
            if q.start_time is not None or q.end_time is not None:
                lo = q.start_time or datetime.min.replace(tzinfo=timezone.utc)
                hi = q.end_time or datetime.max.replace(tzinfo=timezone.utc)
                windowed = [
                    r
                    for r in windowed
                    if (t := _parse_ts(r.get("timestamp"))) is not None and lo <= t <= hi
                ]
            scenario_hits = [r for r in windowed if self._match(r, q)]
            bases.append(
                {
                    "trace_id": trace,
                    "reference_time": base.isoformat() if base else None,
                    "window_start": (base - q.window).isoformat() if (base and q.window) else None,
                    "window_end": base.isoformat() if base else None,
                    "matched": len(scenario_hits),
                }
            )
            if not scenario_hits:
                continue
            hits.append(trace)
            matched.extend(scenario_hits)

        matched.sort(key=lambda r: (_parse_ts(r.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc), r.get("log_id") or ""))
        total = len(matched)
        # 只有一个场景命中时，reference_time 就是该场景的基准；
        # 多场景时各场景基准不同，给单个值会误导调用方，因此置空并靠 scenario_time_bases 表达。
        single = len(hits) == 1
        reference = next((b["reference_time"] for b in bases if b["trace_id"] == hits[0]), None) if single else None
        return LogQueryResult(
            items=matched[: q.limit],
            total=total,
            data_source=self.name,
            dataset=self._display_path(),
            reference_time=reference,
            time_base="absolute" if (q.start_time or q.end_time) else "scenario_latest",
            time_window_applied=self._fmt_window(q.window),
            scenarios=hits,
            # 列出所有参与计算的场景（含零命中的），这样零结果时也能看出基准与窗口边界
            scenario_time_bases=bases,
            notes=list(self._warnings)
            + (["命中多个场景，各场景独立计时，请使用 scenario_time_bases"] if len(hits) > 1 else []),
        )

    def _display_path(self) -> str:
        """对外展示用相对路径，避免把本机绝对路径写进响应。"""
        try:
            return str(self.dataset_dir.relative_to(PROJECT_ROOT)).replace("\\", "/")
        except ValueError:
            return str(self.dataset_dir).replace("\\", "/")

    @staticmethod
    def _match(record: dict[str, Any], q: LogQuery) -> bool:
        if q.src_ip and record.get("src_ip") != q.src_ip:
            return False
        if q.dest_ip and record.get("dest_ip") != q.dest_ip:
            return False
        if q.log_source != "all" and record.get("log_source") != q.log_source:
            return False
        return True

    @staticmethod
    def _fmt_window(window: Optional[timedelta]) -> Optional[str]:
        if window is None:
            return None
        total = int(window.total_seconds() // 60)
        if total % 60 == 0:
            return f"{total // 60}h"
        return f"{total}m"

    def health(self) -> dict[str, Any]:
        try:
            scenarios = self._ensure_loaded()
        except BackendUnavailable as exc:
            return {"available": False, "reason": exc.reason, "dataset_dir": str(self.dataset_dir)}
        return {
            "available": True,
            "dataset_dir": str(self.dataset_dir),
            "scenarios": sorted(scenarios),
            "records": sum(len(v) for v in scenarios.values()),
            "time_base": "scenario_latest",
            "warnings": self._warnings,
        }

    def scenarios_summary(self) -> list[dict[str, Any]]:
        """列出场景及其时间范围，供 V1 运行脚本挑选用例。"""
        out: list[dict[str, Any]] = []
        for trace, logs in sorted(self._ensure_loaded().items()):
            stamps = [t for t in (_parse_ts(r.get("timestamp")) for r in logs) if t]
            out.append(
                {
                    "trace_id": trace,
                    "records": len(logs),
                    "start": min(stamps).isoformat() if stamps else None,
                    "end": max(stamps).isoformat() if stamps else None,
                    "log_sources": sorted({r.get("log_source") for r in logs if r.get("log_source")}),
                }
            )
        return out


# ---------------------------------------------------------------------------
# ClickHouse
# ---------------------------------------------------------------------------


class ClickHouseLogSource:
    """查询 ``log_ai.full_chain_logs`` 真实库。

    驱动采用懒加载：缺 ``clickhouse_connect`` 或连不上时抛 :class:`BackendUnavailable`，
    由上层决定是报 503 还是切回放。**不会**返回 Mock 数据。
    """

    name = "clickhouse"

    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or os.getenv("CLICKHOUSE_DSN", "http://127.0.0.1:8123")
        self._client: Any = None

    def _connect(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import clickhouse_connect  # noqa: PLC0415
        except Exception as exc:
            raise BackendUnavailable(
                self.name,
                "缺少 clickhouse_connect 驱动",
                details={"stage": "import", "hint": "pip install clickhouse-connect", "error": type(exc).__name__},
            ) from exc
        try:
            self._client = clickhouse_connect.get_client(dsn=self.dsn)
            self._client.query("SELECT 1")
        except Exception as exc:
            raise BackendUnavailable(
                self.name,
                redact_text(f"连接 ClickHouse 失败：{type(exc).__name__}: {exc}"),
                details={"stage": "connect", "dsn": redact_text(self.dsn), "hint": "确认 log_ai.full_chain_logs 已建表并导入数据"},
            ) from exc
        return self._client

    def query(self, q: LogQuery) -> LogQueryResult:
        _reject_unknown_source(q.log_source)
        client = self._connect()

        where: list[str] = []
        params: dict[str, Any] = {}
        if q.trace_id:
            where.append("trace_id = {trace_id:String}")
            params["trace_id"] = q.trace_id
        elif q.case_id and q.case_id.upper().startswith("CHAIN-"):
            # case_id 本身就是场景标识时可直接过滤
            where.append("trace_id = {case_trace:String}")
            params["case_trace"] = q.case_id
        if q.src_ip:
            where.append("src_ip = {src_ip:String}")
            params["src_ip"] = q.src_ip
        if q.dest_ip:
            where.append("dest_ip = {dest_ip:String}")
            params["dest_ip"] = q.dest_ip
        if q.log_source != "all":
            where.append("log_source = {log_source:String}")
            params["log_source"] = q.log_source
        if q.start_time is not None or q.end_time is not None:
            # 绝对时间窗：复核历史场景必须用它，`now() - INTERVAL` 只能覆盖近期数据。
            # 必须用 DT64Param 包装：普通 datetime 在 clickhouse-connect 0.8.9 上按秒序列化，
            # 毫秒会被抹掉（.123 → .000），导致边界记录被误包含/误排除。
            from clickhouse_connect.driver.binding import DT64Param  # noqa: PLC0415

            if q.start_time is not None:
                where.append("timestamp >= {start_time:DateTime64(3)}")
                params["start_time"] = DT64Param(q.start_time)
            if q.end_time is not None:
                where.append("timestamp <= {end_time:DateTime64(3)}")
                params["end_time"] = DT64Param(q.end_time)
        elif q.window is not None:
            # 真实库使用服务器当前时间回溯（数据持续写入，这是自然口径）
            where.append("timestamp >= now() - INTERVAL {window_seconds:UInt32} SECOND")
            params["window_seconds"] = int(q.window.total_seconds())
        if not where:
            raise ValueError("至少提供一个过滤条件，不接受无条件全量查询")

        where_sql = " AND ".join(where)
        params["limit"] = int(q.limit)
        columns = ", ".join(
            "user_name AS user" if f == "user" else f for f in CONTRACT_FIELDS
        )
        try:
            rows = client.query(
                f"SELECT {columns} FROM log_ai.full_chain_logs WHERE {where_sql} "
                "ORDER BY timestamp ASC LIMIT {limit:UInt32}",
                parameters=params,
            ).named_results()
            total = client.query(
                f"SELECT count() FROM log_ai.full_chain_logs WHERE {where_sql}", parameters=params
            ).first_row[0]
        except Exception as exc:
            raise BackendUnavailable(
                self.name,
                redact_text(f"查询 log_ai.full_chain_logs 失败：{type(exc).__name__}: {exc}"),
                details={"stage": "query", "dsn": redact_text(self.dsn)},
            ) from exc

        items = [_normalize_record(dict(row)) for row in rows]
        return LogQueryResult(
            items=items,
            total=int(total),
            data_source=self.name,
            dataset="log_ai.full_chain_logs",
            reference_time=datetime.now(timezone.utc).isoformat(),
            time_base="absolute" if (q.start_time or q.end_time) else "server_now",
            time_window_applied=DatasetReplaySource._fmt_window(q.window),
            scenarios=sorted({i.get("trace_id") for i in items if i.get("trace_id")}),
        )

    def health(self) -> dict[str, Any]:
        try:
            self._connect()
        except BackendUnavailable as exc:
            return {"available": False, "reason": exc.reason, "details": exc.details}
        return {"available": True, "dsn": redact_text(self.dsn), "table": "log_ai.full_chain_logs"}


# ---------------------------------------------------------------------------
# Mock（第一周保留，仅在显式开启时使用）
# ---------------------------------------------------------------------------


class MockLogSource:
    """第一周演示数据。只有 ``SECLOG_DATA_SOURCE=mock`` 才会被选中。"""

    name = "mock"

    def __init__(self) -> None:
        from . import mock_data  # 延迟导入，避免循环

        self._mock = mock_data

    def query(self, q: LogQuery) -> LogQueryResult:
        minutes = int(q.window.total_seconds() // 60) if q.window is not None else 60
        picked = self._mock.query_mock_logs(
            src_ip=q.src_ip,
            dest_ip=q.dest_ip,
            trace_id=q.trace_id or (q.case_id if q.case_id and q.case_id.upper().startswith("CHAIN-") else None),
            log_source=q.log_source,
            window_minutes=minutes,
        )
        items = [_normalize_record(r) for r in picked[: q.limit]]
        return LogQueryResult(
            items=items,
            total=len(picked),
            data_source="mock",
            dataset="src/api/mock_data.py",
            reference_time=self._mock.MOCK_REFERENCE_TIME.isoformat(),
            time_base="fixed_demo",
            time_window_applied=DatasetReplaySource._fmt_window(q.window),
            scenarios=sorted({i.get("trace_id") for i in items if i.get("trace_id")}),
        )

    def health(self) -> dict[str, Any]:
        return {"available": True, "records": len(self._mock.MOCK_LOGS), "note": "演示数据"}


# ---------------------------------------------------------------------------
# 选择器
# ---------------------------------------------------------------------------


def resolve_mode(mode: Optional[str] = None) -> str:
    return (mode or os.getenv("SECLOG_DATA_SOURCE", "auto")).strip().lower()


def get_log_source(mode: Optional[str] = None, *, dataset_dir: Path | str | None = None) -> LogSource:
    """按模式返回数据源。

    ``auto``：ClickHouse 可用则用它，否则用数据集回放；**两者都不可用时报错**，
    不回落 Mock——避免把演示数据当成真实查询结果。
    """
    selected = resolve_mode(mode)
    dataset = Path(dataset_dir or os.getenv("SECLOG_DATASET_DIR", DEFAULT_DATASET_DIR))

    if selected == "mock":
        return MockLogSource()
    if selected == "dataset_replay":
        return DatasetReplaySource(dataset)
    if selected == "clickhouse":
        return ClickHouseLogSource()
    if selected != "auto":
        raise ValueError(f"SECLOG_DATA_SOURCE 取值非法：{selected}（auto/clickhouse/dataset_replay/mock）")

    clickhouse = ClickHouseLogSource()
    try:
        clickhouse._connect()
        return clickhouse
    except BackendUnavailable:
        return DatasetReplaySource(dataset)


def available_sources(dataset_dir: Path | str | None = None) -> dict[str, Any]:
    """诊断用：报告两种后端各自是否可用，不做选择。"""
    dataset = Path(dataset_dir or os.getenv("SECLOG_DATASET_DIR", DEFAULT_DATASET_DIR))
    return {
        "mode": resolve_mode(),
        "clickhouse": ClickHouseLogSource().health(),
        "dataset_replay": DatasetReplaySource(dataset).health(),
    }
