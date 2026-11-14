"""ClickHouse 参数绑定：毫秒边界必须用 DT64Param，不能被序列化到秒。

项目锁定 ``clickhouse-connect==0.8.9``，普通 ``datetime`` 参数会按秒序列化，
``.123`` 会变成 ``.000``——历史场景边界上的记录因此被误包含或误排除。
这里用假驱动捕获实际绑定值，不连接网络。
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from api import datasource

pytest.importorskip("clickhouse_connect", reason="未安装 clickhouse-connect")


class _Result:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def named_results(self) -> list[dict]:
        return self._rows

    @property
    def first_row(self) -> tuple[int]:
        return (len(self._rows),)


class _FakeClient:
    """记录每次查询的 SQL 与参数，返回空结果。"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def query(self, sql: str, parameters=None):
        self.calls.append((sql, dict(parameters or {})))
        return _Result([])


def _source() -> tuple[datasource.ClickHouseLogSource, _FakeClient]:
    src = datasource.ClickHouseLogSource(dsn="http://fake:8123")
    fake = _FakeClient()
    src._client = fake  # 跳过真实连接
    return src, fake


def test_millisecond_bounds_use_dt64param():
    src, fake = _source()
    start = datetime(2026, 10, 27, 14, 0, 0, 123000, tzinfo=timezone.utc)
    end = datetime(2026, 10, 27, 14, 0, 0, 124000, tzinfo=timezone.utc)

    src.query(datasource.LogQuery(trace_id="CHAIN-CASE-01", start_time=start, end_time=end))

    from clickhouse_connect.driver.binding import DT64Param

    assert fake.calls, "应当发起查询"
    params = fake.calls[0][1]
    assert isinstance(params["start_time"], DT64Param), "边界必须用 DT64Param 绑定"
    assert isinstance(params["end_time"], DT64Param)
    # 驱动实际格式化出来的值必须保留毫秒
    formatted_start = params["start_time"].format(timezone.utc, True)
    formatted_end = params["end_time"].format(timezone.utc, True)
    assert formatted_start.endswith(".123000"), formatted_start
    assert formatted_end.endswith(".124000"), formatted_end
    assert formatted_start != formatted_end, ".123 与 .124 不能被抹成同一个值"


def test_count_query_shares_the_same_bounds():
    """列表查询与计数查询必须用同一组边界，否则 total 与 items 会对不上。"""
    src, fake = _source()
    start = datetime(2026, 10, 27, 14, 0, 0, 123000, tzinfo=timezone.utc)
    end = datetime(2026, 10, 27, 14, 0, 0, 124000, tzinfo=timezone.utc)

    src.query(datasource.LogQuery(trace_id="CHAIN-CASE-01", start_time=start, end_time=end))

    assert len(fake.calls) == 2, "应分别查询明细与总数"
    for sql, params in fake.calls:
        assert "timestamp >=" in sql and "timestamp <=" in sql
        assert params["start_time"].format(timezone.utc, True).endswith(".123000")
        assert params["end_time"].format(timezone.utc, True).endswith(".124000")


def test_relative_window_still_uses_interval():
    """普通实时查询保持原来的 now() - INTERVAL 行为，不被绝对窗口替换。"""
    src, fake = _source()
    from datetime import timedelta

    src.query(datasource.LogQuery(trace_id="CHAIN-CASE-01", window=timedelta(hours=1)))
    sql, params = fake.calls[0]
    assert "INTERVAL" in sql
    assert params.get("window_seconds") == 3600
    assert "start_time" not in params
