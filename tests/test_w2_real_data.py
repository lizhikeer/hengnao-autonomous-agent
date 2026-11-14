"""第二周：真实数据接线回归测试（数据集回放 / 资产上下文 / 数据源标识 / 案例隔离）。"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DATASET = REPO / "data" / "full_chain_logs"


def _client():
    from fastapi.testclient import TestClient

    from api.app import app

    return TestClient(app)


@pytest.fixture()
def client():
    with _client() as c:
        yield c


# ---------------------------------------------------------------------------
# 数据集回放
# ---------------------------------------------------------------------------


def test_replay_returns_scenario_logs(replay_backend, client):
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01", "limit": 50})
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["data_source"] == "dataset_replay"
    assert body["meta"]["mock"] is False
    assert body["meta"]["backend_available"] is True
    assert body["meta"]["time_base"] == "scenario_latest"
    assert body["meta"]["total"] > 0
    assert body["meta"]["scenarios"] == ["CHAIN-CASE-01"]
    assert all(i["trace_id"] == "CHAIN-CASE-01" for i in body["items"])


def test_replay_time_window_uses_scenario_latest(replay_backend, client):
    """1h 窗口必须以场景最新日志为基准，而不是系统当前时间（否则历史数据永远查不到）。"""
    full = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01", "time_window": "24h"}).json()
    narrow = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01", "time_window": "1m"}).json()
    assert full["meta"]["total"] > narrow["meta"]["total"]
    assert narrow["meta"]["time_window_applied"] == "1m"
    # 窗口内的日志时间必须落在 [基准-window, 基准]
    assert narrow["meta"]["reference_time"] is not None


def test_replay_filters_by_log_source(replay_backend, client):
    r = client.post(
        "/tools/query_logs", json={"trace_id": "CHAIN-CASE-01", "log_source": "auth_log", "limit": 200}
    )
    items = r.json()["items"]
    assert items
    assert {i["log_source"] for i in items} == {"auth_log"}


def test_replay_filters_by_src_ip_across_scenarios(replay_backend, client):
    r = client.post("/tools/query_logs", json={"src_ip": "10.0.0.66", "limit": 200})
    body = r.json()
    assert body["meta"]["total"] > 0
    assert body["meta"]["scenarios"] == ["CHAIN-CASE-03"]
    assert all(i["src_ip"] == "10.0.0.66" for i in body["items"])


def test_replay_unknown_trace_returns_empty_with_note(replay_backend, client):
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-NOT-EXIST"})
    body = r.json()
    assert r.status_code == 200
    assert body["meta"]["total"] == 0
    assert body["items"] == []
    assert body["meta"]["notes"]


def test_case_id_equal_to_scenario_id_also_filters(replay_backend, client):
    """调查 case_id 与场景标识的关系：case_id 直接写成场景标识时也应命中。"""
    r = client.post("/tools/query_logs", json={"case_id": "CHAIN-CASE-02", "limit": 100})
    body = r.json()
    assert body["meta"]["scenarios"] == ["CHAIN-CASE-02"]
    assert body["meta"]["total"] > 0


def test_missing_dataset_reports_unavailable(tmp_path, monkeypatch, client):
    """数据集目录不存在时必须报 503，不能回落 Mock。"""
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "dataset_replay")
    monkeypatch.setenv("SECLOG_DATASET_DIR", str(tmp_path / "nope"))
    app_module = importlib.import_module("api.app")
    app_module.reset_source_cache()
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01"})
    assert r.status_code == 503
    assert r.json()["code"] == "backend_unavailable"
    assert r.json()["details"]["backend"] == "dataset_replay"
    app_module.reset_source_cache()


def test_cliickhouse_mode_never_falls_back_to_mock(monkeypatch, client):
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "clickhouse")
    app_module = importlib.import_module("api.app")
    app_module.reset_source_cache()
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01"})
    assert r.status_code == 503
    assert r.json()["details"]["backend"] == "clickhouse"
    assert "data_source" not in r.json()  # 不能带出 mock 结果
    app_module.reset_source_cache()


def test_invalid_mode_is_rejected(monkeypatch, client):
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "postgres")
    app_module = importlib.import_module("api.app")
    app_module.reset_source_cache()
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01"})
    assert r.status_code == 422
    app_module.reset_source_cache()


# ---------------------------------------------------------------------------
# 案例隔离与证据登记
# ---------------------------------------------------------------------------


def test_evidence_registered_under_case_and_isolated(replay_backend, client):
    r = client.post("/tools/query_logs", json={"case_id": "CASE-W2-A", "trace_id": "CHAIN-CASE-01", "limit": 5})
    ids = [i["log_id"] for i in r.json()["items"]]
    assert ids

    from api.evidence_check import registry

    assert set(ids) <= registry.known_log_ids(case_id="CASE-W2-A")
    assert registry.known_log_ids(case_id="CASE-W2-B") == set()

    resp = client.post(
        "/tools/request_response",
        json={
            "case_id": "CASE-W2-B",
            "action": "block_ip",
            "target_ip": "198.51.100.23",
            "evidence_log_ids": ids[:2],
            "reason": "跨案例引用他人证据",
        },
    )
    assert resp.json()["status"] == "rejected"


# ---------------------------------------------------------------------------
# 资产上下文
# ---------------------------------------------------------------------------


def test_asset_context_covers_case03_entities(client):
    """CHAIN-CASE-03 的三个关键实体必须能查到（正常运维防误报的前提）。"""
    asset = client.post("/tools/get_context", json={"asset_id": "web-prod-01"}).json()
    assert asset["meta"]["data_source"] == "asset_context"
    assert asset["asset_context"]["importance"] == "HIGH"
    windows = asset["asset_context"]["maintenance_windows"]
    assert any(w["start"] == "02:00" and w["end"] == "03:30" for w in windows)
    # 时区在配置顶层声明（config/maintenance-windows.yaml）
    assert "Shanghai" in asset["asset_context"]["timezone"]

    user = client.post("/tools/get_context", json={"user": "ops_zhang"}).json()
    assert user["user_profile"]["account_type"] == "legit_operator"
    assert user["user_profile"]["allowlisted"] is True

    # 台账以 PR #23 的 config/assets.yaml 为准：10.0.0.20 是运维跳板机 nas-host-01，
    # 备份主机 backup-01 是 10.0.0.40
    host = client.post("/tools/get_context", json={"asset_id": "10.0.0.20"}).json()
    assert host["asset_context"]["asset_id"] == "nas-host-01"
    backup = client.post("/tools/get_context", json={"asset_id": "10.0.0.40"}).json()
    assert backup["asset_context"]["asset_id"] == "backup-01"


def test_asset_context_maintenance_window_evaluated_at_log_time(client):
    """维护窗口判断按日志时间：02:10 CST 命中，10:00 CST 不命中。"""
    inside = client.post(
        "/tools/get_context", json={"asset_id": "web-prod-01", "at_time": "2026-10-29T18:10:00Z"}
    ).json()
    outside = client.post(
        "/tools/get_context", json={"asset_id": "web-prod-01", "at_time": "2026-10-30T02:00:00Z"}
    ).json()
    assert inside["asset_context"]["in_maintenance_window"] is True
    assert outside["asset_context"]["in_maintenance_window"] is False


def test_asset_context_unknown_entity_is_zero_not_error(client):
    r = client.post("/tools/get_context", json={"user": "nobody"})
    body = r.json()
    assert r.status_code == 200
    assert body["meta"]["total"] == 0
    assert body["user_profile"] is None
    assert body["meta"]["notes"]


def test_asset_context_missing_config_reports_503(monkeypatch, client):
    monkeypatch.setenv("SECLOG_CONFIG_DIR", str(REPO / "config-does-not-exist"))
    from api import asset_context

    asset_context.reset_cache()
    r = client.post("/tools/get_context", json={"asset_id": "web-prod-01"})
    assert r.status_code == 503
    assert r.json()["code"] == "backend_unavailable"
    asset_context.reset_cache()


# ---------------------------------------------------------------------------
# 数据源标识
# ---------------------------------------------------------------------------


def test_mock_mode_still_labelled_as_mock(client):
    """默认（conftest 强制 mock）下必须如实标 mock。"""
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-ATTACK-01"})
    body = r.json()
    assert body["meta"]["data_source"] == "mock"
    assert body["meta"]["mock"] is True
    assert body["meta"]["backend_available"] is False


def test_replay_meta_has_no_absolute_path(replay_backend, client):
    r = client.post("/tools/query_logs", json={"trace_id": "CHAIN-CASE-01"})
    dataset = r.json()["meta"]["dataset"]
    assert not dataset.startswith("C:\\") and not dataset.startswith("/")
    assert "full_chain_logs" in dataset


# ---------------------------------------------------------------------------
# 时间窗基准：必须锚在"完整场景的最新日志"，而不是"过滤后子集的最后一条"
# ---------------------------------------------------------------------------


def test_window_anchored_on_scenario_not_filtered_subset(replay_backend, client):
    """审查复现的问题：auth_log 最晚 14:07，场景最晚 14:17。

    1 分钟窗口必须以 14:17 为基准，因此 auth_log 一条都不该命中；
    旧实现会返回 14:06/14:07 的两条（早于声明窗口 10 分钟）。
    """
    r = client.post(
        "/tools/query_logs",
        json={"trace_id": "CHAIN-CASE-01", "log_source": "auth_log", "time_window": "1m"},
    )
    body = r.json()
    assert body["items"] == [], "1 分钟窗口内不应出现 auth_log（其最后活动在 10 分钟前）"
    assert body["meta"]["total"] == 0

    # 基准仍要能解释：给出场景基准与窗口边界
    bases = body["meta"]["scenario_time_bases"]
    assert bases and bases[0]["trace_id"] == "CHAIN-CASE-01"
    assert bases[0]["reference_time"]
    assert bases[0]["window_start"] and bases[0]["window_end"]


def test_window_result_within_reported_bounds(replay_backend, client):
    """返回的日志时间必须落在响应自己声明的 [window_start, window_end] 内。"""
    r = client.post(
        "/tools/query_logs",
        json={"trace_id": "CHAIN-CASE-01", "log_source": "auth_log", "time_window": "1h", "limit": 200},
    )
    body = r.json()
    assert body["items"]
    base = body["meta"]["scenario_time_bases"][0]
    start = base["window_start"][:19]
    end = base["window_end"][:19]
    for item in body["items"]:
        assert start <= item["timestamp"][:19] <= end, (item["log_id"], item["timestamp"], start, end)


def test_window_boundary_inclusive_on_exact_edge(tmp_path, monkeypatch):
    """窗口边界必须可判定：刚好落在起点/终点的记录分别应包含/排除。"""
    dataset = tmp_path / "ds"
    dataset.mkdir()
    rows = [
        {"log_id": "L-1", "trace_id": "T-EDGE", "timestamp": "2026-01-01T00:00:00Z", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "log_source": "auth_log"},
        {"log_id": "L-2", "trace_id": "T-EDGE", "timestamp": "2026-01-01T00:05:00Z", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "log_source": "auth_log"},
        {"log_id": "L-3", "trace_id": "T-EDGE", "timestamp": "2026-01-01T00:10:00Z", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "log_source": "nginx_access"},
    ]
    (dataset / "edge.json").write_text(__import__("json").dumps(rows), encoding="utf-8")

    from api import datasource

    source = datasource.DatasetReplaySource(dataset)
    import datetime as dt

    # 窗口 5 分钟：基准 00:10 → 起点 00:05，应包含 00:05 与 00:10，排除 00:00
    res = source.query(
        datasource.LogQuery(trace_id="T-EDGE", log_source="auth_log", window=dt.timedelta(minutes=5), limit=50)
    )
    assert [i["log_id"] for i in res.items] == ["L-2"]
    assert res.scenario_time_bases[0]["reference_time"].startswith("2026-01-01T00:10:00")

    # 窗口 10 分钟：起点 00:00，应包含 00:00 与 00:05
    res2 = source.query(
        datasource.LogQuery(trace_id="T-EDGE", log_source="auth_log", window=dt.timedelta(minutes=10), limit=50)
    )
    assert [i["log_id"] for i in res2.items] == ["L-1", "L-2"]


def test_multi_scenario_reports_per_scenario_bases(replay_backend, client):
    """跨场景查询各场景独立计时：不能用一个 reference_time 概括。"""
    r = client.post("/tools/query_logs", json={"dest_ip": "10.0.0.15", "time_window": "1h", "limit": 200})
    body = r.json()
    assert len(body["meta"]["scenarios"]) > 1
    assert body["meta"]["reference_time"] is None
    bases = {b["trace_id"]: b for b in body["meta"]["scenario_time_bases"]}
    assert len(bases) >= 2
    assert len({b["reference_time"] for b in bases.values()}) > 1
    assert any("scenario_time_bases" in n for n in body["meta"]["notes"])


# ---------------------------------------------------------------------------
# 绝对时间窗：复核历史场景（相对窗口从"当前时间"回溯，查不到几个月前的数据）
# ---------------------------------------------------------------------------


def test_absolute_window_finds_historical_scenario(replay_backend, client):
    r = client.post(
        "/tools/query_logs",
        json={
            "trace_id": "CHAIN-CASE-01",
            "time_start": "2026-10-27T14:00:00Z",
            "time_end": "2026-10-27T15:00:00Z",
            "limit": 200,
        },
    )
    body = r.json()
    assert r.status_code == 200
    assert body["meta"]["time_base"] == "absolute"
    assert body["meta"]["total"] > 0
    for item in body["items"]:
        assert "2026-10-27T14:00:00" <= item["timestamp"] <= "2026-10-27T15:00:00"


def test_absolute_window_outside_data_returns_zero(replay_backend, client):
    """11 月的窗口里没有 10 月的数据，必须返回 0 而不是"最近一小时"。"""
    r = client.post(
        "/tools/query_logs",
        json={"trace_id": "CHAIN-CASE-01", "time_start": "2026-11-01T00:00:00Z", "limit": 200},
    )
    body = r.json()
    assert body["meta"]["total"] == 0
    assert body["meta"]["time_base"] == "absolute"


def test_absolute_window_conflicts_with_relative(replay_backend, client):
    r = client.post(
        "/tools/query_logs",
        json={"trace_id": "CHAIN-CASE-01", "time_window": "1h", "time_start": "2026-10-27T14:00:00Z"},
    )
    assert r.status_code == 422
    assert "互斥" in r.json()["message"]


def test_absolute_window_rejects_inverted_range(replay_backend, client):
    r = client.post(
        "/tools/query_logs",
        json={
            "trace_id": "CHAIN-CASE-01",
            "time_start": "2026-10-27T15:00:00Z",
            "time_end": "2026-10-27T14:00:00Z",
        },
    )
    assert r.status_code == 422
