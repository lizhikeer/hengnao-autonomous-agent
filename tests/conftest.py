"""pytest 公共配置：把 ``src`` 加入导入路径，并在每个用例前清空证据登记表。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def _clean_evidence_registry():
    """证据登记表是进程内单例，用例之间必须隔离，否则会互相污染。"""
    from api.evidence_check import registry

    registry.clear()
    yield
    registry.clear()


@pytest.fixture(autouse=True)
def _isolate_backends(monkeypatch):
    """测试默认跑 Mock 后端。

    第一周的行为契约（mock 数据、固定时间基准）由 Mock 后端承载，保留这些回归用例的价值；
    第二周的真实数据接线由 ``test_w2_*`` 系列显式切换 ``SECLOG_DATA_SOURCE`` 验证。
    这样测试不依赖 ``data/full_chain_logs`` 是否存在的具体内容，也不会因为接上真实库而变红。
    """
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "mock")
    monkeypatch.setenv("SECLOG_SEARCH_MODE", "mock")
    from api import app as api_app

    api_app.reset_source_cache()
    yield
    api_app.reset_source_cache()


@pytest.fixture()
def replay_backend(monkeypatch):
    """切到数据集回放后端（读 data/full_chain_logs）。"""
    monkeypatch.setenv("SECLOG_DATA_SOURCE", "dataset_replay")
    from api import app as api_app

    api_app.reset_source_cache()
    yield
    api_app.reset_source_cache()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as c:
        yield c
