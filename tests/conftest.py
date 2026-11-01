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


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from api.app import app

    with TestClient(app) as c:
        yield c
