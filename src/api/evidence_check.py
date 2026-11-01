"""程序化证据校验：Agent 引用的 log_id 必须由本次调查真实查询返回。

设计要点（对应 Issue #4 第 6 条要求）
------------------------------------
1. **拒绝伪造**：任何从未被 ``/tools/query_logs`` 返回过的 log_id 一律拒绝，
   模型无法凭空写出一个看起来合理的编号来"造证据"。
2. **拒绝跨任务引用**：以 ``case_id`` 查询得到的证据登记在该 case 私有桶中，
   另一个 case 提交处置时引用它会被判为 ``foreign`` 并拒绝。
3. 未携带 case_id 的查询只返回数据，不登记可供处置引用的证据。
4. **只登记、不判定**：本模块只回答"这个编号是不是本次调查查到的"，
   不做恶意/良性判断——那是模型与评测脚本的职责。
5. **无副作用**：登记表驻留内存，进程重启即清空；不写数据库、不发通知。

并发说明：恒脑云端可能并发调用多个工具，登记与校验都在锁内完成。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

#: 保留旧共享桶名称作为拒绝登记的保留值；无 case_id 的查询不登记证据。
UNSCOPED_BUCKET = "__unscoped__"


@dataclass(frozen=True)
class EvidenceRecord:
    """一条已登记证据的溯源信息（供审计与调试）。"""

    log_id: str
    case_id: str | None
    bucket: str
    registered_at: float
    query_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceCheckResult:
    """一次证据校验的结果。"""

    ok: bool
    accepted: list[str] = field(default_factory=list)
    #: 从未被任何查询返回过的编号（伪造嫌疑）
    unknown: list[str] = field(default_factory=list)
    #: 属于其它 case 私有桶的编号（跨任务引用）
    foreign: list[str] = field(default_factory=list)


class EvidenceRegistry:
    """按 case 隔离的证据登记表。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # bucket -> log_id -> record
        self._buckets: dict[str, dict[str, EvidenceRecord]] = {}

    # -- 写入 ---------------------------------------------------------------

    def register(
        self,
        log_ids: Iterable[str],
        *,
        case_id: str | None = None,
        query_params: dict[str, Any] | None = None,
    ) -> int:
        """登记一次查询返回的证据编号，返回新登记条数。"""
        if not case_id or not case_id.strip() or case_id == UNSCOPED_BUCKET:
            return 0
        bucket = case_id
        params = dict(query_params or {})
        now = time.time()
        added = 0
        with self._lock:
            store = self._buckets.setdefault(bucket, {})
            for log_id in log_ids:
                if not log_id:
                    continue
                if log_id in store:
                    continue
                store[log_id] = EvidenceRecord(
                    log_id=log_id,
                    case_id=case_id,
                    bucket=bucket,
                    registered_at=now,
                    query_params=params,
                )
                added += 1
        return added

    # -- 读取 ---------------------------------------------------------------

    def _lookup_bucket(self, log_id: str) -> str | None:
        for bucket, store in self._buckets.items():
            if log_id in store:
                return bucket
        return None

    def check(self, log_ids: Iterable[str], *, case_id: str) -> EvidenceCheckResult:
        """校验一组证据编号是否属于 ``case_id`` 本次调查。

        接受：本 case 私有桶中的编号。
        拒绝：从未登记过的编号（unknown）、其它 case 私有桶中的编号（foreign）。
        """
        bucket = case_id or UNSCOPED_BUCKET
        accepted: list[str] = []
        unknown: list[str] = []
        foreign: list[str] = []
        with self._lock:
            own = self._buckets.get(bucket, {})
            all_buckets = {b: dict(s) for b, s in self._buckets.items()}
        for log_id in log_ids:
            if case_id and case_id != UNSCOPED_BUCKET and log_id in own:
                accepted.append(log_id)
                continue
            owner = next((b for b, s in all_buckets.items() if log_id in s), None)
            if owner is None:
                unknown.append(log_id)
            else:
                foreign.append(log_id)
        return EvidenceCheckResult(
            ok=not unknown and not foreign,
            accepted=accepted,
            unknown=unknown,
            foreign=foreign,
        )

    def snapshot(self, *, case_id: str) -> list[EvidenceRecord]:
        """返回该 case 当前可引用的全部证据（仅本 case）。"""
        bucket = case_id or UNSCOPED_BUCKET
        with self._lock:
            records = list(self._buckets.get(bucket, {}).values())
        return sorted(records, key=lambda r: r.log_id)

    def known_log_ids(self, *, case_id: str) -> set[str]:
        return {r.log_id for r in self.snapshot(case_id=case_id)}

    # -- 维护 ---------------------------------------------------------------

    def clear(self) -> None:
        """清空全部登记（仅供测试与本地调试）。"""
        with self._lock:
            self._buckets.clear()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {bucket: len(store) for bucket, store in self._buckets.items()}


#: 进程内单例。FastAPI 与 MCP 服务共用同一份登记表。
registry = EvidenceRegistry()
