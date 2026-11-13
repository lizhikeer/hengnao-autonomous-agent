#!/usr/bin/env python3
"""一次性运维脚本：从 frpc-seclog.toml 中移除明文 HTTP 隧道段。

背景：`nas-seclog-http` 是阶段 2 验证连通性用的明文 18000 映射，
HTTPS 通道（18443）验证通过后应关闭，避免业务接口以明文暴露在公网。

用法（在容器内以 root 运行，挂载 /etc/frp 到 /hostfrp）：
    docker run --rm -v /etc/frp:/hostfrp python:3.11-slim \
        python /script.py

脚本会先备份，再按 `[[proxies]]` 分段过滤掉 name 命中目标的那一段，
最后保持文件权限 600（属主由调用方恢复）。
"""

from __future__ import annotations

import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("/hostfrp/frpc-seclog.toml")
DROP_NAME = "nas-seclog-http"


def main() -> int:
    if not TARGET.exists():
        print(f"[ERR] 配置不存在: {TARGET}", file=sys.stderr)
        return 1

    raw = TARGET.read_text(encoding="utf-8")
    # 必须精确匹配 `name = "xxx"`：`nas-seclog-https` 包含子串 `nas-seclog-http`，
    # 只用裸名字做 in 判断会把两条隧道一起删掉（第一次运行就踩了这个坑）
    marker = f'name = "{DROP_NAME}"'
    if marker not in raw:
        print(f"[SKIP] 配置里没有 {DROP_NAME}，无需处理")
        return 0

    backup = TARGET.with_suffix(f".toml.bak.{datetime.now():%Y%m%d%H%M}")
    shutil.copy2(TARGET, backup)
    print(f"[OK] 已备份: {backup.name}")

    blocks = raw.split("[[proxies]]")
    head, proxies = blocks[0], blocks[1:]
    kept = [b for b in proxies if marker not in b]
    dropped = len(proxies) - len(kept)

    TARGET.write_text(head + "".join("[[proxies]]" + b for b in kept), encoding="utf-8")
    print(f"[OK] 移除 {dropped} 段（{DROP_NAME}），保留 {len(kept)} 段")

    remaining = TARGET.read_text(encoding="utf-8")
    for line in remaining.splitlines():
        if line.startswith("name = "):
            print(f"     remaining proxy: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
