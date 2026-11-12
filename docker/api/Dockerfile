# SecLog FastAPI / MCP 服务镜像
# 保持精简：只装运行时依赖，不带测试与开发工具
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 国内构建走清华源；如需切换，构建时传 --build-arg PIP_INDEX_URL=...
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

COPY requirements/base.txt requirements/api.txt /app/requirements/

RUN pip install -i "${PIP_INDEX_URL}" -r /app/requirements/base.txt \
 && pip install -i "${PIP_INDEX_URL}" -r /app/requirements/api.txt

COPY src/ /app/src/

# 非 root 运行
RUN useradd --create-home --uid 10001 seclog && chown -R seclog:seclog /app
USER seclog

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

# 同时挂载 REST 与 MCP：
#   /            REST（src/api/app.py，由 @chensz-u 提供）
#   /mcp/        MCP 全量工具（注意尾部斜杠，Starlette Mount + streamable_http_path="/"）
#   /investigation/  仅只读调查工具，处置工具由审批后的节点单独调用
# service.py 用 `from api.app import ...` 这种以 src/ 为根的导入，所以两个路径都要进 PYTHONPATH：
#   /app      → 供 `src.api.service` 被 uvicorn 解析
#   /app/src  → 供 service.py 内部的 `from api.app` / `from mcp_server.server` 解析
ENV PYTHONPATH=/app:/app/src

CMD ["uvicorn", "src.api.service:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
