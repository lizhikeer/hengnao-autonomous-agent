# 知识库入库与混合检索

归属：`@Snowed-night`，对应 Issue #3。使用 small 编码、Qdrant 语义查询、SQLite FTS5/BM25 与服务端 RRF。

## 安装与模型

在仓库根目录使用 Python 3.12 环境。CPU 安装示例：

```powershell
uv venv --python 3.12
& .venv/Scripts/python.exe -m ensurepip
& .venv/Scripts/python.exe -m pip install torch==2.7.1 --index-url https://download.pytorch.org/whl/cpu
& .venv/Scripts/python.exe -m pip install -r requirements/knowledge.txt pytest ruff
& .venv/Scripts/python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-small-zh-v1.5', revision='7999e1d3359715c523056ef9478215996d62a620', local_dir='work/models/bge-small-zh-v1.5', allow_patterns=['*.json','*.txt','model.safetensors'])"
$env:BGE_MODEL_PATH = "$PWD/work/models/bge-small-zh-v1.5"
```

编码器只加载本地权重，正文不加前缀，问题加中文检索前缀，两者输出归一化的 512 维向量。按真实 tokenizer 分块，命中后恢复完整卡片与来源。模型 revision 或本地权重摘要写入 index_profile。

## 运行

```powershell
# 校验现有 20 张卡片和文件来源，不需要启动数据库或模型。
& .venv/Scripts/python.exe scripts/ingest_knowledge.py validate

# 离线开发：在本地目录建立两个 Qdrant 集合。
& .venv/Scripts/python.exe scripts/ingest_knowledge.py init --qdrant-path work/qdrant

# 默认导入为 pending，只存 SQLite。正式批准时由审核人执行下一条命令。
& .venv/Scripts/python.exe scripts/ingest_knowledge.py ingest --qdrant-path work/qdrant
& .venv/Scripts/python.exe scripts/ingest_knowledge.py ingest --qdrant-path work/qdrant --approve-by 审核人标识

& .venv/Scripts/python.exe scripts/ingest_knowledge.py search --qdrant-path work/qdrant --query "UNION SELECT 返回200，应怎样调查"
& .venv/Scripts/python.exe scripts/ingest_knowledge.py withdraw --qdrant-path work/qdrant --card-id KB-SQLI-001 --approve-by 审核人标识 --reason "内容已失效"
```

服务部署省略 `--qdrant-path`，使用 `QDRANT_URL/QDRANT_API_KEY`；镜像需包含 src/、design/knowledge/ 与相应依赖，模型和 SQLite 路径通过配置挂载。本地模式使用真实 Qdrant Local 存储；Payload 索引在 Qdrant 服务模式创建。已有集合的维度或距离不兼容时停止初始化，保留已有数据。

## 卡片与来源契约

- `design/knowledge/legacy-card.schema.json`：兼容现有首周知识卡，规范化为 1.0；补租户、版本和时间元数据，保留原有调查内容。
- `design/knowledge/card.schema.json`：1.1 完整知识卡与案例卡，检查规则、来源和证据之间的引用及证据摘录哈希。
- JSON 接受单张卡或数组。Markdown 接受 JSON 代码块，或 YAML 元数据加正文；正文作为 summary。
- `data/knowledge_cards/manifest.json` 是维护者管理的文件白名单，记录 SHA-256、卡片编号、租户和数据划分。修改文件后须核对来源并更新摘要。案例还校验场景编号及排除清单；独立评测文件不加入白名单。
- 普通导入不信任文件自行声明的 approved。`--approve-by` 是管理端的明确审核操作，不向 Agent 注册。案例还必须具备实验或人工确认记录。

新增卡片按源内容类型选择 1.0 或 1.1；1.0 仅兼容知识卡，案例使用 1.1。相同卡片版本可重试；同版本正文改变时要求增加 version。

同租户、同类型的相同内容使用不同编号再次导入时，返回 duplicate 与原编号，保留原审核状态。重复导入可重试失败索引；旧点清理失败返回 cleanup_pending，新发布版本正常可用，下次导入继续清理。

## 供 API/MCP 调用

```python
from src.knowledge.search import hybrid_search

items = hybrid_search("密码爆破后如何查证", top_k=5, filters={"attack_category": "Brute_Force"})
```

保留基础设施约定的函数签名。`filters` 支持 attack_category、log_sources、exclude_investigation_id、exclude_scenario_ids；tenant_id 只允许与后台配置相同。范围由接口负责人根据认证上下文传入。返回原卡片字段、版本、完整调查步骤、来源、匹配章节与 RRF 排名分；score 是归一化排名分，不是结论正确概率。

复用实例时使用 `KnowledgeService`，每个实例串行调用并在结束时 close。当前 API/MCP 路由仍由接口负责人接线，本模块不修改其 Mock 路由。

## 配置与验证

配置：`BGE_MODEL_PATH`、`KNOWLEDGE_TENANT_ID`、`KNOWLEDGE_SQLITE_PATH`、`QDRANT_LOCAL_PATH`，以及既有的 `QDRANT_URL/QDRANT_API_KEY/QDRANT_KNOWLEDGE_COLLECTION/QDRANT_CASE_COLLECTION`。

```powershell
& .venv/Scripts/python.exe -m pytest src/knowledge/tests -q
& .venv/Scripts/python.exe -m ruff check --config src/knowledge/ruff.toml src/knowledge src/memory/knowledge_store.py scripts/ingest_knowledge.py
```

设置 BGE_MODEL_PATH 后会执行真实 small 编码和混合检索测试；未设置时明确跳过此项。其他用例使用标记为 test-only 的人工向量验证审核、隔离、版本、故障和关键词查询。测试库全部位于临时目录，批准测试副本不更改源卡片状态。
