# src/knowledge/ —— 知识库与向量检索层

**归属：`@Snowed-night`**

职责：Qdrant 集合管理、BGE 中文向量化、语义 + 关键词混合检索、知识卡入库管线。

## 边界

| 允许 | 禁止 |
| :--- | :--- |
| 读写 Qdrant（`security_knowledge` / `verified_cases`） | 直接查询 ClickHouse 日志事实表 |
| 定义知识卡 / 案例卡的检索 Schema | 存放评测集标准答案（必须与检索库物理隔离） |

## 规划中的接口（W1 仅冻结签名，W2 实现）

```python
# src/knowledge/search.py
def hybrid_search(query: str, *, top_k: int = 5, filters: dict | None = None) -> list[dict]: ...
```

配置项见 `src/config.py`：`QDRANT_URL`、`QDRANT_KNOWLEDGE_COLLECTION`、`QDRANT_CASE_COLLECTION`。
