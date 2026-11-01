"""Agent 侧契约与调查控制逻辑（Week 1 骨架）。

* ``results_schema``：Agent 结束节点结构化输出契约（11 字段）+ 正式 JSON Schema。
* ``investigation``：多轮自主调查会话骨架，按工具返回决定下一步（非固定串行）。
"""

__all__ = ["results_schema", "investigation"]
