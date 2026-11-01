"""detection 包的对外入口。

外部模块可以从这里导入规则引擎和异常事件生成器。
"""

from .anomaly_builder import AnomalyEventBuilder
from .rules import RuleEngine, detect_batch

# __all__ 表示这个包希望公开给外部使用的名字。
__all__ = ["AnomalyEventBuilder", "RuleEngine", "detect_batch"]
