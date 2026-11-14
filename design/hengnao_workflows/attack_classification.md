# 攻击分类口径（首期七类）

> 代码：`src/ai_engine/attack_types.py`｜校验：`src/ai_engine/verify.py`｜测试：`tests/test_w2_classification.py`
>
> **状态：我方实现口径。** Issue #17 的正式枚举尚未交付，本文记录可追踪的暂定映射，定稿后只改 `attack_types.py` 一处。

## 依据

`docs/project design/database/知识库总体设计.md`：首批覆盖
**扫描、密码爆破、SQL 注入、XSS、遍历与越权、恶意上传、可疑外连**；
分类基准为 OWASP WSTG v4.2（4.1~4.11）+ MITRE ATT&CK 网络侧三类。

## 七类（结果分类，互不合并）

| 代码 | 中文 | MITRE | 判定特征（日志侧） |
| :--- | :--- | :--- | :--- |
| `Scan` | 扫描探测 | T1046 | dirsearch / nikto / nmap / robots.txt / `.git/` 等敏感路径探测 |
| `Brute_Force` | 密码爆破 | T1110 | hydra / 多次 auth_fail / 短时大量登录失败 |
| `SQL_Injection` | SQL 注入 | T1190 | `UNION SELECT` / `sleep(` / `information_schema` / sqlmap |
| `XSS` | 跨站脚本 | T1059.007 | `<script` / `onerror=` / `javascript:` / `alert(` |
| `Path_Traversal_Privilege` | 目录遍历与越权 | T1083, T1548 | `../` / `%2e%2e` / `/etc/passwd` / 越权访问 |
| `Malicious_Upload` | 恶意上传 | T1105 | `multipart/form-data` / `filename=` / webshell / `cmd=` |
| `C2_Exfiltration` | 可疑外连与数据外传 | TA0011, TA0010 | 固定外连 IP:端口 / beacon / 4444 / 大流量外发 |

另有两个非攻击取值：`insufficient_evidence`（证据不足）、`none`（无恶意行为）。

## 结果分类 → 知识卡分类（多对一，允许）

知识卡目前只有 5 个文件，与 7 类不是一一对应。**结果分类不因此合并**，只在检索时映射：

| 结果分类 | 知识卡 `attack_category` | 说明 |
| :--- | :--- | :--- |
| `Scan` | —（无卡） | 待 @Snowed-night 补卡；检索扫分类现象会零命中 |
| `Brute_Force` | `Brute_Force` | 一一对应 |
| `SQL_Injection` | `SQL_Injection` | 一一对应 |
| `XSS` | `XSS_RCE` | 卡片把 XSS 与 RCE 合并，结果分类不合并 |
| `Path_Traversal_Privilege` | `File_Upload_Traversal` | 卡片把遍历/越权与上传合并 |
| `Malicious_Upload` | `File_Upload_Traversal` | 同上 |
| `C2_Exfiltration` | `C2_Exfiltration` | 一一对应 |

`knowledge_category()` 取组合类型中最末阶段对应的知识卡分类，供 `search_knowledge` 的
`attack_category` 过滤使用。

## 组合格式

`attack_type` 允许多阶段，格式 `<后阶段>_After_<前阶段>`，按时间从左到右展开：

```
SQL_Injection_After_Brute_Force_After_Scan
C2_Exfiltration_After_Malicious_Upload_After_Scan
```

校验时逐段比对（`verify.py` 内联同一份枚举，测试断言两处一致）。

## 别名与历史兼容

| 输入 | 输出 | 性质 |
| :--- | :--- | :--- |
| `XSS_RCE` | `XSS` | 第二周初版合并类，历史兼容 |
| `File_Upload_Traversal` | `Malicious_Upload` | 复合旧值，无法唯一还原；若需遍历语义应按日志重判 |
| `C2_Callback` | `C2_Exfiltration` | 第一周旧值 |
| `Webshell` / `SQLi` / `Recon` / 中文名 | 对应类 | 常见别名 |

旧码仍在校验的兼容集合（`COMPAT_SEGMENTS`）里，用于放行历史产物；**新产出不再使用**。

## 风险分级

| 等级 | 判据 |
| :--- | :--- |
| CRITICAL | 外连阶段累计外发 ≥ 1MB（**确认数据外传**） |
| HIGH | 出现利用或外连（含心跳型 C2） |
| MEDIUM | 仅爆破/扫描，未进入利用 |
| LOW | 无攻击行为，且授权核对通过 |

## 与 truth 的差异（如实记录）

`data/full_chain_logs/*_truth.json` 中：
- `CHAIN-CASE-01` 为 `SQL_Injection_After_Brute_Force` —— 符合七类（缺侦察段）；
- `CHAIN-CASE-02` 为 `Webshell_Upload_And_C2_Callback` —— **不是七类取值**；
- `CHAIN-CASE-03` 为 `Normal_Maintenance_Operation` —— **不是七类取值**。

V1 评测时对后两者套用了**显式归一化规则**（写在 `tests/run_v1_traces.py` 的 `_TRUTH_RULES`，
并把 `truth_normalization_rule` 写进 trace），未修改 truth 文件本身。

## 待对齐项

1. **枚举定稿**：Issue #17 若采用不同命名，改 `attack_types.py` 即可；
2. **truth 口径**：建议队友按七类重写 `attack_type`，否则分类匹配依赖我方映射规则；
3. **扫描类知识卡**缺失；
4. **评测匹配策略**：精确相等过严（我方保留侦察段），建议以"覆盖"为主。
