# 给其他 Agent 的提示词（可直接整段转发）

> 适用场景：你的任务需要访问 SecLog 的恒脑接入端点，或者需要复用那台国内 IPv4 中转机。
> 编写时间：2026-11-23 20:35（实测快照）

---

## 一、如果你是要调 SecLog 的接口，把下面这段给它

```
【环境事实，先读再动手】

你要访问的 SecLog 服务跑在一台家庭 NAS 上（无公网 IPv4），通过朋友的国内家宽 IPv4 中转机 + frp 隧道暴露。这条链路在 2026-11-23 20:28 刚修复并实测通过，当前可用。

唯一入口（不要尝试其他地址，不要自己找 IP）：
  Base URL: https://seclog.91666.icu:18443

四个可用端点：
  GET  /health                    健康检查，返回 mock_mode 字段
  POST /tools/query_logs          全链路日志查询
  POST /mcp/                      全量 MCP（streamable HTTP）
  POST /investigation/            只读调查 MCP

硬性约束（踩过的坑，别重复）：
1. 两个 MCP 端点【必须带尾斜杠】。/mcp 和 /investigation 会 307/404。
2. /tools/query_logs 【至少要给一个过滤条件】：src_ip / dest_ip / trace_id / log_source（非 "all"）。只给 limit 会返回 422，这是设计使然不是故障。
   最小可用请求体：{"case_id":"EVAL-CHAIN-001","trace_id":"CHAIN-ATTACK-01","limit":50}
3. 只支持 GET / POST，不要用 PUT/PATCH/DELETE。
4. 证书是 Let's Encrypt 正式证书，严格 TLS 校验能通过。如果你的代码需要关校验（-k / verify=False）才能连上，说明你的运行环境有问题（代理、CA 库或 SNI），不要把这个当成"服务端证书有问题"去排查链路。

数据现状（重要，避免误判）：
  当前 mock_mode = true。返回的是内置样本数据，不是 ClickHouse 实查。
  每个响应体的 meta 里有 mock / data_source / backend_available 标记，会如实说明。
  不要把 mock 结果当作真实告警上报，也不要去"修复"它——接真实后端是 @chensz-u 的任务（Issue #18）。

连不上时的 30 秒定位顺序：
1) dig +short A seclog.91666.icu    → 应返回 125.112.2.201（家宽 IP，会变）
2) 若解析正常但 18443 连不上，先测 nc -z 9188888.cn 7000
   - 7000 通、18443 不通 → 99% 是 NAS 上 frpc 掉线，不是平台配置问题，也不是朋友没放行
   - 7000 也不通 → 中转机那边下线了，需要人联系朋友
3) 不要反复重试或换 IP 猜测。把上面两条命令的输出发给 @lizhikeer 即可。

绝对不要做：
- 不要修改 NAS 上 /etc/frp/frpc-seclog.toml（尤其不要把 serverAddr 改成 IP，那正是这次断链的原因）
- 不要 docker rm / restart 任何 seclog-* 容器
- 不要重启 seclog-caddy（会中断在途的 ACME 续期与 TLS 服务）
- 不要动恒脑平台侧已配好的 URL 和请求头
```

---

## 二、如果你是要复用那台中转机开自己的隧道，把下面这段给它

```
【中转机使用说明】

这台机器是朋友的国内家宽（住宅宽带），不是云服务器。所有权不在我们这边，我们只有 frpc 客户端权限，没有 frps 配置权。

连接参数：
  frps 地址：9188888.cn        ← 永远用域名，绝对不要写 IP
  控制端口：7000
  传输：TCP + transport.tls
  认证：token（在 NAS 的 /etc/frp/frpc-seclog.toml 里，600 权限，需 root 或 docker 读）

为什么必须用域名：
  家宽是动态 IP，会变（已知从 125.112.0.13 变成 125.112.2.201，未来还会变）。
  A 记录由 NAS 上 cron 每 5 分钟同步一次（脚本 ~/seclog/scripts/ops/ddns_sync.py）。
  2026-11-23 那次全链路掉线，唯一原因就是某个 frpc 把旧 IP 写死了，一直 SYN-SENT。

端口分配：
  18443 已被 SecLog 占用（→ NAS 127.0.0.1:18443 的 Caddy）
  80 / 443 / 5667 / 8090 / 8443 / 15022 / 18080 是朋友自己的业务（443 和 5667 是他的 fnOS），别碰
  你要用新端口，先确认三件事：
    a) frps 侧 allowPorts 是否放行（目前是全开）
    b) 朋友的路由器是否把该端口转发进来（这个要人协调，我们改不了）
    c) 你自己的 frpc 用唯一的 proxy name，别和 nas-seclog-https 撞

一个容易误判的现象：
  frps 的 remotePort 是【懒监听】—— 没有客户端注册成功时，那个端口根本不 open。
  所以"端口连不上"不能推断成"对方没放行"。先确认你的 frpc 日志里有 start proxy success，再看端口。
```

---

## 三、如果你只是想知道"现在到底通不通"

一行命令：

```
curl -sS https://seclog.91666.icu:18443/health
```

返回 `{"status":"ok",...,"mock_mode":true}` 就是通的。
超时就是不通，按上面第一节的 30 秒定位顺序走，别自己猜。

---

## 四、当前遗留（不影响你用，但别误认为已完成）

| 项 | 状态 |
| :--- | :--- |
| API 真实后端（ClickHouse / Qdrant） | 未接，仍是 mock，归 `@chensz-u`（Issue #18） |
| BGE 权重 | 未下载 |
| Qdrant collection | 0 个 |
| 证书续期 reload hook | 未挂，续期后可能仍用旧证书（到期 2027-02-10，暂不紧急） |
