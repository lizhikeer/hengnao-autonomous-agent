# 原始日志样本（W1 交付）

本目录是 **真实采集** 的原始日志，供 `@ribbonfish-jun` 编写统一 Schema 清洗脚本使用。
不是手工拼接的假数据——所有内容都来自实际运行的服务与真实抓包。

| 文件 | 来源 | 采集方式 |
| :--- | :--- | :--- |
| `nginx_access/access.log` | Nginx `nginx:alpine` 容器，`combined` 格式 | `scripts/sample_env/capture_traffic.sh` 用 curl 打真实请求，含正常业务与完整攻击链 |
| `auth/auth_sample.log` | 部署机 `/var/log/auth.log`（sshd） | 通过容器只读挂载宿主 `/var/log` 提取，取最近 400 行 sshd 记录 |
| `zeek/conn.log`、`zeek/http.log` | 由 `seclog-sample.pcap` 解析而来 | 见下方「关于 Zeek 产物」 |

采集时间：2026-11-01　采集人：`@lizhikeer`

---

## 一、Nginx 访问日志

26 行，覆盖 6 种状态码与 4 个攻击阶段：

| 阶段 | 特征 | 样例 |
| :--- | :--- | :--- |
| 正常业务 | Chrome / Safari UA，200 | `GET /`、`GET /api/user?id=1` |
| recon | `sqlmap/1.7.2` UA，探测 `/.env` `/.git/config` `/wp-admin/` `/phpmyadmin/` | 返回 404 / 403 |
| brute_force | `python-requests/2.31.0`，连续 POST `/admin/login.php` | 返回 401 |
| exploitation | SQLi payload `password=' OR 1=1--`、`UNION SELECT` | 返回 200 |
| webshell | `POST /uploads/shell.php` 写入后 `GET ?c=id` | 返回 200 |

**注意**：`src_ip` 是 `172.17.0.1`（Docker bridge 网关），因为请求从宿主机发往容器。
清洗脚本应通过 `asset_id` 台账反查真实资产 IP，不要直接把这个网关地址当攻击源。

## 二、认证日志

400 行 sshd 记录，**82 次成功登录、0 次失败**——这台机器只允许密钥登录，公网爆破在 sshd 层就被拒绝了，
所以没有任何 `Failed password`。这意味着：

- 这份样本**不足以**验证「爆破检测规则」，`@ribbonfish-jun` 需要自行构造带失败记录的补充样本，
  或在 `attack_stage_hint = brute_force` 的标注上参考 Nginx 日志里的爆破段；
- 好处是它真实反映了「只有成功登录」这一常见运维场景，可以用来验证规则不会误报。

时间格式是 RFC3339（`2026-11-02T00:33:19.239043+08:00`），不是传统 syslog 的 `Nov  1 23:52:01`，
因为这是 systemd journal 转发的格式。清洗脚本要按 RFC3339 解析，不要只写死 `%b %d`。

### 脱敏说明

原始日志含真实的家宽 IPv6 与用户名，本仓库为 **public**，已做替换：

| 原始 | 替换为 |
| :--- | :--- |
| 真实 IPv6（`2409:...`） | `2001:db8::1`（RFC 3849 文档保留段） |
| 用户名 `lzk` | `ops` |
| 主机名 | `nas-host-01` |

其余字段（时间、PID、事件类型、消息结构）保持原样。

## 三、Zeek 日志

由 **Zeek 6.x**（`zeek/zeek:lts`）解析 `seclog-sample.pcap` 产出：

```bash
docker run --rm \
    -v /vol4/seclog/samples/pcap:/pcap:ro \
    -v /vol4/seclog/samples/zeek:/out \
    zeek/zeek:lts zeek -C -r /pcap/seclog-sample.pcap Log::default_logdir=/out
```

- `conn.log`：25 条连接，带真实状态机（`conn_state`、`history` 如 `ShADTadtFf`）
- `http.log`：25 条 HTTP 请求，覆盖正常业务与 4 个攻击阶段（10 条命中攻击特征）
- `-C` 关闭校验和校验：抓包在容器虚拟网卡上进行，校验和可能未被卸载，不关会丢包

**清洗脚本必须按 `#fields` 表头解析，不要按列序号硬编码**——Zeek 版本升级会增删字段。

### 备用方案（镜像不可用时）

`scripts/sample_env/pcap_to_zeek.py` 是纯标准库的等价解析器。本项目部署机拉 `zeek/zeek` 镜像
曾连续失败 30 分钟（Docker Hub 直连 EOF、国内加速源反复中断在 25MB），最终用了 12 分 48 秒才拉通。
在离线或网络受限环境可先用它兜底。

它与真 Zeek 的差异（写清洗脚本时注意）：

| 项目 | `pcap_to_zeek.py` | 真 Zeek |
| :--- | :--- | :--- |
| `conn_state` | 简化判定（SF / S1 / RSTO） | 完整状态机（含 S0、REJ、RSTR 等） |
| `history` | 固定 `ShADadFf` | 逐包真实标记 |
| `uid` | 确定性派生（`C` + 6 位） | 随机 17 字符 |
| 额外日志 | 无 | `files.log` 等 |

## 四、如何重新生成

```bash
# 1. 采集（需要 nginx:alpine 与 python:3.11-slim 镜像）
cd ~/seclog
CAPTURE_SECONDS=35 SAMPLE_NGINX_PORT=18081 ./scripts/sample_env/capture_traffic.sh

# 2. 用 Zeek 解析 PCAP（主路径）
docker run --rm -v /vol4/seclog/samples/pcap:/pcap:ro -v /vol4/seclog/samples/zeek:/out \
    zeek/zeek:lts zeek -C -r /pcap/seclog-sample.pcap Log::default_logdir=/out

# 3. 备选：Zeek 镜像不可用时的标准库解析器
python3 scripts/sample_env/pcap_to_zeek.py \
    --pcap /vol4/seclog/samples/pcap/seclog-sample.pcap \
    --outdir /vol4/seclog/samples/zeek
```

**端口注意**：`18080` 已被宿主机其他服务占用，样本站点固定用 `18081`。
