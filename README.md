# flux

A multi-protocol proxy server written in Rust.

## Supported Protocols

| Protocol | Transport |
|---|---|
| Hysteria2 | QUIC + TLS |
| VLESS | plain TCP |
| VLESS | TCP + TLS |
| VLESS | WebSocket |
| VLESS | WebSocket + TLS |
| VLESS | **Reality** (new) |
| VLESS | **XHTTP** (TCP h1/h2, session 跨连接共享) |
| VLESS | **XHTTP + HTTP/3 (QUIC)** — 对齐 Xray `xhttp` + `alpn=h3` (new) |
| Spectre | QUIC + JLS + Brutal |

## Usage

```
flux -c config.toml
```

Default config path is `config.toml` in the current directory.

## Configuration

Only configure what you need. Omit a section entirely to disable that protocol — no `enable: false` required.

### Minimal examples

See the `configs/` directory for ready-to-use examples:

| File | Description |
|---|---|
| `configs/hysteria2-only.toml` | Hysteria2 only |
| `configs/vless-tls.toml` | VLESS + TLS |
| `configs/vless-ws.toml` | VLESS + WebSocket |
| `configs/vless-reality.toml` | VLESS + Reality |
| `configs/full.toml` | All protocols |

### 出口 IP（多公网 IP 服务器）

若服务器有多个公网 IP，可在任意协议节点（`wireguard` 除外）加上 `outbound_bind_ipv4` / `outbound_bind_ipv6` 指定出站时绑定的本地 IP：

```toml
[[node]]
tag                 = "us-1"
type                = "vless"
listen              = "0.0.0.0:8443"
uuid                = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
outbound_bind_ipv4  = "203.0.113.10"          # 可选
outbound_bind_ipv6  = "2001:db8::1"           # 可选
```

规则：

- **两者都不填**：使用系统默认路由，不受影响。
- **只填一个**：该节点所有出站流量都必须从这个 IP 走。若某个目标域名解析结果里没有对应地址族的记录（比如只填了 `outbound_bind_ipv6`，但目标域名只有 IPv4 记录），会拒绝该次连接（`info` 级别日志说明原因，不影响其他连接）。
- **两者都填**：按目标地址的地址族自动选择对应的出口 IP——访问 IPv4 网站走 `outbound_bind_ipv4`，访问 IPv6 网站走 `outbound_bind_ipv6`。

`outbound_bind_ipv4` / `outbound_bind_ipv6` 对应的 IP 必须已经配置在本机网卡上，否则连接会失败。

### Config reference

```toml
# Logging — optional, default: info
[log]
level = "info"   # trace | debug | info | warn | error

# Hysteria2 — omit section to disable
[hysteria2]
listen = "0.0.0.0:443"

[hysteria2.tls]
cert = "/path/to/cert.pem"        # omit both cert+key to auto-generate self-signed
key  = "/path/to/key.pem"
# self_signed_domain = "example.com"

[hysteria2.auth]
type     = "password"
password = "your-password"

# optional
[hysteria2.bandwidth]
up   = "1000 mbps"
down = "1000 mbps"

# VLESS — omit section to disable
[vless]
listen = "0.0.0.0:8443"
uuid   = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# transport defaults to plain TCP if omitted
[vless.transport]
type = "tcp"        # tcp | ws | reality
tls  = true         # ignored for type=reality

# TLS fields (for type=tcp/ws with tls=true)
cert               = "/path/to/cert.pem"
key                = "/path/to/key.pem"
self_signed_domain = "example.com"

# WebSocket fields (for type=ws)
ws_path = "/vless"
ws_host = "your.domain.com"   # optional

# Reality fields (for type=reality)
[vless.transport.reality]
private_key = "<base64 x25519 private key>"
public_key  = "<base64 x25519 public key>"
short_ids   = ["abcd1234", "ef567890"]
dest        = "example.com:443"
server_name = "example.com"
```

### Generating a Reality keypair

```bash
# Private key (base64)
openssl genpkey -algorithm x25519 2>/dev/null | openssl pkey -noout -text 2>&1 \
  | grep -A 3 "priv:" | tail -n +2 | tr -d ' :\n' | xxd -r -p | base64

# Public key (base64) — derive from the private key
# Use xray or any x25519 tool, e.g.:
#   xray x25519
```

### Spectre

QUIC + JLS 伪装 + Brutal 拥塞控制的自研协议（移植自 spectre 项目）。认证失败的
QUIC 握手被透明转发到 `upstream` 指向的真实站点，主动探测者看到的是一个正常
网站；通过 JLS 认证的客户端在控制流 AUTH 之后，每个代理目标开一条双向流
（TCP Connect / UDP Associate / Padding），UDP 走 QUIC datagram + 分片重组。
Brutal 的目标速率取客户端 AUTH 帧声明的下载速率（0 = 退回 BBR）。

```yaml
nodes:
  - name: sp-in
    type: spectre
    port: 4433
    password: your-strong-password   # JLS 密钥，须与客户端一致
    server-name: www.cloudflare.com  # SNI，须与客户端一致
    upstream: www.cloudflare.com:443 # 未认证流量转发到此，须支持 HTTP/3
    # 可选字段（括号内为默认值）：
    # username: spectre               # ("spectre") JLS 用户名；留空则不校验
    # obfs-psk: "at-least-4-bytes"    # Salamander 报文混淆 PSK，须与客户端一致
    # udp-timeout: 120s               # (120s) UDP 会话空闲超时
    # udp-relay-ipv6: false           # (false) 是否中继 IPv6 UDP
```

Spectre 节点同样支持通用的 `outbound-bind-ipv4` / `outbound-bind-ipv6` /
`outbound-socks5` 出站字段（TCP 与 UDP 出站均走统一出口）。

## Web 面板（-d 面板模式）

网页面板用于**节点在线情况、流量统计、历史连接 IP、节点的网页增删改**。用 Rust 实现（复用项目已有的 hyper），登录页 + 单文件响应式前端全部编译进二进制，不依赖任何外部 CDN。

面板模式与配置文件完全解耦：`flux -d /path` 启动，**不读任何 yaml**，一切数据落在 /path 目录：

| 文件 | 说明 |
|---|---|
| `flux.sqlite` | 加密数据库（AES-256-GCM 全量加密）：节点配置、面板设置、流量统计、连接记录、IP 聚合 |
| `flux.key` | 主密钥文件（自动生成，unix 权限 600）。**与 flux.sqlite 分开备份**，两者同时泄露才可解密 |

首次启动自动初始化：面板端口 **9080**，用户名 `admin`，**随机生成 16 位初始密码并只在终端打印一次**（不再使用公开已知的 admin/admin；忘记了用 `flux set-password` 重设，密码至少 8 位）。

```bash
flux -d /etc/flux                        # 启动面板模式，浏览器访问 http://<ip>:9080
flux set-user ops -d /etc/flux           # 修改登录用户名
flux set-password 'S3cret!' -d /etc/flux # 修改登录密码（数据库中只存 PBKDF2 哈希）
flux set-port 9443 -d /etc/flux          # 修改面板端口
```

面板「设置」页同样可改**用户名 / 密码 / 端口**；端口修改后监听器自动在新端口重新绑定，改用户名或密码后所有会话失效、强制重新登录。

命令行 `set-user` / `set-password` 可在服务运行时执行：登录时每次从数据库读取最新凭据，下次登录即生效（已登录的会话不会被踢下线）。`set-port` 需重启服务才会改监听端口。

### 纯配置模式（-c）

`flux -c xx.yaml` 只跑 `nodes` 里的节点：**不启动面板、不创建数据库**，配置文件只允许 `log-level` 与 `nodes` 两类顶层字段，多写 web / db 等字段会直接报错。适合无面板需求的纯代理场景。

### 加密说明

- 数据库中所有表值（节点凭据、连接记录含目标地址与 IP、统计聚合）均经 AES-256-GCM 加密落盘。
- 客户端 IP、节点名等表键以 HMAC-SHA256 哈希存储，明文不进键。
- 面板密码只存 PBKDF2-HMAC-SHA256（100k 迭代）哈希。

### 统计口径

- **在线**：节点当前存在活跃客户端连接即视为在线（绿点）；面板同时显示最近连接时间与累计连接数，便于区分「暂时空闲」和「无人使用」。
- **流量**：13 种入站协议全覆盖，分别统计上行（客户端→服务端）与下行（服务端→客户端）。TCP 类按中继字节数累计，QUIC / UDP 类按流或数据报累计（含少量协议开销）。
- **持久化**：连接记录、按小时桶、按月汇总、IP 聚合都写入加密 SQLite（WAL 模式）。后台每 5 秒批量落盘一次，不会在每次连接关闭时开写事务。
- **不会自动清理**：没有 retention、不会过期删除。面板「按月统计与数据清理」可清理指定月份，或清空全部历史数据（流量、连接记录、IP 统计）。

### 面板访问安全

- **防爆破（三层）**：①单 IP 15 分钟内失败 5 次即锁定，累犯时长翻倍（15 分钟 → … 上限 24 小时）；②全站 10 分钟内失败 60 次视为分布式爆破，进入 5 分钟全局冷却，期间仅放行近期成功登录过的 IP；③PBKDF2 校验在 blocking 线程池执行且并发上限 2，防止登录请求拖垮 CPU。
- 用户名错误与密码错误耗时一致（始终完整执行 PBKDF2），无法计时枚举用户名。
- 修改用户名 / 密码 / 端口必须提供**当前密码**，输错同样计入防爆破。
- 先鉴权再读请求体；登录请求体上限 4 KiB，其余接口 2 MiB；读体 15 秒超时、请求头 10 秒超时（防 slowloris）。
- 状态变更请求校验 `Origin` / `Sec-Fetch-Site`（叠加 SameSite=Lax），所有响应带 `X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy: no-referrer`、`Cache-Control: no-store` 等头。
- 环境变量：`FLUX_PANEL_HOST=127.0.0.1` 只监听本机（推荐配合 HTTPS 反代）；`FLUX_TRUST_PROXY=1` 信任反代的 `X-Forwarded-For/Host`（反代必须覆盖而非追加该头）；`FLUX_SECURE_COOKIE=1` 给会话 cookie 加 `Secure`。
- 锁定状态存于内存，重启清零；面板仍是明文 HTTP，公网访问务必放在 HTTPS 反代之后。

### 已知限制

- 同一协议配置多个节点时，深层中继里无法精确区分归属，流量会归到该协议的第一个节点；连接在线状态与连接记录仍按节点精确统计。
- `xhttp` 传输与 ShadowQuic 的上游库未向服务端暴露真实客户端地址，这些连接的历史 IP 显示为占位地址（`0.0.0.0`）。
- 面板是明文 HTTP，**不要直接暴露公网**；如需远程访问请置于 HTTPS 反向代理之后。
- `flux.key` 与运行目录权限即数据边界：能读 `/path/flux.key` 的账户即可解密 `flux.sqlite`。

## Build

```bash
cargo build --release
```

Binary: `target/release/flux`
