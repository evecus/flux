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

## Web 面板

可选的网页面板，用于查看**节点在线情况、流量统计、历史连接 IP**。用 Rust 实现（复用项目已有的 hyper），登录页 + 单文件响应式前端全部编译进二进制，不依赖任何外部 CDN。

在配置文件**顶层**（与 `log-level` / `nodes` 平级）添加：

```yaml
web: true                         # 默认 false
web-bind: 127.0.0.1:9080         # 默认值
web-auth: admin:your-password    # web: true 时必填，登录页用户名:密码
db: flux.db                      # 省略 = 配置文件同目录下的 flux.db
```

浏览器访问 `http://127.0.0.1:9080`，用 `web-auth` 的用户名密码登录（会话 Cookie，24 小时有效）。

### 开关语义

| | `web: false`（默认） | `web: true` |
|---|---|---|
| HTTP 监听 | 不启动 | 启动于 `web-bind` |
| 统计收集 | **完全关闭**，埋点只是一次空指针判断 | 开启 |
| redb 数据库 | **不创建、不打开、不触碰磁盘** | 打开/创建 `db` 指定文件 |

即：不开面板时不会有任何额外磁盘写入，代理路径与性能不受影响。

### 路径与 `-d`

- `-d /path`：自动在该目录寻找 `*.yaml` / `*.yml`，优先 `config.yaml` → `config.yml` → 字典序第一个；存在多个且无法唯一确定时报错，请用 `-c` 明确指定。
- 配置文件里的 **`cert` / `key` 相对路径**以及 **`db` 相对路径**，一律相对**配置文件所在目录**解析；使用 `-d /path` 时即 `/path`。省略 `db` 时默认落在该目录的 `flux.db`。
- 证书相对路径示例：`cert: certs/fullchain.pem` + `-d /etc/flux` → `/etc/flux/certs/fullchain.pem`。

### 统计口径

- **在线**：节点当前存在活跃客户端连接即视为在线（绿点）；面板同时显示最近连接时间与累计连接数，便于区分「暂时空闲」和「无人使用」。
- **流量**：13 种入站协议全覆盖，分别统计上行（客户端→服务端）与下行（服务端→客户端）。TCP 类按中继字节数累计，QUIC / UDP 类按流或数据报累计（含少量协议开销）。
- **持久化**：连接记录、按小时桶、按月汇总、IP 聚合都写入 redb。后台每 5 秒批量落盘一次，不会在每次连接关闭时开写事务。
- **不会自动清理**：没有 retention、不会过期删除。面板「按月统计与数据清理」可清理指定月份，或清空全部历史数据（流量、连接记录、IP 统计）。

### 已知限制

- 同一协议配置多个节点时，深层中继里无法精确区分归属，流量会归到该协议的第一个节点；连接在线状态与连接记录仍按节点精确统计。
- `xhttp` 传输与 ShadowQuic 的上游库未向服务端暴露真实客户端地址，这些连接的历史 IP 显示为占位地址（`0.0.0.0`）。
- 面板是明文 HTTP + Basic 风格凭据，**不要直接监听公网地址**；如需远程访问请置于 HTTPS 反向代理之后。

## Build

```bash
cargo build --release
```

Binary: `target/release/flux`
