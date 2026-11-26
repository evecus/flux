//! 节点管理器（`-d` 面板模式专用，数据库为唯一真源）。
//!
//! 节点配置保存在加密数据库的 `nodes` 表里。新增 / 编辑 / 删除节点时：
//! 校验 → 写数据库 → 停旧任务 → 启新任务，其它节点不受影响。
//! 删除节点时同步从统计表移除，避免统计串位。

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

use crate::config::{self, NetLayer, NodeConfig};
use crate::stats::{NodeInfo, Stats};

/// 一个运行中的节点句柄。
struct RunningNode {
    task: JoinHandle<()>,
    proto: String,
    listen: String,
    port: u16,
}

struct ManagerState {
    /// name → 运行中句柄
    running: HashMap<String, RunningNode>,
}

pub struct NodeManager {
    state: Mutex<ManagerState>,
    /// 数据库目录（节点内相对路径以此为基准解析）。
    base_dir: std::path::PathBuf,
    stats: Arc<Stats>,
}

/// 从节点 JSON 中剔除所有 null 值字段（递归），保证入库内容干净。
fn strip_nulls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|_, val| !val.is_null());
            for val in m.values_mut() {
                strip_nulls(val);
            }
        }
        Value::Array(a) => {
            for val in a.iter_mut() {
                strip_nulls(val);
            }
        }
        _ => {}
    }
}

impl NodeManager {
    pub fn new(base_dir: std::path::PathBuf, stats: Arc<Stats>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ManagerState {
                running: HashMap::new(),
            }),
            base_dir,
            stats,
        })
    }

    fn db(&self) -> &crate::stats::db::Db {
        &self.stats.db
    }

    /// 启动时从数据库加载全部节点并逐个运行。
    pub fn start_all(self: &Arc<Self>) {
        let nodes = self.list_details();
        for mut decl in nodes {
            let name = decl.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if let Err(e) = self.resolve_cert_ref(&mut decl) {
                tracing::error!("[manager] skip node `{name}`: cert-ref resolve: {e:#}");
                continue;
            }
            let raw: NodeConfig = match serde_json::from_value(decl.clone()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("[manager] skip invalid node `{name}`: {e:#}");
                    continue;
                }
            };
            self.launch(raw);
        }
    }

    /// 列出全部节点的声明配置（供前端编辑表单回填）。
    pub fn list_details(&self) -> Vec<Value> {
        match self.list_nodes_blocking() {
            Ok(rows) => rows.into_iter().map(|(_, v)| v).collect(),
            Err(e) => {
                tracing::error!("[manager] list nodes: {e:#}");
                Vec::new()
            }
        }
    }

    fn list_nodes_blocking(&self) -> Result<Vec<(String, Value)>> {
        let db = Arc::clone(&self.stats.db);
        // NodeManager 的方法多为同步上下文调用；这里直接调用（SQLite 快路径，
        // 与刷盘任务写事务由 SQLite 串行化）。
        db.list_nodes()
    }

    /// 新增节点。`value` 为前端提交（kebab-case 字段）的完整节点 JSON。
    pub async fn add_node(&self, value: Value) -> Result<Value> {
        let mut decl_node = value;
        strip_nulls(&mut decl_node);
        self.resolve_cert_ref(&mut decl_node)?;

        let raw: NodeConfig =
            serde_json::from_value(decl_node.clone()).context("invalid node config")?;
        let name = raw.name.clone();
        if name.trim().is_empty() {
            bail!("node name must not be empty");
        }

        // 校验并派生（相对路径解析 + finalize），拿到运行所需信息。
        let mut runnable = raw.clone();
        let info = self.validate(&mut runnable)?;

        self.check_port_available(&name, info.port, runnable.inner.layer(), None)?;

        // 写数据库 → 启动运行副本。
        {
            if self.db().get_node(&name)?.is_some() {
                bail!("duplicate node name `{name}`");
            }
            self.db().put_node(&name, &decl_node)?;
        }
        self.launch_with_info(runnable, info.clone());
        Ok(serde_json::json!({ "ok": true, "name": name }))
    }

    /// 编辑节点。`old_name` 定位旧节点，value 为新配置（name 可改）。
    pub async fn update_node(&self, old_name: &str, value: Value) -> Result<Value> {
        let mut decl_node = value;
        strip_nulls(&mut decl_node);
        self.resolve_cert_ref(&mut decl_node)?;

        let raw: NodeConfig =
            serde_json::from_value(decl_node.clone()).context("invalid node config")?;
        let new_name = raw.name.clone();
        if new_name.trim().is_empty() {
            bail!("node name must not be empty");
        }

        let mut runnable = raw.clone();
        let info = self.validate(&mut runnable)?;

        self.check_port_available(&new_name, info.port, runnable.inner.layer(), Some(old_name))?;

        {
            if new_name != old_name && self.db().get_node(&new_name)?.is_some() {
                bail!("duplicate node name `{new_name}`");
            }
            if self.db().get_node(old_name)?.is_none() {
                bail!("node `{old_name}` not found");
            }
            if new_name != old_name {
                self.db().delete_node(old_name)?;
            }
            self.db().put_node(&new_name, &decl_node)?;
        }

        // 停旧启新。
        self.stop(old_name).await;
        self.launch_with_info(runnable, info);
        Ok(serde_json::json!({ "ok": true, "name": new_name }))
    }

    /// 删除节点。
    pub async fn delete_node(&self, name: &str) -> Result<Value> {
        {
            if self.db().get_node(name)?.is_none() {
                bail!("node `{name}` not found");
            }
            self.db().delete_node(name)?;
        }
        self.stop(name).await;
        Ok(serde_json::json!({ "ok": true }))
    }

    // ── SSL 证书（cert-ref 解析 + 面板证书管理）────────────────────────────

    /// 把节点声明中的 `cert-ref: <证书id>` 解析为具体文件路径：
    /// 从数据库取证书记录 → 写出 PEM 文件 → 填充 `cert`/`key`/`cert-domain`
    /// 字段 → 删除 `cert-ref`。之后节点配置走既有的 cert/key 文件机制，
    /// 13 个协议模块无需感知证书来源。
    pub fn resolve_cert_ref(&self, decl: &mut Value) -> Result<()> {
        let Some(id) = decl.get("cert-ref").and_then(|v| v.as_str()).map(|s| s.to_string())
        else {
            return Ok(());
        };
        if id.is_empty() {
            // 空串 = 用户在下拉里选了「手动填写」，直接移除。
            if let Some(obj) = decl.as_object_mut() {
                obj.remove("cert-ref");
            }
            return Ok(());
        }
        let rec = self
            .db()
            .get_cert(&id)?
            .ok_or_else(|| anyhow::anyhow!("引用的证书 `{id}` 不存在"))?;
        if rec["status"].as_str() != Some("active") {
            bail!(
                "引用的证书 `{id}` 尚未就绪（状态 {}），请先在 SSL 证书页完成申请",
                rec["status"].as_str().unwrap_or("?")
            );
        }
        crate::acme::write_pem_files(&self.base_dir, &id, &rec)?;
        let crt = self.base_dir.join("certs").join(format!("{id}.crt"));
        let key = self.base_dir.join("certs").join(format!("{id}.key"));
        let obj = decl
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("node decl is not an object"))?;
        obj.insert("cert".into(), Value::String(crt.to_string_lossy().into_owned()));
        obj.insert("key".into(), Value::String(key.to_string_lossy().into_owned()));
        if let Some(d) = rec["domains"].as_array().and_then(|a| a.first()) {
            obj.insert("cert-domain".into(), d.clone());
        }
        obj.remove("cert-ref");
        Ok(())
    }

    /// 列出全部证书记录。
    pub fn list_certs(&self) -> Result<Vec<Value>> {
        Ok(self
            .db()
            .list_certs()?
            .into_iter()
            .map(|(id, mut rec)| {
                if rec.get("key-pem").is_some() {
                    rec["key-pem"] = Value::Null; // 私钥不回传前端
                }
                rec["id"] = Value::String(id);
                rec
            })
            .collect())
    }

    /// 新建证书记录并启动后台申请任务。返回记录 id。
    pub fn create_cert(
        self: &Arc<Self>,
        domains: Vec<String>,
        email: &str,
        cf_token: &str,
        zone_id: &str,
        auto_renew: bool,
    ) -> Result<String> {
        if domains.is_empty() {
            bail!("至少填写一个域名");
        }
        if email.trim().is_empty() {
            bail!("邮箱不能为空");
        }
        if cf_token.trim().is_empty() {
            bail!("Cloudflare API Token 不能为空");
        }
        let id = crate::config::gen_uuid();
        let rec = serde_json::json!({
            "id": id,
            "domains": domains,
            "email": email.trim(),
            "cf-token": cf_token.trim(),
            "zone-id": zone_id.trim(),
            "auto-renew": auto_renew,
            "status": "pending",
            "error": "",
        });
        self.db().put_cert(&id, &rec)?;
        self.spawn_issue(&id);
        Ok(id)
    }

    /// 触发重新申请/续签（后台执行）。
    pub fn reissue_cert(self: &Arc<Self>, id: &str) -> Result<()> {
        if self.db().get_cert(id)?.is_none() {
            bail!("证书 `{id}` 不存在");
        }
        self.spawn_issue(id);
        Ok(())
    }

    /// 删除证书记录与 PEM 文件；被节点引用时拒绝删除。
    pub fn delete_cert(&self, id: &str) -> Result<()> {
        for (name, decl) in self.list_nodes_blocking()? {
            if decl.get("cert-ref").and_then(|v| v.as_str()) == Some(id) {
                bail!("证书正被节点 `{name}` 引用，请先解除引用或删除该节点");
            }
        }
        self.db().delete_cert(id)?;
        for ext in ["crt", "key"] {
            let _ = std::fs::remove_file(self.base_dir.join("certs").join(format!("{id}.{ext}")));
        }
        Ok(())
    }

    /// 后台跑一次 ACME 申请；成功后热重载引用该证书的节点。
    fn spawn_issue(self: &Arc<Self>, id: &str) {
        let id = id.to_string();
        let db = Arc::clone(&self.stats.db);
        let dir = self.base_dir.clone();
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = crate::acme::run_issue(db, &id, &dir).await {
                tracing::error!("[acme] issue task `{id}`: {e:#}");
                return;
            }
            mgr.reload_nodes_using_cert(&id);
        });
    }

    /// 热重载所有引用指定证书的节点（续签后加载新证书文件）。
    pub fn reload_nodes_using_cert(self: &Arc<Self>, cert_id: &str) {
        let names: Vec<String> = self
            .list_nodes_blocking()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, decl)| decl.get("cert-ref").and_then(|v| v.as_str()) == Some(cert_id))
            .map(|(name, _)| name)
            .collect();
        if names.is_empty() {
            return;
        }
        tracing::info!("[manager] 证书 {cert_id} 已更新，重载节点: {names:?}");
        for name in names {
            // 停旧 → 从库取最新声明 → 重启。
            let db_decl = self.list_nodes_blocking().ok().and_then(|rows| {
                rows.into_iter().find(|(n, _)| n == &name).map(|(_, v)| v)
            });
            let Some(mut decl) = db_decl else { continue };
            if self.resolve_cert_ref(&mut decl).is_err() {
                continue;
            }
            let Ok(node) = serde_json::from_value::<NodeConfig>(decl) else { continue };
            let mgr = Arc::clone(self);
            tokio::spawn(async move {
                mgr.stop(&name).await;
                // 先在 clone 上算统计信息，再把 node 所有权交给 launch_with_info。
                let info = {
                    let mut n = node.clone();
                    mgr.validate(&mut n)
                        .unwrap_or_else(|_| crate::stats::NodeInfo {
                            name: name.clone(),
                            proto: name.clone(),
                            listen: "::".into(),
                            port: 0,
                        })
                };
                mgr.launch_with_info(node, info);
            });
        }
    }

    // ── 面板设置 ────────────────────────────────────────────────────────────

    /// 面板设置（用户名 / 端口回填；密码只回传是否已设置）。
    pub fn panel_settings(&self) -> Result<crate::stats::db::PanelSettings> {
        self.db().panel_settings()
    }

    /// 修改登录用户名。
    pub fn set_user(&self, user: &str) -> Result<()> {
        if user.trim().is_empty() {
            bail!("用户名不能为空");
        }
        self.db().set_panel_user(user.trim())
    }

    /// 修改登录密码（写 PBKDF2 哈希，不存明文）。
    pub fn set_password(&self, pass: &str) -> Result<()> {
        if pass.chars().count() < 8 {
            bail!("密码至少 8 位");
        }
        let hash = crate::crypto::hash_password(pass)?;
        self.db().set_panel_pass_hash(&hash)
    }

    /// 修改面板端口。返回新端口。
    pub fn set_port(&self, port: u16) -> Result<u16> {
        if port == 0 {
            bail!("端口不能为 0");
        }
        if crate::node_manager::NodeManager::port_in_use_layer(port, NetLayer::Tcp) {
            bail!("端口 {port} 已被占用（TCP 层），无法使用");
        }
        self.db().set_panel_port(port)?;
        Ok(port)
    }

    /// 当前配置里在指定传输层上已声明的端口集合。
    /// 一键配置按协议层避让：TCP 层已用的端口不阻碍 UDP 节点选用同一端口。
    pub fn used_ports_by_layer(&self, layer: NetLayer) -> std::collections::HashSet<u16> {
        // 端口集合来自数据库节点声明（覆盖未运行成功的节点）。
        self.list_nodes_blocking()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| {
                let kind = v.get("type").and_then(|x| x.as_str())?;
                let port = v.get("port").and_then(|x| x.as_u64())? as u16;
                let l = config::layer_of_type(kind)?;
                (l == layer).then_some(port)
            })
            .collect()
    }

    /// 检测端口在指定传输层上是否已被系统占用。TCP 与 UDP 互不干扰：
    /// 同一端口的 TCP 被占不影响 UDP 绑定，反之亦然。
    /// 每次绑定后立即 drop 释放，避免临时 socket 互相干扰导致双栈误判。
    pub fn port_in_use_layer(port: u16, layer: NetLayer) -> bool {
        use std::net::{TcpListener, UdpSocket};
        if port == 0 {
            return true;
        }
        match layer {
            NetLayer::Tcp => match TcpListener::bind(("0.0.0.0", port)) {
                Ok(sock) => {
                    drop(sock);
                    false
                }
                Err(_) => true,
            },
            NetLayer::Udp => match UdpSocket::bind(("0.0.0.0", port)) {
                Ok(sock) => {
                    drop(sock);
                    false
                }
                Err(_) => true,
            },
        }
    }

    /// 启动前预检：所有节点的端口 + web 端口，任一被占用即 bail 退出进程。
    /// 同时检查配置内是否有两个节点在同一传输层争用同一端口。
    /// `web_port` 为 Some 时按 TCP 层检测 web 面板端口。
    pub fn preflight_ports(&self, web_port: Option<u16>) -> Result<()> {
        // (port, layer) -> 节点名，用于配置内同层端口冲突检测
        let mut claimed: std::collections::HashSet<(u16, NetLayer)> =
            std::collections::HashSet::new();
        for (name, decl) in self.list_nodes_blocking()? {
            let kind = decl.get("type").and_then(|x| x.as_str()).unwrap_or("");
            let port = decl
                .get("port")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u16;
            let Some(layer) = config::layer_of_type(kind) else {
                bail!("节点 `{name}` 协议 `{kind}` 无法识别");
            };
            if !claimed.insert((port, layer)) {
                bail!(
                    "节点 `{name}` 的端口 {port}/{} 与另一节点重复（同一传输层不能共用端口）",
                    layer.name()
                );
            }
            if Self::port_in_use_layer(port, layer) {
                bail!(
                    "节点 `{name}` 的端口 {port} 已被占用（{} 层），无法启动",
                    layer.name()
                );
            }
        }

        if let Some(port) = web_port {
            if Self::port_in_use_layer(port, NetLayer::Tcp) {
                bail!("Web 面板端口 {port} 已被占用（TCP 层），无法启动");
            }
        }
        Ok(())
    }

    /// 检查端口是否可安全使用：系统层面该传输层未被占用 + 配置内无同层冲突。
    /// `exclude_name` 为编辑场景下要排除的节点自身（避免误判自己占用的端口）。
    pub fn check_port_available(
        &self,
        name: &str,
        port: u16,
        layer: NetLayer,
        exclude_name: Option<&str>,
    ) -> Result<()> {
        if port == 0 {
            bail!("端口不能为 0");
        }
        // 判断被排除的节点（编辑中的自己）当前是否就占用着这个 (port, layer)。
        // 若是，则系统层检测到的占用来自自身，属正常情况，应跳过。
        let mut occupied_by_self = false;
        for (n, decl) in self.list_nodes_blocking()? {
            let port_n = decl.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            let layer_n = decl
                .get("type")
                .and_then(|x| x.as_str())
                .and_then(config::layer_of_type)
                .unwrap_or(layer);
            let same_slot = port_n == port && layer_n == layer;
            if exclude_name.map_or(false, |e| e == n) {
                if same_slot {
                    occupied_by_self = true;
                }
                continue;
            }
            if same_slot {
                bail!(
                    "端口 {port} 已被节点 `{n}` 占用（{} 层），请换一个端口",
                    layer.name()
                );
            }
        }
        if !occupied_by_self && Self::port_in_use_layer(port, layer) {
            bail!(
                "节点 `{name}` 的端口 {port} 已被系统其它程序占用（{} 层），无法保存",
                layer.name()
            );
        }
        Ok(())
    }

    /// 校验单个节点：解析相对路径 + finalize，返回统计所需 NodeInfo。
    fn validate(&self, node: &mut NodeConfig) -> Result<NodeInfo> {
        config::Config::resolve_node_paths(node, &self.base_dir);
        let (proto, listen, port) = config::Config::finalize_node(node)
            .with_context(|| format!("node `{}`", node.name))?;
        Ok(NodeInfo {
            name: node.name.clone(),
            proto: proto.to_string(),
            listen,
            port,
        })
    }

    /// 启动节点（先注册统计，再 spawn 运行任务）。
    fn launch(&self, mut node: NodeConfig) {
        let info = match self.validate(&mut node) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("[manager] skip invalid node `{}`: {e:#}", node.name);
                return;
            }
        };
        self.launch_with_info(node, info);
    }

    fn launch_with_info(&self, node: NodeConfig, info: NodeInfo) {
        let name = info.name.clone();
        let (proto, listen, port) = (info.proto.clone(), info.listen.clone(), info.port);
        self.stats.add_node(info);
        let task = spawn_protocol(node);
        let mut st = self.state.lock().unwrap();
        // 若同名旧任务仍在（异常路径），先移除引用，避免句柄泄漏；端口由调用方保证已释放。
        st.running.insert(
            name,
            RunningNode {
                task,
                proto,
                listen,
                port,
            },
        );
    }

    /// 停止节点：abort 任务并等待其结束（确保监听端口释放），再移除统计。
    async fn stop(&self, name: &str) {
        let handle = {
            let mut st = self.state.lock().unwrap();
            st.running.remove(name)
        };
        if let Some(rn) = handle {
            rn.task.abort();
            // 等待任务真正结束，端口/端点释放。
            let _ = rn.task.await;
            self.stats.remove_node(&rn.proto, &rn.listen, rn.port);
        }
    }
}

/// 按协议类型把节点配置跑成一个 tokio 任务。
/// 与 main.rs 启动逻辑保持一致；顶层 future 被 abort 时会 drop 其持有的
/// TcpListener / UdpSocket / QUIC Endpoint，从而释放端口。
pub fn spawn_protocol(node: NodeConfig) -> JoinHandle<()> {
    let tag = node.name.clone();
    tokio::spawn(async move {
        let result = match node.inner {
            config::NodeInner::Hysteria2(c) => {
                let c = Arc::new(c);
                crate::hysteria2::server::run(c).await
            }
            config::NodeInner::Vless(c) => {
                let c = Arc::new(c);
                crate::vless::listener::run(c).await
            }
            config::NodeInner::Vmess(c) => {
                let c = Arc::new(c);
                crate::vmess::run(c).await
            }
            config::NodeInner::Trojan(c) => {
                let c = Arc::new(c);
                crate::trojan::run(c).await
            }
            config::NodeInner::Shadowsocks(c) => {
                let c = Arc::new(c);
                crate::shadowsocks::server::run(c).await
            }
            config::NodeInner::Tuic(c) => {
                let c = Arc::new(c);
                crate::tuic::run(c).await
            }
            config::NodeInner::Wireguard(c) => {
                let c = Arc::new(c);
                crate::wireguard::server::run(c).await
            }
            config::NodeInner::Anytls(c) => {
                let c = Arc::new(c);
                crate::anytls::server::run(c).await
            }
            config::NodeInner::Socks(c) => {
                let c = Arc::new(c);
                crate::socks::run(c).await
            }
            config::NodeInner::Http(c) => {
                let c = Arc::new(c);
                crate::http::run(c).await
            }
            config::NodeInner::Naiveproxy(c) => {
                let c = Arc::new(c);
                crate::naiveproxy::run(c).await
            }
            config::NodeInner::Shadowquic(c) => {
                let c = Arc::new(c);
                crate::shadowquic::run(c).await
            }
            config::NodeInner::Spectre(c) => {
                let c = Arc::new(c);
                crate::spectre::run(c).await
            }
        };
        if let Err(e) = result {
            // abort 期间的报错视为正常退出。
            tracing::error!("[{tag}] server exited: {e:#}");
        }
    })
}
