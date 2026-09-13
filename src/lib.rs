use base64::Engine;
use serde::{Deserialize, Serialize};
use worker::*;

const HTML_UI: &str = include_str!("../static/index.html");

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub uuid: String,
    pub addresses: Vec<String>,
    pub port: u16,
    pub path: String,
    pub enable_vless: bool,
    pub enable_trojan: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            uuid: "0f86505f-6f0b-48d0-9ba3-f2574570d3c9".to_string(),
            addresses: vec![
                "172.71.218.190".to_string(),
                "104.16.123.96".to_string(),
                "162.159.137.85".to_string(),
            ],
            port: 443,
            path: "/?ed=2048".to_string(),
            enable_vless: true,
            enable_trojan: false,
        }
    }
}

fn build_vless(uuid: &str, addr: &str, port: u16, host: &str, path: &str, remark: &str) -> String {
    format!(
        "vless://{}@{}:{}?encryption=none&security=tls&type=ws&host={}&path={}#{}",
        uuid, addr, port, host, urlencoding::encode(path), urlencoding::encode(remark)
    )
}

fn build_trojan(uuid: &str, addr: &str, port: u16, host: &str, path: &str, remark: &str) -> String {
    format!(
        "trojan://{}@{}:{}?security=tls&type=ws&host={}&path={}#{}",
        uuid, addr, port, host, urlencoding::encode(path), urlencoding::encode(remark)
    )
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| Response::from_html(HTML_UI))
        .get_async("/api/config", |_req, ctx| async move {
            let config = match ctx.kv("CONFIG_KV") {
                Ok(kv) => kv.get("user_config").json::<AppConfig>().await.ok().flatten().unwrap_or_default(),
                Err(_) => AppConfig::default(),
            };
            Response::from_json(&config)
        })
        .post_async("/api/config", |mut req, ctx| async move {
            let new_config: AppConfig = match req.json().await {
                Ok(val) => val,
                Err(_) => return Response::error("Invalid JSON Body", 400),
            };

            if let Ok(kv) = ctx.kv("CONFIG_KV") {
                if let Ok(put) = kv.put("user_config", &new_config) {
                    let _ = put.execute().await;
                    return Response::ok("Config saved successfully");
                }
            }
            Response::error("KV Namespace CONFIG_KV Not Bound or Failed", 500)
        })
        .get_async("/sub/:uuid", |req, ctx| async move {
            // 修复点 1：转换 &String 为 String
            let req_uuid = ctx.param("uuid").cloned().unwrap_or_default();
            
            let config = match ctx.kv("CONFIG_KV") {
                Ok(kv) => kv.get("user_config").json::<AppConfig>().await.ok().flatten().unwrap_or_default(),
                Err(_) => AppConfig::default(),
            };

            if req_uuid != config.uuid {
                return Response::error("Unauthorized: Invalid UUID", 401);
            }

            let host = req.url()?.host_str().unwrap_or_default().to_string();
            let mut links = Vec::new();

            for (idx, addr) in config.addresses.iter().enumerate() {
                if config.enable_vless {
                    let remark = format!("Rust-VLESS-{}", idx + 1);
                    links.push(build_vless(&config.uuid, addr, config.port, &host, &config.path, &remark));
                }
                if config.enable_trojan {
                    let remark = format!("Rust-Trojan-{}", idx + 1);
                    links.push(build_trojan(&config.uuid, addr, config.port, &host, &config.path, &remark));
                }
            }

            // 修复点 2：使用新版标准的 Base64 Engine 编码
            let plain_text = links.join("\n");
            let encoded_sub = base64::engine::general_purpose::STANDARD.encode(plain_text);

            let mut headers = Headers::new();
            headers.set("Content-Type", "text/plain; charset=utf-8")?;
            Ok(Response::ok(encoded_sub)?.with_headers(headers))
        })
        // 修复点 3：去掉 & 引用符
        .run(req, env)
        .await
}
