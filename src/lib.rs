use serde::{Deserialize, Serialize};
use worker::*;

// 编译期嵌入静态 UI 文件 (防路径与长文本错乱)
const HTML_UI: &str = include_str!("../static/index.html");

// 1. 配置项结构体
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
            uuid: "351c9981-04b6-4103-aa4b-864aa9c91469".to_string(),
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

// 2. 节点拼装算法
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

// 3. Worker 主路由入口
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    let router = Router::new();

    router
        // 路由 1: 渲染前端 UI 页面
        .get("/", |_, _| {
            Response::from_html(HTML_UI)
        })

        // 路由 2: UI 读取配置 API
        .get_async("/api/config", |_req, ctx| async move {
            let config = match ctx.kv("CONFIG_KV") {
                Ok(kv) => kv.get("user_config").json::<AppConfig>().await?.unwrap_or_default(),
                Err(_) => AppConfig::default(),
            };
            Response::from_json(&config)
        })

        // 路由 3: UI 保存配置 API
        .post_async("/api/config", |mut req, ctx| async move {
            let new_config: AppConfig = match req.json().await {
                Ok(val) => val,
                Err(_) => return Response::error("Invalid JSON Body", 400),
            };

            if let Ok(kv) = ctx.kv("CONFIG_KV") {
                kv.put("user_config", &new_config)?.execute().await?;
                Response::ok("Config saved successfully")
            } else {
                Response::error("KV Namespace CONFIG_KV Not Bound", 500)
            }
        })

        // 路由 4: v2rayN 订阅拉取 API
        .get_async("/sub/:uuid", |req, ctx| async move {
            let req_uuid = ctx.param("uuid").unwrap_or_default();
            
            let config = match ctx.kv("CONFIG_KV") {
                Ok(kv) => kv.get("user_config").json::<AppConfig>().await?.unwrap_or_default(),
                Err(_) => AppConfig::default(),
            };

            // UUID 身份鉴权
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

            // 输出 v2rayN 识别的 Base64 字符串
            let plain_text = links.join("\n");
            let encoded_sub = base64::encode(plain_text);

            let mut headers = Headers::new();
            headers.set("Content-Type", "text/plain; charset=utf-8")?;
            Ok(Response::ok(encoded_sub)?.with_headers(headers))
        })
        .run(req, &env)
        .await
}
