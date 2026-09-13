use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::*;

// ============================================================
// 全局常量与默认配置
// ============================================================
const DEFAULT_AUTH_TOKEN: &str = "351c9981-04b6-4103-aa4b-864aa9c91469";

const OFFICIAL_DIRECT_IPS: &[&str] = &[
    "172.71.218.190", "162.158.228.87", "162.158.189.134", "162.158.26.63",
    "162.158.25.86", "162.158.29.216", "162.158.218.160", "162.158.227.214",
    "172.69.118.198", "172.69.119.150",
];

fn b64_encode(input: &str) -> String {
    BASE64.encode(input)
}

fn b64_decode(input: &str) -> String {
    let bytes = BASE64.decode(input).unwrap_or_default();
    String::from_utf8(bytes).unwrap_or_default()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ConfigSnapshot {
    wk: String,
    ev: String,
    et: String,
    ex: String,
    ech: String,
    tp: String,
    #[serde(rename = "customDNS")]
    custom_dns: String,
    #[serde(rename = "customECHDomain")]
    custom_ech_domain: String,
    alpn: String,
    d: String,
    p: String,
    yx: String,
    #[serde(rename = "yxURL")]
    yx_url: String,
    s: String,
    homepage: String,
    scu: String,
    ena: String,
    epd: String,
    epi: String,
    egi: String,
    ae: String,
    rm: String,
    qj: String,
    dkby: String,
    yxby: String,
    ipv4: String,
    ipv6: String,
    #[serde(rename = "ispMobile")]
    isp_mobile: String,
    #[serde(rename = "ispUnicom")]
    isp_unicom: String,
    #[serde(rename = "ispTelecom")]
    isp_telecom: String,
}

impl Default for ConfigSnapshot {
    fn default() -> Self {
        Self {
            wk: "".into(),
            ev: "yes".into(),
            et: "no".into(),
            ex: "no".into(),
            ech: "no".into(),
            tp: "".into(),
            custom_dns: "https://223.5.5.5/dns-query".into(),
            custom_ech_domain: "cloudflare-ech.com".into(),
            alpn: "".into(),
            d: "".into(),
            p: "".into(),
            yx: "".into(),
            yx_url: "".into(),
            s: "".into(),
            homepage: "".into(),
            scu: b64_decode("aHR0cHM6Ly91cmwudjEubWsvc3Vi"),
            ena: "no".into(),
            epd: "yes".into(),
            epi: "yes".into(),
            egi: "yes".into(),
            ae: "".into(),
            rm: "".into(),
            qj: "".into(),
            dkby: "no".into(),
            yxby: "".into(),
            ipv4: "yes".into(),
            ipv6: "yes".into(),
            isp_mobile: "yes".into(),
            isp_unicom: "yes".into(),
            isp_telecom: "yes".into(),
        }
    }
}

fn is_truthy(val: &str, default_val: bool) -> bool {
    let t = val.trim().to_lowercase();
    if t.is_empty() { return default_val; }
    matches!(t.as_str(), "yes" | "true" | "1" | "on")
}

struct ParsedAddress {
    address: String,
    port: Option<u16>,
}

fn parse_address_port(input: &str) -> ParsedAddress {
    if input.contains('[') && input.contains(']') {
        let re = Regex::new(r"^\[([^\]]+)\](?::(\d+))?$").unwrap();
        if let Some(caps) = re.captures(input) {
            let addr = caps.get(1).unwrap().as_str().to_string();
            let port = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok());
            return ParsedAddress { address: addr, port };
        }
    }
    if let Some(pos) = input.rfind(':') {
        let addr = &input[..pos];
        let port_str = &input[pos + 1..];
        if !addr.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if port > 0 {
                    return ParsedAddress { address: addr.to_string(), port: Some(port) };
                }
            }
        }
    }
    ParsedAddress { address: input.to_string(), port: None }
}

// ============================================================
// 主入口 (Worker Fetch Event)
// ============================================================
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let mut config = ConfigSnapshot::default();

    // Worker 0.8.5 标准 KV 访问方式
    if let Ok(kv) = env.kv("C") {
        if let Ok(Some(val)) = kv.get("c").text().await {
            if let Ok(parsed) = serde_json::from_str::<ConfigSnapshot>(&val) {
                config = parsed;
            }
        }
    }

    let auth_token = env.var("u").or_else(|_| env.var("U"))
        .map(|v| v.to_string())
        .unwrap_or_else(|_| DEFAULT_AUTH_TOKEN.to_string())
        .to_lowercase();
        
    let custom_path = config.d.clone();
    let path = req.path();

    // 1. WebSocket 升级支持
    if req.headers().get("Upgrade")?.unwrap_or_default() == "websocket" {
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        server.accept()?;
        return Response::from_websocket(pair.client);
    }

    // 2. API 路由匹配
    if path.contains("/api/config") {
        return handle_api_config(req, &config, &env).await;
    }

    if path.contains("/api/preferred-ips") {
        return Response::from_json(&json!({
            "status": "success",
            "ips": OFFICIAL_DIRECT_IPS
        }));
    }

    if path.ends_with("/region") {
        return Response::from_json(&json!({
            "region": if config.wk.is_empty() { "CF" } else { &config.wk },
            "detectionMethod": "Rust Native Worker",
            "timestamp": Date::now().to_string()
        }));
    }

    // 3. 订阅路由匹配
    if path.ends_with("/sub") || path == format!("/{}", auth_token) || (!custom_path.is_empty() && path == format!("/{}", custom_path)) {
        return handle_subscription(req, &auth_token, &config).await;
    }

    // 4. 控制面板 HTML
    if path == "/" {
        if !config.homepage.trim().is_empty() {
            if let Ok(url) = config.homepage.trim().parse() {
                if let Ok(resp) = Fetch::Url(url).send().await {
                    return Ok(resp);
                }
            }
        }
        return Response::from_html(render_terminal_html(&custom_path));
    }

    Response::error("Not Found", 404)
}

// ============================================================
// API 配置处理
// ============================================================
async fn handle_api_config(mut req: Request, config: &ConfigSnapshot, env: &Env) -> Result<Response> {
    if req.method() == Method::Post {
        let mut new_config = config.clone();
        if let Ok(json_body) = req.json::<serde_json::Value>().await {
            if let Some(obj) = json_body.as_object() {
                if let Some(v) = obj.get("wk") { new_config.wk = v.as_str().unwrap_or("").to_string(); }
                if let Some(v) = obj.get("yx") { new_config.yx = v.as_str().unwrap_or("").to_string(); }
                if let Some(v) = obj.get("d") { new_config.d = v.as_str().unwrap_or("").to_string(); }
            }
        }
        if let Ok(kv) = env.kv("C") {
            let str_val = serde_json::to_string(&new_config).unwrap_or_default();
            let _ = kv.put("c", str_val)?.execute().await;
            let _ = kv.put("c_ver", Date::now().to_string())?.execute().await;
        }
        return Response::from_json(&json!({"status": "success", "message": "配置更新成功"}));
    }

    Response::from_json(&config)
}

// ============================================================
// 订阅节点生成逻辑
// ============================================================
async fn handle_subscription(req: Request, uuid: &str, config: &ConfigSnapshot) -> Result<Response> {
    let host = req.url()?.host().map(|h| h.to_string()).unwrap_or_else(|| "localhost".into());
    let user_agent = req.headers().get("User-Agent")?.unwrap_or_default().to_lowercase();

    let mut nodes = Vec::new();

    if is_truthy(&config.ev, true) {
        let vless_link = format!(
            "vless://{}@{}:443?encryption=none&security=tls&sni={}&type=ws&host={}&path={}#{}",
            uuid, host, host, host, urlencoding::encode(&config.tp), urlencoding::encode("Rust-VLESS-Node")
        );
        nodes.push(vless_link);
    }

    if is_truthy(&config.et, false) {
        let trojan_link = format!(
            "trojan://{}@{}:443?security=tls&sni={}&type=ws&host={}&path={}#{}",
            uuid, host, host, host, urlencoding::encode(&config.tp), urlencoding::encode("Rust-Trojan-Node")
        );
        nodes.push(trojan_link);
    }

    if !config.yx.trim().is_empty() {
        for item in config.yx.split(',') {
            let item = item.trim();
            if item.is_empty() { continue; }
            let mut name = String::new();
            let mut addr_part = item;
            if item.contains('#') {
                let parts: Vec<&str> = item.splitn(2, '#').collect();
                addr_part = parts[0].trim();
                name = parts[1].trim().to_string();
            }
            let parsed = parse_address_port(addr_part);
            let port = parsed.port.unwrap_or(443);
            if name.is_empty() {
                name = format!("自定义优选-{}:{}", parsed.address, port);
            }
            let node_link = format!(
                "vless://{}@{}:{}?encryption=none&security=tls&sni={}&type=ws&host={}&path={}#{}",
                uuid, parsed.address, port, host, host, urlencoding::encode(&config.tp), urlencoding::encode(&name)
            );
            nodes.push(node_link);
        }
    }

    if user_agent.contains("clash") {
        let yaml_content = format!(
            "port: 7890\nallow-lan: true\nmode: rule\nproxies:\n{}",
            nodes.iter().map(|n| format!("  # node: {}", n)).collect::<Vec<_>>().join("\n")
        );
        return Response::ok(yaml_content);
    }

    let encoded_sub = b64_encode(&nodes.join("\n"));
    Response::ok(encoded_sub)
}

// ============================================================
// 终端 HTML 模版
// ============================================================
fn render_terminal_html(custom_path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>终端 v3.0 (Rust Engine)</title>
    <style>
        :root {{
            --cp-bg: #05030e; --cp-cyan: #00f0ff; --cp-pink: #ff2bd6; --cp-mint: #00ff9d; --cp-red: #ff3860; --cp-text: #e6f5ff;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: "JetBrains Mono", monospace; background: var(--cp-bg); color: var(--cp-text);
            height: 100vh; display: flex; justify-content: center; align-items: center; overflow: hidden;
        }}
        .terminal {{
            width: 90%; max-width: 800px; height: 500px; background: rgba(10, 8, 32, 0.95);
            border: 1px solid var(--cp-cyan); box-shadow: 0 0 20px rgba(0, 240, 255, 0.4);
            display: flex; flex-direction: column;
        }}
        .header {{ background: rgba(0, 240, 255, 0.1); padding: 10px; font-weight: bold; color: var(--cp-cyan); border-bottom: 1px solid var(--cp-cyan); }}
        .body {{ padding: 20px; flex: 1; overflow-y: auto; font-size: 14px; line-height: 1.6; }}
        .line {{ margin-bottom: 8px; }}
        .prompt {{ color: var(--cp-pink); margin-right: 8px; }}
        input {{ background: transparent; border: none; outline: none; color: var(--cp-cyan); font-family: inherit; font-size: 14px; width: 70%; }}
    </style>
</head>
<body>
    <div class="terminal">
        <div class="header">// 终端 v3.0 [Rust WebAssembly Engine]</div>
        <div class="body" id="termBody">
            <div class="line"><span class="prompt">root:~$</span><span>恭喜你来到这</span></div>
            <div class="line"><span class="prompt">root:~$</span><span>请输入你{}变量的值</span></div>
            <div class="line">
                <span class="prompt">root:~$</span>
                <input type="text" id="uuidInput" autofocus placeholder="输入后回车...">
            </div>
        </div>
    </div>
    <script>
        const input = document.getElementById('uuidInput');
        input.addEventListener('keypress', function (e) {{
            if (e.key === 'Enter') {{
                const val = input.value.trim();
                if (val) {{
                    window.location.href = '/' + val;
                }}
            }}
        }});
    </script>
</body>
</html>"#,
        if custom_path.is_empty() { "U" } else { "D" }
    )
}
