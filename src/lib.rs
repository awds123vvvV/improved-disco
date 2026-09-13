use subtle::ConstantTimeEq;
use worker::*;

// 配置落脚点与密码 (UUID)
const UUID_HEX: &str = "0f86505f-6f0b-48d0-9ba3-f2574570d3c9"; // 去除横杠的 32 位 hex
const PROXY_IP: &str = "saas.sin.fan";
const PROXY_PORT: u16 = 50001;

#[event(fetch)]
pub async fn main(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    // 仅响应 WebSocket 升级请求，非 WS 请求一律响应无特征 404
    let headers = req.headers();
    if headers.get("Upgrade").unwrap_or(None) != Some("websocket".to_string()) {
        return Response::empty().map(|r| r.with_status(404));
    }

    // 建立 WebSocket Pair
    let pair = WebSocketPair::new()?;
    let client = pair.client;
    let server = pair.server;

    server.accept()?;

    // 异步监听 Client 数据流
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = handle_stream(server).await {
            console_log!("VLESS Stream Error: {:?}", e);
        }
    });

    Response::from_websocket(client)
}

async fn handle_stream(ws: WebSocket) -> Result<()> {
    let mut events = ws.events()?;
    let mut socket_writer: Option<Socket> = None;

    while let Some(event) = events.next().await {
        match event? {
            WebsocketEvent::Message(msg) => {
                if let Some(bytes) = msg.bytes() {
                    if let Some(ref socket) = socket_writer {
                        // 建立 Socket 连接后，后续流量直接透明转发
                        let mut writer = socket.writer();
                        writer.write_all(&bytes).await?;
                    } else {
                        // 首次数据包：解包 VLESS 报头并进行安全验证
                        if bytes.len() < 24 {
                            let _ = ws.close(Some(1002), Some("Invalid Header"));
                            return Ok(());
                        }

                        // 1. 常量时间 UUID 匹配 (防侧信道攻击)
                        let target_uuid = hex::decode(UUID_HEX).map_err(|_| Error::RustError("Hex Decode Error".into()))?;
                        let incoming_uuid = &bytes[1..17];
                        if incoming_uuid.ct_eq(&target_uuid).unwrap_u8() != 1 {
                            let _ = ws.close(Some(1008), Some("Unauthorized"));
                            return Ok(());
                        }

                        // 2. 解析偏移量与目标 IP 类型
                        let opt_len = bytes[17] as usize;
                        let port_idx = 19 + opt_len;
                        let addr_type = bytes[port_idx + 2];
                        let addr_len = match addr_type {
                            1 => 4,  // IPv4
                            3 => 16, // IPv6
                            2 => (bytes[port_idx + 3] + 1) as usize, // 域名
                            _ => return Ok(()),
                        };
                        let raw_data_idx = port_idx + 3 + addr_len;

                        // 3. 防 SSRF：拦截私有 / 回环 IP 访问 (IPv4 127.x.x.x / 10.x.x.x 等)
                        if addr_type == 1 && (bytes[port_idx + 3] == 127 || bytes[port_idx + 3] == 10) {
                            let _ = ws.close(Some(1008), Some("Blocked IP"));
                            return Ok(());
                        }

                        // 4. 建立 TCP Socket 连接
                        let socket = Socket::builder().connect(PROXY_IP, PROXY_PORT)?;
                        let mut writer = socket.writer();
                        writer.write_all(&bytes[raw_data_idx..]).await?;

                        // 5. 启动异步反向回流 (Remote -> WebSocket)
                        let ws_clone = ws.clone();
                        let reader = socket.reader();
                        let vless_version = bytes[0];
                        
                        wasm_bindgen_futures::spawn_local(async move {
                            let mut buffer = vec![0u8; 4096];
                            let mut reader = reader;
                            let mut header_sent = false;

                            while let Ok(n) = reader.read(&mut buffer).await {
                                if n == 0 { break; }
                                if !header_sent {
                                    // 拼接 2 字节 VLESS 响应头
                                    let mut resp_buf = vec![vless_version, 0];
                                    resp_buf.extend_from_slice(&buffer[..n]);
                                    let _ = ws_clone.send_with_bytes(&resp_buf);
                                    header_sent = true;
                                } else {
                                    let _ = ws_clone.send_with_bytes(&buffer[..n]);
                                }
                            }
                            let _ = ws_clone.close(None, None);
                        });

                        socket_writer = Some(socket);
                    }
                }
            }
            WebsocketEvent::Close(_) => break,
        }
    }
    Ok(())
}