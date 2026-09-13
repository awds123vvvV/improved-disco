use futures_util::StreamExt;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::*;

const UUID_HEX: &str = "0f86505f-6f0b-48d0-9ba3-f2574570d3c9";
const PROXY_IP: &str = "saas.sin.fan";
const PROXY_PORT: u16 = 50001;

#[event(fetch)]
pub async fn main(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let headers = req.headers();
    if headers.get("Upgrade").unwrap_or(None) != Some("websocket".to_string()) {
        return Response::empty().map(|r| r.with_status(404));
    }

    let pair = WebSocketPair::new()?;
    let client = pair.client;
    let server = pair.server;

    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = handle_stream(server).await {
            console_log!("VLESS Stream Error: {:?}", e);
        }
    });

    Response::from_websocket(client)
}

async fn handle_stream(ws: WebSocket) -> Result<()> {
    let mut events = ws.events()?;
    let mut socket_writer: Option<tokio::io::WriteHalf<Socket>> = None;

    while let Some(event) = events.next().await {
        match event? {
            WebsocketEvent::Message(msg) => {
                if let Some(bytes) = msg.bytes() {
                    if let Some(ref mut writer) = socket_writer {
                        let _ = writer.write_all(&bytes).await;
                    } else {
                        if bytes.len() < 24 {
                            let _ = ws.close(Some(1002), Some("Invalid Header"));
                            return Ok(());
                        }

                        let target_uuid = hex::decode(UUID_HEX)
                            .map_err(|_| Error::RustError("Hex Decode Error".into()))?;
                        let incoming_uuid = &bytes[1..17];
                        if incoming_uuid.ct_eq(&target_uuid).unwrap_u8() != 1 {
                            let _ = ws.close(Some(1008), Some("Unauthorized"));
                            return Ok(());
                        }

                        let opt_len = bytes[17] as usize;
                        let port_idx = 19 + opt_len;
                        let addr_type = bytes[port_idx + 2];
                        let addr_len = match addr_type {
                            1 => 4,
                            3 => 16,
                            2 => (bytes[port_idx + 3] + 1) as usize,
                            _ => return Ok(()),
                        };
                        let raw_data_idx = port_idx + 3 + addr_len;

                        if addr_type == 1 && (bytes[port_idx + 3] == 127 || bytes[port_idx + 3] == 10) {
                            let _ = ws.close(Some(1008), Some("Blocked IP"));
                            return Ok(());
                        }

                        let socket = Socket::builder().connect(PROXY_IP, PROXY_PORT)?;
                        let (mut reader, mut writer) = tokio::io::split(socket);
                        let _ = writer.write_all(&bytes[raw_data_idx..]).await;

                        let ws_clone = ws.clone();
                        let vless_version = bytes[0];

                        wasm_bindgen_futures::spawn_local(async move {
                            let mut buffer = vec![0u8; 4096];
                            let mut header_sent = false;

                            while let Ok(n) = reader.read(&mut buffer).await {
                                if n == 0 {
                                    break;
                                }
                                if !header_sent {
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

                        socket_writer = Some(writer);
                    }
                }
            }
            WebsocketEvent::Close(_) => break,
        }
    }
    Ok(())
}
