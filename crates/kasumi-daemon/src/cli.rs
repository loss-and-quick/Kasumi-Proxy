//! One-shot CLI helpers that prefer the running daemon's answer. The connectivity
//! verdict that refines `connecting` into `connected` / `noInternet` lives only in
//! the daemon process, so a separate CLI process asks it instead of reporting the
//! platform's raw process-up state.

use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use kasumi_backend::fsjson::read_json;
use kasumi_backend::{Command, CommandError, Platform, Response, dispatch};
use kasumi_core::contract::WsInfo;

/// How long `status` waits on the daemon before falling back to the raw state.
pub const DAEMON_TIMEOUT: Duration = Duration::from_millis(1500);

const REQUEST_ID: i64 = 1;

/// `Status` as the running daemon reports it, or the platform's raw process-up
/// state when no daemon answers in time.
pub async fn status(platform: &dyn Platform, timeout: Duration) -> Result<Response, CommandError> {
    match ask_daemon_status(&platform.paths().ws_info, timeout).await {
        Some(resp) => Ok(resp),
        None => dispatch(platform, Command::Status).await,
    }
}

async fn ask_daemon_status(ws_info: &Path, timeout: Duration) -> Option<Response> {
    let info: WsInfo = read_json(ws_info).await?;
    tokio::time::timeout(timeout, request_status(&info))
        .await
        .ok()?
}

async fn request_status(info: &WsInfo) -> Option<Response> {
    let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.ok()?;
    let req = serde_json::json!({ "id": REQUEST_ID, "cmd": "status" });
    ws.send(Message::Text(req.to_string())).await.ok()?;
    // Pushed status frames share the socket; only the correlated reply counts.
    while let Some(Ok(msg)) = ws.next().await {
        let Message::Text(text) = msg else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if v.get("id").and_then(|i| i.as_i64()) != Some(REQUEST_ID) {
            continue;
        }
        if v.get("ok") != Some(&serde_json::Value::Bool(true)) {
            return None;
        }
        return serde_json::from_value(v.get("value")?.clone()).ok();
    }
    None
}
