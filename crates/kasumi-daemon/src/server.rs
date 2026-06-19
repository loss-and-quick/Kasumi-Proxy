//! The daemon's loopback HTTP/WS server. The WebSocket carries the typed
//! `Command`/`Response` (one request per frame, correlated by `id`) plus
//! server-initiated `status`/`subApplied` push frames. The upgrade is token-gated
//! because loopback isn't private between apps on Android. Where a `webroot` is
//! set, the React build is served over HTTP with an SPA fallback.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;

use kasumi_backend::commands::{Command, Response as CmdResponse};
use kasumi_backend::fsjson::write_json_atomic;
use kasumi_backend::Service;
use kasumi_core::contract::{PushFrame, WsInfo};

/// One WS request: an `id` for correlation plus the flattened [`Command`].
#[derive(Deserialize)]
struct WsRequest {
    id: i64,
    #[serde(flatten)]
    command: Command,
}

/// One WS reply, correlated by `id`. `value` carries the typed response on success;
/// `error` carries the message on failure.
#[derive(Serialize)]
struct WsReply {
    id: i64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<CmdResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Clone)]
struct ServerState {
    service: Arc<Service>,
    token: Arc<String>,
}

/// Bind the server on loopback, write its `{port, token}` to `wsInfo` for the UI to
/// bootstrap from, and serve until the process exits.
pub async fn serve(service: Arc<Service>) -> anyhow::Result<()> {
    let token = Arc::new(Uuid::new_v4().to_string());
    let webroot = service.platform().paths().webroot.clone();
    let ws_info_path = service.platform().paths().ws_info.clone();

    let state = ServerState {
        service,
        token: token.clone(),
    };
    let mut app = Router::new()
        .route("/ping", get(ping))
        .route("/ws", get(ws_handler));
    if let Some(root) = webroot {
        // SPA: unknown routes resolve to index.html for client-side routing.
        let index = root.join("index.html");
        app = app.fallback_service(ServeDir::new(root).fallback(ServeFile::new(index)));
    }
    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    write_json_atomic(
        &ws_info_path,
        &WsInfo {
            port,
            token: (*token).clone(),
        },
    )
    .await?;

    axum::serve(listener, app).await?;
    Ok(())
}

async fn ping() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "ok": true }))
}

async fn ws_handler(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    if params.get("token").map(String::as_str) != Some(state.token.as_str()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state.service))
}

fn frame<T: Serialize>(value: &T) -> Message {
    Message::Text(serde_json::to_string(value).unwrap_or_default().into())
}

async fn handle_socket(socket: WebSocket, service: Arc<Service>) {
    let (mut sink, mut stream) = socket.split();
    let mut events = service.subscribe();

    // All outgoing frames (replies + pushes) funnel through one channel to a single
    // writer task that owns the sink. This frees the read loop to dispatch each
    // request on its own task instead of blocking on it: a slow probe (real-ping /
    // speed spins up a throwaway core for several seconds) no longer stalls every
    // other command or push, so the UI's concurrent batch tests stream their
    // per-profile results as each resolves instead of draining one at a time.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Send the current status immediately so a fresh client renders without waiting
    // for the next push tick.
    if let Some(status) = service.current_status().await {
        let _ = tx.send(frame(&PushFrame::Status { value: status }));
    }

    // Fan server-pushed events into the same outgoing channel.
    let push_tx = tx.clone();
    let pusher = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(push) => {
                    if push_tx.send(frame(&push)).is_err() {
                        break;
                    }
                }
                // A slow client that lagged behind just resyncs on the next push.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    while let Some(incoming) = stream.next().await {
        match incoming {
            Ok(Message::Text(text)) => {
                let Ok(req) = serde_json::from_str::<WsRequest>(text.as_str()) else {
                    continue;
                };
                let service = service.clone();
                let reply_tx = tx.clone();
                tokio::spawn(async move {
                    let reply = match service.dispatch(req.command).await {
                        Ok(value) => WsReply {
                            id: req.id,
                            ok: true,
                            value: Some(value),
                            error: None,
                        },
                        Err(e) => WsReply {
                            id: req.id,
                            ok: false,
                            value: None,
                            error: Some(e.0),
                        },
                    };
                    let _ = reply_tx.send(frame(&reply));
                });
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }

    // Client gone: drop our channel handles so the writer drains and exits, and stop
    // forwarding pushes. In-flight dispatch tasks finish on their own; their replies
    // are dropped once the writer is gone.
    drop(tx);
    pusher.abort();
    let _ = writer.await;
}
