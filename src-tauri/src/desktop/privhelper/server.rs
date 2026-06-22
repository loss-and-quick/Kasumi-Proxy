//! Root side of privilege separation: serve [`proto`] requests against a real
//! [`Platform`] (the in-helper [`DesktopPlatform`]) over a unix socket.
//!
//! The helper runs as root and owns the data-path; the unprivileged GUI is the
//! only client. Each connection is a sequence of newline-delimited
//! [`PrivRequest`]s, each answered with exactly one [`PrivReply`]. Dispatch is
//! kept in [`dispatch`] — a pure async map from request to reply — so it can be
//! exercised without a socket.

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use kasumi_backend::platform::{Platform, StartDataPath, StopDataPath};

use super::proto::{PrivReply, PrivRequest};

/// Map one request to its reply by calling into `platform`. Errors are folded into
/// `PrivReply::Err` so a failing operation never drops the connection.
pub async fn dispatch(platform: &Arc<dyn Platform>, req: PrivRequest) -> PrivReply {
    match req {
        PrivRequest::Ping => PrivReply::Pong,
        PrivRequest::BootInit => to_reply(platform.boot_init().await),
        PrivRequest::StartDataPath { engine, socks_port } => to_reply(
            platform
                .start_data_path(StartDataPath { engine, socks_port })
                .await,
        ),
        PrivRequest::StopDataPath { keep_service_state } => to_reply(
            platform
                .stop_data_path(StopDataPath { keep_service_state })
                .await,
        ),
        PrivRequest::ServiceState => match platform.service_state().await {
            Ok(s) => PrivReply::State(s),
            Err(e) => PrivReply::Err {
                message: e.to_string(),
            },
        },
        PrivRequest::Capabilities => match platform.capabilities().await {
            Ok(c) => PrivReply::Capabilities {
                xray: c.cores.xray,
                singbox: c.cores.singbox,
                tun: c.tun,
            },
            Err(e) => PrivReply::Err {
                message: e.to_string(),
            },
        },
        PrivRequest::ProxyStatus => match platform.proxy_status().await {
            Ok(p) => PrivReply::Proxy {
                running: p.running,
                socks_port: p.socks_port,
                http_port: p.http_port,
            },
            Err(e) => PrivReply::Err {
                message: e.to_string(),
            },
        },
        PrivRequest::DataPathHealthy => PrivReply::Healthy {
            healthy: platform.data_path_healthy().await,
        },
    }
}

/// `Ok(())` → `PrivReply::Ok`, otherwise the stringified error.
fn to_reply(r: anyhow::Result<()>) -> PrivReply {
    match r {
        Ok(()) => PrivReply::Ok,
        Err(e) => PrivReply::Err {
            message: e.to_string(),
        },
    }
}

/// Bind `socket_path` and serve requests against `platform` until the process
/// exits. Removes any stale socket first. Connections are served concurrently;
/// within a connection requests are answered in order.
pub async fn serve(platform: Arc<dyn Platform>, socket_path: &str) -> anyhow::Result<()> {
    let _ = tokio::fs::remove_file(socket_path).await;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind privilege-helper socket {socket_path}"))?;
    loop {
        let (stream, _addr) = listener.accept().await?;
        let platform = platform.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(platform, stream).await {
                eprintln!("kasumi-helper: connection ended: {e}");
            }
        });
    }
}

/// Read requests line by line and write one reply per request.
async fn serve_conn(platform: Arc<dyn Platform>, stream: UnixStream) -> anyhow::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<PrivRequest>(&line) {
            Ok(req) => dispatch(&platform, req).await,
            Err(e) => PrivReply::Err {
                message: format!("malformed request: {e}"),
            },
        };
        let mut buf = serde_json::to_vec(&reply)?;
        buf.push(b'\n');
        write.write_all(&buf).await?;
        write.flush().await?;
    }
    Ok(())
}
