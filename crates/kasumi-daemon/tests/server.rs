//! Integration test for the daemon's HTTP/WS server: static webroot + SPA
//! fallback, token gating, and the typed `Command`/`Response` over WebSocket.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio_tungstenite::tungstenite::Message;

use kasumi_backend::Service;
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    BackendPaths, Engine, InstalledCores, Platform, PlatformCapabilities, StartDataPath,
    StopDataPath,
};
use kasumi_core::contract::{RunState, ServiceState, WsInfo};

struct StubPlatform {
    paths: BackendPaths,
}

impl StubPlatform {
    fn new() -> (Arc<Self>, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_path_buf();
        let web = d.join("web");
        std::fs::create_dir_all(&web).unwrap();
        std::fs::write(web.join("index.html"), b"INDEX").unwrap();
        let paths = BackendPaths {
            data_dir: d.clone(),
            srs_dir: d.join("srs"),
            dat_dir: d.join("dat"),
            app_state: d.join("app-state.json"),
            profiles: d.join("profiles.json"),
            xray_config: d.join("xray.json"),
            singbox_config: d.join("singbox.json"),
            engine_file: d.join("engine"),
            run_dir: d.join("run"),
            ws_info: d.join("ws.json"),
            webroot: Some(web),
        };
        (Arc::new(Self { paths }), dir)
    }
}

#[async_trait]
impl Platform for StubPlatform {
    fn paths(&self) -> &BackendPaths {
        &self.paths
    }
    async fn start_data_path(&self, _opts: StartDataPath) -> anyhow::Result<()> {
        Ok(())
    }
    async fn stop_data_path(&self, _opts: StopDataPath) -> anyhow::Result<()> {
        Ok(())
    }
    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        Ok(ServiceState {
            state: RunState::Stopped,
            error: None,
            upload_bytes: 0,
            download_bytes: 0,
            uptime_sec: 0,
            engine: None,
        })
    }
    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
        Ok(PlatformCapabilities {
            cores: InstalledCores::default(),
            tun: true,
            bridge: "ksu".into(),
        })
    }
    fn core_path(&self, _engine: Engine) -> PathBuf {
        PathBuf::new()
    }
    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
        Ok(ProxyStatus {
            running: false,
            socks_port: 0,
            http_port: 0,
            force_port: 0,
        })
    }
}

/// Start the server in the background and return its bound `{port, token}`.
async fn start_server() -> (WsInfo, TempDir) {
    let (platform, dir) = StubPlatform::new();
    let ws_info_path = platform.paths().ws_info.clone();
    let service = Service::new(platform as Arc<dyn Platform>).await;
    tokio::spawn(async move {
        kasumi_daemon::server::serve(service).await.unwrap();
    });
    // Wait for the listener to bind and write its wsInfo.
    for _ in 0..50 {
        if let Ok(bytes) = std::fs::read(&ws_info_path)
            && let Ok(info) = serde_json::from_slice::<WsInfo>(&bytes)
        {
            return (info, dir);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not write wsInfo");
}

#[tokio::test]
async fn ping_and_static_and_spa_fallback() {
    let (info, _dir) = start_server().await;
    let base = format!("http://127.0.0.1:{}", info.port);
    let http = reqwest::Client::new();

    let ping = http.get(format!("{base}/ping")).send().await.unwrap();
    assert!(ping.status().is_success());
    assert_eq!(ping.json::<serde_json::Value>().await.unwrap()["ok"], true);

    let index = http.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(index.text().await.unwrap(), "INDEX");

    // Unknown route → SPA fallback to index.html.
    let spa = http.get(format!("{base}/profiles")).send().await.unwrap();
    assert_eq!(spa.text().await.unwrap(), "INDEX");
}

#[tokio::test]
async fn ws_requires_token() {
    let (info, _dir) = start_server().await;
    let bad = format!("ws://127.0.0.1:{}/ws?token=wrong", info.port);
    assert!(tokio_tungstenite::connect_async(&bad).await.is_err());
}

#[tokio::test]
async fn ws_typed_request_response() {
    let (info, _dir) = start_server().await;
    let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    // First frame is the initial status push.
    let first = ws.next().await.unwrap().unwrap();
    let first: serde_json::Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    assert_eq!(first["event"], "status");

    // Send a typed readState request and find its correlated reply.
    ws.send(Message::Text(r#"{"id":7,"cmd":"readState"}"#.into()))
        .await
        .unwrap();
    let reply = loop {
        let msg = ws.next().await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        if v.get("id") == Some(&serde_json::json!(7)) {
            break v;
        }
    };
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["value"]["kind"], "state");
    // The default state carries the mandatory base group.
    let groups = reply["value"]["value"]["groups"].as_array().unwrap();
    assert!(groups.iter().any(|g| g["id"] == "g-main"));
}
