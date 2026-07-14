//! A tiny PAC (proxy auto-config) server for the `pac` proxy mode. It serves one
//! static PAC over HTTP on loopback that points browsers at the core's local http +
//! socks inbound, with a DIRECT fallback for loopback/plain hosts. There is only one
//! server per process, so it is held in a module global rather than on the platform.
//! Like the rest of the OS-proxy layer it runs in the GUI process, not the helper.

use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

static SERVER: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// The PAC script pointing at the local proxy, DIRECT for loopback/plain hosts.
fn build_pac(http_port: u16, socks_port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{\n  \
         if (isPlainHostName(host) || host == \"localhost\" || shExpMatch(host, \"127.*\")) \
         return \"DIRECT\";\n  \
         return \"PROXY 127.0.0.1:{http_port}; SOCKS5 127.0.0.1:{socks_port}; DIRECT\";\n}}\n"
    )
}

/// Start (replacing any prior) the PAC server on `pac_port` and return the URL to
/// hand the OS, or `None` if the port could not be bound.
pub async fn start(pac_port: u16, http_port: u16, socks_port: u16) -> Option<String> {
    stop().await;
    let listener = TcpListener::bind(("127.0.0.1", pac_port)).await.ok()?;
    let pac = build_pac(http_port, socks_port);
    let handle = tokio::spawn(serve(listener, pac));
    *SERVER.lock().unwrap() = Some(handle);
    Some(format!("http://127.0.0.1:{pac_port}/proxy.pac"))
}

/// Stop the PAC server if running. Idempotent. Awaits the aborted task so the
/// listener is truly dropped before a caller re-binds the port (restart with new
/// ports).
pub async fn stop() {
    let handle = SERVER.lock().unwrap().take();
    if let Some(h) = handle {
        h.abort();
        let _ = h.await;
    }
}

/// Answer every connection with the same PAC document until the task is aborted.
async fn serve(listener: TcpListener, pac: String) {
    let body = pac.into_bytes();
    let response = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            // Transient accept errors (EMFILE, …) mustn't spin the loop hot.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let head = response.clone();
        let body = body.clone();
        tokio::spawn(async move {
            // Drain the request line so the client doesn't see a reset before the body.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.flush().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_the_pac_and_stops() {
        let url = start(10811, 10809, 10808).await.expect("pac server binds");
        assert_eq!(url, "http://127.0.0.1:10811/proxy.pac");

        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", 10811))
            .await
            .unwrap();
        sock.write_all(b"GET /proxy.pac HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        sock.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.0 200 OK"));
        assert!(out.contains("PROXY 127.0.0.1:10809; SOCKS5 127.0.0.1:10808; DIRECT"));

        // Stop frees the port for a re-bind (restart with new ports).
        stop().await;
        let again = start(10811, 1081, 1080).await.expect("rebind after stop");
        assert!(again.ends_with("/proxy.pac"));
        stop().await;
    }
}
