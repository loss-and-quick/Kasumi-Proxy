//! The byte transport under the privilege boundary, abstracted over the OS so the
//! protocol layer ([`super::proto`]) and the request loop ([`super::server`]) stay
//! neutral. Linux uses a unix socket (root helper, pkexec); Windows a named pipe
//! (LocalSystem service, SCM). Both reduce to a framed `AsyncRead`/`AsyncWrite`
//! pair, so callers hold boxed halves and never name the concrete stream.

/// The read half of a helper connection, type-erased over the OS stream.
pub type BoxRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
/// The write half of a helper connection, type-erased over the OS stream.
pub type BoxWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

/// Connect to the helper at `addr` (a socket path on Linux, a pipe name on
/// Windows) and return its split halves.
#[cfg(unix)]
pub async fn connect(addr: &str) -> anyhow::Result<(BoxRead, BoxWrite)> {
    use anyhow::Context;
    let stream = tokio::net::UnixStream::connect(addr)
        .await
        .with_context(|| format!("connect privilege-helper socket {addr}"))?;
    let (read, write) = tokio::io::split(stream);
    Ok((Box::new(read), Box::new(write)))
}

/// Open the helper's named pipe, retrying while the service is mid-accept (a pipe
/// instance serves one client at a time, so a fresh instance may not be listening
/// for the brief window between accept and the next `create`).
#[cfg(windows)]
pub async fn connect(addr: &str) -> anyhow::Result<(BoxRead, BoxWrite)> {
    use anyhow::Context;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let client = loop {
        match ClientOptions::new().open(addr) {
            Ok(c) => break c,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("open privilege-helper pipe {addr}"));
            }
        }
    };
    let (read, write) = tokio::io::split(client);
    Ok((Box::new(read), Box::new(write)))
}
