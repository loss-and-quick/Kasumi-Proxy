//! Headless-daemon library: the HTTP/WS server the KSU/Magisk/APatch module hosts
//! the WebUI from (serving the React build + a token-gated typed WebSocket over the
//! neutral backend), the Android `Platform` implementation, and the argv dispatch.

pub mod android;
pub mod run;
pub mod server;
