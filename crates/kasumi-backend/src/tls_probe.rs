use base64::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::{
    self, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

use crate::commands::CommandError;

#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TlsCertInfo {
    pub sha256_hex: String,
    pub sha256_base64: String,
    pub subject: String,
    pub issuer: String,
    pub valid_until: Option<String>,
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn probe_tls_cert(
    host: &str,
    port: u16,
    sni: Option<&str>,
    insecure: bool,
) -> Result<TlsCertInfo, CommandError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        probe_tls_cert_inner(host, port, sni, insecure),
    )
    .await
    .map_err(|_| {
        CommandError(format!(
            "TLS probe timed out after 5s connecting to {host}:{port}"
        ))
    })?
}

async fn probe_tls_cert_inner(
    host: &str,
    port: u16,
    sni: Option<&str>,
    insecure: bool,
) -> Result<TlsCertInfo, CommandError> {
    let target_name = sni.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(host);

    let server_name = ServerName::try_from(target_name.to_string())
        .map_err(|e| CommandError(format!("invalid server name '{target_name}': {e}")))?;

    let config = if insecure {
        ClientConfig::builder_with_provider(ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|e| CommandError(format!("TLS config error: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder_with_provider(ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|e| CommandError(format!("TLS config error: {e}")))?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let tcp_stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| CommandError(format!("failed to connect to {host}:{port}: {e}")))?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| CommandError(format!("TLS handshake failed with {host}:{port}: {e}")))?;

    let (_, conn) = tls_stream.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| CommandError("no peer certificates presented by server".into()))?;

    let leaf = certs
        .first()
        .ok_or_else(|| CommandError("empty peer certificate chain".into()))?;

    let leaf_der = leaf.as_ref();
    let hash = Sha256::digest(leaf_der);
    let sha256_hex = hex::encode(hash);
    let sha256_base64 = BASE64_STANDARD.encode(hash);

    let (_, parsed) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|e| CommandError(format!("failed to parse X.509 certificate: {e}")))?;

    let subject = parsed.subject().to_string();
    let issuer = parsed.issuer().to_string();
    let dt = parsed.validity().not_after.to_datetime();
    let valid_until =
        chrono::DateTime::from_timestamp(dt.unix_timestamp(), 0).map(|d| d.to_rfc3339());

    Ok(TlsCertInfo {
        sha256_hex,
        sha256_base64,
        subject,
        issuer,
        valid_until,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_self_signed_cert_success() {
        let (url, _reqs) = crate::testutil::serve_tls(b"ok").await;
        let parsed = reqwest::Url::parse(&url).unwrap();
        let host = parsed.host_str().unwrap();
        let port = parsed.port().unwrap();

        let cert = probe_tls_cert(host, port, Some("localhost"), true)
            .await
            .expect("probe with insecure=true should succeed");

        assert_eq!(cert.sha256_hex.len(), 64);
        assert!(
            cert.sha256_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(cert.sha256_base64.len(), 44);
        assert!(cert.subject.contains("localhost"));
        assert!(cert.issuer.contains("localhost"));
        assert!(cert.valid_until.is_some());
    }

    #[tokio::test]
    async fn probe_self_signed_cert_fails_when_secure() {
        let (url, _reqs) = crate::testutil::serve_tls(b"ok").await;
        let parsed = reqwest::Url::parse(&url).unwrap();
        let host = parsed.host_str().unwrap();
        let port = parsed.port().unwrap();

        let res = probe_tls_cert(host, port, Some("localhost"), false).await;
        assert!(
            res.is_err(),
            "probe with insecure=false should reject self-signed cert"
        );
    }

    #[tokio::test]
    async fn probe_unreachable_endpoint_fails() {
        let res = probe_tls_cert("127.0.0.1", 1, None, true).await;
        assert!(res.is_err());
    }
}
