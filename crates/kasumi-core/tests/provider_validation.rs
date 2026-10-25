//! Provider graph validation must preserve connection paths and bound graph work.
use kasumi_core::custom_sanitize::{SanitizeError, sanitize_provider_xray};
use kasumi_core::provider_graph::{MAX_GRAPH_DEPTH, MAX_GRAPH_NODES};
use serde_json::{Value, json};

fn server(tag: &str) -> Value {
    json!({
        "tag": tag, "protocol": "vless",
        "settings": { "vnext": [{ "address": "node.example", "port": 443,
            "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
        "streamSettings": { "network": "tcp", "security": "tls" }
    })
}

fn loopback(tag: Option<&str>) -> Value {
    let mut outbound = json!({ "protocol": "loopback", "settings": { "inboundTag": "virtual" } });
    if let Some(tag) = tag {
        outbound["tag"] = tag.into();
    }
    outbound
}

fn virtual_config(rules: Value) -> Value {
    json!({ "outbounds": [loopback(Some("entry")), server("exit")], "routing": { "rules": rules } })
}

#[test]
fn socket_option_casing_cannot_preserve_platform_routing_controls() {
    for key in ["sockopt", "SOCKOPT", "Sockopt", "SockOpt"] {
        let mut outbound = server("exit");
        outbound["streamSettings"][key] = json!({ "mark": 255, "interface": "test-interface" });
        if let Ok(sanitized) = sanitize_provider_xray(&json!({ "outbounds": [outbound] })) {
            let encoded = sanitized.into_provider_json().to_string();
            assert!(!encoded.contains("test-interface"));
            assert!(!encoded.contains("255"));
        }
    }
}

#[test]
fn chain_field_aliases_cannot_silently_remove_required_hops() {
    for key in ["DialerProxy", "DIALERPROXY", "dialerproxy"] {
        let mut outbound = server("exit");
        outbound["streamSettings"]["sockopt"][key] = "entry".into();
        assert!(matches!(
            sanitize_provider_xray(&json!({ "outbounds": [outbound, server("entry")] })),
            Err(SanitizeError::Incompatible { .. })
        ));
    }
}

#[test]
fn separate_tcp_and_udp_rules_fully_cover_a_virtual_context() {
    let config = virtual_config(json!([
        { "type": "field", "inboundTag": ["virtual"], "network": "tcp", "outboundTag": "exit" },
        { "type": "field", "inboundTag": ["virtual"], "network": "udp", "outboundTag": "exit" }
    ]));
    assert!(sanitize_provider_xray(&config).is_ok());
}

#[test]
fn full_port_ranges_fully_cover_a_virtual_context() {
    let config = virtual_config(json!([
        { "type": "field", "inboundTag": ["virtual"], "port": "32768-65535,1-32767", "outboundTag": "exit" }
    ]));
    assert!(sanitize_provider_xray(&config).is_ok());
}

#[test]
fn declared_terminals_count_toward_the_graph_node_budget() {
    let outbounds: Vec<_> = (0..=MAX_GRAPH_NODES)
        .map(|index| server(&format!("node-{index}")))
        .collect();
    assert!(matches!(
        sanitize_provider_xray(&json!({ "outbounds": outbounds })),
        Err(SanitizeError::Incompatible {
            reason: "routing graph exceeds node limit",
            ..
        })
    ));
}

#[test]
fn long_chains_exceed_the_depth_budget_independently_of_traversal_order() {
    let mut outbounds: Vec<_> = (0..=MAX_GRAPH_DEPTH)
        .map(|index| {
            let mut outbound = server(&format!("node-{index}"));
            if index < MAX_GRAPH_DEPTH {
                outbound["streamSettings"]["sockopt"]["dialerProxy"] =
                    format!("node-{}", index + 1).into();
            }
            outbound
        })
        .collect();
    for _ in 0..8 {
        assert!(matches!(
            sanitize_provider_xray(&json!({ "outbounds": outbounds })),
            Err(SanitizeError::Incompatible {
                reason: "routing graph exceeds depth limit",
                ..
            })
        ));
        outbounds.rotate_left(1);
    }
}

#[test]
fn an_unnamed_first_loopback_cannot_implicitly_route_back_to_itself() {
    assert!(matches!(
        sanitize_provider_xray(&json!({ "outbounds": [loopback(None), server("exit")] })),
        Err(SanitizeError::Incompatible { .. })
    ));
}

#[test]
fn network_arrays_require_individual_protocol_names() {
    let config = virtual_config(json!([
        { "type": "field", "inboundTag": ["virtual"], "network": ["tcp,udp"], "outboundTag": "exit" }
    ]));
    assert!(matches!(
        sanitize_provider_xray(&config),
        Err(SanitizeError::Incompatible { .. })
    ));
}

#[test]
fn transport_headers_are_opaque_metadata_not_connection_references() {
    let mut outbound = server("exit");
    let headers = json!({
        "DialerProxy": "header-value",
        "CertificateFile": "literal-header-value",
        "MasterKeyLog": "another-header-value",
        "sockopt": "header-text"
    });
    outbound["streamSettings"]["network"] = "ws".into();
    outbound["streamSettings"]["wsSettings"]["headers"] = headers.clone();
    let sanitized = sanitize_provider_xray(&json!({ "outbounds": [outbound] })).unwrap();
    assert_eq!(
        sanitized.outbounds[0]["streamSettings"]["wsSettings"]["headers"],
        headers
    );
}

#[test]
fn omission_diagnostics_do_not_copy_unknown_metadata_keys() {
    let marker = "private-metadata-marker";
    let mut outbound = server("exit");
    outbound["streamSettings"][marker] = json!({ "masterKeyLog": "unused-output.log" });
    let sanitized = sanitize_provider_xray(&json!({ "outbounds": [outbound] })).unwrap();
    assert!(sanitized.dropped.iter().all(|path| !path.contains(marker)));
}

#[test]
fn unsupported_rule_types_are_rejected() {
    let config = virtual_config(json!([
        { "type": "unsupported", "inboundTag": ["virtual"], "network": "tcp,udp", "outboundTag": "exit" }
    ]));
    assert!(matches!(
        sanitize_provider_xray(&config),
        Err(SanitizeError::Incompatible { .. })
    ));
}
