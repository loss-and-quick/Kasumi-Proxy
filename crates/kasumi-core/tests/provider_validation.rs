//! Validation and compilation tests for provider connection graphs.

use kasumi_core::custom_sanitize::{SanitizeError, sanitize_provider_xray};
use kasumi_core::custom_target::Target;
use kasumi_core::profile::Profile;
use kasumi_core::provider_graph::{
    MAX_GRAPH_DEPTH, MAX_GRAPH_NODES, ProviderFragment, compile_custom_profile,
};
use kasumi_core::state::{AdvancedSettings, RoutingMode};
use kasumi_core::xray_config::{BuildKind, build_xray_config};
use serde_json::{Value, json};

fn server(tag: &str) -> Value {
    json!({
        "tag": tag, "protocol": "vless",
        "settings": { "vnext": [{ "address": "node.example", "port": 443,
            "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
        "streamSettings": { "network": "tcp", "security": "tls" }
    })
}

fn freedom(tag: &str) -> Value {
    json!({ "tag": tag, "protocol": "freedom" })
}

fn blackhole(tag: &str) -> Value {
    json!({ "tag": tag, "protocol": "blackhole" })
}

fn loopback(tag: Option<&str>, inbound_tag: &str) -> Value {
    let mut outbound = json!({ "protocol": "loopback", "settings": { "inboundTag": inbound_tag } });
    if let Some(t) = tag {
        outbound["tag"] = t.into();
    }
    outbound
}

fn virtual_config(rules: Value) -> Value {
    json!({
        "outbounds": [loopback(Some("entry"), "virtual"), server("exit")],
        "routing": { "rules": rules }
    })
}

fn custom_provider(raw: Value) -> Profile {
    serde_json::from_value(json!({
        "protocol": "custom",
        "meta": { "id": "p1", "remarks": "p1", "groupId": "g1" },
        "raw": raw.to_string(),
        "origin": "provider",
    }))
    .unwrap()
}

#[test]
fn implicit_fallback_becomes_explicit() {
    let cfg = json!({
        "outbounds": [server("default-exit"), server("other-exit")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["other-"],
                "strategy": { "type": "leastLoad" }
            }],
            "rules": [{
                "type": "field",
                "network": "tcp,udp",
                "balancerTag": "lb"
            }]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": "https://example.org/generate_204",
                "interval": "10s",
                "timeout": "2s",
                "sampling": 1
            },
            "subjectSelector": ["default-exit", "other-exit"]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization succeeds");
    assert_eq!(sanitized.fragment.balancers.len(), 1);
    let balancer = &sanitized.fragment.balancers[0];
    assert_eq!(balancer.tag, "lb");
    assert_eq!(balancer.fallback_tag.as_deref(), Some("default-exit"));

    let rendered = sanitized.fragment.render(&cfg.to_string()).unwrap();
    let emitted_b = &rendered.balancers[0];
    assert_eq!(
        emitted_b["fallbackTag"].as_str().unwrap(),
        rendered
            .outbounds
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "node.example")
            .unwrap()["tag"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn stateless_balancers_keep_ignoring_health_without_a_fallback() {
    // Xray only filters random/roundRobin members by health once the balancer
    // has a fallbackTag, so adding one would change which members they pick.
    let cfg = json!({
        "outbounds": [server("default-exit"), server("other-exit")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["other-"],
                "strategy": { "type": "roundRobin" }
            }],
            "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": "https://example.org/generate_204",
                "interval": "10s",
                "timeout": "2s",
                "sampling": 1
            },
            "subjectSelector": ["default-exit", "other-exit"]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization succeeds");
    let rendered = sanitized.fragment.render(&cfg.to_string()).unwrap();
    assert!(rendered.balancers[0].get("fallbackTag").is_none());
}

#[test]
fn loopback_entry_resolving_to_a_service_is_rejected() {
    let cfg = json!({
        "outbounds": [loopback(Some("entry"), "inside"), freedom("direct"), server("node")],
        "routing": { "rules": [
            { "type": "field", "inboundTag": ["inside"], "network": "tcp,udp", "outboundTag": "direct" }
        ] }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "the profile's default route is not a proxy"),
        "expected rejection of a loopback entry that ends in a service, got: {err:?}"
    );
}

#[test]
fn cycle_through_implicit_default_rejected() {
    let cfg = json!({
        "outbounds": [
            loopback(Some("lb-loopback"), "ctx-loop"),
            server("node-1")
        ],
        "routing": {
            "balancers": [{
                "tag": "lb-1",
                "selector": ["node-"],
                "strategy": { "type": "leastLoad" }
            }],
            "rules": [{
                "type": "field",
                "inboundTag": ["ctx-loop"],
                "network": "tcp,udp",
                "balancerTag": "lb-1"
            }]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": "https://example.org/generate_204",
                "interval": "10s",
                "timeout": "2s",
                "sampling": 1
            },
            "subjectSelector": ["node-"]
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "routing graph contains a cycle"),
        "expected cycle rejection through implicit default, got: {err:?}"
    );
}

#[test]
fn service_entry_rejected() {
    let freedom_first = json!({
        "outbounds": [freedom("direct"), server("proxy-node")]
    });
    let err = sanitize_provider_xray(&freedom_first).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "the profile's default route is not a proxy"),
        "expected rejection of service entry outbound, got: {err:?}"
    );

    let all_service_balancer = json!({
        "outbounds": [server("decoy"), freedom("f1"), blackhole("b1")],
        "routing": {
            "balancers": [{
                "tag": "svc-lb",
                "selector": ["f", "b"],
                "strategy": { "type": "roundRobin" }
            }],
            "rules": [{
                "type": "field",
                "network": "tcp,udp",
                "balancerTag": "svc-lb"
            }]
        }
    });
    let err = sanitize_provider_xray(&all_service_balancer).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { .. }),
        "expected rejection of service balancer, got: {err:?}"
    );
}

#[test]
fn udp_only_rule_provides_udp_target_while_tcp_uses_default_different_proxy_rejected() {
    let cfg = json!({
        "outbounds": [server("node-a"), server("node-b")],
        "routing": {
            "rules": [{
                "type": "field",
                "network": "udp",
                "outboundTag": "node-b"
            }]
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "ambiguous TCP and UDP targets"),
        "expected ambiguous targets error, got: {err:?}"
    );
}

#[test]
fn udp_service_target_falls_back_to_tcp_proxy_target_with_warning() {
    let cfg = json!({
        "outbounds": [server("node-a"), freedom("direct")],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "network": "udp",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "network": "tcp",
                    "outboundTag": "node-a"
                }
            ]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization succeeds");
    assert_eq!(
        sanitized.fragment.entry,
        kasumi_core::provider_graph::TargetRef::Outbound("node-a".into())
    );
    assert!(
        sanitized.dropped.iter().any(|d| d.contains("udpPolicy")),
        "expected dropped warning for ignored UDP service policy"
    );
}

#[test]
fn external_conditional_rules_absent_from_routing_and_reported() {
    let cfg = json!({
        "outbounds": [server("node-a")],
        "routing": {
            "rules": [
                { "type": "field", "domain": ["domain:blocked.example"], "outboundTag": "node-a" },
                { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "node-a" },
                { "type": "field", "port": "80,443", "outboundTag": "node-a" }
            ]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization succeeds");
    assert_eq!(sanitized.fragment.outbounds.len(), 1);
    assert!(sanitized.dropped.contains(&"routing.rules[0]".to_string()));
    assert!(sanitized.dropped.contains(&"routing.rules[1]".to_string()));
    assert!(sanitized.dropped.contains(&"routing.rules[2]".to_string()));
}

#[test]
fn global_mode_routing_contains_no_provider_external_rule() {
    let cfg = json!({
        "outbounds": [server("node-a"), server("node-b")],
        "routing": {
            "rules": [
                { "type": "field", "domain": ["domain:google.com"], "outboundTag": "node-b" },
                { "type": "field", "network": "tcp,udp", "outboundTag": "node-a" }
            ]
        }
    });
    let profile = custom_provider(cfg);
    let settings = AdvancedSettings {
        routing_mode: RoutingMode::Global,
        ..AdvancedSettings::default()
    };
    let xray_cfg = build_xray_config(&profile, &settings, &[], &[]).expect("build succeeds");
    let rules = xray_cfg["routing"]["rules"]
        .as_array()
        .expect("rules array");
    for rule in rules {
        assert!(
            rule.get("domain").is_none(),
            "global mode routing must not contain provider domain rules"
        );
    }
}

#[test]
fn context_with_conditional_scoped_rule_rejected() {
    let cfg = json!({
        "outbounds": [loopback(Some("lb-entry"), "v-context"), server("exit")],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["v-context"],
                "domain": ["example.com"],
                "outboundTag": "exit"
            }]
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "context-scoped conditional rules are not supported"),
        "expected rejection of context conditional rule, got: {err:?}"
    );
}

#[test]
fn every_xray_condition_key_makes_an_unscoped_rule_a_dropped_warning() {
    let conditions = [
        ("domain", json!(["domain:example.com"])),
        ("domains", json!(["domain:example.com"])),
        ("ip", json!(["10.0.0.0/8"])),
        ("port", json!("80,443")),
        ("sourceIP", json!(["10.0.0.0/8"])),
        ("source", json!(["10.0.0.0/8"])),
        ("sourcePort", json!("443")),
        ("user", json!(["user@example.com"])),
        ("vlessRoute", json!("1000-2000")),
        ("protocol", json!(["http"])),
        ("attrs", json!({ "x": "y" })),
        ("localIP", json!(["127.0.0.1"])),
        ("localPort", json!("1080")),
        ("process", json!(["curl"])),
    ];
    for (key, value) in conditions {
        let mut conditional_rule = serde_json::Map::new();
        conditional_rule.insert("type".into(), "field".into());
        conditional_rule.insert("outboundTag".into(), "node-a".into());
        conditional_rule.insert(key.into(), value.clone());
        let unconditional_rule = json!({ "type": "field", "outboundTag": "node-a" });
        let cfg = json!({
            "outbounds": [server("node-a")],
            "routing": { "rules": [unconditional_rule, Value::Object(conditional_rule)] }
        });
        let sanitized = sanitize_provider_xray(&cfg)
            .unwrap_or_else(|e| panic!("{key} rule must classify, got: {e:?}"));
        assert!(
            sanitized.dropped.contains(&"routing.rules[1]".to_string()),
            "unscoped {key} rule must be dropped with a warning"
        );
    }
}

#[test]
fn unscoped_source_condition_rules_are_dropped_with_a_warning() {
    let cfg = json!({
        "outbounds": [server("node-a")],
        "routing": {
            "rules": [
                { "type": "field", "sourcePort": "443", "outboundTag": "node-a" },
                { "type": "field", "source": ["10.0.0.0/8"], "outboundTag": "node-a" },
                { "type": "field", "process": ["curl"], "outboundTag": "node-a" }
            ]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization succeeds");
    assert!(sanitized.dropped.contains(&"routing.rules[0]".to_string()));
    assert!(sanitized.dropped.contains(&"routing.rules[1]".to_string()));
    assert!(sanitized.dropped.contains(&"routing.rules[2]".to_string()));
    let rendered = sanitized
        .fragment
        .render(&cfg.to_string())
        .expect("render succeeds");
    let rule_text = serde_json::to_string(&rendered.rules).expect("serialize rendered rules");
    assert!(!rule_text.contains("sourcePort"));
    assert!(!rule_text.contains("process"));
}

#[test]
fn context_scoped_source_condition_rules_are_rejected() {
    for (key, value) in [
        ("sourcePort", json!("443")),
        ("source", json!(["10.0.0.0/8"])),
        ("process", json!(["curl"])),
        ("localPort", json!("1080")),
    ] {
        let mut rule = serde_json::Map::new();
        rule.insert("type".into(), "field".into());
        rule.insert("inboundTag".into(), json!(["v-context"]));
        rule.insert("outboundTag".into(), "exit".into());
        rule.insert(key.into(), value);
        let cfg = json!({
            "outbounds": [loopback(Some("lb-entry"), "v-context"), server("exit")],
            "routing": { "rules": [Value::Object(rule)] }
        });
        let err = sanitize_provider_xray(&cfg)
            .err()
            .unwrap_or_else(|| panic!("expected rejection of context-scoped {key} rule"));
        assert!(
            matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "context-scoped conditional rules are not supported"),
            "expected rejection of context-scoped {key} rule, got: {err:?}"
        );
    }
}

#[test]
fn rule_tag_is_kept_as_rule_metadata() {
    let cfg = json!({
        "outbounds": [loopback(Some("lb-entry"), "v-context"), server("exit")],
        "routing": {
            "rules": [{
                "type": "field",
                "ruleTag": "ctx-route",
                "inboundTag": ["v-context"],
                "network": "tcp,udp",
                "outboundTag": "exit"
            }]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("ruleTag is metadata, not a condition");
    assert!(sanitized.dropped.is_empty());
}

#[test]
fn unknown_rule_condition_keys_are_still_rejected() {
    let cfg = json!({
        "outbounds": [server("node-a")],
        "routing": {
            "rules": [
                { "type": "field", "sourceTag": ["x"], "outboundTag": "node-a" }
            ]
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "unsupported rule field"),
        "expected rejection of unknown rule key, got: {err:?}"
    );
}

#[test]
fn plain_entry_gets_tag_proxy_without_loopback() {
    let cfg = json!({
        "outbounds": [server("single-node")]
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization succeeds");
    assert!(sanitized.fragment.plain_entry);

    let profile = custom_provider(cfg);
    let Profile::Custom(c) = profile else {
        unreachable!()
    };
    let active = compile_custom_profile(&c, &[], BuildKind::Runtime).unwrap();
    assert_eq!(active.target, Target::Outbound("proxy".into()));
    assert_eq!(active.outbounds.len(), 1);
    assert_eq!(active.outbounds[0]["tag"], "proxy");
    assert_eq!(active.outbounds[0]["protocol"], "vless");
    assert!(
        !active
            .rules
            .iter()
            .any(|r| r["inboundTag"] == json!(["proxy-select"]))
    );
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
    for key in ["SockOpt", "SOCKOPT", "sockopt"] {
        let mut outbound = server("exit");
        outbound["streamSettings"][key]["dialerProxy"] = "entry".into();
        if key == "sockopt" {
            let sanitized = sanitize_provider_xray(&json!({
                "outbounds": [outbound, server("entry")]
            }))
            .expect("canonical sockopt.dialerProxy dials through the graph");
            assert!(
                sanitized
                    .fragment
                    .outbounds
                    .iter()
                    .any(|o| o.tag == "exit" && o.dialer_proxy.as_deref() == Some("entry"))
            );
        } else {
            assert!(matches!(
                sanitize_provider_xray(&json!({ "outbounds": [outbound, server("entry")] })),
                Err(SanitizeError::Incompatible { .. })
            ));
        }
    }
    for wrapper in ["ProxySettings", "PROXYSETTINGS"] {
        let mut outbound = server("exit");
        outbound[wrapper]["tag"] = "entry".into();
        assert!(matches!(
            sanitize_provider_xray(&json!({ "outbounds": [outbound, server("entry")] })),
            Err(SanitizeError::Incompatible { .. })
        ));
    }
    for key in ["Tag", "TAG"] {
        let mut outbound = server("exit");
        outbound["proxySettings"][key] = "entry".into();
        assert!(matches!(
            sanitize_provider_xray(&json!({ "outbounds": [outbound, server("entry")] })),
            Err(SanitizeError::Incompatible { .. })
        ));
    }
    let mut outbound = server("exit");
    outbound["proxySettings"]["tag"] = "entry".into();
    let sanitized = sanitize_provider_xray(&json!({ "outbounds": [outbound, server("entry")] }))
        .expect("canonical proxySettings.tag dials through the graph");
    assert!(
        sanitized
            .fragment
            .outbounds
            .iter()
            .any(|o| o.tag == "exit" && o.dialer_proxy.as_deref() == Some("entry"))
    );
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
        let res = sanitize_provider_xray(&json!({ "outbounds": outbounds }));
        match res {
            Err(SanitizeError::Incompatible {
                ref path,
                ref reason,
            }) => {
                assert_eq!(
                    *reason, "routing graph exceeds depth limit",
                    "path={path}, reason={reason}"
                );
            }
            Err(e) => panic!("other error: {e:?}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
        outbounds.rotate_left(1);
    }
}

#[test]
fn an_unnamed_first_loopback_cannot_implicitly_route_back_to_itself() {
    assert!(matches!(
        sanitize_provider_xray(
            &json!({ "outbounds": [loopback(None, "virtual"), server("exit")] })
        ),
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
fn synthetic_cascade_profile_preserves_structure_and_adds_explicit_fallback() {
    let cfg = json!({
        "outbounds": [
            server("default-exit"),
            server("node-1"),
            server("node-2"),
            loopback(Some("lb-sticky-fb"), "v-sticky-in"),
            loopback(Some("lb-main-fb"), "v-main-in"),
            loopback(Some("lb-lte-fb"), "v-lte-in"),
        ],
        "routing": {
            "balancers": [
                {
                    "tag": "balancer-all",
                    "selector": ["node-2"],
                    "strategy": { "type": "leastLoad" }
                    // No fallbackTag: implicit fallback to default-exit
                },
                {
                    "tag": "balancer-lte",
                    "selector": ["node-2"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "lb-lte-fb"
                },
                {
                    "tag": "balancer-main",
                    "selector": ["node-1"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "lb-main-fb"
                },
                {
                    "tag": "balancer-sticky",
                    "selector": ["node-1"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "lb-sticky-fb"
                }
            ],
            "rules": [
                { "type": "field", "inboundTag": ["v-lte-in"], "balancerTag": "balancer-all" },
                { "type": "field", "inboundTag": ["v-main-in"], "balancerTag": "balancer-lte" },
                { "type": "field", "inboundTag": ["v-sticky-in"], "balancerTag": "balancer-main" },
                { "type": "field", "network": "tcp,udp", "balancerTag": "balancer-sticky" }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": "https://example.org/generate_204",
                "interval": "3m",
                "timeout": "3s",
                "sampling": 5
            },
            "subjectSelector": ["node-1", "node-2"]
        }
    });

    let sanitized = sanitize_provider_xray(&cfg).expect("cascade must sanitize");
    assert_eq!(
        sanitized.fragment.entry,
        kasumi_core::provider_graph::TargetRef::Balancer("balancer-sticky".into())
    );
    assert_eq!(sanitized.fragment.balancers.len(), 4);
    let all_bal = sanitized
        .fragment
        .balancers
        .iter()
        .find(|b| b.tag == "balancer-all")
        .unwrap();
    assert_eq!(all_bal.fallback_tag.as_deref(), Some("default-exit"));

    let rendered = sanitized
        .fragment
        .render(&cfg.to_string())
        .expect("cascade must render");
    assert!(rendered.burst_observatory.is_some());
    assert_eq!(rendered.rules[0]["inboundTag"], json!(["proxy-select"]));
    assert!(
        rendered.rules[0]["balancerTag"]
            .as_str()
            .unwrap()
            .contains(":b:")
    );
    assert_eq!(rendered.rules.len(), 4);
}

#[test]
fn a_bare_string_balancer_strategy_is_rejected() {
    let cfg = json!({
        "outbounds": [server("node-a")],
        "routing": {
            "balancers": [{ "tag": "lb", "selector": ["node-"], "strategy": "random" }],
            "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "lb" }]
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { ref path, .. } if path == "routing.balancers[0].strategy"),
        "expected rejection of a string strategy, got: {err:?}"
    );
}

#[test]
fn an_outbound_naming_two_dialer_hops_is_rejected() {
    let mut chained = server("node-a");
    chained["streamSettings"]["sockopt"] = json!({ "dialerProxy": "hop-1" });
    chained["proxySettings"] = json!({ "tag": "hop-2" });
    let cfg = json!({ "outbounds": [chained, server("hop-1"), server("hop-2")] });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "both dialerProxy and proxySettings.tag are set"),
        "expected rejection of two dialer hops, got: {err:?}"
    );
}

#[test]
fn a_null_or_empty_dialer_proxy_does_not_conflict_with_proxy_settings() {
    for unset in [Value::Null, json!("")] {
        let mut chained = server("node-a");
        chained["streamSettings"]["sockopt"] = json!({ "dialerProxy": unset });
        chained["proxySettings"] = json!({ "tag": "hop-1" });
        let cfg = json!({ "outbounds": [chained, server("hop-1")] });
        let sanitized = sanitize_provider_xray(&cfg)
            .unwrap_or_else(|e| panic!("dialerProxy {unset} should name no hop: {e:?}"));
        assert_eq!(
            sanitized.fragment.outbounds[0].dialer_proxy.as_deref(),
            Some("hop-1")
        );
    }
}

#[test]
fn proxy_settings_without_a_tag_is_rejected() {
    for missing in [json!({}), json!({ "tag": "" }), json!({ "tag": null })] {
        let mut chained = server("node-a");
        chained["proxySettings"] = missing.clone();
        let cfg = json!({ "outbounds": [chained, server("hop-1")] });
        let err = sanitize_provider_xray(&cfg).unwrap_err();
        assert!(
            matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "proxySettings requires a tag"),
            "expected rejection of proxySettings {missing}, got: {err:?}"
        );
    }
}

#[test]
fn rules_without_a_type_are_accepted_like_xray_does() {
    // Xray parses every routing rule as a field rule, so providers often leave
    // `type` out; both the entry rule and a context rule must still count.
    let cfg = json!({
        "outbounds": [
            server("decoy"),
            server("node-a"),
            loopback(Some("fallback"), "inside"),
        ],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-"],
                "strategy": { "type": "leastLoad" },
                "fallbackTag": "fallback"
            }],
            "rules": [
                { "inboundTag": ["inside"], "network": "tcp,udp", "outboundTag": "decoy" },
                { "network": "tcp,udp", "balancerTag": "lb" }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": "https://example.org/generate_204",
                "interval": "10s",
                "timeout": "2s",
                "sampling": 1
            },
            "subjectSelector": ["node-"]
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("rules without type are valid Xray");
    assert_eq!(
        sanitized.fragment.entry,
        kasumi_core::provider_graph::TargetRef::Balancer("lb".into())
    );
    assert_eq!(sanitized.fragment.contexts.len(), 1);
}

#[test]
fn a_stateless_balancer_fallback_without_an_observatory_is_dropped_with_a_warning() {
    // Xray refuses to start a random/roundRobin balancer that names a fallback
    // when nothing observes its members; the members themselves still route.
    for strategy in [
        Value::Null,
        json!({ "type": "random" }),
        json!({ "type": "roundRobin" }),
    ] {
        let mut balancer = json!({ "tag": "lb", "selector": ["node-"], "fallbackTag": "direct" });
        if !strategy.is_null() {
            balancer["strategy"] = strategy.clone();
        }
        let cfg = json!({
            "outbounds": [server("node-a"), server("node-b"), freedom("direct")],
            "routing": {
                "balancers": [balancer],
                "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
            }
        });
        let sanitized =
            sanitize_provider_xray(&cfg).unwrap_or_else(|e| panic!("strategy {strategy}: {e:?}"));
        assert!(
            sanitized
                .dropped
                .iter()
                .any(|d| d == "routing.balancers[0].fallbackTag"),
            "strategy {strategy}: {:?}",
            sanitized.dropped
        );
        let rendered = sanitized.fragment.render(&cfg.to_string()).unwrap();
        assert!(rendered.balancers[0].get("fallbackTag").is_none());
        assert_eq!(
            rendered.balancers[0]["selector"].as_array().unwrap().len(),
            2
        );
    }
}

#[test]
fn an_observation_balancer_without_an_observatory_is_still_rejected() {
    let cfg = json!({
        "outbounds": [server("node-a"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": { "type": "leastPing" }, "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "balancer members not covered by observatory"),
        "got: {err:?}"
    );
}

#[test]
fn observed_loopbacks_cannot_hide_service_only_probe_paths() {
    for (kind, observation) in [
        (
            "observatory",
            json!({
                "subjectSelector": ["watched"],
                "probeURL": "https://example.org/generate_204", "probeInterval": "10s"
            }),
        ),
        (
            "burstObservatory",
            json!({
                "subjectSelector": ["watched"],
                "pingConfig": {
                    "destination": "https://example.org/generate_204",
                    "interval": "10s", "timeout": "2s", "sampling": 1
                }
            }),
        ),
    ] {
        let mut cfg = json!({
            "outbounds": [server("node-main"), loopback(Some("watched"), "inside"), freedom("direct")],
            "routing": { "rules": [
                { "inboundTag": ["inside"], "network": "tcp,udp", "outboundTag": "direct" },
                { "network": "tcp,udp", "outboundTag": "node-main" }
            ] }
        });
        cfg[kind] = observation;
        let err = sanitize_provider_xray(&cfg).unwrap_err();
        assert!(
            matches!(err, SanitizeError::Incompatible { ref path, reason } if path == &format!("{kind}.subjectSelector") && reason == "observatory selector matches service outbound"),
            "{kind} must not probe through a service-only loopback: {err:?}"
        );
    }
}

#[test]
fn a_burst_ping_label_is_omitted_without_changing_probes() {
    let cfg = json!({
        "outbounds": [server("node-a")],
        "burstObservatory": {
            "subjectSelector": ["node-"],
            "pingConfig": {
                "tag": "diagnostic-label",
                "destination": "https://example.org/generate_204",
                "httpMethod": "HEAD", "interval": "10s", "timeout": "2s", "sampling": 1
            }
        }
    });
    let sanitized = sanitize_provider_xray(&cfg).expect("the ping label is not an Xray setting");
    assert!(
        sanitized
            .dropped
            .iter()
            .any(|path| path == "burstObservatory.pingConfig.tag")
    );
    let rendered = sanitized.fragment.render(&cfg.to_string()).unwrap();
    let ping = &rendered.burst_observatory.as_ref().unwrap()["pingConfig"];
    assert!(ping.get("tag").is_none());
    assert_eq!(ping["httpMethod"], "HEAD");
    assert_eq!(ping["destination"], "https://example.org/generate_204");
    let persisted = sanitized.into_provider_json();
    assert!(
        persisted["burstObservatory"]["pingConfig"]
            .get("tag")
            .is_none()
    );
    let again = sanitize_provider_xray(&persisted).unwrap();
    assert!(
        !again
            .dropped
            .iter()
            .any(|path| path == "burstObservatory.pingConfig.tag")
    );
}

#[test]
fn burst_observatory_connectivity_is_stripped_with_warning_and_stable_across_reingest() {
    let raw_burst_obs = json!({
        "pingConfig": {
            "destination": "https://example.org/generate_204",
            "connectivity": "https://example.org/connectivity_check",
            "interval": "10s",
            "timeout": "2s",
            "sampling": 1
        },
        "subjectSelector": ["node-"]
    });
    let cfg = json!({
        "outbounds": [server("node-1"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": { "type": "leastPing" }, "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "burstObservatory": raw_burst_obs
    });

    // 1. Sanitizer succeeds and records dropped warning for connectivity
    let sanitized = sanitize_provider_xray(&cfg).expect("sanitization should succeed");
    assert!(
        sanitized
            .dropped
            .contains(&"burstObservatory.pingConfig.connectivity".to_string())
    );

    // 2. Fragment and sanitized struct have connectivity stripped while retaining destination
    let bobs = sanitized.burst_observatory.as_ref().unwrap();
    let ping_cfg = bobs.get("pingConfig").unwrap();
    assert_eq!(
        ping_cfg.get("destination").and_then(Value::as_str),
        Some("https://example.org/generate_204")
    );
    assert!(ping_cfg.get("connectivity").is_none());

    // 3. Persisted provider JSON omits connectivity
    let persisted = sanitized.into_provider_json();
    let persisted_ping_cfg = &persisted["burstObservatory"]["pingConfig"];
    assert!(persisted_ping_cfg.get("connectivity").is_none());
    assert_eq!(
        persisted_ping_cfg
            .get("destination")
            .and_then(Value::as_str),
        Some("https://example.org/generate_204")
    );

    // 4. Re-sanitizing persisted JSON is stable and idempotent
    let resanitized = sanitize_provider_xray(&persisted).expect("resanitize should succeed");
    assert!(
        !resanitized
            .dropped
            .contains(&"burstObservatory.pingConfig.connectivity".to_string())
    );
    assert_eq!(resanitized.clone().into_provider_json(), persisted);

    // 5. Rendered active outbounds retains burstObservatory and destination, omits connectivity
    let raw_str = persisted.to_string();
    let active = resanitized
        .fragment
        .render(&raw_str)
        .expect("render should succeed");
    let active_burst_obs = active.burst_observatory.unwrap();
    assert_eq!(
        active_burst_obs["pingConfig"]["destination"],
        "https://example.org/generate_204"
    );
    assert!(active_burst_obs["pingConfig"].get("connectivity").is_none());

    // 6. Direct ProviderFragment::build API still rejects unstripped connectivity
    let direct_err = ProviderFragment::build(
        vec![server("node-1")],
        None,
        None,
        Some(&cfg["burstObservatory"]),
        &[],
    )
    .unwrap_err();
    assert_eq!(
        direct_err,
        SanitizeError::Incompatible {
            path: "burstObservatory.pingConfig.connectivity".into(),
            reason: "unsupported burst connectivity check",
        }
    );
}

fn balancer_leastload_config(costs: Value) -> Value {
    json!({
        "outbounds": [server("node-1"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": costs
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    })
}

#[test]
fn costs_on_non_leastload_strategies_are_rejected() {
    for strat in ["random", "roundRobin", "leastPing"] {
        let cfg = json!({
            "outbounds": [server("node-1"), freedom("direct")],
            "routing": {
                "balancers": [{
                    "tag": "lb", "selector": ["node-"],
                    "strategy": {
                        "type": strat,
                        "settings": {
                            "costs": [{ "match": "node-1", "value": 2 }]
                        }
                    },
                    "fallbackTag": "direct"
                }],
                "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
            },
            "observatory": {
                "subjectSelector": ["node-"],
                "probeURL": "https://example.org/generate_204",
                "probeInterval": "10s"
            }
        });
        let err = sanitize_provider_xray(&cfg).unwrap_err();
        assert_eq!(
            err,
            SanitizeError::Incompatible {
                path: "routing.balancers[0].strategy.settings.costs".into(),
                reason: "leastLoad costs is not supported",
            }
        );
    }
}

#[test]
fn object_and_non_array_costs_are_rejected_while_null_and_empty_are_accepted() {
    // Non-array types reject
    for invalid in [json!({"match": "node"}), json!("string"), json!(42)] {
        let cfg = balancer_leastload_config(invalid);
        let err = sanitize_provider_xray(&cfg).unwrap_err();
        assert_eq!(
            err,
            SanitizeError::Incompatible {
                path: "routing.balancers[0].strategy.settings.costs".into(),
                reason: "balancer costs must be an array",
            }
        );
    }

    // null and empty array are accepted
    for valid in [Value::Null, json!([])] {
        let cfg = balancer_leastload_config(valid);
        assert!(sanitize_provider_xray(&cfg).is_ok());
    }
}

#[test]
fn null_and_non_object_cost_entries_are_safely_rejected() {
    let cfg_null = balancer_leastload_config(json!([null]));
    assert_eq!(
        sanitize_provider_xray(&cfg_null).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0]".into(),
            reason: "cost entry cannot be null",
        }
    );

    let cfg_number = balancer_leastload_config(json!([123]));
    assert_eq!(
        sanitize_provider_xray(&cfg_number).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0]".into(),
            reason: "cost entry must be an object",
        }
    );
}

#[test]
fn unknown_cost_fields_and_invalid_field_types_are_rejected() {
    let cfg_unknown = balancer_leastload_config(json!([{"match": "a", "extra": true}]));
    assert_eq!(
        sanitize_provider_xray(&cfg_unknown).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0].extra".into(),
            reason: "unknown cost rule field",
        }
    );

    let cfg_bad_match = balancer_leastload_config(json!([{"match": 123}]));
    assert_eq!(
        sanitize_provider_xray(&cfg_bad_match).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0].match".into(),
            reason: "cost match must be a string",
        }
    );

    let cfg_bad_regexp = balancer_leastload_config(json!([{"regexp": "yes"}]));
    assert_eq!(
        sanitize_provider_xray(&cfg_bad_regexp).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0].regexp".into(),
            reason: "cost regexp must be a boolean",
        }
    );

    let cfg_bad_value = balancer_leastload_config(json!([{"value": "ten"}]));
    assert_eq!(
        sanitize_provider_xray(&cfg_bad_value).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0].value".into(),
            reason: "cost value must be a number",
        }
    );
}

#[test]
fn explicit_f32_overflow_is_rejected() {
    let cfg = balancer_leastload_config(json!([{"match": "node", "value": 1e40}]));
    assert_eq!(
        sanitize_provider_xray(&cfg).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0].value".into(),
            reason: "cost value exceeds float32 range",
        }
    );
}

#[test]
fn auto_cost_zero_and_non_exact_f32_are_rejected() {
    // Auto cost 0
    let cfg_zero = json!({
        "outbounds": [server("node-0"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [{ "match": "node-0", "value": 0 }]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });
    assert_eq!(
        sanitize_provider_xray(&cfg_zero).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0]".into(),
            reason: "auto cost value cannot be zero",
        }
    );

    // Auto cost 0.1 (not exact f32)
    let cfg_inexact = json!({
        "outbounds": [server("node-0.1"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [{ "match": "node-[0-9.]+", "regexp": true }]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });
    assert_eq!(
        sanitize_provider_xray(&cfg_inexact).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0]".into(),
            reason: "auto cost value requires exact float32 representation",
        }
    );
}

#[test]
fn unsupported_and_invalid_regex_syntax_are_rejected() {
    let cases = [
        ("node\\Qabc\\E", "unsupported regex syntax: literal quoting"),
        ("(?x)node", "unsupported regex flag"),
        ("(?u)node", "unsupported regex flag"),
        ("(?R)node", "unsupported regex flag"),
        ("[a-z&&[0-9]]", "unsupported regex character class operator"),
        ("[a-z--[d]]", "unsupported regex character class operator"),
        ("[a-z~~[d]]", "unsupported regex character class operator"),
        ("[a[b]]", "unsupported regex nested character class"),
        ("\\u0033", "unsupported regex escape sequence"),
        ("\\U00000033", "unsupported regex escape sequence"),
        ("\\<3", "unsupported regex escape sequence"),
        ("\\1", "unsupported regex escape sequence"),
        ("a**", "unsupported regex stacked quantifier"),
        ("a++", "unsupported regex stacked quantifier"),
        ("a{1001}", "regex repetition count exceeds limit"),
        ("(a{100}){11}", "regex repetition count exceeds limit"),
        ("a{01}", "unsupported regex quantifier spelling"),
        ("a{ 2 }", "unsupported regex quantifier spelling"),
        ("(?P<a.b>node)", "invalid regex capture group name"),
        ("[--9]", "unsupported regex character class syntax"),
        ("[---]", "unsupported regex character class syntax"),
        ("[a-z", "invalid regex pattern"),
    ];

    for (pat, expected_reason) in cases {
        let cfg = balancer_leastload_config(json!([{"match": pat, "regexp": true, "value": 2}]));
        let err = sanitize_provider_xray(&cfg).unwrap_err();
        assert_eq!(
            err,
            SanitizeError::Incompatible {
                path: "routing.balancers[0].strategy.settings.costs[0].match".into(),
                reason: expected_reason,
            },
            "pattern {pat} should fail with {expected_reason}"
        );
    }
}

#[test]
fn bounded_non_ascii_regex_rejected_but_unicode_literal_costs_accepted() {
    // Non-ASCII regex pattern rejected
    let cfg_non_ascii_pattern =
        balancer_leastload_config(json!([{"match": "node-東京", "regexp": true, "value": 2}]));
    assert_eq!(
        sanitize_provider_xray(&cfg_non_ascii_pattern).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs[0].match".into(),
            reason: "regexp costs require ASCII pattern",
        }
    );

    // Non-ASCII candidate tag with regex rule rejected
    let cfg_non_ascii_tag = json!({
        "outbounds": [server("node-東京"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [{ "match": "node", "regexp": true, "value": 2 }]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });
    assert_eq!(
        sanitize_provider_xray(&cfg_non_ascii_tag).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs".into(),
            reason: "regexp costs require ASCII tags",
        }
    );

    // Non-ASCII candidate tag with substring literal rule IS ACCEPTED!
    let cfg_unicode_literal = json!({
        "outbounds": [server("node-東京"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb", "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [{ "match": "東京", "regexp": false, "value": 3.0 }]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });
    let sanitized =
        sanitize_provider_xray(&cfg_unicode_literal).expect("unicode literal should be accepted");
    let active = sanitized
        .fragment
        .render(&cfg_unicode_literal.to_string())
        .expect("render succeeds");
    let b = &active.balancers[0];
    let rendered_costs = b["strategy"]["settings"]["costs"].as_array().unwrap();
    assert_eq!(rendered_costs.len(), 1);
    assert_eq!(rendered_costs[0]["value"], 3.0);
}

#[test]
fn cost_rule_count_limits_are_enforced() {
    let too_many_rules: Vec<Value> = (0..65)
        .map(|i| json!({ "match": format!("node-{i}"), "value": 1 }))
        .collect();
    let cfg = balancer_leastload_config(Value::Array(too_many_rules));
    assert_eq!(
        sanitize_provider_xray(&cfg).unwrap_err(),
        SanitizeError::Incompatible {
            path: "routing.balancers[0].strategy.settings.costs".into(),
            reason: "balancer costs exceeds maximum rule limit",
        }
    );
}

#[test]
fn valid_parent_leastload_with_loopback_members_to_child_random_pools() {
    let cfg = json!({
        "outbounds": [
            server("node-child-1"),
            server("node-child-2"),
            loopback(Some("loop-child"), "v-child"),
            freedom("direct")
        ],
        "routing": {
            "balancers": [
                {
                    "tag": "bal-child",
                    "selector": ["node-child-"],
                    "strategy": { "type": "random" }
                },
                {
                    "tag": "bal-parent",
                    "selector": ["loop-child"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "direct"
                }
            ],
            "rules": [
                { "inboundTag": ["v-child"], "balancerTag": "bal-child" },
                { "network": "tcp,udp", "balancerTag": "bal-parent" }
            ]
        },
        "observatory": {
            "subjectSelector": ["loop-child"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let sanitized =
        sanitize_provider_xray(&cfg).expect("parent with loopback member should be accepted");
    assert_eq!(sanitized.fragment.balancers.len(), 2);
    let parent_b = sanitized
        .fragment
        .balancers
        .iter()
        .find(|b| b.tag == "bal-parent")
        .unwrap();
    assert_eq!(parent_b.members, vec!["loop-child"]);
    assert_eq!(parent_b.fallback_tag.as_deref(), Some("direct"));
}

#[test]
fn loopback_service_primary_candidate_rejected() {
    let cfg = json!({
        "outbounds": [
            loopback(Some("loop-srv"), "v-srv"),
            freedom("direct")
        ],
        "routing": {
            "balancers": [
                {
                    "tag": "bal-all-service",
                    "selector": ["loop-srv"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "direct"
                }
            ],
            "rules": [
                { "inboundTag": ["v-srv"], "outboundTag": "direct" },
                { "network": "tcp,udp", "balancerTag": "bal-all-service" }
            ]
        },
        "observatory": {
            "subjectSelector": ["loop-srv"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert_eq!(
        err,
        SanitizeError::Incompatible {
            path: "routing.balancers".into(),
            reason: "the profile's default route is not a proxy",
        }
    );
}

#[test]
fn named_and_noncapturing_groups_accepted_without_flag_misclassification() {
    let good_patterns = [
        "(?P<proxy>node)",
        "(?<proxy>node)",
        "(?:node)",
        "(?i)node",
        "[a-z[:digit:]]",
    ];

    for pat in good_patterns {
        let cfg = balancer_leastload_config(json!([{"match": pat, "regexp": true, "value": 2}]));
        assert!(
            sanitize_provider_xray(&cfg).is_ok(),
            "pattern '{pat}' should be accepted"
        );
    }
}

#[test]
fn burst_observatory_http_method_validation_and_preservation() {
    fn burst_cfg(method: Value) -> Value {
        json!({
            "outbounds": [server("node-1"), freedom("direct")],
            "routing": {
                "balancers": [{
                    "tag": "lb", "selector": ["node-"],
                    "strategy": { "type": "leastPing" }, "fallbackTag": "direct"
                }],
                "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
            },
            "burstObservatory": {
                "pingConfig": {
                    "destination": "https://example.org/generate_204",
                    "interval": "10s",
                    "timeout": "2s",
                    "sampling": 1,
                    "httpMethod": method
                },
                "subjectSelector": ["node-"]
            }
        })
    }

    // 1. Valid methods: GET, HEAD, whitespace, empty, null
    for valid in [
        json!("GET"),
        json!("HEAD"),
        json!("  GET  "),
        json!(""),
        json!("   "),
        Value::Null,
    ] {
        let cfg = burst_cfg(valid.clone());
        let sanitized = sanitize_provider_xray(&cfg).expect("valid httpMethod should be accepted");
        let raw_str = sanitized.clone().into_provider_json().to_string();
        let rendered = sanitized.fragment.render(&raw_str).expect("render");
        let bobs = rendered.burst_observatory.unwrap();
        if let Some(s) = valid.as_str() {
            assert_eq!(bobs["pingConfig"]["httpMethod"], s);
        }
    }

    // 2. Non-idempotent / unsupported methods rejected
    for invalid_method in ["POST", "PUT", "DELETE", "PATCH", "CONNECT"] {
        let cfg = burst_cfg(json!(invalid_method));
        let err = sanitize_provider_xray(&cfg).unwrap_err();
        assert_eq!(
            err,
            SanitizeError::Incompatible {
                path: "burstObservatory.pingConfig.httpMethod".into(),
                reason: "unsupported probe HTTP method",
            }
        );
    }

    // 3. Non-string type rejected
    let cfg_num = burst_cfg(json!(123));
    assert_eq!(
        sanitize_provider_xray(&cfg_num).unwrap_err(),
        SanitizeError::Incompatible {
            path: "burstObservatory.pingConfig.httpMethod".into(),
            reason: "httpMethod must be a string",
        }
    );
}

#[test]
fn canonical_hyphen_character_classes_are_accepted() {
    let valid_hyphens = ["[-a]", "[^-a]", "[a-]", "[a\\-b]", "[\\--9]", "[0-9]"];

    for pat in valid_hyphens {
        let cfg = balancer_leastload_config(json!([{"match": pat, "regexp": true, "value": 2}]));
        assert!(
            sanitize_provider_xray(&cfg).is_ok(),
            "pattern '{pat}' should be accepted"
        );
    }
}

#[test]
fn mixed_loopback_service_candidate_in_balancer_rejected() {
    let cfg = json!({
        "outbounds": [
            server("node-proxy"),
            loopback(Some("loop-srv"), "v-srv"),
            freedom("direct")
        ],
        "routing": {
            "balancers": [
                {
                    "tag": "lb-mixed",
                    "selector": ["node-proxy", "loop-srv"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "direct"
                }
            ],
            "rules": [
                { "inboundTag": ["v-srv"], "outboundTag": "direct" },
                { "network": "tcp,udp", "balancerTag": "lb-mixed" }
            ]
        },
        "observatory": {
            "subjectSelector": ["node-proxy", "loop-srv"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert_eq!(
        err,
        SanitizeError::Incompatible {
            path: "routing.balancers[0].selector".into(),
            reason: "balancer selector matches service outbound",
        }
    );
}

#[test]
fn profile_costs_matching_text_budget_exceeded_rejected() {
    // Reusing the same tag in different balancers still consumes the shared
    // matching budget, even though each individual candidate set is small.
    let large_tag = format!("node-{}", "a".repeat(70 * 1024));
    let rules: Vec<Value> = (0..64)
        .map(|i| json!({ "match": format!("rule-{i}"), "value": 1 }))
        .collect();
    let balancers: Vec<Value> = (0..16)
        .map(|i| {
            json!({
                "tag": format!("lb-{i}"), "selector": ["node-"],
                "strategy": { "type": "leastLoad", "settings": { "costs": rules } }
            })
        })
        .collect();
    let cfg = json!({
        "outbounds": [server(&large_tag)],
        "routing": {
            "balancers": balancers,
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb-0" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204", "probeInterval": "10s"
        }
    });
    let err = sanitize_provider_xray(&cfg).unwrap_err();
    assert!(
        matches!(err, SanitizeError::Incompatible { reason, .. } if reason == "profile costs exceeds matching text budget"),
        "expected the profile-wide matching budget to reject repeated scanning: {err:?}"
    );
}
