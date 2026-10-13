//! For every core, TUN engine, proxy mode, host and app filter, the data-path plan,
//! the config built with it and the state recorded from it describe the same data
//! path. Start, the watchdog and teardown each read one of these, so a combination
//! where they disagree is a data path that gets torn down or never bridged.

use serde_json::Value;
use strum::IntoEnumIterator;

use kasumi_core::app_process::apply_process_filter;
use kasumi_core::contract::RunState;
use kasumi_core::core_config::{CoreConfig, build_core_config};
use kasumi_core::data_path_plan::{AppRouting, HostTraits, TunPlan};
use kasumi_core::data_path_state::DataPathState;
use kasumi_core::enums::{CoreEngine, TunEngine};
use kasumi_core::profile::{Profile, Protocol};
use kasumi_core::share::parse_share_link;
use kasumi_core::state::{AdvancedSettings, AppFilterMode, ProxyMode, SingboxStack};

const HOSTS: [HostTraits; 2] = [
    HostTraits {
        proxy_modes: false,
        app_routing: AppRouting::PerUid,
        pinned_singbox_stack: None,
    },
    HostTraits {
        proxy_modes: true,
        app_routing: AppRouting::PerProcess,
        pinned_singbox_stack: Some(SingboxStack::Gvisor),
    },
];
const MODES: [ProxyMode; 4] = [
    ProxyMode::Tun,
    ProxyMode::ProxyOnly,
    ProxyMode::System,
    ProxyMode::Pac,
];
const UID_KEY: &str = "org.game:10200";
const EXE_KEY: &str = "exe:/usr/bin/curl";

fn profile() -> Profile {
    parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None).unwrap()
}

fn inbounds(cfg: &Value) -> &Vec<Value> {
    cfg["inbounds"].as_array().unwrap()
}

fn inbound<'a>(cfg: &'a Value, tag: &str) -> Option<&'a Value> {
    inbounds(cfg).iter().find(|i| i["tag"] == tag)
}

fn port(inbound: &Value) -> u16 {
    let port = inbound
        .get("listen_port")
        .or_else(|| inbound.get("port"))
        .and_then(Value::as_u64)
        .unwrap();
    u16::try_from(port).unwrap()
}

struct Case {
    engine: CoreEngine,
    tun: TunEngine,
    mode: ProxyMode,
    host: HostTraits,
    force_key: Option<&'static str>,
    http_port: Option<u16>,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for engine in CoreEngine::iter() {
        for tun in TunEngine::iter() {
            for mode in MODES {
                for host in HOSTS {
                    for force_key in [None, Some(UID_KEY), Some(EXE_KEY)] {
                        for http_port in [None, Some(10810)] {
                            out.push(Case {
                                engine,
                                tun,
                                mode,
                                host,
                                force_key,
                                http_port,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

fn settings(c: &Case) -> AdvancedSettings {
    let mut s = AdvancedSettings {
        proxy_mode: c.mode,
        local_http_port: c.http_port,
        ..Default::default()
    };
    s.core_by_protocol.insert(Protocol::Vless, c.engine);
    s.tun_by_core.insert(c.engine, c.tun);
    if let Some(key) = c.force_key {
        s.app_filter.insert(key.into(), AppFilterMode::ForceProxy);
    }
    s
}

fn build(c: &Case, s: &AdvancedSettings) -> CoreConfig {
    let p = profile();
    build_core_config(&p, s, &[], std::slice::from_ref(&p), "", c.host).unwrap()
}

#[test]
fn plan_config_and_state_agree() {
    for c in cases() {
        let s = settings(&c);
        let built = build(&c, &s);
        let plan = &built.plan;
        let at = format!(
            "{:?} + {:?}, {:?}, {:?}, force {:?}, http {:?}",
            c.engine, c.tun, c.mode, c.host, c.force_key, c.http_port
        );
        assert_eq!(plan.engine, c.engine, "{at}");

        let mode = if c.host.proxy_modes {
            c.mode
        } else {
            ProxyMode::Tun
        };
        assert_eq!(plan.mode, mode, "{at}");

        let native = c.engine == CoreEngine::SingBox
            && c.tun == TunEngine::SingboxTun
            && mode == ProxyMode::Tun;
        assert_eq!(matches!(plan.tun, TunPlan::Native { .. }), native, "{at}");
        assert_eq!(
            matches!(plan.tun, TunPlan::None),
            mode != ProxyMode::Tun,
            "{at}"
        );
        let has_tun_inbound = inbounds(&built.config).iter().any(|i| i["type"] == "tun");
        assert_eq!(has_tun_inbound, native, "{at}");

        let force_tun = c.host.app_routing == AppRouting::PerUid && c.force_key == Some(UID_KEY);
        match &plan.tun {
            TunPlan::Native { force_tun: f } => {
                assert_eq!(*f, force_tun, "{at}");
                assert_eq!(inbound(&built.config, "tun-force").is_some(), *f, "{at}");
            }
            TunPlan::External(ext) => {
                assert_eq!(ext.engine, c.tun, "{at}");
                assert_eq!(ext.force_tun, force_tun, "{at}");
                assert_eq!(
                    ext.uid_filter.is_some(),
                    c.host.app_routing == AppRouting::PerUid,
                    "{at}"
                );
            }
            TunPlan::None => {}
        }

        let force_in = inbound(&built.config, "force-in").expect("force-in inbound");
        assert_eq!(port(force_in), plan.ports.force, "{at}");
        let http_in = match c.engine {
            CoreEngine::SingBox => inbound(&built.config, "socks-in"),
            CoreEngine::Xray => inbound(&built.config, "http-in"),
        };
        assert_eq!(http_in.map(port), Some(plan.os_proxy_http_port()), "{at}");

        let state = plan.state(RunState::Connecting);
        let read = DataPathState::from_json(state.to_json().as_bytes()).unwrap();
        assert_eq!(read.helpers(), plan.helpers(), "{at}");
        assert_eq!(
            read.external_tun(),
            plan.external().map(|e| e.engine),
            "{at}"
        );
        assert_eq!(read.socks_port, plan.ports.socks, "{at}");
        assert_eq!(
            read.listening_ports(0),
            (plan.ports.socks, plan.ports.http, plan.ports.force),
            "{at}"
        );

        if c.host.app_routing == AppRouting::PerProcess && c.force_key == Some(EXE_KEY) {
            let mut filtered = built.config.clone();
            apply_process_filter(c.engine, &s, &mut filtered);
            assert_eq!(filtered != built.config, plan.sees_processes(), "{at}");
        }
    }
}
