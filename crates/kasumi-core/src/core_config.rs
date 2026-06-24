//! Resolve the core engine for a profile and build its exact launch config.
//! Shared by the backend (to launch the core) and config-diffing
//! (restart-on-change).

use serde_json::Value;

use crate::core::{resolve_core, resolve_tun};
use crate::enums::{CoreEngine, TunEngine};
use crate::profile::Profile;
use crate::singbox_config::{SingboxBuildOpts, build_singbox_config};
use crate::state::{AdvancedSettings, RoutingRule};
use crate::xray_config::build_xray_config;

/// Engine + TUN engine + config JSON for a profile, mirroring what the core is
/// launched with.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreConfig {
    pub engine: CoreEngine,
    /// The resolved TUN engine for this core. When it isn't `SingboxTun`, the
    /// core is built socks-only (an external tun→socks engine fronts it).
    pub tun: TunEngine,
    /// The built config as a JSON value (serialize to a string when writing it
    /// to disk; comparing values is order-independent for restart diffing).
    pub config: Value,
}

/// Build the launch config for a profile. `srs_dir` is the platform's rule-set
/// directory (sing-box only); pass `""` when only diffing configs.
pub fn build_core_config(
    profile: &Profile,
    settings: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
    srs_dir: &str,
) -> Result<CoreConfig, String> {
    let engine = resolve_core(profile, settings);
    let tun = resolve_tun(engine, settings);
    let config = match engine {
        CoreEngine::SingBox => build_singbox_config(
            profile,
            settings,
            routing_rules,
            profiles,
            SingboxBuildOpts {
                // An external tun engine fronts sing-box → build it socks-only
                // (no native tun inbound). SingboxTun keeps the native tun.
                no_tun: tun != TunEngine::SingboxTun,
                srs_dir,
            },
        )?,
        CoreEngine::Xray => build_xray_config(profile, settings, routing_rules, profiles)?,
    };
    Ok(CoreConfig {
        engine,
        tun,
        config,
    })
}

/// True when two resolved core configs differ — i.e. the core must be restarted.
/// A TUN-engine switch counts too: it changes how the data-path is brought up even
/// when the xray config JSON is identical.
pub fn active_config_changed(prev: &CoreConfig, next: &CoreConfig) -> bool {
    prev.engine != next.engine || prev.tun != next.tun || prev.config != next.config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::parse_share_link;

    #[test]
    fn dispatches_by_resolved_engine() {
        let s = AdvancedSettings::default();
        let xray = parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None).unwrap();
        let sb = parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex", None).unwrap();

        let cx = build_core_config(&xray, &s, &[], std::slice::from_ref(&xray), "").unwrap();
        assert_eq!(cx.engine, CoreEngine::Xray);
        assert!(cx.config["outbounds"].is_array());

        let cs = build_core_config(&sb, &s, &[], std::slice::from_ref(&sb), "").unwrap();
        assert_eq!(cs.engine, CoreEngine::SingBox);
        assert!(cs.config["route"].is_object());
    }

    #[test]
    fn singbox_external_tun_is_socks_only() {
        let sb = parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex", None).unwrap();
        let tun_inbounds = |c: &CoreConfig| {
            c.config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|i| i["type"] == "tun")
                .count()
        };

        // Default: sing-box keeps its native tun inbound.
        let s = AdvancedSettings::default();
        let native = build_core_config(&sb, &s, &[], std::slice::from_ref(&sb), "").unwrap();
        assert_eq!(native.tun, TunEngine::SingboxTun);
        assert_eq!(tun_inbounds(&native), 1);

        // tun2socks for sing-box → socks-only config, no tun inbound, mixed kept.
        let mut s2 = AdvancedSettings::default();
        s2.tun_by_core
            .insert(CoreEngine::SingBox, TunEngine::Tun2socks);
        let ext = build_core_config(&sb, &s2, &[], std::slice::from_ref(&sb), "").unwrap();
        assert_eq!(ext.tun, TunEngine::Tun2socks);
        assert_eq!(tun_inbounds(&ext), 0);
        assert!(
            ext.config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["type"] == "mixed")
        );
    }

    #[test]
    fn change_detection() {
        let s = AdvancedSettings::default();
        let p = parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None).unwrap();
        let a = build_core_config(&p, &s, &[], std::slice::from_ref(&p), "").unwrap();
        let b = a.clone();
        assert!(!active_config_changed(&a, &b));

        let mut s2 = s.clone();
        s2.fragment = true; // changes the built config
        let c = build_core_config(&p, &s2, &[], std::slice::from_ref(&p), "").unwrap();
        assert!(active_config_changed(&a, &c));
    }

    #[test]
    fn engine_switch_counts_as_change() {
        // A switch of resolved engine is a restart trigger on its own, regardless
        // of how the two cores' config JSON compare.
        let s = AdvancedSettings::default();
        let xray = parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None).unwrap();
        let sb = parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex", None).unwrap();
        let a = build_core_config(&xray, &s, &[], std::slice::from_ref(&xray), "").unwrap();
        let b = build_core_config(&sb, &s, &[], std::slice::from_ref(&sb), "").unwrap();
        assert_ne!(a.engine, b.engine);
        assert!(active_config_changed(&a, &b));
    }
}
