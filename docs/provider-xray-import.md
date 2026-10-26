# Provider Xray configuration imports

## 1. Architectural model

When a subscription imports a complete Xray JSON configuration ("provider-origin custom profile"), Kasumi treats it as an exit fragment rather than an independent application configuration.

Kasumi's own routing remains authoritative:
- Client listening ports, TUN/VPN routing, socks/http inbounds, and DNS configurations belong exclusively to Kasumi.
- Kasumi routing rules and operating modes (Global, Rules, Custom) decide whether traffic connects directly, is blocked, or routes through a proxy profile.
- Once Kasumi directs traffic to a profile, Xray executes the provider's connection topology: server chains (`dialerProxy`), balancers, observation engines, and internal loopback failovers. Kasumi neither emulates nor second-guesses internal balancing decisions.
- Provider external routing policy (such as geo/domain/ip entry rules or listener definitions) is not imported into Kasumi. Dropped external rules are reported to the user as diagnostic warnings.
- Previously imported profiles in existing state must be refreshed from their subscription to compile under this linker contract.

## 2. Compilation pipeline

The compilation pipeline converts untrusted provider JSON into a validated, linked configuration fragment through seven discrete stages:

1. **Strip client-owned and host-level settings** (`custom_sanitize.rs`):
   Client listeners (`inbounds`), logging configurations (`log`), control APIs (`api`, `stats`, `policy`), and reverse tunnels (`reverse`) are dropped from the top-level and never passed to the core. Outbound stream settings are cleaned in two ways: `masterKeyLog` is stripped from `tlsSettings` (local filesystem path), and socket option fields outside the allowlist (`SOCKOPT_KEYS`) are stripped from `sockopt`. Local certificate and key files (`certificateFile`, `keyFile`) inside `streamSettings` cause the profile to be rejected as incompatible rather than silently stripped, because removing them would silently weaken the security posture. Non-canonical casing of any monitored field is also rejected.
2. **Build typed fragment in a single validation pass** (`provider_graph.rs`):
   A `ProviderFragment` is constructed directly from the sanitized outbounds, balancers, observatory, and routing rules. All structural bounds, prefix expansions, references, and cycle detections are validated in this single pass. Runtime and probe builders only render this fragment; they never re-validate or re-expand selectors.
3. **Make Xray implicit behavior explicit**:
   - The provider config's first outbound (`outbounds[0]`) is designated as the explicit `default_handler`.
   - An observation-driven balancer (`leastPing`, `leastLoad`) without a `fallbackTag` receives an explicit fallback pointing to `default_handler`. Those strategies return an empty pick when no member is qualified, and Xray then dispatches to its first outbound; in the linked config that would be `proxy` again, an endless loop. `random` and `roundRobin` never return an empty pick on their own, and naming a fallback for them would make Xray start filtering their members by health, so they are left as written.
   - The reverse case: a `random` or `roundRobin` balancer that names a `fallbackTag` while the profile has no observatory. Xray then requires an observatory and refuses to start. Such a balancer never had health data to fall back on, so the `fallbackTag` is dropped with a warning and the balancer keeps its plain member choice. Kasumi does not synthesize an observatory, since that would add background probe traffic the provider never configured.
   - Routing rules are field rules whether or not they carry `"type": "field"`; Xray never reads that key, so it is not required.
   - A loopback entry is followed through its context before deciding whether the default route is a proxy.
   - Any context where no rule matches routes explicitly to `default_handler`.
4. **Resolve entry and context targets using Xray semantics**:
   - Loopback outbounds (`settings.inboundTag`) define virtual context inbounds. Rules whose `inboundTag` entries match virtual inbounds belong to those contexts; mixing virtual and real listener tags in one rule is rejected.
   - For the external entry and each context, applicable rules are traversed in declaration order. A rule is conditional when it sets any Xray match key other than `inboundTag`, `network` and a full-range `port`; the key list is `XRAY_RULE_CONDITIONS` in `xray_config.rs`, the same one Xray's own "rule has no effective fields" check uses. `domains` is a separate key in Xray's `RawFieldRule`, not an alias of `domain`, so it counts as a condition. Unscoped conditional rules are external policy and skipped with a warning; context-scoped conditional rules are rejected. `ruleTag` is metadata; any other unknown key is rejected rather than guessed at.
   - The first unconditional rule covering all TCP traffic (`rule_covers_network`) determines the TCP target; if none, it routes to `default_handler`. UDP follows the same logic. If UDP targets a service outbound (`freedom`, `blackhole`, `dns`) while TCP targets a proxy, a warning is recorded and the TCP target is used. If TCP and UDP resolve to differing proxy targets, the configuration is rejected as ambiguous.
   - If the entry resolves to a service outbound or an all-service balancer, the configuration is rejected because a profile's default route must be a proxy.
5. **Namespace tags with prefix-free identities**:
   A deterministic seed is derived via `provider_outbounds_identity` (SHA-256 of outbounds with tags and REALITY picks removed). Outbounds, balancers, and virtual inbounds receive fixed-length, colon-terminated tags (`ks-provider:{seed}:{o|b|v}:{index:08x}:`). This ensures prefix-free selector matching and prevents core restarts when subscription updates only refresh server picks.
6. **Link at `proxy`**:
   - If the entry target is a plain outbound not referenced by any balancer, observer, fallback, dialer, or context, it takes the tag `proxy` directly with no loopback hop.
   - Otherwise, `proxy` is created as a loopback outbound targeting `proxy-select`, paired with an internal rule `proxy-select -> entry_target`. Context rules and the `proxy-select` rule are placed ahead of user rules in routing.
7. **Consistent probe execution**:
   Connection probes reuse the exact same `ProviderFragment` and entry target as the runtime. User-origin custom configurations execute verbatim at runtime, while their probes compile through the fragment, reporting diagnostic errors when unrepresentable.

## 3. Preserved, warned, and rejected settings

| Category | Settings | Rationale |
| --- | --- | --- |
| **Preserved** | Proxy outbounds, credentials, stream settings, `dialerProxy` chains, balancers, single observation engine (`observatory` or `burstObservatory`), virtual loopbacks (`settings.inboundTag`), context routing rules. | Necessary to reproduce the provider's intended connection topology and multi-node exit strategies. |
| **Ignored (Warning)** | Listener settings (`inbounds`), log file paths (`log`), management services (`api`, `stats`, `policy`), external conditional routing rules (any Xray match key: `domain`, `ip`, `port`, `sourcePort`, `process`, `user`, `attrs` and the rest), UDP service policies differing from TCP proxy targets, and a `random`/`roundRobin` `fallbackTag` in a profile without an observatory (Xray would refuse to start). | Kasumi's platform routing and DNS policy are authoritative. Provider configurations cannot override system egress or intercept client-owned traffic. |
| **Rejected (Incompatible)** | Local certificate or key files (`certificateFile`, `keyFile`), non-canonical field aliases (including `sockopt` and `proxySettings.tag` casing, since Xray binds JSON keys case-insensitively and an alias would hide a graph edge), unknown rule keys, unpinned `allowInsecure`, unknown protocols, cyclic dependencies, graph depth or node limit violations, ambiguous entry targets, simultaneous standard and burst observatories, burst `connectivity` checks, leastLoad `costs`, and profiles whose default route is not a proxy. | Violates fail-closed security guarantees, introduces infinite loops, or relies on features unsupported by Kasumi's core architecture. |

## 4. Worked example: balancer cascade

### Provider configuration (before compilation)

```json
{
  "outbounds": [
    { "tag": "decoy", "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": 1 }] } },
    { "tag": "node-1", "protocol": "vless", "settings": { "vnext": [{ "address": "a.example", "port": 443 }] } },
    { "tag": "node-2", "protocol": "vless", "settings": { "vnext": [{ "address": "b.example", "port": 443 }] } },
    { "tag": "loop-fallback", "protocol": "loopback", "settings": { "inboundTag": "v-fallback" } }
  ],
  "routing": {
    "balancers": [
      { "tag": "bal-all", "selector": ["node-2"], "strategy": { "type": "leastLoad" } },
      { "tag": "bal-sticky", "selector": ["node-1"], "strategy": { "type": "leastLoad" }, "fallbackTag": "loop-fallback" }
    ],
    "rules": [
      { "type": "field", "inboundTag": ["v-fallback"], "balancerTag": "bal-all" },
      { "type": "field", "network": "tcp,udp", "balancerTag": "bal-sticky" }
    ]
  },
  "burstObservatory": {
    "pingConfig": { "destination": "https://example.org/generate_204", "interval": "10s", "timeout": "2s", "sampling": 1 },
    "subjectSelector": ["node-1", "node-2"]
  }
}
```

### Linked configuration (after compilation)

```json
{
  "outbounds": [
    { "tag": "proxy", "protocol": "loopback", "settings": { "inboundTag": "proxy-select" } },
    { "tag": "ks-provider:c1b0...:o:00000000:", "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": 1 }] } },
    { "tag": "ks-provider:c1b0...:o:00000001:", "protocol": "vless", "settings": { "vnext": [{ "address": "a.example", "port": 443 }] } },
    { "tag": "ks-provider:c1b0...:o:00000002:", "protocol": "vless", "settings": { "vnext": [{ "address": "b.example", "port": 443 }] } },
    { "tag": "ks-provider:c1b0...:o:00000003:", "protocol": "loopback", "settings": { "inboundTag": "ks-provider:c1b0...:v:00000000:" } }
  ],
  "routing": {
    "balancers": [
      {
        "tag": "ks-provider:c1b0...:b:00000000:",
        "selector": ["ks-provider:c1b0...:o:00000002:"],
        "fallbackTag": "ks-provider:c1b0...:o:00000000:",
        "strategy": { "type": "leastLoad" }
      },
      {
        "tag": "ks-provider:c1b0...:b:00000001:",
        "selector": ["ks-provider:c1b0...:o:00000001:"],
        "fallbackTag": "ks-provider:c1b0...:o:00000003:",
        "strategy": { "type": "leastLoad" }
      }
    ],
    "rules": [
      { "type": "field", "inboundTag": ["force-in"], "network": "tcp,udp", "outboundTag": "proxy" },
      { "type": "field", "inboundTag": ["proxy-select"], "network": "tcp,udp", "balancerTag": "ks-provider:c1b0...:b:00000001:" },
      { "type": "field", "inboundTag": ["ks-provider:c1b0...:v:00000000:"], "network": "tcp,udp", "balancerTag": "ks-provider:c1b0...:b:00000000:" },
      { "type": "field", "inboundTag": ["socks-in", "http-in"], "port": 53, "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["socks-in", "http-in"], "network": "tcp,udp", "outboundTag": "proxy" }
    ]
  },
  "burstObservatory": {
    "pingConfig": { "destination": "https://example.org/generate_204", "interval": "10s", "timeout": "2s", "sampling": 1 },
    "subjectSelector": ["ks-provider:c1b0...:o:00000001:", "ks-provider:c1b0...:o:00000002:"]
  }
}
```

Notice:
- `bal-all` had no `fallbackTag`; compilation gave it an explicit fallback pointing to the default handler (`ks-provider:...:o:00000000:`), preventing recursion.
- User traffic hitting `socks-in` routes to `proxy`, loops into `proxy-select`, and enters `bal-sticky`.
- If `bal-sticky` fails, traffic cascades to `loop-fallback` -> `v-fallback` -> `bal-all`.
- If `bal-all` fails, traffic falls back to `o:00000000:` and terminates cleanly.

## 5. Implementation architecture & resource bounds

### Resource bounds

| Parameter | Limit | Purpose |
| --- | --- | --- |
| Max graph nodes | 1024 | Prevents resource exhaustion from oversized declarations. |
| Max graph depth | 256 | Binds DAG traversal and dialer chain recursion. |
| Max selector members | 64 | Binds candidate sets for balancers and observatories. |
| Min probe interval | 10 s | Prevents abusive health check frequencies. |
| Max burst timeout | 60 s | Binds background observation probe duration. |
| Max burst sampling | 20 | Binds packet bursts per observation check. |
| Default burst interval | 60 s | Default period between burst checks. |
| Default burst timeout | 5 s | Default timeout per burst probe packet. |
| Default burst sampling | 10 | Default packet count per burst check. |

### Code locations

- `crates/kasumi-core/src/provider_graph.rs`: Defines `ProviderFragment`, `FragmentOutbound`, `FragmentBalancer`, `FragmentObservatory`, `FragmentContext`, and `TargetRef`. Implements fragment building, cycle and depth validation, explicit default assignment, target resolution, and prefix-free rendering (`render`, `compile_custom_profile`).
- `crates/kasumi-core/src/custom_sanitize.rs`: Implements `sanitize_provider_xray` and `SanitizedXray`. Strips client-owned top-level keys, `masterKeyLog` from TLS settings (`strip_host_files`), and non-allowlisted sockopt fields. Rejects `certificateFile`, `keyFile`, unpinned `allowInsecure`, and non-canonical field-name casing (`validate_stream_security`, inline proxySettings check).
- `crates/kasumi-core/src/custom_target.rs`: Defines `Target` and `describe()` for probe diagnostics and UI representations.
- `crates/kasumi-core/src/xray_config.rs`: Merges rendered `ActiveOutbounds` from the fragment compiler into Kasumi's top-level Xray configuration.
- `crates/kasumi-backend/src/jobs.rs`: Builds test core configurations for profile latency probes via `build_xray_probe_config`.
