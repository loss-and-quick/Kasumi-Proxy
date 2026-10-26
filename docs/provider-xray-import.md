# Provider Xray configuration imports

A full Xray configuration from a subscription is not a second application configuration.
It describes a profile-level connection graph. Kasumi keeps ownership of its listeners,
system routing, DNS policy, filesystem access and user-selected routing rules.

Provider configurations require the subscription's existing provider-config consent.
This consent does not permit a provider to create listeners, read local keys or replace
Kasumi's platform routing controls.

## Connection behavior

The importer validates the graph before creating a provider-origin custom profile. Its
connection behavior includes outbounds, chains, routing conditions, balancers, health
observations and fallback transitions. A required dependency must not be deleted merely
to produce JSON that starts successfully.

In particular, a loopback outbound is a virtual router transition, not a listening
socket. Its `settings.inboundTag` identifies an internal routing context. It is distinct
from an actual `inbounds` listener definition.

Balancer strategies that use health observations must retain those observations. Replacing
`leastLoad` with random selection after removing `burstObservatory` changes the profile,
even if one server still happens to work.

## Integration into Kasumi

Kasumi's user rules first choose direct access, blocking or a profile. Internal transitions
of the selected profile stay inside that profile's routing graph; they must not be
captured a second time by global user rules.

Provider outbound, balancer and virtual-inbound names are isolated from Kasumi's own tags.
Prefix selectors are resolved against the provider's outbound set before composition.
Generated names are prefix-free, including after tags are rewritten. HTTP transport
headers are opaque metadata, not tag references, and remain unchanged.
A selector must not accidentally include another profile or a client-owned outbound.

The profile's initial route is determined from its applicable routing rules, not from an
assumption that its first outbound or an outbound called `proxy` is its intended exit.
Anonymous outbounds receive compiler-local identities only after validation; they do not
become new selector matches and are not written back into the source configuration.
Runtime traffic and connection tests use the same default-path selection. Tests skip
external conditional entry policy, but retain reachable internal routing and observation
dependencies. A required internal geodata dependency is an error when unavailable, not
an excuse to remove a routing condition.

Original listener tags may be retained as tag-only ingress metadata. Their original
addresses, ports, authentication and listener configuration are never executed. Multiple
original entry points that imply different routing behavior cannot be collapsed silently.

User-owned raw configurations still run as written. Their isolated connection checks
reuse this graph compiler so the path reported by a check is the path it actually routes.
A probe does not attach external `.via` metadata that the raw runtime does not execute.
If the isolated representation is unsupported, the check reports that it cannot test the
configuration rather than silently dropping required transitions.

## Observation traffic

Health checks generate background network requests. Only the supported, bounded
observation configuration is accepted. Probe selectors must identify eligible proxy
outbounds within the profile. Probe URLs and resource settings are validated, and a
configuration outside the supported limits is rejected rather than silently clamped.
The current bounds are 64 selected members, a minimum probe interval of 10 seconds,
burst sampling of at most 20, and a burst timeout of at most 60 seconds. Burst HTTP
methods are limited to GET and HEAD. The graph has at most 1,024 nodes and 256 nodes
along a dependency path.

Xray's burst `connectivity` setting is not equivalent to its regular destination probe:
it uses a separate direct HTTP client. A nonempty value is unsupported by this import
path because it needs a separate egress-policy decision. It is not silently removed.

URL validation rejects explicit local destinations; it does not claim that checking a
hostname prevents DNS rebinding. Routed health requests remain associated with the
selected proxy outbounds. Probe URLs, query strings and credentials must not be logged.

## Client-owned settings

Provider listener definitions, logging destinations, control-plane configuration and
other client-owned settings are not activated by an import. Socket marks and platform
bindings remain controlled by Kasumi. Omissions are reported as field paths, without
including configuration values or credentials.

Kasumi's DNS policy remains authoritative. Importing a profile is not permission to
replace system DNS or activate arbitrary provider telemetry. This import path does not
provide general provider-DNS translation or a user-managed unrestricted raw-config mode.

Local certificate/key files are not implicitly available to a subscription. A connection
that requires an unsupported local asset must be rejected rather than accepted after
removing the dependency. TLS verification and certificate pins must not be weakened to
make an import pass.

## Incompatibility and updates

Unknown required features, dangling references, ambiguous identifiers, unsupported routing
structures and nonterminating graph cycles are incompatibilities. Removing a chain hop
must not turn a chained connection into a direct dial. Removing an unsupported rule
condition must not broaden the rule.

An incompatible provider configuration fails the subscription update. For a JSON array,
a required incompatibility must not silently replace the previous list with only the
remaining configurations. The previous working profiles and subscription metadata are
retained, and the subscription exposes an actionable error. Routine client-owned
omissions are warnings rather than claims of full configuration equivalence.

Only the validated representation is persisted as an executable provider profile.
Original arbitrary response bodies are not newly retained by this feature.
Tag-dependent `leastLoad.settings.costs` are currently unsupported: their original
substring/regular-expression matching cannot be retained by blindly renaming tags.
A nonempty costs configuration is rejected explicitly, rather than applied with different
weights. Multiple simultaneous observation engines and ambiguous original ingress choices
are also unsupported. Attaching a `.via` chain to an expanded loopback/fallback graph
is rejected until every reachable terminal dialer can be chained consistently; a chain
must never be attached only to its preferred member. Profiles
imported by earlier versions may already have lost their observation and fallback
settings; those settings can only be restored by fetching the subscription again.
