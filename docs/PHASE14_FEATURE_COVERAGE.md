<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 product and inspiration-inventory coverage

Status: local reconciliation complete; production and field capabilities remain
**[UNVERIFIED]** where stated.

This map reconciles the Kurdistan VPN product requirements with
`vpn_app_inspiration_feature_inventory.md`. The inventory is an inspiration
input, not authority to copy another product or weaken Kurd profile policy.

Dispositions:

- `delivered-local`: implemented and covered by repository/emulator evidence;
- `production-evidence-required`: implementation or final enablement depends on
  owned production systems and Phase 14 field evidence;
- `safely-replaced`: the user outcome is retained through a safer Kurd-native
  design;
- `rejected`: conflicts with security, privacy, platform, or signed authority.

| Capability group | Disposition | Kurdistan VPN result | Evidence or clearing condition |
| --- | --- | --- | --- |
| Home dashboard and navigation | delivered-local | Original Home, Profiles, and Settings structure; truthful lifecycle, active profile, session-plan digest, DNS/IP/MTU, counters, duration, failure and recovery | Phase 14 exact device manifest and accessibility gate |
| Connect/disconnect | delivered-local | Android VPN consent, verified session authority, TUN start/stop, recover-internet action, no false protected state | Runtime authority tests and emulator gate |
| Public exit location, live speed, real relay health | production-evidence-required | Surface remains unavailable until an owned relay/provider supplies verified redacted observations | Owned relay, provider, device and field matrix |
| Profile/provider list | delivered-local | Search, favorite filter, sorting, selection, expiry, encrypted export, delete confirmation, read-only provider projection | Product-surface tests and protected-state tests |
| Add/import | delivered-local | File, confirmed clipboard, `kurd://artifact`, share intent, offline single/multipart QR, encrypted backup restore | Exact import and recovery tests |
| Arbitrary VLESS/VMess/Trojan/Shadowsocks editor | safely-replaced | External text cannot mint Kurd authority. Future import may enter non-executable quarantine for review | Requires reviewed parser and explicit compatibility policy |
| Transport/security/fingerprint editor | safely-replaced | Signed profile and operator policy define eligible strategies; Android may only narrow authority | Session-plan intersection and verifier tests |
| Allow-insecure, unsafe fingerprints, certificate bypass | rejected | Not exposed | Product claim/permission/artifact verifier |
| Traffic shaping, fragmentation, padding, cover streams | production-evidence-required | May be selected only from signed, bounded, runtime-consumed strategy policy | Live carrier implementation and measured field evidence |
| Share/copy/QR/export | safely-replaced | Encrypted profile export and redacted diagnostics; no default secret URL/JSON or unencrypted backup | Export and secret-canary tests |
| Per-app routing | delivered-local | Launchable-app discovery without broad package visibility; all/include/exclude drafts; encrypted package sets | Unit and exact device tests; OEM drift remains external |
| Auto-connect and boot | safely-replaced | Foreground user start and OS-managed always-on are truthful; illegal background starts are not simulated | Platform/OEM evidence required before more automation |
| Kill switch | safely-replaced | Android lockdown truth comes from the OS; app exposes status and recovery, not a fake toggle | Physical OEM lockdown matrix required |
| LAN/hotspot access | production-evidence-required | Disabled until narrow binding, authentication, abuse control, relay-backed routing and owned-network evidence exist | Authorized network and abuse-control review |
| TUN and proxy modes | production-evidence-required | TUN is local-runtime backed. Local/hotspot proxy modes remain disabled until they feed the same verified Kurd session without direct egress | Runtime implementation plus field evidence |
| DNS presets/custom DNS | safely-replaced | Internal in-tunnel DNS is fail-closed. External resolvers remain unavailable until authenticated tunnel carriage and leak tests pass | Owned resolver/relay test matrix |
| IPv4/IPv6/dual stack | production-evidence-required | IPv4 local path is validated. IPv6 choices remain unavailable until end-to-end transport, DNS, routing and device evidence exist | IPv6 relay and OEM matrix |
| Memory, mux, fragmentation, UDP controls | safely-replaced | Only runtime-consumed, bounded values may be exposed; inert or authority-widening controls stay absent | Per-control execution tests and resource evidence |
| Provider/profile updates | production-evidence-required | Offline signed updates and read-only capability projection exist; remote scheduling waits for a verified signed endpoint | Production provider, rollback and revocation evidence |
| Probe methods/history | production-evidence-required | Bounded Kurd-session loopback probe exists; external TCP/HTTP/ICMP require signed targets and rate limits | Owned target and field evidence |
| Appearance and localization | delivered-local | Original warm light/dark palette, high contrast, reduced motion, adaptive navigation, exact locale key parity, RTL and 200 percent text tests | Human linguistic, Switch Access and physical foldable review remain external |
| About, licenses, privacy, support | partial-local | Version and privacy boundaries are present; public legal/support/community endpoints require accountable production owners | Published policy/support ownership and store review |
| URL automation | safely-replaced | `kurd://` import requires preview and confirmation; silent external start/routing is absent | Signed-action authority and Android abuse review required |
| Backup/restore | delivered-local | Versioned passphrase-encrypted backup, preview, verification, rollback protection, selective restore and credential regeneration | Host/device recovery tests; cross-OEM reinstall remains external |
| Performance monitoring | partial-local | Bounded runtime/session counters exist without telemetry | Long-duration physical-device CPU, memory, thermal, battery, FD and thread evidence required |
| Excluded routes and expert controls | safely-replaced | Canonical bounded routing policy and runtime-consumed MTU/metered settings; no arbitrary unsafe routing | Unit/runtime/device gates |
| Logs and diagnostics | delivered-local | Encrypted bounded categorical events, filtering, retention, clear, preview and redacted export; no payloads or destinations | Secret-canary and device tests |
| Scoped reset and recovery | delivered-local | Settings, profiles/providers, routing, diagnostics and full reset with process-death recovery | Exact device manifest |
| Privacy dashboard/app lock/biometric reveal | partial-local | Storage/privacy state and biometric-protected sensitive exports exist; a complete human-reviewed privacy dashboard remains release work | Privacy review and physical-device matrix |
| Onboarding/troubleshooting | production-evidence-required | Local failure explanations and recovery exist; full permission/OEM/captive-portal guidance requires verified device behavior | OEM and field matrix |
| DNS/WebRTC leak guidance | safely-replaced | DNS leak validation must use owned test domains; WebRTC behavior belongs to apps/browser and is guidance, not a false VPN guarantee | Controlled field evidence |
| Usage statistics | safely-replaced | No telemetry or destination history. Optional local aggregate counters may be added only with privacy review and bounded retention | Privacy approval and local-only implementation |
| Public censorship-resilience claim | rejected | No guaranteed bypass, undetectability, anonymity or impossibility-of-blocking claim | Phase 14 verifier rejects these claims |

## Release boundary

The locally implemented app is not a public VPN service until production
authority, provider, relay fleet, signing, distribution, monitoring, support,
physical-device, hostile-network, and recovery evidence all pass. The current
release decision therefore remains `NO_GO`.

`ROADMAP.md` assigns the remaining production implementation and evidence to
Phases 16-22. Phase 15 integrates and freezes this candidate; it does not widen
the local feature claims in this map.
