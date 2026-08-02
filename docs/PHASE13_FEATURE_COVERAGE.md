# Phase 13 Android Product Feature Coverage

Status: local implementation validation complete. This map is authoritative for local Phase 13 scope. A feature is `delivered-local` only when the linked implementation and automated evidence exist. External relay, provider, field, release, and production-authority evidence stays `phase14-unverified`.

| Inventory | Phase 13 disposition | Local implementation or boundary | Remaining evidence |
|---|---|---|---|
| D0 coverage | delivered-local | Home, Profiles and Providers, Settings, recovery, diagnostics, native runtime and operator projection modules | Full host, combined, and three-level emulator gates pass |
| D1 navigation | delivered-local | Typed Home, Profiles and Providers, Settings, import, routing, recovery, diagnostics and About destinations | API 26, API 34, and API 36 device manifests pass; physical adaptive hardware remains Phase 14 |
| D2 dashboard | delivered-local | Verified profile, immutable session digest, lifecycle, counters, DNS/IP/MTU and truthful failure state | Physical-device rates and exit location are Phase 14 |
| D3 profile actions | delivered-local | Select, favorite, detail, encrypted export and confirmed delete; unsafe plain sharing is absent | Operator compatibility remains unavailable without signed evidence |
| D4 profile/provider management | safely-replaced | Local search, favorite filter, sort, expiry and read-only verified provider projection | Remote provider health/quota is Phase 14 |
| D5 imports | delivered-local | File, clipboard-confirmed, `kurd://artifact`, share intent, single QR, multipart QR and encrypted backup | Provider network import is Phase 14 |
| D6 manual editor | safely-replaced | Arbitrary protocol/secret editing is not permitted to create Kurd authority | Reviewed external-format quarantine is future work |
| D7 transport selection | safely-replaced | Signed profile strategy authority only; UI cannot invent carriers | Live strategy fleet is Phase 14 |
| D8 carrier/security options | safely-replaced | Only signed, validated profile policy reaches the session plan; unsafe toggles are absent | Production strategy authoring belongs to operator tooling and Phase 14 |
| D9 traffic shaping | safely-replaced | Profile-authorized runtime policy only; inert user controls are disabled | Live measured shaping evidence is Phase 14 |
| D10 export | delivered-local | Encrypted profile backup and previewed redacted diagnostics | Plain secret URL/JSON export intentionally absent |
| D11 per-app routing | delivered-local | Launchable-app discovery, all/include/exclude drafts, encrypted package sets and pre-establishment application | Install/remove drift device evidence pending |
| D12 connection behavior | partial-local | Foreground user start, system VPN consent, stop and Recover Internet | Boot/background, trusted Wi-Fi and hotspot exposure unavailable pending Phase 14 authority |
| D13 tunnel modes | partial-local | TUN, internal fail-closed DNS, IPv4, MTU and metered behavior | Local proxy, IPv6/dual stack and external DNS unavailable until runtime-backed and validated |
| D14 updates | safely-replaced | Offline signed update bundles and read-only provider capability projection | Remote WorkManager updates require a verified signed endpoint in Phase 14 |
| D15 probes | partial-local | Bounded Kurd-session loopback probe with categorical result | HTTP, TCP and ICMP require authorized targets and Phase 14 evidence |
| D16 appearance | partial-local | System/light/dark, high contrast, reduced motion, exact locale-key parity, pseudo-English, pseudo-RTL, 200 percent text, and API 34/36 automated accessibility checks | Human linguistic review, Switch Access, and foldable hardware remain Phase 14 evidence |
| D17 application section | partial-local | About, privacy/recovery and diagnostics | Public support/rate/community endpoints remain absent |
| D18 About | delivered-local | App/core/schema/registry/relay/diagnostic/crypto versions and privacy boundary | Public legal/contact endpoints remain Phase 14 product operations |
| D19 automation | safely-replaced | `kurd://` signed artifact import requires preview and confirmation | External `kurdistanvpn://` actions remain disabled until signed-action and authorization gates exist |
| D20 backup/restore | delivered-local | Versioned passphrase-encrypted backup, preview, verification, rollback protection and local credential regeneration | Device reinstall matrix pending final device gate |
| D21 performance | partial-local | Runtime packet/reply counters and bounded native handles | CPU/battery/thermal and long-run field measurements are Phase 14 |
| D22 expert settings | safely-replaced | Only runtime-consumed MTU, metered and routing values are enabled; inert resource controls are disabled | Additional controls require measured execution paths |
| D23 logs | delivered-local | Encrypted bounded categorical event store, level/retention, filters, clear, preview and redacted export | Local artifact and emulator canary evidence pass; physical-device evidence remains Phase 14 |
| D24 reset | delivered-local | Confirmed settings, profiles/providers, routing, diagnostics, and full reset scopes; the full path retains journaled interrupted-reset recovery | Exact API 36 device manifest exercises scope selection and confirmation; physical-device storage-fault evidence remains Phase 14 |
| D25 privacy defaults | delivered-local | Encrypted artifacts and package rules, no telemetry, no remote crash reporting, bounded diagnostics and explicit export authorization | Local APK/artifact and API 36 canary gates pass; physical-device evidence remains Phase 14 |
| D26 MVP inventory | partial-local | Offline profile, protected state, settings, routing, backup, logs and local Kurd runtime are present | Complete real-network MVP is Phase 14 `[UNVERIFIED]` |
| D27 roadmap features | phase14-unverified | Only locally executable recovery, accessibility and diagnostics items are in Phase 13 | Network/field features require Phase 14 |
| D28 Kurdistan-native whole | partial-local | Signed profile authority, immutable session plan, permitted strategy/relay fingerprints and local authenticated Kurd transport | Public relay fleet, rotation and field selection evidence are Phase 14 |

## Explicitly unavailable in Phase 13

- Public or hotspot proxy exposure.
- Unauthenticated local proxying.
- Public relays, unrestricted Internet egress or provider networking.
- External DNS that cannot be proven to traverse the authenticated session.
- IPv6-only or dual-stack modes without end-to-end local runtime support.
- Automatic reconnect, boot/background startup or external automation without fresh authority and platform evidence.
- Claims of guaranteed bypass, undetectability, anonymity or production readiness.

`testdata/evidence/phase13/acceptance-status.json` records the mandatory local gates separately from the Phase 14 external evidence that remains unverified.
