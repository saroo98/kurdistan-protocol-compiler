# Phase 18 Android production-contract admission

## Status

| Field | Result |
| --- | --- |
| Task 0 execution | `COMPLETE` |
| Baseline identity | `VERIFIED` |
| Full Phase 18 production-contract admission | `NOT_GRANTED` |
| Reason | Required primitives are absent for several dependent workstreams, and current relied-on settings/runtime contracts are unversioned or conflict with tracked live-data-plane contracts. |
| Phase 18 implementation work | `NOT_STARTED` |
| Qualification and release | `UNEXECUTED`; `NO_GO` |

Task 0 is complete because this document records the exact integrated baseline, every required primitive, all capability-gated dispositions, and every verified stop condition. It does not record admission success. A missing optional capability is final for this admission baseline; a missing required primitive stops only the workstream that depends on it. No Android substitute may be invented.

## Evidence rules

- All immutable repository source evidence below is bound to the commit and tree in the next section.
- Source paths and line ranges refer to that immutable tree.
- Branch, remote-ref, PR, and initial-worktree observations are separately identified point-in-time checks. They are not inferred from the immutable tree.
- Tests, fixtures, historical results, and UI declarations are not treated as production capabilities.
- Historical Phase 15 through Phase 17 results remain evidence only for their original subjects.
- The tracked tree contains no accepted KIP prose path. Existing KIP identifiers are therefore treated only as references already present in source or historical evidence. No admission result below depends on reconstructing absent prose.
- `ADMITTED` is used only where a stable production symbol or platform contract supplies the capability. `NOT_ADMITTED` means no complete production capability exists at this baseline.

## Immutable baseline and initial state

| Property | Exact value | Evidence |
| --- | --- | --- |
| Branch | `phase18/android-product-surface` | `git branch --show-current` |
| Commit | `7d583d186c7e5fbb6fc1e9843049ad8edb940a0a` | `git rev-parse HEAD` |
| Tree | `7d641e7d780f2d628a147baee24b05a305cfdeaf` | `git show -s --format=%T HEAD` |
| Public integration | At Task 0 observation time, GitHub reported PR #45 merged and `origin/main` resolved to the commit above. | Point-in-time GitHub PR metadata and `git ls-remote origin refs/heads/main`; independently rechecked before publication |
| Initial tracked/untracked status | Empty before creation of this document | Point-in-time `git status --porcelain=v1 --untracked-files=all` observation |

### `preExistingUnrelatedChanges`

| Repository-relative path | Status | Byte length | SHA-256 |
| --- | --- | ---: | --- |
| _None_ | _None_ | _Not applicable_ | _Not applicable_ |

There was no pre-existing path to assign outside Phase 18 ownership.

## Application and toolchain identity

| Contract | Integrated value | Exact source |
| --- | --- | --- |
| Release namespace/application ID | `org.kurdistanvpn.app` | `android/app/build.gradle.kts:12-24` |
| Internal application ID | `org.kurdistanvpn.app.internal` through the base ID and `.internal` suffix | `android/app/build.gradle.kts:12-43` |
| Android SDKs | minimum 26; compile 36; target 36; build tools 36.0.0 | `android/app/build.gradle.kts:12-25` |
| Java bytecode level | Java 17 | `android/app/build.gradle.kts:65-68` |
| Android native toolchain | NDK `28.2.13676358` | `android/app/build.gradle.kts:15-17` |
| Release ABIs | `arm64-v8a` | `android/app/build.gradle.kts:45-49` |
| Internal/debug ABIs | `arm64-v8a`, `x86_64` | `android/app/build.gradle.kts:29-43` |
| Android libraries | AGP 9.2.1; Kotlin/KSP 2.3.10; Room 2.8.4; DataStore 1.2.1; coroutines 1.10.2; other pinned versions remain in the catalog. | `android/gradle/libs.versions.toml:1-22` |
| Included modules | 19 modules, including `:data:protected-state`; no Phase 18-specific module has yet been added. | `android/settings.gradle.kts:40-62` |
| Application boundary | backup and cleartext disabled; exported launcher/import activity; nonexported authority-reissue service | `android/app/src/main/AndroidManifest.xml:9-47` |
| VPN boundary | nonexported `:vpn` service; `BIND_VPN_SERVICE`; foreground-service and network permissions; system always-on declaration | `android/runtime/android/src/main/AndroidManifest.xml:3-25` |

## Stable product identities

| Identity | Integrated value | Exact source |
| --- | --- | --- |
| Android bridge | `kurd-android-bridge-v1`; binary magic `KVAB`; encoding 1 | `internal/androidbridge/abi.go:19-33` |
| Go core | `kurd-go-core-phase9-v1` | `internal/androidbridge/abi.go:19-23` |
| Profile schema | `product-profile-admission-v1`; authority version 1 | `internal/product/profile/profile.go:18-23` |
| Strategy registry | `permitted-fallback-v1` | `internal/product/strategy/strategy.go:17` |
| Relay schema | `offline-relay-descriptor-admission-v1` | `internal/product/relaydescriptor/relaydescriptor.go:16-21` |
| Runtime policy | numeric schema 2; `kurd-wire-v1`; `tls13-tcp`; canonical policy maximum 64 KiB; live-program maximum 48 KiB | `internal/product/runtimepolicy/policy_v2.go:26-32` |
| Session plan | `session-plan-v2`; supported strategy `strategy.kurd-tls13-tcp` | `internal/product/sessionplan/sessionplan_v2.go:21-27` |
| Diagnostic export | `offline-diagnostic-export-v1`; local-user-initiated, redacted, no telemetry | `internal/product/diagnosticexport/diagnosticexport.go:15-22` |
| Cryptographic suite | suite `0x0001`; COSE ES256; HPKE base mode with P-256/HKDF-SHA256/AES-256-GCM; reserved PQ/hybrid IDs are unsupported | `internal/product/envelope/phase8_suite.go:16-61`; `internal/product/envelope/phase8_suite.go:104-121` |
| ABI compatibility projection | bridge/core/profile/strategy/relay/diagnostic identities, suite, and hard bounds are emitted by `CurrentABIInfo` | `internal/androidbridge/abi.go:67-96` |

## Required runtime primitive admission

The planned `ProductionNativeSession` and `ProductionNativeMaintenance` adapters do not exist in this tree. That is expected before their owning work. The following table distinguishes stable underlying primitives from those future adapters.

| Required capability | Integrated production primitive | Primitive result | Final adapter status and consequence |
| --- | --- | --- | --- |
| Full-duplex packet ingress/egress | `PacketPumpV1.Run` starts independent TUN-read, carrier-write, carrier-read, TUN-write, and idle workers. It validates outbound raw IP, authenticates inbound records, writes TUN, then commits replay state. The release path authenticates TLS and Kurd, constructs the live carrier, and runs this pump over the real TUN and selected endpoint. `internal/runtime/ip_tunnel_v1.go:208-275`; `internal/runtime/ip_tunnel_v1.go:327-370`; `internal/runtime/ip_tunnel_v1.go:417-556`; `cmd/kandroidbridge/phase17_release_unix.go:130-305` | `PRESENT` | Task 7/9 adapter is planned; no parallel Android packet protocol is admitted. |
| Socket-protection pause/resume | Native creates an unconnected, nonblocking, close-on-exec TCP socket. Android receives its descriptor, calls `VpnService.protect`, binds it to the selected `Network`, and only then commits protection; native connect/TLS/Kurd authentication occur after that commit. `cmd/kandroidbridge/phase17_release_unix.go:45-127`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/NativeTunnelController.kt:139-279`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:389-425`; `internal/androidbridge/runtime_session_v2.go:411-538` | `PRESENT` | The current path always binds to a selected network. A future optional-network-handle form is not yet an adapter contract. |
| Route/DNS/IP plan | Signed policy admits IPv4, IPv6, or dual stack, validates canonical IP-literal endpoint/address forms, limits routes and numeric in-tunnel DNS, and binds MTU, protocols, resource limits, and fallback. Plan construction can narrow but not widen; Android revalidates the exact TUN configuration before establishment. `internal/product/runtimepolicy/policy_v2.go:57-130`; `internal/product/runtimepolicy/policy_v2.go:392-510`; `internal/product/sessionplan/sessionplan_v2.go:179-225`; `internal/product/sessionplan/sessionplan_v2.go:312-356`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/NativeTunnelController.kt:505-542`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:692-725` | `PRESENT` | Tasks 7/10 own the final Android port and policy presentation. |
| Node/path/strategy/exit projection | The live plan and snapshot carry a strategy ID, relay key ID, plan digest, and truncated deterministic fingerprints, but no node, path, country/region, or independently measured exit field. `internal/product/sessionplan/sessionplan_v2.go:57-82`; `internal/androidbridge/runtime_session_v2.go:54-78`; `internal/androidbridge/runtime_session_v2.go:789-805` | `PARTIAL` | Strategy/relay fingerprints are admitted only as the current bounded deterministic projection, not as a non-linkability claim. Node/path/exit-dependent Task 16/17 work is stopped until a versioned safe projection exists. |
| Metrics | `RuntimeNetworkDiagnosticsV1` defines fourteen bounded aggregate counters and explicitly excludes addresses, payloads, profile material, credentials, and stable session identifiers. The release provider reads the live packet pump and the release bridge maps all fourteen values. `internal/androidbridge/runtime_session_v2.go:95-117`; `cmd/kandroidbridge/phase17_release_unix.go:295-305`; `cmd/kandroidbridge/phase17_release.go:59-75` | `PRESENT` | Tasks 7/16/19 may adapt these counters, but cannot infer latency, speed, path, or exit evidence. |
| Fallback | Policy permits at most four ordered endpoints, five total/reconnect attempts, ten seconds per attempt, and thirty seconds maximum backoff. Native advances one endpoint only after `ENDPOINT_UNAVAILABLE` and closes the failed network first. `internal/product/runtimepolicy/policy_v2.go:531-550`; `internal/product/runtimepolicy/policy_v2.go:632-647`; `internal/androidbridge/runtime_session_v2.go:411-552` | `PRESENT_UNDERLYING` | The current native session owns bounded endpoint fallback. Task 7/11 must map that behavior without claiming an in-session Android reconnect operation. |
| Reconnect | `RuntimeStartCoordinator` validates the authority request's signed retry budget, retires the current owner, prevents a new start before cleanup is `CLEAN`, and schedules a fresh authority request with bounded 1/2/4/8/16-second delays. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeStartCoordinator.kt:94-210`; `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeAuthorityReissueContract.kt:5-40`; `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136` | `PARTIAL` | Fresh-session re-arm is present. `NativeLiveRuntimeSession` has no in-session `requestReconnect` operation, so Task 11 must use a contract correction rather than pretend it exists. |
| Handover | A network change cancels/fails the current attempt; `NativeLiveRuntimeSession` has no handover operation. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:310-324` | `ABSENT` | Task 11 make-before-break/session-preserving handover is stopped. |
| Revocation | OS VPN revocation and service destruction stop the runtime; the same-UID authority client also aborts the current runtime when a registered active-revision invalidation arrives. Authority is rechecked before TUN and active publication. The live native interface has no externally driven signed profile/deployment revocation or active-session revalidation operation. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:165-466`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeAuthorityReissueClient.kt:277-325`; `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136` | `PARTIAL` | OS revoke and registered local active-revision invalidation are admitted. Task 18 external signed profile/deployment revocation remains stopped. |
| Same-deployment update | The production native surface has no same-deployment-update-specific check, verify, materialize, activate, or release operation. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:181-205` | `ABSENT` | Task 18 update work is stopped until a versioned primitive exists. |
| Bounded probe | The live native session has no probe operation. The legacy 32 KiB round-trip function returns `CodeTrustUnavailable` in release builds. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-142`; `cmd/kandroidbridge/phase11_release.go:1-14` | `ABSENT` | Task 19 probe work is stopped; diagnostics counters are not a probe substitute. |
| Proxy stream | The live native session has no stream-open/read/write/close surface. `proxy_semantics` is only an allowed signed live-program capability token, not a product stream primitive. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136`; `internal/protocol/liveprogram/program_v1.go:227-240` | `ABSENT` | Task 12 and proxy-dependent work are stopped. No local listener may be presented as Kurd-backed behavior. |

## Capability-gated feature ledger

There are exactly fifteen capability-gated rows in the current Phase 18 planning coverage. Each has one binary result.

| ID | Result | Bound contract evidence | Consequence |
| --- | --- | --- | --- |
| P18-F005 | `NOT_ADMITTED` | The exhaustive live snapshot contains fingerprints and route/limit fields, but no verified region/country/exit field. `internal/androidbridge/runtime_session_v2.go:54-78` | Do not display inferred exit geography. |
| P18-F014 | `ADMITTED` | `PlanV2.StrategyID`; signed profile strategy IDs enter plan construction, and `selectStrategyV2` accepts only signed `strategy.kurd-tls13-tcp`. `internal/product/sessionplan/sessionplan_v2.go:57-283` | Task 17 may expose only this signed/runtime intersection. |
| P18-F015 | `ADMITTED` | `runtimeNarrowingV2` carries manual strategy choice; `selectStrategyV2` rejects unsigned or unsupported values. `internal/androidbridge/runtime_session_v2.go:755-786`; `internal/product/sessionplan/sessionplan_v2.go:272-283` | Manual choice remains narrowing, never authority. |
| P18-F016 | `NOT_ADMITTED` | The live snapshot and narrowing surface contain no fragmentation, padding, noise, Mux, or cover-stream control. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:78-102`; `internal/androidbridge/runtime_session_v2.go:755-786` | Do not expose inert expert controls. |
| P18-F022 | `ADMITTED` | Manifest `SUPPORTS_ALWAYS_ON`; `RuntimeServiceCommand.AutomaticTrigger`; an unmarked system/OEM lifecycle start is automatic, while marked private actions require the exact marker/request contract. Automatic authority still requires unlocked, prepared, and enabled state. `android/runtime/android/src/main/AndroidManifest.xml:9-24`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt:7-56`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:137-159`; `android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueAdmission.kt:60-72` | Tasks 11/20 may present Android system always-on truth. This does not admit direct-boot access. |
| P18-F025 | `NOT_ADMITTED` | `buildAuthorityV2` rejects `AllowLAN` as authority widening; Android's live-transport validation independently rejects it with `LAN_POLICY_NOT_IMPLEMENTED`. `internal/product/sessionplan/sessionplan_v2.go:202-208`; `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt:103-116` | LAN bypass remains unavailable. |
| P18-F029 | `NOT_ADMITTED` | `NativeLiveRuntimeSession` has no Kurd-backed proxy stream or listener operation. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136` | Local-proxy-only mode remains unavailable. |
| P18-F033 | `ADMITTED` | Signed `AllowedIPModes`, `selectIPModeV2`, and runtime narrowing support IPv4-only, IPv6-only, and dual-stack; `AUTO` is Android request-side selection, not an extra signed mode. `internal/product/runtimepolicy/policy_v2.go:57-130`; `internal/product/sessionplan/sessionplan_v2.go:312-356`; `internal/androidbridge/runtime_session_v2.go:755-771` | Tasks 10/21/30 may expose only the signed/native/Android intersection. |
| P18-F035 | `NOT_ADMITTED` | Authenticated numeric in-tunnel DNS bytes exist, but no named public-resolver identity or policy exists. `internal/product/sessionplan/sessionplan_v2.go:329-356`; `internal/androidbridge/runtime_session_v2.go:67-78` | No public-DNS preset claim. |
| P18-F039 | `NOT_ADMITTED` | No live probe request/result exists; the available runtime observations are aggregate counters. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136`; `internal/androidbridge/runtime_session_v2.go:95-117` | Probe controls remain unavailable. |
| P18-F046 | `NOT_ADMITTED` | No production distribution-channel/rate/share contract exists in the native surface or bounded runtime command contract. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:181-205`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt:19-56` | Distribution UI is omitted. |
| P18-F047 | `NOT_ADMITTED` | The app admits `kurd://artifact` VIEW and octet-stream SEND for import, but there is no general automation grammar or authority-changing deep-link contract. Runtime private commands reject unknown actions/extras. `android/app/src/main/AndroidManifest.xml:26-47`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt:19-56` | Existing import preview is not automation admission. |
| P18-F049 | `ADMITTED` | `KurdNativeCore.createBackup/openBackup/restoreBackup`; payload v2 writing with explicit v1 input compatibility and unknown-version rejection; product backup is bounded to 128 records and 8 MiB. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:196-205`; `android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/BackupPayloadCodec.kt:9-122`; `internal/product/backup/backup.go:35-49` | Task 24 may add a bounded encrypted QR/copy/SAF adapter; plaintext secret export is not admitted. |
| P18-F050 | `NOT_ADMITTED` | Numeric signed limits exist, but no versioned measured named preset bundle or requested/effective preset contract exists. `internal/product/sessionplan/sessionplan_v2.go:386-410` | Do not present performance presets. |
| P18-F053 | `NOT_ADMITTED` | The admitted plan fixes MTU at 1280 and rejects LAN/widening; runtime narrowing has no route, UDP-policy, queue/reconnect-limit, reset, or reversal command. `internal/product/sessionplan/sessionplan_v2.go:202-208`; `internal/androidbridge/runtime_session_v2.go:755-786` | Expert controls remain unavailable. |

Admission count: **5 `ADMITTED`**, **10 `NOT_ADMITTED`**, **15 total**.

## Hard bounds

| Surface | Exact admitted bound | Exact source |
| --- | --- | --- |
| Raw IP packet | The outbound TUN-read buffer is capped at 65,535 bytes. Valid packet minima are family-specific: 20 bytes for IPv4 and 40 bytes for IPv6. This row does not assert a universal inbound packet cap. | `internal/runtime/ip_tunnel_v1.go:208-339`; `internal/runtime/ip_packet_v1.go:180-212` |
| Kurd wire | 48-byte header; 65,536-byte control payload; 1,048,576-byte data payload; maximum outer record 1,048,624 bytes. | `internal/protocol/wirev1/codec.go:13-19` |
| Carrier record | 4-byte length prefix around a maximum 1,048,624-byte outer record. | `internal/runtime/ip_tunnel_v1.go:669-675` |
| Signed profile object | 1,048,576 bytes; signed payload 1,044,480 bytes; sealed frame/input 1,052,763 bytes. | `internal/product/envelope/phase8_suite.go:45-77` |
| ABI result | 1,118,299 bytes, defined as maximum sealed input plus 65,536 bytes. | `internal/androidbridge/abi.go:24-30` |
| Runtime policy/program | encoded policy 65,536 bytes; canonical live program 49,152 bytes. | `internal/product/runtimepolicy/policy_v2.go:26-32` |
| Endpoints/routes | at most four ordered endpoints and two route prefixes; an address is exactly 4 or 16 bytes according to family. | `internal/product/runtimepolicy/policy_v2.go:392-510`; `internal/product/runtimepolicy/policy_v2.go:632-665` |
| Per-app routing | at most 64 package names; each is 3 through 255 characters. No aggregate encoded-byte maximum is declared. | `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/VpnRoutingPolicy.kt:12-41` |
| Generic signed live-program streams | permitted concurrent values are 2, 4, 8, or 16. This does not admit a Phase 18 proxy stream. | `internal/protocol/liveprogram/program_v1.go:165-170` |
| Probe | `NOT_ADMITTED`; therefore no production probe size exists. | `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-136` |
| Offline diagnostic export | at most 6 categories, 10 entries per category, 28 total entries, and 4,096 encoded bytes. | `internal/product/diagnosticexport/diagnosticexport.go:15-22` |
| Protected presentation events | internal protected projection permits at most 200 events and 32,700 encoded bytes; this is not the offline export schema. | `android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMutationBroker.kt:59-102` |
| Backup | product artifact payload at most 8 MiB and 128 records; Android payload v2 also caps each verify request at 1 MiB and the key record at 192 KiB. | `internal/product/backup/backup.go:35-49`; `android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/BackupPayloadCodec.kt:9-184` |
| Runtime resources | packets/frames/messages at most 2^24; queue 256; reconnect attempts 5; attempt timeout 10 seconds; maximum backoff 30 seconds. | `internal/product/runtimepolicy/policy_v2.go:531-550`; `internal/protocol/liveprogram/program_v1.go:192-205` |

### Stream-bound conflict

The numeric wire bound is admitted, but the application-slot selection contract is not. Tracked prose/config state application slots `1..64`, a keyed five-tuple mapping, padding slot 65534, and control slot 65535. The live packet pump initializes its counter at 1, increments before sealing, and therefore first emits stream 2 before allocating sequential IDs through 65534; the record layer accepts nonzero application IDs below 65535. These are incompatible contracts. `docs/protocol/KURD-WIRE-V1-LIVE.md:30-50`; `config/runtime/live-data-plane-v1.json:140-160`; `internal/runtime/ip_tunnel_v1.go:208-230`; `internal/runtime/ip_tunnel_v1.go:417-422`; `internal/runtime/ip_tunnel_v1.go:659-666`; `internal/runtime/process_duplex_record_v1.go:276-400`.

No Phase 18 stream adapter may rely on a canonical application-slot mapping until that conflict is corrected and versioned.

## Endpoint, protection, binding, and connection ownership

1. Runtime policy contains ordered IP-literal address bytes and ports; there is no endpoint DNS resolver in the live path. `internal/product/runtimepolicy/policy_v2.go:57-62`; `internal/product/runtimepolicy/policy_v2.go:392-405`.
2. Native selects the endpoint and creates `SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC` without connecting. `cmd/kandroidbridge/phase17_release_unix.go:45-65`.
3. `RuntimeSocketPrepare` publishes the descriptor while the state is `SOCKET_PREPARED`. `internal/androidbridge/runtime_session_v2.go:411-471`.
4. Android calls `VpnService.protect`, then binds the descriptor to the selected Android `Network`. Any false return or exception prevents protected commit and follows the owned cleanup path. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/NativeTunnelController.kt:167-279`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:401-425`.
5. Only `RuntimeSocketCommitProtected(true)` invokes native connect, TLS authentication, and Kurd authentication. `internal/androidbridge/runtime_session_v2.go:474-538`; `cmd/kandroidbridge/phase17_release_unix.go:77-127`.

Result: the current path proves **protect-before-connect** and **bind-before-connect** for every attempted socket. Native owns IP-literal endpoint selection and connect. Android owns framework protection and network binding. The current binding is mandatory; no optional network-handle adapter exists yet.

## Failure and cancellation contract

### Native error codes

The bridge defines and bounds this exact sequence: `OK`, `INVALID_ARGUMENT`, `SIZE_LIMIT`, `INVALID_HANDLE`, `WRONG_HANDLE_TYPE`, `ALREADY_CLOSED`, `CANCELLED`, `TRUST_UNAVAILABLE`, `VERIFICATION_REJECTED`, `POLICY_REJECTED`, `STORAGE_FAILURE`, `RECOVERY_REQUIRED`, `QUARANTINED`, `INCOMPATIBLE`, `INTERNAL_FAILURE`, `ENDPOINT_UNAVAILABLE`, `TLS_REJECTED`, `KURD_AUTH_REJECTED`, `TUN_IO_FAILED`, `DNS_UNAVAILABLE`, `NETWORK_LOST`, `FALLBACK_EXHAUSTED`, `NODE_DRAINED`, `DEPLOYMENT_DISABLED`, `RESOURCE_LIMIT`, and `STATE_CORRUPT`. `internal/androidbridge/abi.go:36-65`.

Kotlin maps all published numeric native failures to a bounded `OperationError`; unknown values become `INTERNAL_FAILURE`. `android/core/model/src/main/kotlin/org/kurdistanvpn/core/model/AppState.kt:200-225`; `android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt:949-976`.

The live Android tunnel adds explicit acquisition/stage failures and a three-state cleanup result: `CLEANUP_REQUIRED`, `UNPROVEN`, or `CLEAN`. `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/LiveRuntimeModels.kt:6-65`.

### Cancellation and cleanup

- Native state owns a context cancellation function. `Cancel` is guarded by `stopOnce`, publishes stopping, cancels the context, closes the network, retains the first cleanup result, and publishes closed. `DestroyResult` separately destroys credentials, plan, snapshot, factory, and context once. `internal/androidbridge/runtime_session_v2.go:657-720`.
- After close, Kotlin returns `CANCELLED` from socket, protection, status, diagnostics, and stop operations; `attachTun` returns `INVALID_INPUT`. Stop uses one owned release object, and close wipes the opening snapshot in `finally`. `android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt:488-569`.
- The process coordinator marks cancellation before retirement and refuses a successor until cleanup is `CLEAN`. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeStartCoordinator.kt:133-152`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeStartCoordinator.kt:179-210`.
- Native packet-pump cancellation closes the pump and returns the parent context error; parser, queue, authentication, TUN, and replay failures close the session instead of fabricating success. `internal/runtime/ip_tunnel_v1.go:241-275`; `internal/runtime/ip_tunnel_v1.go:417-556`.

No cancellation path is an authorization or success receipt.

## Persistence and migration admission

| Surface | Current state | Admission result |
| --- | --- | --- |
| Room metadata | Database version 2, exported schema. `MIGRATION_1_2` adds committed revision, operation ID, quarantine reason, protected projection, recipient binding, and a unique client-key index. `android/data/metadata/src/main/kotlin/org/kurdistanvpn/data/metadata/ProfileCatalog.kt:137-157` | `ADMITTED_VERSIONED` |
| Room authority eligibility | Row eligibility requires a positive committed revision, quarantine reason `NONE`, transaction state `FINALIZED`, and health `AVAILABLE`. Separately, projection reads validate the witness and require every row's revision and operation ID to match it before checking the image digest and bindings. `android/data/metadata/src/main/kotlin/org/kurdistanvpn/data/metadata/ProfileCatalog.kt:47-78`; `android/data/metadata/src/main/kotlin/org/kurdistanvpn/data/metadata/ProfileCatalog.kt:205-229` | `ADMITTED_FAIL_CLOSED` |
| Settings | Single-process Preferences DataStore named `phase9_nonsecret_settings`; explicit keys exist, and projection witnesses use the exact `kurdistan-settings-projection-v1\u0000` digest domain. There is no settings schema-version field or migration registry. `android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt:51-83`; `android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt:279-315`; `android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt:395-445` | `NOT_ADMITTED_AS_FORWARD_VERSIONED_CONTRACT` |
| Settings stored projection | Pure bounded KSP1 serialization permits 1 through 65,536 stored bytes and performs no default population, repair, or persistence while decoding. `android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt:450-483` | `ADMITTED_AS_CURRENT_CODEC_ONLY` |
| Secure envelope | Magic `KVE1`; legacy format version 1; operation-bound format version 2; AES-256-GCM, 12-byte nonce, 128-bit tag; record ID 64 bytes; wrapped key 512 bytes; secure blob 8 MiB. `android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureEnvelope.kt:15-22`; `android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureEnvelope.kt:81-175` | `ADMITTED_IMPLEMENTATION_VERSIONED` |
| Secure data classes | Wire classes 1 through 18; protected-state additions are recipient index, journal control/record, checkpoint, reset manifest, and projection witness. `android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/SecureEnvelope.kt:24-43` | `ADMITTED_CURRENT_SET` |
| Protected journal | Version-1 digest domains and control encoding; bounded to 256 records, 8 MiB per epoch, 64 KiB per record, 2 MiB checkpoint, 4,096 objects, 256 MiB live objects, and 512 MiB retained objects. Reads never repair. `android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateContracts.kt:7-63`; `android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateOperationJournal.kt:7-176`; `android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateOperationJournal.kt:291-463`; `android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateJournalLifecycle.kt:14-23` | `ADMITTED_CURRENT_JOURNAL` |
| Protected-state migration | One-way, explicitly confirmed adoption of legacy v1 bytes. Original state is not modified or collected; invalid relationships become non-connectable, and unauthenticated bytes are not re-encrypted as trusted state. `android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateMigrationCoordinator.kt:28-243` | `ADMITTED_BOUNDED_MIGRATION` |
| Backup payload | Current writes are v2; v1 is accepted only as historical input; unknown versions fail. `android/data/secure/src/main/kotlin/org/kurdistanvpn/data/secure/BackupPayloadCodec.kt:9-122` | `ADMITTED_VERSIONED` |
| Runtime command/status IPC | Private START/STOP commands require marker version 2, but the broader `VpnRuntimeContract` query/status action and extra set has no enclosing schema/version identifier. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt:19-56`; `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt:161-205` | `NOT_ADMITTED_AS_FORWARD_VERSIONED_CONTRACT` |

The baseline adds no Phase 18 schema or module. Future work must not call the current unversioned settings or query/status IPC surfaces stable Phase 18 contracts without an explicit compatibility/migration correction; private START/STOP classification already requires marker version 2.

## Contract conflicts and scoped stop ledger

| Scope | Finding | Evidence | Required result |
| --- | --- | --- | --- |
| Admission-wide | Runtime status conflict | Tracked live-data-plane config says `runtimeStatusScope: loopback-only-predecessor`; the integrated service publishes `ACTIVE_KURD_LIVE` only after the live native controller and final authority barrier. `config/runtime/live-data-plane-v1.json:169-188`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:443-466` | Version or correct the conflicting contract before it is relied on for Phase 18 admission. |
| Admission-wide | Stream-slot conflict | Public prose/config require slots 1 through 64 and keyed selection; live source allocates sequential IDs through 65534. `docs/protocol/KURD-WIRE-V1-LIVE.md:30-50`; `config/runtime/live-data-plane-v1.json:140-160`; `internal/runtime/ip_tunnel_v1.go:659-666` | Align and version the source and contract before stream-dependent work. |
| Admission-wide | Unversioned relied contracts | Preferences DataStore keys and the broader query/status action and extra set have no schema or compatibility version. Private START/STOP classification is separately marked version 2. `android/data/settings/src/main/kotlin/org/kurdistanvpn/data/settings/Phase9SettingsStore.kt:279-315`; `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStatus.kt:161-205`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt:19-56` | Add explicit compatibility and migration behavior before treating the unversioned surfaces as Phase 18 contracts. |
| Bounded integration | Declared recipient-field wrapper ceilings differ by layer | `RuntimeStartWire` permits recipient request/private material up to 512/128 bytes. JNI declares 4,096/4,096-byte recipient API wrapper ceilings, while the native runtime-open decoder independently enforces the canonical 512/128-byte enrollment bounds. `android/runtime/api/src/main/kotlin/org/kurdistanvpn/runtime/api/RuntimeStartWire.kt:10-39`; `android/core/native-jni/src/main/kotlin/org/kurdistanvpn/core/nativejni/NativeBridge.kt:715-730`; `internal/androidbridge/runtime_session_v2.go:738-742`; `internal/product/enrollment/request_v1.go:25-30` | The effective current producer and native-decoder bound is 512/128. A future public adapter must define one normative prefilter ceiling and keep every layer fail closed. |
| Task 11 | In-place reconnect and handover are absent. | Required-primitive table above. | Stop only Task 11 work that assumes those primitives; fresh-session re-arm remains available. |
| Task 12 | Kurd-backed proxy stream is absent. | Required-primitive table above. | Stop proxy implementation; do not substitute a local listener. |
| Tasks 16/17 | Node/path/exit safe projection is absent. | Required-primitive table above. | Stop those projections; strategy/relay fingerprints remain usable. |
| Task 18 | The native live and maintenance surfaces expose neither same-deployment update nor externally driven signed profile/deployment revocation operations. Existing local active-revision invalidation is a different mechanism and does not substitute for either missing primitive. `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:127-205` | Stop update and external signed-revocation implementation; preserve the existing local invalidation path. |
| Task 19 | Bounded production probe is absent. | Required-primitive table above. | Stop probe implementation. |

These are the only verified Task 0 stops. Missing optional capability rows are already resolved as `NOT_ADMITTED` and do not block unrelated admitted work.

## Contract delta from pre-execution expectations

| Planned expectation | Integrated baseline observation | Delta disposition |
| --- | --- | --- |
| Public-main rebound after Phase 17 integration | At Task 0 observation time, GitHub reported PR #45 merged and `origin/main` resolved to the admitted commit/tree. | Point-in-time integration observation; immutable source claims remain bound to the commit/tree above. |
| Full-duplex release data plane | Present through live V2 socket/TUN lifecycle and `PacketPumpV1`. | Underlying primitive admitted. |
| Protected-state consistency foundation | `:data:protected-state`, bounded typed journal, projection witnesses, Room v2 migration, operation-bound envelopes, quarantine, reset, and migration infrastructure are present. | Current foundation admitted; no Phase 18 schema change occurred. |
| Marked versus unmarked system-start model | Marked private START/STOP requires marker v2 and bounded request ID; null/standard/OEM lifecycle action becomes `AutomaticTrigger`; first unlock, VPN preparation, and automatic-enabled checks remain required. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/RuntimeServiceCommand.kt:7-56`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:137-159`; `android/app/src/main/kotlin/org/kurdistanvpn/app/RuntimeAuthorityReissueAdmission.kt:60-72` | Primitive admitted for system always-on truth. |
| Final runtime-facing Phase 18 ports | Planned adapter files/symbols are absent, as expected before their owning task. | Future adapter work only. |
| Complete runtime primitive set | As documented individually in the required-runtime-primitive table above, node/path/exit, handover, externally driven signed profile/deployment revocation, update, probe, and proxy-stream primitives are absent; reconnect is fresh-session only. The exhaustive snapshot/diagnostic projection contains no node/path/exit field, and the live plus maintenance interfaces contain none of the missing runtime or maintenance operations. `internal/androidbridge/runtime_session_v2.go:54-117`; `android/core/native-api/src/main/kotlin/org/kurdistanvpn/core/nativeapi/KurdNativeCore.kt:120-205` | Dependent workstreams stopped. |
| Versioned persisted/control compatibility | As documented in the persistence and migration admission table above, Room, secure-envelope operations, journal, migration, backup, and private START/STOP marker classification are versioned; Preferences DataStore and the broader query/status IPC contract are not. | Full admission not granted. |
| One coherent live wire contract | Numeric framing matches, but runtime-status scope and stream-slot selection conflict with live source. | Full admission not granted. |
| Phase 18 qualification | No Task 0 action installs, runs, or qualifies the app. | Remains unexecuted. |

## Reserved test range and legacy round-trip boundary

Release service code opens `NativeLiveRuntimeSession`, transfers the TUN to `NativeTunnelController`, and reaches `ACTIVE_KURD_LIVE` only after the live controller and final authority barrier. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/KurdVpnService.kt:352-466`.

The release legacy round-trip function returns `CodeTrustUnavailable`. `cmd/kandroidbridge/phase11_release.go:1-14`.

`DeterministicPacketEngine` and `TunPacketLoop` remain under `src/main`, including reserved address `198.18.0.53`. An immutable tree-wide call-site audit found no production caller; Android call sites outside their declarations are test-only. The candidate verifier lists `TunPacketLoop` as forbidden and rejects an APK containing any forbidden marker. `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/DeterministicPacketEngine.kt:6-15`; `android/runtime/android/src/main/kotlin/org/kurdistanvpn/runtime/android/TunPacketLoop.kt:11-80`; `cmd/phase17verify/artifact.go:38-317`.

Result: the current release path does **not** require the reserved test range or the round-trip-only data plane. The dormant production-source classes are not positive release evidence and should not be used by a Phase 18 adapter.

## Historical evidence boundary

| Record | Exact historical claim | Phase 18 treatment |
| --- | --- | --- |
| Phase 15 production contract | Bound to commit `bd7fb851bdc5103fb77310839e1cdeebfe8ffda1`; status `FROZEN_FOR_IMPLEMENTATION`; release `NO_GO`. `testdata/evidence/phase15/production-contract.json:2-13`; `testdata/evidence/phase15/production-contract.json:28-35` | Identity/reference only; not current execution proof. |
| Phase 15 overlay | Path/hash manifest for its own change subject. `testdata/evidence/phase15/production-contract-overlay.json:2-18` | Not copied forward as Phase 18 proof. |
| Phase 16 VPS qualification | Bound to commit `b33cf7ed31bdc5aa8cd45e438054f9fdde1c0176`; built from a dirty tree; `relayDataPlane:false`; `NO_GO`. `testdata/evidence/phase16/self-hosted-vps-qualification.json:2-19`; `testdata/evidence/phase16/self-hosted-vps-qualification.json:67-73` | Historical only. |
| Phase 16 overlays | Hash manifests for their original production-runtime/trust subjects. `testdata/evidence/phase16/production-runtime-overlay.json:1-17`; `testdata/evidence/phase16/production-trust-overlay.json:1-22` | Historical only. |
| Phase 17 acceptance registry | Version 2, 190 definitions, claim policy `DEFINITIONS_AND_SOURCE_MAPPING_ONLY`; entries are not execution evidence. `config/phase17-acceptance-registry-v2.json:2-28`; `config/phase17-acceptance-registry-v2.json:30-51` | Definitions remain useful; execution is not promoted. |
| Installed D01-D08 | Installed-device requirements remain `UNEXECUTED`. `config/phase17-acceptance-registry-v2.json:1090-1270` | Unexecuted. |
| Candidate/campaign G03-G04 | Both remain `UNEXECUTED`. `config/phase17-acceptance-registry-v2.json:2121-2161` | Candidate and campaign gates remain closed. |
| Qualification policy | Requires install, service health, traffic/DNS/egress, revocation, restart, restore, rollback, crash-free, privacy, Stress, and soak evidence. `config/phase17/qualification-policy-v1.json:2-26`; `config/phase17/qualification-policy-v1.json:37-100` | None is executed by Task 0. |

## Final Task 0 determination

The immutable integrated baseline is authentic and contains a substantial production foundation: a real full-duplex live TUN path, strict protect/bind-before-connect ordering, signed route/DNS/IP narrowing, bounded fallback, fresh-session reconnect, aggregate metrics, versioned Room migration, a bounded protected-state journal, versioned encrypted objects, and versioned backup input handling.

Full Phase 18 production-contract admission is nevertheless **not granted** because:

1. node/path/exit projection, in-place handover, externally driven signed profile/deployment revocation, same-deployment update, bounded live probe, and proxy-stream primitives are absent;
2. reconnect exists only as clean fresh-session re-arm, not the planned in-session operation;
3. Preferences DataStore and the broader query/status IPC contract are relied-on but unversioned, although private START/STOP classification already requires marker version 2;
4. tracked live-data-plane status scope and stream-slot contracts conflict with the integrated live source.

Task 0 records those facts and stops. It does not authorize Task 1, product implementation, migration, installation, qualification, candidate construction, Stress, soak, final review, merge, or release.

## Second-read validation

After drafting, every cited path/range and every named production symbol must be reread from the immutable baseline. Validation succeeds only if:

- every path resolves in the bound tree;
- every line is in range;
- each cited range materially supports the associated claim;
- the capability ledger contains exactly 15 unique rows, with exactly 5 `ADMITTED` and 10 `NOT_ADMITTED` results;
- no source/test/UI declaration is promoted beyond what its production caller proves;
- the initial status remains distinguishable from the single Task 0 document;
- no local path, credential, ignored evidence, or nonpublic planning material enters this document.
