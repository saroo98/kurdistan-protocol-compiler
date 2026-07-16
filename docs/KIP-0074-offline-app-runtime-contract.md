<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0074: Offline App-Runtime Contract

## Status

- status: implemented contract
- scope: M7 deterministic offline eligibility only
- implementation: `internal/product/appruntime`

M7 opens only the app-runtime catalog entry. It combines explicit user intent,
caller-supplied platform-readiness metadata, admitted lifecycle state, the exact
M4 fallback request and result, and the exact M5 relay request and admission.
It returns a categorical offline disposition and next contract state. It does
not inspect a device, start or stop a service, create a tunnel, route packets,
configure DNS, install a kill switch, access storage, use a relay, or perform
networking or cryptography.

## Version and vocabulary

The exact v1 version is `offline-app-runtime-v1`. Evaluator intents are
`evaluate`, `connect`, and `recover`. States are `inactive`, `eligible`,
`blocked`, and terminal `disconnect_pending`. Dispositions are
`ready_to_start`, `remain_inactive`, `blocked`, and `shutdown_required`.

`ready_to_start` is eligibility metadata for a future adapter. It does not mean
connected, protected, tunneled, routed, authenticated, or service-running.
`shutdown_required` requests future adapter action and does not acknowledge
that shutdown completed.

## Exact evidence recomputation

Every non-disconnect evaluation requires an exact admitted lifecycle state and
an exact contract version. The evaluator calls `strategy.Select` on the complete
M4 request, requires exact equality with the claimed selected result, requires
the M5 request to embed those same values, and calls `relaydescriptor.Admit` on
the complete M5 request. The resulting admission must exactly equal the claim
and bind the same profile, scope, evidence reference, generation, and family.

These checks prove consistency among offline contracts only. They do not prove
profile signatures, relay authenticity or reachability, real platform
permission, protected storage, routing, DNS, kill-switch installation, or
production security. Endpoint references and identifiers are transient inputs
to exact predecessor recomputation. They are never interpreted, retained,
echoed, or included in runtime output.

## Platform failure and recovery

The caller supplies exact-v1 booleans for known permission state, VPN consent,
protected-storage availability, safe routing, safe DNS, and kill-switch
availability. Any missing safety condition returns `blocked` with one fixed
reason. Incompatible predecessor or platform versions return
`incompatible_contract`. Malformed top-level state or non-monotonic generation
returns a stable error and a zero decision.

Evaluation returns `eligible/remain_inactive`; connect and recover return
`eligible/ready_to_start` only after full current revalidation. The evaluator
stores no hidden state, reads no clock, and performs no retries, callbacks,
workers, or external effects. Process recreation therefore requires the caller
to supply state and all current evidence again.

## Disconnect invariant

`RequestDisconnect` accepts generations only and always returns terminal
`disconnect_pending/shutdown_required`. Both-zero input yields generation 1;
otherwise the output uses the larger supplied generation without incrementing,
so overflow is impossible and repeated calls are byte-identical.

An evaluator already in `disconnect_pending` short-circuits before reading or
validating intent, versions, platform state, or nested predecessor evidence. It
retains shutdown-required state at the larger current/requested generation.
Only a separately authorized future live adapter may acknowledge actual
shutdown and provide a new canonical inactive state.

## Diagnostics and privacy

The package does not import diagnostic export. Diagnostics cannot grant
permission, storage, routing, DNS, kill-switch, profile, fallback, relay, or
runtime authority, and diagnostic failure cannot block shutdown. Output contains
no profile, client, relay, endpoint, device, app, session, user, or destination
identifier and no arbitrary caller text.

## Closed boundaries

M7 adds no Android or Gradle project, VpnService, TUN, UI, file or protected
storage, process or service control, packet handling, routing, DNS, sockets,
network, telemetry, operator system, deployment, or production cryptography.
A later milestone requires separate planning, authorization, implementation,
and review before opening any such boundary.
