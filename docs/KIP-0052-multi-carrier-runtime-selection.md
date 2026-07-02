<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0052: Multi-Carrier Runtime Selection

Milestone 46 adds a deterministic selection layer across the reviewed carrier families already present in the lab stack. It does not add a new concrete carrier. The purpose is to prove that Kurdistan can assemble a profile-sensitive carrier candidate bundle, apply review and health constraints, pick primary and backup choices, and reject unsafe fallback behavior while keeping trace output payload-free and secret-free.

## Scope

The selector composes these existing layers:

- HTTPS-like lab carrier contract and prototype evidence.
- Constrained request/response carrier contract and prototype evidence.
- Transport bundle, pathrace, and pathhealth reports.
- Carrier review and measurement review constraints.
- Local pipeline and lab-egress boundary checks.
- Generated/interpreted parity checks.

The selector emits only safe summaries: family classes, decision buckets, counts, gate outcomes, stable hashes, and high-level reason classes.

## Carrier Family Inventory

The inventory uses bounded family classes:

- `https_like_lab`
- `dns_survival_lab`
- `constrained_request_response_lab`
- `rejected_unsafe`
- `control_unsafe`

Only reviewed lab families can become eligible runtime candidates. Unsafe and control classes remain present as negative fixtures so gates can prove they are blocked.

## Candidate Bundle Assembly

Candidate bundles record:

- family class
- profile seed
- profile-sensitive eligibility bucket
- carrier review gate
- measurement review gate
- pathrace gate
- pathhealth gate
- lab-egress gate
- risk class
- selection decision

The fixture baseline uses deterministic profile seeds and stable ordering. The selector intentionally varies eligible primary and backup choices across profiles so one carrier family does not silently become a universal default.

## Selection Decisions

The selector records these decision classes:

- `selected_primary`
- `selected_backup`
- `raced_and_selected`
- `raced_and_rejected`
- `blocked_by_measurementreview`
- `blocked_by_carrierreview`
- `blocked_by_pathhealth`
- `blocked_by_profile_policy`
- `blocked_as_high_risk`
- `blocked_as_unsafe_fallback`

Selection is a reportable lab decision. It is not permission to use public egress or to bypass carrier review.

## Backpressure, Reset, and Error Mapping

M46 does not alter stream or carrier runtime behavior. It verifies that selected candidates carry safe compatibility evidence for:

- carrier-induced backpressure metadata
- pathhealth degradation
- reset and close result classes
- error isolation classes
- failover and fallback decisions

Fallback is only allowed when review, measurement, health, pathrace, transport-bundle, and lab-egress constraints all pass.

## Misuse Controls

The audit model includes explicit controls for:

- `multicarrierselect_fixed_carrier_default`
- `multicarrierselect_profile_insensitive_selection`
- `multicarrierselect_padding_only_selection_variation`
- `multicarrierselect_high_risk_default_allowed`
- `multicarrierselect_unsafe_fallback_allowed`
- `multicarrierselect_measurementreview_bypass`
- `multicarrierselect_carrierreview_bypass`
- `multicarrierselect_pathhealth_bypass`
- `multicarrierselect_pathrace_bypass`
- `multicarrierselect_transportbundle_bypass`
- `multicarrierselect_labegress_bypass`
- `multicarrierselect_public_network_allowed`
- `multicarrierselect_payload_logging_allowed`
- `multicarrierselect_secret_leak`
- `multicarrierselect_generated_backend_drift`

All controls must be detected in quick mode.

## Fixtures

Committed fixture outputs live under:

```text
testdata/multicarrierselect/
  multicarrierselect-report-golden.json
  carrier-inventory-report.json
  candidate-bundle-report.json
  selection-policy-report.json
  profile-sensitivity-report.json
  pathrace-report.json
  pathhealth-report.json
  failover-fallback-report.json
  composition-report.json
  multicarrierselect-misuse-report.json
  multicarrierselect-parity-report.json
  public-claim-safety-report.json
```

These fixtures contain review metadata, buckets, and hashes only. They do not contain payloads, packet captures, resolver addresses, exact request strings, domains, keys, nonces, auth tags, proof material, or secret-bearing traces.

## Generated Backend Parity

Generated modules include multi-carrier selection constants and tests. The scanner verifies generated output contains profile-specific selection data and fixture/parity tests. The generated backend version for this milestone is `0.46.0-lab`.

## Commands

```bash
go run ./cmd/kcheck multicarrierselect --quick
go run ./cmd/kcheck multicarrierselect --full --out testdata/audit/multicarrierselect.json
go run ./cmd/kcheck multicarrierselect generate --out testdata/multicarrierselect/multicarrierselect-report-golden.json --force
go run ./cmd/kcheck multicarrierselect verify
go run ./cmd/kcheck multicarrierselect compare --old testdata/multicarrierselect/multicarrierselect-report-golden.json --new testdata/multicarrierselect/multicarrierselect-report-golden.json
go run ./cmd/kcheck codegen --quick
```

## Limitations

M46 is still a deterministic lab selection model. It does not implement public carrier routing, real carrier probing, arbitrary target forwarding, public-network egress, packet capture, payload logging, or automatic deployment behavior. It proves that selection evidence can be composed and audited before a broader carrier mutation audit begins.

## Next Milestone

M47 should attack the selector and carrier composition layer for fixed-carrier collapse, profile-insensitive selection, padding-only selection variation, unsafe fallback, high-risk default selection, review-gate bypasses, and generated backend drift.
