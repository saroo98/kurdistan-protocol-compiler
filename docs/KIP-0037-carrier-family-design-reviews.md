<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0037: Carrier-Family Design Reviews

Milestone 31 adds carrier-family design review infrastructure before any concrete carrier work.

The review layer records which carrier families are safe for synthetic modeling, which require manual review, and which are blocked by risk. It deliberately does not implement HTTP, TLS, DNS, QUIC, UDP, CDN, bridge provisioning, or external-network behavior.

## Reviewed Families

`internal/carrierreview` evaluates design descriptors for:

- `https_like_tcp`
- `dns_survival`
- `experimental_udp_quic`
- `domestic_media_risk`
- `relay_bridge_rotation`

Each descriptor records readiness, risk class, default eligibility, manual-review requirements, synthetic-only status, forbidden claims, and trace-hygiene preconditions.

## Audit Gates

`kcheck carrierreview --quick` and the default quick audit include gates for:

- carrier-family descriptors
- readiness matrix coverage
- risk gating
- misuse detection
- generated backend parity
- trace hygiene
- mutant detection
- fixture drift

## Fixtures

Committed fixtures under `testdata/carrierreview/` freeze the family descriptors, readiness matrix, controls, and generated/interpreted review parity.

## Commands

```bash
go run ./cmd/kcheck carrierreview --quick
go run ./cmd/kcheck carrierreview --full --out testdata/audit/carrierreview.json
go run ./cmd/kcheck carrierreview verify
```

## Limitations

Carrier review is a design gate, not a carrier implementation. The project still has no live carrier, public-network probing, concrete DNS/HTTPS/UDP/QUIC behavior, relay endpoint allocation, or deployment path in this milestone.
