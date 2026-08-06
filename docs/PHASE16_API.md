<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 16 operator API

> **Realignment notice:** this document describes the superseded centralized
> operator interface. KIP-0093 requires a deployment-local self-hosted
> administration interface. Retain reusable validation and lifecycle logic,
> but do not expose or deploy this interface until it is reconciled with
> `PHASE16_SELF_HOSTED_VPS_COMPLETION_PLAN.md`.

`api/operator/v1/operator.openapi.yaml` is the authoritative HTTP surface for
the private production operator service. The service is an authority boundary,
not a public profile API and not an Android application backend.

## Identity

The implementation validates the signature, exact audience, allowed issuer,
expiry, issued-at time, authorized party, subject, and recent authentication
time of Google-signed ID tokens. Privileged requests additionally require a
bounded unique token identifier. Raw tokens, email addresses, and external
subjects never enter domain state. An environment-keyed HMAC maps the external
subject to an opaque actor alias.

Entitlements are resolved for every request from a versioned mapping. Cached
roles cannot authorize a later phase after group removal or policy revision.
The application enforces requester, approver, and executor separation even when
the surrounding cloud session has already received privileged approval.

## Mutation contract

Every mutation requires:

- `Kurdistan-API-Version: v1`;
- an exact `application/json` content type;
- a bounded, unique `Idempotency-Key`;
- explicit expected revision and epoch fields;
- a body no larger than 64 KiB;
- strict JSON without duplicate or unknown fields; and
- a fresh privileged authentication context.

The API returns only categorical errors and a transient correlation alias. It
never returns provider errors, stack traces, raw profile fields, key material,
operator personal data, or private infrastructure endpoints.

## Readiness

`/v1/health/live` means that the HTTP process can answer. `/v1/health/ready`
means that the configured authority store, entitlement source, and trusted-time
boundary are usable. A live process that cannot prove those dependencies must
remain unready and reject mutations.

The OpenAPI server URL is an `.invalid` documentation sentinel. The real
private endpoint is an owner input and must never be committed.

## Current implementation boundary

Profile issue/rotation intent, independently verified finalization, profile
revocation, and signed root-bound emergency deny have verifier-backed source
adapters. The API reports `EFFECT_PENDING`, `FAILED_RETRYABLE`,
`FAILED_TERMINAL`, `ANCHORED`, `PUBLISHED`, or `FINALIZED` only from the exact
durable outbox record. An executed compatibility operation is never returned as
success by itself, and a profile is not readable as issued/current until its
matching effect is acknowledged.

The key-rotation and recovery routes are reserved by the versioned OpenAPI
contract but are not production-capable yet. Their source schemas, ceremony or
recovery proof adapters, durable transitions, and isolated command binaries do
not exist, so the backend rejects them fail-closed. This is an explicit Phase
16 blocker, not an implicit or simulated feature.
