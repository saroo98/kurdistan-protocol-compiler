<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 16 operator API

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
