<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 incident response

Status: procedure ready; production exercise **[UNVERIFIED]**

## Severity

- **Critical:** key/signing compromise, authority widening, traffic/DNS escape,
  payload/secret exposure, kill-switch failure, malicious update, operator loss
  of control, or widespread unsafe routing.
- **High:** repeatable crash/ANR loop, major fleet outage, failed revocation,
  recovery failure, or material privacy/availability regression.
- **Medium:** bounded degradation with a safe fallback and no authority/privacy
  impact.

## Response

1. Detect and classify using redacted categorical evidence.
2. Contain through rollout halt, emergency deny, revocation, relay drain, or
   feature disablement that cannot widen authority.
3. Preserve immutable evidence digests and operator actions without secrets or
   user traffic.
4. Eradicate the cause and add a non-recurrence test or gate.
5. Recover through the rollback runbook and verify the full product path.
6. Communicate truthful impact, affected versions, user actions, limitations,
   and recovery status.
7. Complete a blameless review with owners and deadlines for every corrective
   action.

The incident owner, security owner, operator owner, Android owner, privacy
owner, communications owner, and release owner must be distinct role aliases
where practical. Emergency actions require dual control when production keys,
authority, or fleet-wide state is involved.
