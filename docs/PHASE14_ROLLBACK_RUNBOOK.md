<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 rollback and recovery runbook

Status: local procedure ready; production drills **[UNVERIFIED]**

Rollback is a product-wide operation, not only an APK downgrade. Android
version monotonicity, profile generation, provider publication, relay state,
revocation, and signing authority must remain consistent.

## Triggers

- authority or signature failure;
- profile/provider rollback acceptance;
- traffic or DNS escape;
- kill-switch or recovery failure;
- crash/ANR regression or resource exhaustion;
- relay compromise, operator compromise, or signing incident;
- invalid privacy or capability claim;
- failed staged-rollout thresholds.

## Sequence

1. Freeze rollout and open a redacted incident record.
2. Identify the exact app, profile, provider, relay, and authority generations.
3. Activate emergency deny or revoke affected artifacts where required.
4. Drain affected relays without silently moving clients to an unauthorized path.
5. Restore the last known-good provider publication and compatible relay set.
6. Publish a monotonic corrective profile/update; never lower generation floors.
7. Roll the app forward to the repaired build. Use platform-supported rollback
   only when its signing and data-migration guarantees are proven.
8. Verify connection, DNS, routing, kill switch, recovery, revocation, backup,
   diagnostics, and operator control before resuming rollout.
9. Record recovery objectives, actual duration, data loss, limitations, and
   follow-up actions without secrets or user traffic.

## Required drills

- bad app candidate before public rollout;
- bad provider publication;
- relay compromise and drain;
- profile authority revocation;
- signing-key incident;
- database restore and immutable audit reconciliation;
- regional relay loss;
- Android key invalidation and encrypted backup restore;
- interrupted reset and process-death recovery.

A paper walkthrough is not a production pass. Each production drill remains
**[UNVERIFIED]** until observed against the declared environment.
