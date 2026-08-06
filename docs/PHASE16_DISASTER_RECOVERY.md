# Phase 16 Disaster Recovery

> **Realignment notice:** KIP-0093 requires owner-controlled encrypted backup,
> migration to a replacement VPS, and monotonic deployment-local recovery.
> Cloud-specific recovery steps in this historical document are not current
> deployment authority.

## Authority

This runbook covers the production trust control plane. It does not authorize
restoring an older authority epoch, replacing an HSM key, or activating public
VPN infrastructure. Every production action requires the role-separated
approval defined in `config/production/actions.json`.

## Recovery objectives

- Control-plane RTO: at most four hours.
- Publication and emergency-control RTO: at most 30 minutes.
- RPO: zero acknowledged authority transitions.
- An operation is acknowledged only after its required external audit anchor
  and publication postcondition have durable readback receipts.

## Restore sequence

1. Declare the incident, freeze ordinary mutations, and preserve evidence.
2. Capture the current immutable publication and audit-anchor heads.
3. Restore the newest transactionally consistent Spanner backup into a new
   database. Never restore in place.
4. Verify migration checksums and apply only monotonic schema migrations.
5. Verify the complete audit sequence and previous-anchor linkage.
6. Run the restore verifier against the pre-incident, public, and audit heads.
7. Reject an older epoch, revision, sequence, equal-sequence fork, unknown key,
   or missing acknowledged transition.
8. Replay only pending outbox effects using their original effect IDs and new
   fenced leases.
9. Run read-only profile, revocation, emergency-deny, and KMS public-key checks.
10. Switch service traffic only after two-person approval and exact image
    digest verification.
11. Retain the prior database for forensic review. Authority state is never
    rolled backward as a rollback mechanism.
12. Record actual RTO, RPO, heads, image digests, approver aliases, and result
    in the private evidence store.

## Required drills

Qualification must exercise database loss, regional loss, worker backlog,
audit and publication outages, disabled issuer, recovery-root activation,
trusted-time rollback, identity outage, compromised session, and image
rollback. Production drills are read-only or explicitly approved. A local
unit test or emulator result is not a production drill receipt.
