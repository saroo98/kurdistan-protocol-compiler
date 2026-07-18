# Phase 8 Recovery Runbook

This runbook covers deterministic offline recovery contracts only. It does not
authorize live services, production keys, or operator actions.

## Safety rules

1. Preserve the exact failed artifact, active record, and last-known-good record
   as secret-bearing local evidence. Never paste keys, payloads, recipients, or
   raw profiles into logs.
2. Do not weaken time, generation, root, revocation, issuer-scope, recipient, or
   safety floors to make recovery succeed.
3. Re-run the complete verification path. Metadata-only legacy state is never a
   recovery authority.
4. A rejection must leave committed active and last-known-good state unchanged.
5. Quarantine ambiguous or partially committed state and stop automatic use.
6. Treat local CLI inputs and outputs as untrusted filesystem paths: use the
   root-anchored commands only, refuse symlink/reparse traversal and existing
   output names, and keep recovered artifacts in the approved local location.

## Issuer replacement

- Install the newer root-authorized issuer delegation and current revocation
  set through the offline authority path.
- Verify that the retired issuer cannot authorize a new artifact.
- Admit only an artifact signed by the replacement issuer and bound to the same
  provider, lineage, profile namespace, root epoch, and required floors.
- Record the authenticated artifact digest and resulting generation.

## Newer generation replacing a revoked profile

- Keep the revoked generation inactive.
- Require a strictly newer full-snapshot generation with a distinct content ID,
  valid previous-content link, current root view, and current revocation set.
- Verify, stage, mark, commit, and finalize in order. Never merge omitted members
  from the revoked snapshot.

## Local-wrap loss

- Treat the locally wrapped secret as unavailable, not as an authentication
  failure that can be bypassed.
- Keep the signed profile and non-secret metadata quarantined until an authorized
  local wrap is recreated by the future platform keystore integration.
- Do not export or recreate device credentials from logs, backups, or profile
  payloads. Local-only credentials must be regenerated.

## Interrupted activation

- Before the commit boundary, discard the staged candidate and restore the prior
  active and last-known-good records.
- At or after a verified commit boundary, retain only the fully reverified newer
  candidate and preserve the prior record as last-known-good.
- If snapshot, recovery, or quarantine itself fails, leave the system
  unavailable and require operator repair. Do not guess which state won.

## Verification commands

```powershell
go test -count=1 ./internal/product/profile -run 'Recovery|PersistenceFault|Issuer|Revok'
go test -count=1 ./internal/product/lifecycle
go test -count=1 ./internal/product/envelope -run 'TestWO807|TestIndependentInterop'
```

The ten-minute fuzz commands are listed separately in
`testdata/evidence/phase8-fuzz-command-manifest.json` and must not be marked
complete without recording their required runtime observations.
