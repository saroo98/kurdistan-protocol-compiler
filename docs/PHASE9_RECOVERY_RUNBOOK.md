<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 9 Recovery Runbook

This runbook covers the offline Android foundation only. It contains no relay,
VPN, provider, or network recovery procedure.

## Normal recovery

On startup the app checks the native ABI and storage state before presenting
profiles. Incomplete admission records are resumed from the encrypted import
request. A profile remains unavailable until exact bytes are reopened,
reverified by Go, committed, and finalized.

An interrupted restore is represented by an encrypted `RESTORE_BATCH` plus
metadata rows in `RESTORE_PENDING`. Pending rows are invisible to normal profile
listing. Recovery reverifies every record, then publishes all accepted rows and
supersedes older generations in one Room transaction. Failure removes pending
rows and blobs without changing the previously available set. If cleanup itself
fails, the affected rows remain quarantined instead of being silently forgotten.

## Failure states

- `KeyInvalidated`: preserve ciphertext, do not create a replacement key under
  the same alias, and offer encrypted-backup restore or explicit reset.
- `DegradedStorage`: stop admission/export and preserve existing material for
  recovery.
- `Quarantined`: do not use the affected record; retain the categorical state
  for local diagnosis.
- `MigrationRequired`: stop before reading or activating profiles when ABI or
  schema compatibility fails.
- `FatalRecovery`: present only reset/restore guidance and make no profile
  available.

## User actions

1. Prefer restoring a passphrase-encrypted `kurd-backup-v1` file.
2. Preview the restore and confirm only after the counts and scope are correct.
3. If no usable backup exists, explicitly reset local protected state.
4. Reimport profiles from an authorized source after reset.

The app never silently downgrades Argon2id parameters, bypasses current Go
verification, accepts an older generation, or treats a partial transaction as
usable.

## Claims and limitations

Explicit reset deletes all protected blobs, including interrupted staging files,
deletes metadata, writes a durable recovery marker, destroys the availability
KEK, and creates a fresh empty store and KEK. Startup completes a marker-backed
reset if the process stops partway through. This is cryptographic erasure of the
old protected state, not a claim of secure physical deletion from flash.
Recovery from a lost passphrase, destroyed Keystore key, rooted-device
compromise, or damaged backup ciphertext is not possible by design.
