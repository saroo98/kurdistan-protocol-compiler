# Backup and restore

Create backups outside the live data directory:

```sh
kurdctl backup create \
  --data-dir /var/lib/kurd-node \
  --recipient-registry-dir /var/lib/kurd-node/recipient-registry \
  --file /media/offline/node.kurd-backup
kurdctl backup verify --file /media/offline/node.kurd-backup
```

The passphrase is read from standard input. The backup uses Argon2id and
AES-256-GCM. Backup version 3 contains authenticated authority state, encrypted
online keys, profiles, revocations, the audit head, and the owner-local
recipient-use registry needed to preserve device-enrollment replay protection.
It does not contain the offline root recovery private key; preserve that
artifact separately.

Version 1 backups remain readable and migrate into the current state format.
Version 2 backups remain readable only when the saved state has no recipient-use
ledger. A version 2 backup that references a recipient registry cannot restore
safely because that older format did not contain the registry; verification and
restore therefore fail closed instead of weakening replay protection.

Restore is two-step and fail-closed:

```sh
kurdctl restore preview --file node.kurd-backup --data-dir /var/lib/kurd-node-restored
kurdctl restore apply \
  --file node.kurd-backup \
  --data-dir /var/lib/kurd-node-restored \
  --recipient-registry-dir /var/lib/kurd-node-restored/recipient-registry \
  --expected-digest <preview-digest>
```

Restored state is quarantined, drained, and recovery-unconfirmed. Confirm the
offline recovery artifact, run doctor, then explicitly resume. An equal or
older backup cannot overwrite an existing deployment.

The restore operation validates the recipient registry against the state ledger
and installs it before the restored deployment is made visible. An absent,
damaged, mismatched, or partially written registry rejects the restore. Never
create a replacement registry merely to bypass this rejection; recover from a
complete version 3 backup or reinitialize a new test deployment with new device
enrollment capabilities.

When a root administrator restores into `/var/lib/kurd-node`, restore the
directory ownership to the dedicated account before confirmation:

```sh
sudo chown -R kurd-node:kurd-node /var/lib/kurd-node
sudo chmod 0700 /var/lib/kurd-node
```

After total-host recovery succeeds, verify the root fingerprint, generation,
revocation epoch, audit head, and publication cursor before destroying the
quarantined predecessor. An endpoint change invalidates the live relay
descriptor and requires a newly issued profile. Restore never silently reuses
a stale endpoint or lowers relay, revocation, generation, revision, or audit
authority.

Native upgrades require `KURD_BACKUP_PASSPHRASE_FILE` when state exists. The
file must be root-owned, non-symlinked, and mode `0400` or `0600`. The upgrade
creates and verifies an encrypted backup under `/var/backups/kurd-node` before
installing the candidate. The passphrase is inherited on standard input and is
never placed in argv, an environment value, or a log.
