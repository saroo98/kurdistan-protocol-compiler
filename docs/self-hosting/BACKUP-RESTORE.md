# Backup and restore

Create backups outside the live data directory:

```sh
kurdctl backup create --data-dir /var/lib/kurd-node --file /media/offline/node.kurd-backup
kurdctl backup verify --file /media/offline/node.kurd-backup
```

The passphrase is read from standard input. The backup uses Argon2id and
AES-256-GCM and contains authenticated authority state, encrypted online keys,
profiles, revocations, and the audit head. It does not contain the offline root
recovery private key; preserve that artifact separately.

Restore is two-step and fail-closed:

```sh
kurdctl restore preview --file node.kurd-backup --data-dir /var/lib/kurd-node-restored
kurdctl restore apply --file node.kurd-backup --data-dir /var/lib/kurd-node-restored --expected-digest <preview-digest>
```

Restored state is quarantined, drained, and recovery-unconfirmed. Confirm the
offline recovery artifact, run doctor, then explicitly resume. An equal or
older backup cannot overwrite an existing deployment.

When a root administrator restores into `/var/lib/kurd-node`, restore the
directory ownership to the dedicated account before confirmation:

```sh
sudo chown -R kurd-node:kurd-node /var/lib/kurd-node
sudo chmod 0700 /var/lib/kurd-node
```

After total-host recovery succeeds, verify the root fingerprint, generation,
revocation epoch, audit head, and publication cursor before destroying the
quarantined predecessor. An endpoint change belongs to Phase 17 because it
changes the live relay descriptor.
