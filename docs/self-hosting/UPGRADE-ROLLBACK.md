# Upgrade and rollback

Verify the new archive before extraction. From the verified candidate
directory, run `./upgrade.sh --check` first. Applying an upgrade with existing
state requires a root-owned passphrase file:

```sh
sudo env KURD_BACKUP_PASSPHRASE_FILE=/root/.config/kurd-node/backup-passphrase \
  ./upgrade.sh --apply
```

The apply path drains the node, creates and verifies an encrypted backup,
stops the socket/service/network unit, installs atomically, performs the
authenticated v1-to-v2 migration when needed, runs doctor, resumes, and
restores the prior activation state. It can automatically restore the previous
package and exact v1 state only before the first v2 transaction advances the
revision.

For an existing state-v2 installation, the apply path first requires the
extracted source tree to be root-owned, non-writable by group or other users,
and free of links. It then stages the entire package in a root-controlled
temporary snapshot, binds that snapshot to the checksum-inventory digest
retained before the original verification boundary, and independently verifies
every inventoried file. Preflight and installation run only from this snapshot.
The snapshot's exact `kurdctl` is separately staged for the dedicated service
account and used only for pre-install drain and encrypted backup operations. It
is revalidated before every use, and the installed `kurdctl` must match the
originally retained digest before migration. Snapshot and bridge paths are
removed before migration or service restart; a failed removal retains the
paths for the exit trap to retry. Signal handlers use explicit nonzero statuses,
so an interruption cannot be reported as a successful upgrade. This permits a
repaired state-v2 decoder to back up and upgrade a valid state that the installed
predecessor can no longer decode, without rewriting authority state or bypassing
the backup contract. Genuine state-v1 predecessors continue to use the
installed binary for the authenticated v1-to-v2 migration path. Any staging,
identity, permission, digest, drain, backup, verification, cleanup,
installation, migration, or doctor failure stops the upgrade categorically.

Explicit rollback is:

```sh
sudo /usr/local/lib/kurd-node/rollback.sh --apply --confirm rollback
```

Rollback validates the host and the previous package before mutation. A prior
state-v1 package is accepted only if `kurdctl migration rollback` verifies the
authenticated migration marker, exact v1 backup digest, deployment identity,
generation, and unchanged source revision. After any v2 transaction, rollback
to a v1 package fails closed. A v2-capable previous package keeps the current
monotonic state.

Never replace authority state manually or restore an older generation,
revocation epoch, relay epoch, revision, or audit head.
