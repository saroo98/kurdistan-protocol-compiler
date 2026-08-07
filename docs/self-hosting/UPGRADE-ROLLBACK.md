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
