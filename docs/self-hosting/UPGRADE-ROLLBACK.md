# Upgrade and rollback

Phase 16 packages are installed side-by-side only after archive verification.
They are engineering packages, not publicly signed releases. Authenticate the
outer archive SHA-256 through an owner-selected channel before using the inner
manifest and checksum inventory.
Before an upgrade:

1. Drain the node.
2. Create and verify an encrypted backup outside the node directory.
3. Verify the new archive, manifest, architecture, and checksums.
4. Stop the service and preserve the previous binaries and manifest.
5. Install the new files, run `kurdctl doctor`, and start the service.
6. Resume only after the publication digest and authority revision are valid.

Rollback restores the previous binaries, not older authority state. Never
replace current state with a lower generation, revocation epoch, revision, or
audit head. If the new binary wrote an incompatible schema, use its documented
forward recovery or restore a newer verified backup into quarantine.

Public release signatures and automated update metadata are Phase 19 work.
Phase 16 does not contact an update server.

From an extracted candidate directory:

```sh
./upgrade.sh --check
sudo ./upgrade.sh --apply
```

The apply path drains authority publication, preserves the previous binaries,
service policy, helper scripts, documentation, and manifest, installs the
candidate atomically, runs doctor as the unprivileged service account, resumes,
and restores the previous installation automatically on failure.

Explicit rollback is:

```sh
sudo /usr/local/lib/kurd-node/rollback.sh --apply --confirm rollback
```

Rollback never restores an older authority state. If no verified previous
installation exists, it fails without changing the current installation.
