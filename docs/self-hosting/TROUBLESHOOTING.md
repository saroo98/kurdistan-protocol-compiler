# Troubleshooting

Run:

```sh
kurdctl doctor --data-dir /var/lib/kurd-node
systemctl status kurd-node --no-pager
journalctl -u kurd-node --since today
```

The node emits bounded authority/publication health only. It must never emit
profiles, keys, passphrases, DNS questions, destinations, payloads, or raw
frames. Use `kurdctl logs export-redacted` for a local reviewed support file.

- `clock health rejected`: correct the host clock, then use `clock repair` with
  the offline recovery artifact and explicit confirmation.
- `another state transaction is active`: confirm no `kurdctl` is running. A
  stale lock must be removed only after preserving state and verifying process
  ownership.
- `recovery artifact rejected`: do not retry by weakening validation. Confirm
  the exact deployment recovery artifact and exact passphrase.
- `rollback rejected`: use the newest accepted profile/backup and do not lower
  generation or revocation state.
- service not ready: recovery must be confirmed and deployment-local deny must
  be inactive. Phase 16 still reports the relay data plane unavailable.
