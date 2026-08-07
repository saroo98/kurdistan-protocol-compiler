# Troubleshooting

Run:

```sh
kurdctl doctor --data-dir /var/lib/kurd-node
systemctl status kurd-node --no-pager
systemctl status kurd-node.socket kurd-node-network.service --no-pager
journalctl -u kurd-node -u kurd-node.socket -u kurd-node-network --since today
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
- `preflight` rejects IPv6: the current native package requires one IPv4 and
  one IPv6 default route through the same explicit egress interface. Do not
  bypass this check; use a later reviewed IPv4-only profile mode instead.
- port conflict: stop the unrelated listener or choose a separately reviewed
  port/profile. The systemd-owned socket is accepted only with
  `--allow-systemd-socket`.
- service not ready: verify recovery confirmation, local emergency deny,
  system time, `kurd0`, Unbound, the owned nftables table, and the exact
  profile/relay generation. Do not weaken verification to make it start.
