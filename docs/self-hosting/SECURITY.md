# Self-hosting security boundary

- The deployment root is unique to one owner. Its private key exists only in
  the passphrase-encrypted recovery artifact.
- The online issuer and relay keys are encrypted in owner-only local state.
- There is no Kurdistan account, central directory, global root, universal
  disable, analytics, advertising, remote crash reporting, or traffic log.
- `kurdctl` never accepts passphrases as command-line values. Do not place
  passphrases in shell history, environment variables, support bundles, or
  process arguments.
- Profile and QR exports are owner-only files. Delete temporary copies after
  the intended device imports them.
- A deployment disable or key rotation affects only that deployment and
  advances signed revocation state. It cannot control another deployment.
- The native live package opens only its configured Kurd TLS listener through
  systemd socket activation. Root owns the isolated `inet kurd_node` table,
  systemd-networkd owns `kurd0`, and Unbound accepts only the TUN client pools.
  The relay process cannot edit those policies.
- Software key custody is not hardware-backed. TPM, PKCS#11, or HSM adapters
  may be added later but are never mandatory for self-hosting.

Run `kurdctl doctor` after clock changes, storage recovery, upgrades, and
permission changes. A clock repair requires the offline recovery artifact.
