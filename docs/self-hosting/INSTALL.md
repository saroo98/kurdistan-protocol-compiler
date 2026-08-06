# Native installation

Phase 16 supports Linux `amd64` and `arm64` engineering archives. These
archives are deterministic and checksum-bound but are not public release
artifacts. Protected distribution signing is a Phase 19 gate.

## Platform qualification matrix

| Platform | Phase 16 evidence | Status |
|---|---|---|
| Ubuntu Server 26.04 LTS, `amd64`, systemd | Fresh external owner-VPS install, upgrade, rollback, re-upgrade, recovery, service sandbox, and doctor | Qualified |
| Linux `arm64`, systemd | Deterministic cross-build and strict archive verification | Package-qualified; native ARM64 host execution remains unverified |
| Other systemd Linux distributions on `amd64` or `arm64` | Portable static binary and preflight contract only | Unverified until the complete native install and recovery matrix passes on that distribution |

“Linux support” in Phase 16 therefore means the verified archive and preflight
contract, not an unsupported claim that every distribution or kernel has been
field-tested. Phase 21 owns the broader host and provider matrix.

1. Obtain the archive and its SHA-256 through an authenticated owner-selected
   channel. Compare the outer archive digest before extraction.
2. On a trusted workstation, run:

   ```sh
   kurdpackage verify --archive kurd-node-<version>-linux-<arch>.tar.gz
   ```

3. Extract into a new empty directory, inspect `manifest.json`,
   `SHA256SUMS`, and the scripts, then run:

   ```sh
   sudo ./preflight.sh --install
   sudo ./install.sh --install
   ```

4. Initialize authority as the dedicated service account. Keep recovery and
   backup destinations outside `/var/lib/kurd-node` and off the VPS after
   confirmation.

The installer creates the unprivileged `kurd-node` account, installs only the
two binaries, systemd policy, helper scripts, documentation, and manifests,
and leaves service start under explicit owner control. Phase 16 opens no relay
port. Do not add a firewall exception for a future Phase 17 listener.

The systemd service has no network address family. It can read deployment
state and atomically publish the local signed authority snapshot, but cannot
make an outbound connection or accept Internet traffic.

Uninstall removes installed binaries and service policy but intentionally
preserves `/var/lib/kurd-node`. Delete authority state only after a separately
verified backup and an explicit owner decision.
