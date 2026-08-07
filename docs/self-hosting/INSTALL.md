# Native installation

The native package supports Linux `amd64` and `arm64` engineering builds with
systemd, systemd-networkd, nftables, Unbound, iproute2, and `/dev/net/tun`.
Ubuntu Server 26.04 `amd64` is the current owner-controlled qualification host.
Other distributions and ARM64 execution remain unverified until their full
host matrices pass.

The installer verifies the manifest and every checksum, checks the archive
architecture, discovers one common IPv4/IPv6 egress interface, validates time
sync, memory, disk, TUN, the TCP port, systemd units, Unbound, and the rendered
nftables rules before changing the host.

It installs only project-owned files:

- `kurd-node` and `kurdctl`;
- three systemd units;
- the `kurd0` networkd TUN definition;
- one forwarding sysctl file;
- the isolated nftables table `inet kurd_node`;
- one TUN-only Unbound fragment;
- helpers, manifests, checksums, and documentation.

The relay process runs as `kurd-node`, receives port 443 through systemd socket
activation, owns no capability, and can open only `/dev/net/tun` plus its
declared address families. Root applies network policy through the separate
oneshot unit. Neither install nor preflight initializes keys, enables units, or
contacts an update service.

Uninstall removes only those owned files and the owned nftables table. It
preserves `/var/lib/kurd-node` and `/var/backups/kurd-node` by default.
