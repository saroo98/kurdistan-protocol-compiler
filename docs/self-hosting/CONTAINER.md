# Optional container qualification adapter

The native systemd package is authoritative for the live relay. The container files
exist to prove that the same Linux binaries can run under an additional
isolation boundary. They are not signed public images and they do not enable a
relay data plane.

Build from an already verified native package context. Do not download a base
image or run a package manager during the build. The supplied scratch image:

- runs as UID/GID `65532`;
- has no shell, package manager, or remote assets;
- uses a read-only root filesystem;
- drops every Linux capability;
- sets `no-new-privileges`;
- uses `network_mode: none` and is explicitly labelled
  `relay-data-plane=false`;
- stores only owner authority state in the mounted volume.

Before initialization, make the volume writable only by UID/GID `65532`.
Passphrases must enter through standard input. Never place them in the image,
Compose file, environment variables, labels, command arguments, or logs.

Container equivalence covers owner-local authority only. It cannot accept
relay traffic, obtain TUN ownership, alter routing, or satisfy any live
data-plane evidence gate.
