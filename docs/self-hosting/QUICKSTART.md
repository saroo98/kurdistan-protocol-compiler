# Kurd node self-hosting quick start

The native Phase 17 engineering package combines owner-local authority with
an authenticated Kurd TLS/TCP relay. It remains unsigned until the Phase 19
distribution gate and has not yet completed the external data-path acceptance
campaign.

1. Obtain the archive and its separately authenticated SHA-256, then verify it
   on a trusted workstation with `kurdpackage verify --archive <archive>`.
2. Extract into a new empty directory and inspect `manifest.json`,
   `SHA256SUMS`, and the scripts.
3. Run `sudo ./preflight.sh --install`, followed by
   `sudo ./install.sh --install`. Installation does not create authority keys,
   enable the listener, or start the service.
4. Initialize the owner-local authority. The recovery destination must be
   outside `/var/lib/kurd-node`. Passphrases enter on standard input only.
5. Confirm the recovery artifact and run `kurdctl doctor`.
6. Export a fresh device enrollment request from the Android app. Transfer the
   exact request to the owner through an authenticated channel.
7. Issue a sealed live profile into a new empty directory:

   ```sh
   sudo -u kurd-node /usr/local/bin/kurdctl profile create \
     --data-dir /var/lib/kurd-node \
     --name phone \
     --valid-for 168h \
     --recipient-request /path/to/device.kurd-enrollment \
     --recipient-registry-dir /var/lib/kurd-node/recipient-registry \
     --output-dir /var/lib/kurd-node/export-phone
   ```

8. Transfer only the intended `kurd://` profile or QR to that device. A
   recipient request is single-use by default.
9. Enable the native network policy and socket only after preflight and local
   checks pass:

   ```sh
   sudo systemctl enable --now kurd-node-network.service kurd-node.socket
   sudo systemctl start kurd-node.service
   sudo systemctl is-active kurd-node.service kurd-node.socket
   ```

10. Copy the encrypted recovery artifact and current encrypted backups off the
    VPS. Losing both is unrecoverable.

Do not claim successful Internet egress until the Phase 17 namespace, emulator,
and owner-VPS evidence gates have passed for the exact build.
