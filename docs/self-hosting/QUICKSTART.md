# Kurd node self-hosting quick start

Phase 16 provides deployment-local authority, provisioning, encrypted backup,
profile QR generation, and publication. The public Kurd relay and Internet
egress data plane are intentionally unavailable until Phase 17.

1. Download the archive and its separately delivered SHA-256 through an
   authenticated owner-selected channel. Phase 16 engineering archives are
   checksum-bound but unsigned; public distribution signing is a Phase 19
   gate.
2. Run `kurdpackage verify --archive <archive>` on a trusted workstation.
3. Extract into a new empty directory, inspect the manifest and scripts, then
   run `sudo ./preflight.sh --install` and `sudo ./install.sh --install`.
4. Choose a recovery path outside `/var/lib/kurd-node`. Keep it offline.
5. Enter passphrases on standard input, never as an argument:

   ```sh
   sudo -u kurd-node /usr/local/bin/kurdctl init \
     --data-dir /var/lib/kurd-node \
     --name owner-node \
     --endpoint 203.0.113.10:443 \
     --recovery-file /media/offline/owner-recovery.kurd-recovery
   sudo -u kurd-node /usr/local/bin/kurdctl recovery confirm \
     --data-dir /var/lib/kurd-node \
     --recovery-file /media/offline/owner-recovery.kurd-recovery
   ```

6. Create a profile into a new empty directory:

   ```sh
   sudo -u kurd-node /usr/local/bin/kurdctl profile create \
     --data-dir /var/lib/kurd-node --name phone --valid-for 168h \
     --output-dir /var/lib/kurd-node/export-phone
   ```

7. Copy only the intended profile artifact/QR to the Android device. Treat it
   as sensitive. Confirm the displayed deployment fingerprint.
8. Run `sudo -u kurd-node kurdctl doctor --data-dir /var/lib/kurd-node`, then
   `sudo systemctl enable --now kurd-node`.

9. Copy the encrypted recovery artifact and encrypted backups off the VPS.
   After verifying the offline copies, remove the VPS copies. Losing both the
   root recovery artifact and all current backups is unrecoverable.

The app cannot carry traffic through this package until the Phase 17 relay is
installed. A Phase 16 profile proves authority and import behavior only.
