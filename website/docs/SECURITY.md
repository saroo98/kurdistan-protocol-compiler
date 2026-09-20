# Public website boundary

Only `dist` is served. Never publish private briefs, original uploads, planning records, reports containing private text, credentials or local backups.

The app preview is synthetic and isolated. Do not add `allow-same-origin` to its sandbox. Keep `connect-src 'none'` for the iframe. Parent/child presentation messages must verify the source and allowlisted payload values.

The generated security-header manifest is applied by the included preview server. Verify equivalent headers on the actual hosting platform before release. GitHub Pages does not automatically enforce every generated header configuration. Public font files allow anonymous cross-origin reads so the opaque iframe can use them without relaxing its sandbox.
