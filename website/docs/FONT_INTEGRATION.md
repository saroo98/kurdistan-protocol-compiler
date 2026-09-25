# Local font assets

The owner supplied and authorized KMagroon and shasenem-kiteb WOFF2 files. The display and reading roles use those files on Sorani pages, including the phone demo.

IBM Plex Mono and IBM Plex Sans Latin and extended-Latin subsets are self-hosted. They were obtained from Google Fonts on 2026-09-19. Their SIL Open Font License is included at `public/assets/fonts/OFL-IBM-Plex.txt`.

The app preview also includes the supplied IBM Plex Sans semibold asset as `plex-sans-600-demo.woff2`, under the same included license. Its `KurdUI` CSS alias preserves the app's typography without requesting an external font service.

No visitor requests a Google Fonts service. Build manifests bind all distributed font bytes. `font-display: swap` preserves readable fallback text during loading.
