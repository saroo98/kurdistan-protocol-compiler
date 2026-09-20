# Kurdistan VPN website

Static, three-language website with an isolated interactive app demonstration. The website version is not a VPN release.

Requires Node 22 or newer. No build or runtime package dependencies are required.

```sh
npm run build
node scripts/serve.mjs --host 127.0.0.1 --port 4180
npm run lint
npm test
npm run test:artifacts
```

Open `http://127.0.0.1:4180/kurdistan-protocol-compiler/en/`. Sorani and Kurmanji use `ckb/` and `kmr/`. Set `SITE_URL` before building for a different hosting prefix.

Browser verification requires Playwright 1.62.1 with Chromium and axe-core 4.13.0. Set `PLAYWRIGHT_MODULE` to an installed Playwright module and `AXE_SOURCE` to axe-core's `axe.min.js` when they are not resolvable locally. Python 3 is used for performance inventory and ZIP packaging. The production build does not depend on these QA tools. CI installs them separately from production source.

```sh
npm run verify
npm run package
```

Verification fails closed. Packaging checks the current source, production manifest and evidence against the completed verification receipt. The archive includes the authorized fonts, source, tests, static output and current screenshots. Private originals, historical reports and planning documents are excluded.

See `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/FONT_INTEGRATION.md` and `docs/LIMITATIONS.md`. Local QA does not establish production VPN availability, native-language approval or field performance.
