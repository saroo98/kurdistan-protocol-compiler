# Website architecture

Node generates static documents from `src/content`, shared components and locale data. Browser enhancements are small local ES modules. The production directory is `dist`; the preview server serves only that directory.

The embedded app uses a sandboxed, opaque-origin iframe. Its source is `src/prototype/app.html`. The hosted adapter exchanges allowlisted presentation messages with the parent, validating the message source. Its CSP denies network connections. No real profile or credential should be entered.

`src/phase3/refinement.mjs` renders the supplied visual direction within the existing website. `src/client/prototype-refinement.js` refines the full app demonstration, preserving its import, settings, grouping and Grandma Mode flows. Synthetic latency results are separate from profile authority and selected connection state.

Builds reject private planning markers. Artifact tests validate routes, unique IDs, metadata, local links, privacy boundaries and manifests. `performance-budgets.json` is the shared performance budget. CSS comments are removed from delivery; authored source remains readable.
