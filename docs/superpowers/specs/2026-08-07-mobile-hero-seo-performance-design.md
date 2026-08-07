# Mobile Hero, SEO, and Performance Design

Date: 2026-08-07

## Objective

Remove the excessive empty space beneath the scaled Android preview on narrow screens, improve static discoverability for the temporary GitHub Pages deployment, and reduce initial asset weight without changing the established visual identity or adding runtime dependencies.

## Confirmed direction

Use a scale-aware mobile device stage. The phone remains the supporting visual, but its container reserves only the phone's visible transformed height. The next section then follows with deliberate breathing room instead of an invisible layout box.

The canonical public URL is:

`https://saroo98.github.io/kurdistan-protocol-compiler/`

## Current evidence

At a 390 by 844 viewport:

- The Android device is visually about 351 pixels tall.
- Its stage reserves about 566 pixels because CSS transforms do not change layout geometry.
- The resulting blank region between the visible device and the next section boundary is about 218 pixels.
- The hero texture is a 1536 by 1024 WebP weighing 387,648 bytes and is served unchanged to mobile.
- The three Fontsource imports emit about 184 KB of font subsets, including Cyrillic, Greek, Vietnamese, and Latin Extended subsets that the English interface does not require.
- The page has a useful title and description, but lacks canonical, robots, sitemap, social-card, and structured-data coverage.

## Layout design

### Reading order

The mobile reading path remains:

1. Product promise and current release boundary.
2. Primary and secondary actions.
3. Android product preview.
4. Trust model introduction.

No new facts, badges, cards, or decorative filler will be added.

### Mobile composition

At 560 pixels and below:

- The device stage receives an explicit compact block size that matches the transformed phone.
- The phone remains centered, with its transform origin at the top center.
- The stage clips only the unscaled overflow, not the visible phone.
- The visual space from the phone bottom to the next section boundary should be approximately 16 to 32 pixels.
- The trust-section heading should retain roughly 72 to 88 pixels of top breathing room from the section boundary.
- The hero background texture continues through the device stage and fades before the trust section.

At 561 pixels and above, the existing tablet and desktop composition remains unchanged unless browser verification exposes an actual regression.

### Responsive and localized behavior

- English and Sorani retain the same DOM and focus order.
- RTL changes no geometry assumptions inside the English-only phone illustration.
- The compact stage must hold at 320, 360, 390, 430, and 560 pixel widths without horizontal overflow.
- Mobile navigation and language-menu behavior remain unchanged.

## Performance design

### Hero image

- Preserve the existing desktop WebP as the wide candidate.
- Generate a smaller mobile WebP from the same artwork and use a native `picture` source at 560 pixels and below.
- Keep the hero image eager and high priority because it is above the fold.
- Add intrinsic dimensions so its geometry is explicit.
- Target a mobile candidate of no more than 140 KB without obvious banding or loss of the woven texture.

### Fonts

- Replace package-wide Fontsource CSS imports with explicit local `@font-face` declarations for only the Latin variable font files used by English.
- Keep the existing KMagroon and Shasenem Kiteb WOFF2 files for Sorani.
- Preserve `font-display: swap`.
- Avoid loading Latin Extended, Vietnamese, Cyrillic, Greek, and italic font files.
- Expected English font payload reduction is about 90 KB before compression.

### Runtime

- Add no production dependency.
- Add no scroll listener, resize listener, or JavaScript layout measurement.
- Keep the layout correction entirely in CSS.
- Do not lazy-load the above-fold hero image.
- The minified JavaScript bundle should not materially grow from this work.

## SEO design

### Static metadata

Add to the English server-rendered document head:

- Canonical URL with the confirmed GitHub Pages address.
- `robots` directive allowing indexing and large image previews.
- Open Graph type, site name, title, description, canonical URL, locale, alternate Sorani locale, and social image.
- Twitter large-image card metadata.
- A 1200 by 630 static social card built from the existing Kurdistan mark and routeweave visual language.
- WebSite JSON-LD containing the project name, canonical URL, description, and supported languages.

The structured data must not describe the Android app as released, downloadable, production-ready, or proven against censorship.

### Crawl files

- Add `public/robots.txt` with the sitemap address for portability and future root-domain hosting.
- Add `public/sitemap.xml` containing the single canonical URL.
- Do not add `hreflang` links because English and Sorani do not yet have separate crawlable URLs.

GitHub Pages serves this project below an origin subpath. Crawlers normally treat only the origin-level `/robots.txt` as authoritative, which this project deployment cannot control. The project-local file will therefore be correct and directly accessible, but it must not be described as an authoritative crawler policy until the site moves to a custom domain or an origin root controlled by the project.

### Runtime localization

- Continue updating document title and description when the user switches languages.
- Preserve fluent Sorani metadata already stored in the translation source.
- The default static crawlable metadata remains English until separate localized routes exist.

## Components and files

Expected implementation scope:

- `website/src/components/Hero.tsx`: responsive image markup and intrinsic image attributes.
- `website/src/index.css`: scale-aware mobile stage and explicit font-face declarations.
- `website/src/main.tsx`: remove broad Fontsource CSS imports.
- `website/index.html`: canonical, social metadata, robots directive, and WebSite JSON-LD.
- `website/public/robots.txt`: crawler policy and sitemap reference.
- `website/public/sitemap.xml`: canonical page entry.
- `website/public/og-kurdistan-vpn.png`: static sharing card.
- `website/src/assets/routeweave-hero-mobile.webp`: optimized mobile hero candidate.
- Existing tests may be extended for semantic image and metadata behavior where useful.

## Failure behavior

- If the mobile source cannot load, the desktop WebP remains the `img` fallback.
- If custom fonts are delayed or unavailable, the existing system fallbacks render immediately.
- If JavaScript is unavailable, English title, description, canonical, social metadata, and structured data remain present in the HTML document.
- The site must remain usable when reduced motion is enabled.

## Verification

### Layout

- Measure the visible device, stage, hero boundary, and trust heading at 320, 390, and 560 pixels.
- Confirm the invisible reserved space is removed and the stage does not crop the visible phone.
- Inspect English and Sorani states.
- Confirm no horizontal overflow and no navigation regression.

### SEO

- Verify one H1, descriptive title, description, canonical, robots directive, Open Graph values, Twitter values, and valid WebSite JSON-LD.
- Verify `robots.txt` and `sitemap.xml` resolve from the GitHub Pages base path after the Vite build, while retaining the documented origin-root limitation for `robots.txt`.
- Confirm metadata makes no unsupported release or censorship-resistance claim.

### Performance

- Compare production build asset sizes before and after.
- Confirm the mobile hero candidate is selected at a narrow viewport.
- Confirm unused language font subsets are absent from the production output.
- Run the component tests, lint, production build, Impeccable detector, and a bounded desktop/mobile browser review.

## Out of scope

- Separate English and Sorani routes or server-side rendering.
- A live Android download.
- New marketing claims or product capabilities.
- Changes to desktop hero art direction.
- New analytics, tracking, service workers, or runtime performance libraries.
