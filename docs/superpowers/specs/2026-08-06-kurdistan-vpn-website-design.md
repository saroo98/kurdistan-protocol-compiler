# Kurdistan VPN Website Design

## Objective

Create a premium, responsive public website for Kurdistan VPN that makes the project compelling to everyday Android users while giving self-hosting operators a credible technical path. The site must build anticipation for the Android release without suggesting that a public production relay or unrestricted Internet-egress path exists today.

## Audience and Actions

The primary visitor is an everyday Android VPN user who wants a simple answer to three questions: what Kurdistan VPN is, why its approach matters, and when they can use it. The primary action is a visibly unavailable `Download for Android · Coming soon` control. Secondary actions are `See how it works` and `View on GitHub`.

The secondary visitor is a technical early adopter or self-hosting operator. Their path begins after the everyday explanation and leads to signed profiles, owner-controlled authority, deployment fingerprints, `kurdctl`, `kurd-node`, documentation, and source code.

## Visual Direction: Routeweave

Routeweave treats the network as a living woven fabric. Threads split, cross, and reform while a signed profile remains the stable organizing center. The metaphor connects the compiler's changing transport behavior, the project's Kurdish identity, and the owner's control of each independent deployment.

The design avoids category-default shields, glowing globes, anonymous server maps, flags, and dark neon cybersecurity dashboards. It also avoids a soft generic privacy-app treatment.

### Visual System

- Palette: deep indigo and near-black foundations, electric teal for active routes, saffron for trust and fingerprint states, warm ivory for readable surfaces, and restrained violet inherited from the Android identity.
- Material: woven bands, interlaced route lines, punched registration marks, matte fibers, and crisp profile seals. Surfaces are dimensional but not glassy.
- Typography: a distinctive contemporary display sans paired with a highly readable humanist body face and a compact technical mono for fingerprints and status. The final selection must support a robust system fallback and future Arabic-script localization.
- Geometry: larger woven fields and offset panels rather than repeated rounded cards. Corners derive from the existing Android shape language but remain selective.
- Motion: one orchestrated route-weaving sequence across the hero and mechanism section. Motion stops or reduces when `prefers-reduced-motion` is enabled.

## Page Architecture

### 1. Navigation

A restrained sticky header contains the Kurdistan VPN mark, `How it works`, `Privacy`, `Self-host`, `Status`, and a compact disabled Android action. On mobile, navigation collapses into an accessible disclosure menu with complete keyboard and screen-reader behavior.

### 2. First Viewport

The first viewport states `Your internet. Your route. Coming to Android.` It pairs concise explanatory copy with an Android product frame held inside a large woven network field. Active threads flow toward a signed profile seal, reorganize, and continue through the phone. The Android action is visibly marked coming soon, with `See how it works` and GitHub available immediately.

A compact release-boundary note is visible without scrolling: the Android foundation and controlled paths exist, while the public production data plane remains in development.

### 3. Everyday Flow

A three-part story explains the intended user experience:

1. Receive a Kurd profile from a trusted deployment owner.
2. Verify the displayed deployment fingerprint.
3. Connect through the profile's bounded transport policy when the public data plane is released.

This section uses one continuous woven path rather than three isolated cards.

### 4. Signed Profile Demonstration

An interactive, explicitly synthetic profile preview shows how the deployment name, fingerprint, expiry, and permitted behavior become a readable trust decision. No real profile, QR code, endpoint, credential, or secret appears. Changing the selected synthetic profile updates the surrounding route weave and trust state.

### 5. Privacy and Decentralization

The section contrasts the project's real architecture with centralized VPN assumptions: no mandatory Kurdistan account, no central relay directory, no advertising system, no required product analytics, and no product-wide shutdown authority. Copy stays factual and avoids promising anonymity.

### 6. Self-Hosting Path

A denser operator section introduces deployment-local authority, `kurdctl`, `kurd-node`, owner-controlled VPS infrastructure, signed profiles, backups, and recovery. It links to the existing self-hosting documentation and GitHub repository. Technical detail is progressive disclosure, never required to understand the main page.

### 7. Honest Status

The current boundary is presented as a sign of engineering discipline. Implemented foundations and unavailable production capabilities are visually distinct. The website never presents a public download, public relay, unrestricted Internet egress, production-readiness claim, benchmark, customer quote, or field-proven bypass claim.

### 8. Close

The closing section returns to the woven Android composition with a larger disabled `Download for Android · Coming soon` action, GitHub follow-through, release-status language, and the project license.

## Components and Boundaries

The React application is a single public route composed from focused sections and small reusable primitives. Content and synthetic demonstration data live outside render-heavy components. A route-weave visual component owns decorative animation and exposes a static fallback. Interactive controls use native semantic elements and do not depend on pointer hover.

The generated raster asset supplies the hero's textile atmosphere. Product UI, text, icons, profile data, and interactive routes remain code-native so they are accessible, responsive, and editable.

## State and Data Flow

The site has no backend and collects no user data. The only state is local presentation state: mobile navigation, selected synthetic profile, motion preference, and viewport-aware visual density. The Android button remains disabled and explains its status through visible text rather than a tooltip.

External links point to repository-controlled GitHub and documentation destinations. Any future download URL requires a deliberate release change and must not be inferred from the current repository.

## Failure and Fallback Behavior

- The core message and every action remain usable if JavaScript animation is unavailable.
- The generated hero asset has a CSS color-and-pattern fallback.
- Reduced-motion users receive a static woven field with no route travel.
- Narrow screens preserve headline clarity, action visibility, and the complete Android frame without horizontal scrolling.
- External link failures do not block page navigation or hide the pre-release status.

## Accessibility and Localization

The build targets WCAG 2.2 AA contrast and interaction requirements, visible focus, semantic landmarks, heading order, keyboard operation, descriptive action labels, and minimum touch target sizing. Decorative artwork is hidden from assistive technology. The layout avoids directional assumptions that would prevent future right-to-left support.

## Verification

Validation will include the React/Vite production build, lint or static checks available in the new web project, focused component tests for the disabled download state and synthetic profile interaction, and a bounded visual pass at desktop and mobile viewport sizes. The final review will check claim accuracy against `README.md`, `PRODUCT.md`, and `docs/safety.md`, plus overflow, focus, reduced motion, contrast, and missing assets.

## Non-Goals

- No live Android download or waitlist backend.
- No authentication, account, payment, telemetry, analytics, or user-data collection.
- No real profiles, QR codes, endpoints, relay addresses, credentials, or production statistics.
- No deployment, publishing, commit, push, or GitHub Pages configuration change without separate authorization.
