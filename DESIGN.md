---
name: Kurdistan VPN
description: A code-native trust site for independently operated, profile-defined routes.
colors:
  night: "#090a19"
  night-raised: "#11132b"
  indigo: "#17102e"
  violet: "#8278b8"
  teal: "#48bdb3"
  teal-deep: "#147f79"
  saffron: "#d6a04d"
  ivory: "#f3efe5"
  ink: "#171427"
  muted: "#aaa8b6"
  line: "rgba(234, 231, 242, 0.12)"
typography:
  display:
    fontFamily: "Bricolage Grotesque Variable, Arial, sans-serif"
    fontSize: "clamp(4rem, 6.4vw, 5.4rem)"
    fontWeight: 610
    lineHeight: 0.96
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Bricolage Grotesque Variable, Arial, sans-serif"
    fontSize: "clamp(2.6rem, 4.5vw, 4.35rem)"
    fontWeight: 580
    lineHeight: 1.01
    letterSpacing: "-0.035em"
  title:
    fontFamily: "Bricolage Grotesque Variable, Arial, sans-serif"
    fontSize: "1.45rem"
    fontWeight: 650
    lineHeight: 1.6
    letterSpacing: "-0.03em"
  body:
    fontFamily: "Manrope Variable, Segoe UI, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "normal"
  label:
    fontFamily: "Azeret Mono Variable, Cascadia Mono, monospace"
    fontSize: "0.58rem"
    fontWeight: 700
    lineHeight: 1.6
    letterSpacing: "0.08em"
rounded:
  control: "12px"
  action: "14px"
  panel: "16px"
  feature: "28px"
  pill: "999px"
  full: "50%"
components:
  android-coming-soon:
    backgroundColor: "#246c6c"
    textColor: "#c5ece8"
    rounded: "{rounded.control}"
    padding: "0 22px"
    height: "52px"
  button-secondary:
    backgroundColor: "rgba(12, 13, 30, 0.58)"
    textColor: "{colors.ivory}"
    rounded: "{rounded.control}"
    padding: "0 22px"
    height: "52px"
  navigation-header:
    backgroundColor: "rgba(9, 10, 25, 0.97)"
    textColor: "{colors.ivory}"
    padding: "0 24px"
    height: "70px"
  profile-selector-selected:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    padding: "0 4px"
    height: "64px"
  profile-ticket:
    backgroundColor: "{colors.indigo}"
    textColor: "{colors.ivory}"
    rounded: "{rounded.panel}"
    padding: "clamp(28px, 3.5vw, 42px)"
  operator-console:
    backgroundColor: "#081018"
    textColor: "#cbd9e4"
    rounded: "{rounded.panel}"
    padding: "15px 24px"
  status-ledger:
    backgroundColor: "{colors.night}"
    textColor: "{colors.muted}"
    padding: "42px 48px"
  routeweave-field:
    width: "100%"
    height: "360px"
---

# Design System: Kurdistan VPN

## Overview

**Creative North Star: "Routeweave"**

Routeweave makes trust legible as a woven route rather than a security emblem. Matte threads split, cross, and rejoin around independently operated nodes, while signed-profile surfaces act as stable registration points. The result is tactile, resilient, trustworthy, and quietly optimistic.

The system alternates deep indigo and near-black fields with warm ivory product surfaces. Muted teal carries active routes and successful trust states; restrained saffron marks fingerprints, release boundaries, focus, and review. Product UI and evidence remain code-native even when a generated textile image supplies quiet atmosphere on the edge of a composition.

**Key Characteristics:**

- Matte woven routes and registration marks form the recurring visual grammar.
- Dark network fields alternate with warm ivory trust and profile surfaces.
- Muted teal carries active paths; saffron appears only at consequential moments.
- Offset panels, ledgers, and continuous paths replace generic card grids.
- Code-native profile, status, and operator surfaces keep technical evidence editable and accessible.

## Colors

The palette balances a deep, low-glare network field with clear route energy and warm, readable product surfaces.

### Primary

- **Quiet Route Teal** (`colors.teal`): Active woven threads, primary trust decisions, success markers, and forward motion.
- **Deep Route Teal** (`colors.teal-deep`): Verified indicators and teal-on-ivory states that need stronger contrast.

### Secondary

- **Saffron Release Marker** (`colors.saffron`): Fingerprint and trust seals, focus outlines, review states, and unreleased-status markers.

### Tertiary

- **Woven Violet** (`colors.violet`): A restrained inherited identity accent used for alternate route threads and the third journey knot.

### Neutral

- **Midnight Field** (`colors.night`): Default page and hero foundation.
- **Raised Midnight** (`colors.night-raised`): Compact controls and the mobile navigation surface.
- **Indigo Trust Surface** (`colors.indigo`): Signed-profile tickets, footer fields, and dark product containers.
- **Warm Ivory Surface** (`colors.ivory`): High-readability product demonstrations and light device screens.
- **Ivory Ink** (`colors.ink`): Primary text and marks on warm ivory.
- **Muted Thread** (`colors.muted`): Supporting copy on dark fields; it brightens under increased-contrast preferences.
- **Woven Hairline** (`colors.line`): Dividers and low-emphasis borders that organize without turning the page into boxes.

### Named Rules

**The Active Thread Rule.** Teal marks routes, successful trust states, and forward action. It stays muted and never washes entire surfaces.

**The Saffron Scarcity Rule.** Saffron is reserved for trust, release boundaries, focus, or required review.

## Typography

**Display Font:** Bricolage Grotesque Variable (with Arial and sans-serif fallbacks)
**Body Font:** Manrope Variable (with Segoe UI and sans-serif fallbacks)
**Label/Mono Font:** Azeret Mono Variable (with Cascadia Mono and monospace fallbacks)

**Character:** Bricolage gives the public story a distinctive, human tension; Manrope keeps explanations calm and readable. Azeret Mono turns fingerprints, commands, route notes, and status labels into compact technical evidence.

### Hierarchy

- **Display** (610, `clamp(4rem, 6.4vw, 5.4rem)`, 0.96): Hero statements only, with controlled negative tracking (`-0.035em`).
- **Headline** (580, `clamp(2.6rem, 4.5vw, 4.35rem)`, 1.01): Major section theses; mobile narrows to `clamp(2.45rem, 12vw, 3.35rem)`.
- **Title** (650, `1.45rem`, 1.6): Journey steps and prominent subheads, with compact tracking (`-0.03em`).
- **Body** (400, `1rem`, 1.6): General explanation; lead paragraphs expand to `clamp(0.98rem, 1.2vw, 1.08rem)` and stay near 56-68 characters.
- **Label** (700, `0.58rem`, `0.08em`, uppercase): Fingerprints, route notes, commands, synthetic-state labels, and status metadata.

### Named Rules

**The Three-Voice Rule.** Bricolage persuades, Manrope explains, and Azeret Mono authenticates technical detail; never swap their jobs.

## Layout

The desktop shell is capped at `1180px` with `28px` side gutters. Major sections use asymmetric two-column grids and calm `112-132px` vertical bands; the three-step journey is tied together by one low-contrast route rather than isolated cards. Large fields and offset framed objects create hierarchy before borders do.

At `1040px`, columns tighten and four-up operator facts become two-up. At `820px`, the shell becomes a single column, gutters become `16px`, the navigation becomes an accessible disclosure surface, and the journey route rotates into a vertical guide. At `560px`, gutters become `14px`, primary actions stack, ticket metadata becomes one column, and operator facts become a bordered list.

**The Continuous Path Rule.** Use connected route structure before isolated card grids when explaining a sequence, dependency, or trust handoff.

## Elevation & Depth

The system is tonal first and selectively lifted. Dark fields, warm surfaces, hairlines, clipped ticket notches, and woven overlap establish most depth; structural shadows are reserved for the Android frame, signed-profile ticket, operator console, mobile navigation, and small consequential markers.

### Shadow Vocabulary

- **Device Lift** (`18px 30px 64px rgba(0, 0, 0, 0.4)`): Controlled separation under the rotated Android product frame.
- **Ticket Lift** (`18px 28px 60px rgba(42, 30, 72, 0.16)`): Soft indigo cast beneath the signed-profile ticket on ivory.
- **Console Lift** (`18px 24px 54px rgba(1, 4, 9, 0.22)`): Low, dense depth for the operator console.
- **Temporary Menu Lift** (`0 24px 50px rgba(0, 0, 0, 0.4)`): Mobile navigation only.
- **Teal State Glow** (`0 12px 30px rgba(16, 120, 114, 0.16)`): Restrained emphasis for active teal controls and route cores.

### Named Rules

**The Matte-by-Default Rule.** Surfaces stay matte and tonal at rest; deep shadows belong only to framed objects, temporary navigation, or state markers.

## Shapes

Controls use gently curved corners (`12px`), actions use slightly broader corners (`14px`), and compact panels use (`16px`). Larger identity objects use selective feature curves (`28px`), while pills (`999px`) are reserved for short state labels and circles (`50%`) for knots, status points, or seals. The Android frame is intentionally more rounded (`48px` outer, `39px` inner) than the surrounding site.

Profile tickets use opposing semicircular edge punches and dashed separators to feel issued rather than card-like. Route bands use round caps, variable widths, stitched dashes, and occasional registration crosses; square and circular knots keep the weave tactile.

**The Selective Curve Rule.** Large radii signal a device, seal, knot, or issued artifact. Ordinary content should not become a field of interchangeable rounded cards.

## Components

### Buttons

- **Shape:** Compact tactile actions with a `12px` radius and `52px` minimum height.
- **Primary:** Muted teal with dark teal ink and a two-line Android label; every shipped Android action is visibly disabled with a desaturated teal surface and “Coming soon” text.
- **Hover / Focus:** Secondary actions shift toward a lighter raised-indigo surface on hover. All links and buttons use a `3px` saffron focus outline offset by `4px`.
- **Secondary / Text:** Secondary actions are dark, bordered, and directional; text links carry less surface weight and turn teal on hover.

### Chips

- **Style:** Synthetic and profile-state labels use compact uppercase or high-weight text on violet-, teal-, or saffron-tinted pills.
- **State:** Teal means verified, saffron means review or unreleased, and violet identifies the synthetic demonstration without implying live data.

### Cards / Containers

- **Corner Style:** Signed-profile and operator surfaces use `16px` corners; the ticket adds edge punches and a dashed issue line.
- **Background:** Profile evidence uses Indigo Trust Surface on Warm Ivory; operator evidence uses a near-black console inside a blue-black section.
- **Shadow Strategy:** Only framed product objects receive structural lift; ledgers and fact groups remain flat and separated by hairlines.
- **Internal Padding:** Profile tickets use `clamp(28px, 4vw, 50px)`; console rows use `15px 24px` and results use `26px 24px`.

### Navigation

The fixed header uses an almost-opaque Midnight Field, a single woven hairline, `70px` height, and compact medium-weight links. At `820px`, it becomes a `66px` header with a native button-controlled disclosure panel; links retain `48px` minimum touch height, visible focus, and a clearly disabled Android pill.

### Signed Profile Selector

Profile choices are full-width `70px` rows separated by ink hairlines, not tabs in floating capsules. The selected row uses primary ivory ink and a small ring in Deep Route Teal; state copy stays secondary until a choice is made.

### Status Ledger

Implemented and unreleased capability lists share one bordered ledger. Teal and saffron points distinguish state, while row dividers and short leading ticks make the contrast scannable without fabricated percentages or scorecards.

### Routeweave Network Field

The signature component is a code-native SVG field of four restrained, round-capped paths with a darker offset underlay, stitched highlights, and registration points. Teal leads, deep blue and violet diversify the weave, and saffron identifies consequential crossings. The hero uses only the matte textile image, confined to the device side; the journey routes travel for `18s`, stitches travel for `12s`, profile and footer instances remain static, and reduced-motion preferences collapse all animation to a single frame.

**The Code-Native Trust Rule.** Keep routes, labels, fingerprints, profile states, and controls as accessible code. Raster texture may provide atmosphere, never product truth.

## Do's and Don'ts

### Do:

- **Do** let routes split, cross, and rejoin around independently operated nodes.
- **Do** reserve muted teal for active paths and successful trust, and saffron for consequential release or review moments.
- **Do** keep hero texture behind the device and away from headline, actions, and boundary copy.
- **Do** place fingerprints, commands, route notes, and technical state in Azeret Mono.
- **Do** collapse asymmetric desktop layouts into clear single-column flows at `820px` and preserve full action visibility at `560px`.
- **Do** keep profile examples visibly synthetic and product evidence code-native.

### Don't:

- **Don't** expand the quiet, almost-opaque header into glossy glass cards, gradients, or a generic SaaS sheen.
- **Don't** substitute shields, locks, globes, flags, or anonymous server maps for the Routeweave metaphor.
- **Don't** build hierarchy from repeated rounded cards when a ledger, issued ticket, console, or continuous path fits.
- **Don't** invent metrics, testimonials, production readiness, guaranteed bypass, anonymity, or unsupported security claims.
- **Don't** show real profiles, QR codes, endpoints, credentials, keys, recovery material, or private device data.
