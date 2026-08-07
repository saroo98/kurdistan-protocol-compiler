# Kurdish Typography and Dedication Design

## Goal

Give the Sorani experience an authored Kurdish typographic voice and add a clearly visible, respectful dedication without changing the restrained product hierarchy.

## Approved typography

- Use the supplied `KMagroon.woff2` as the Sorani display face for `h1`, `h2`, and `h3`.
- Use the supplied `shasenem-kiteb.woff2` as the Sorani reading and interface face for body copy, navigation, buttons, labels, and footer text.
- Keep the existing Manrope and Bricolage Grotesque typography unchanged in English.
- Serve local WOFF2 assets from `/fonts`, declare them with `font-display: swap`, and retain system Kurdish-capable fallbacks.
- Keep the illustrated phone interface in English and LTR in both locales.

## Approved dedication

English:

> Made with immense ❤️ by Saro Xizirnijad, for the Kurdish people and in honor of all they have endured in *Rojhelat*.

Sorani:

> سارۆ خزرنژاد بە خۆشەویستییەکی بێ‌سنوورەوە ❤️ بۆ گەلی کورد دروستی کردووە؛ بە ڕێزگرتن لە هەموو ئەو ئازارەی لە *ڕۆژهەڵات* بەسەریان هاتووە.

The Sorani version must use the name `سارۆ خزرنژاد` exactly.

## Placement and hierarchy

Place the dedication across the full footer width between the main footer actions and the metadata row. A single quiet divider, generous breathing room, ivory text, and a slightly larger reading size make it clearly visible while preserving the footer heading as the primary element. The place name is emphasized typographically, not turned into a badge or decorative callout.

## Responsive and RTL behavior

The dedication follows the active reading direction, wraps naturally on narrow screens, and remains readable at 320px. Footer spacing contracts on mobile. Font changes are scoped to `html[lang='ckb']`, so English metrics and layouts are unaffected.

## Validation

- A user-facing test verifies that the dedication changes with the selected locale and uses `سارۆ خزرنژاد` in Sorani.
- Unit tests, lint, and the production build pass.
- The Impeccable typography detector reports no violations.
- English and Sorani are visually inspected at desktop and mobile widths, including font loading, wrapping, RTL flow, and horizontal overflow.
