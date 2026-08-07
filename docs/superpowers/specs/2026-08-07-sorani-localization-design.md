# Kurdistan VPN Sorani Localization Design

## Goal

Add a professional English and Central Kurdish (Sorani) experience to the existing React website while keeping the interface restrained, accessible, and easy to understand. The illustrated phone screen remains English.

## Approved direction

Use a small, dependency-free React locale layer. A typed locale dictionary supplies all website copy, a context exposes the active locale and setter, and a compact language selector lives in the site header. The two choices are `English` with the United Kingdom flag and `کوردی` with an authored Kurdistan flag asset.

## Locale behavior

- Supported locales are `en` and `ckb`.
- English is the first-visit default.
- A valid saved selection in `localStorage` is restored on later visits.
- Changing locale updates the React UI immediately.
- The document root uses `lang="en" dir="ltr"` for English and `lang="ckb" dir="rtl"` for Sorani.
- The selector is keyboard operable, exposes its expanded state, closes after selection, and names both language choices accessibly.
- The mobile navigation and language menu must not obscure or break one another.

## Translation scope

Translate every user-facing website string, including navigation, headings, paragraphs, buttons, disabled release labels, profile demonstration data, interaction feedback, status lists, footer copy, and accessibility labels.

Do not translate the UI shown inside the illustrated Android phone. The phone preview remains an English product mockup in both locales.

Sorani copy must be fluent rather than mechanically literal. Technical terminology follows the existing Android `values-ckb` resource where it is already established, including `پرۆفایل` for profile, `پەنجەمۆر` for fingerprint, `دامەزراندن` for deployment, `ڕێلەی` for relay, `دەسەڵات` for authority, `نهێنیکراو` for encrypted, and `پاڵپشت` for backup. Product names, command names, protocol identifiers, GitHub, Android, VPN, VPS, QR, and license identifiers remain in their conventional technical forms where translation would reduce clarity.

## Component architecture

- `LocaleProvider` owns locale state, persistence, root document attributes, and the typed translation value.
- `useLocale()` is the only component-facing API for locale state and copy.
- `LanguageSwitcher` owns only its menu-open state and selection UI.
- Locale dictionaries live in a focused content module rather than being scattered across components.
- Existing external URLs and non-translatable constants remain separate from copy.
- The profile demo retains its current behavior while its labels, synthetic content, and status messages come from the active dictionary.

## Visual and RTL treatment

The language control is a quiet header utility, not a primary call to action. It uses the existing dark surface, subtle border, and focus treatment. The menu is compact and identifies both choices with an authored flag and text.

RTL mode uses CSS logical properties for flow-dependent spacing and alignment. Headings and body copy align naturally to the reading direction, while code, fingerprints, command lines, and the English phone mockup retain LTR direction. Layouts must tolerate Sorani text expansion at desktop and mobile widths without clipping.

## Interaction boundaries

The site already contains meaningful interaction through mobile navigation and the synthetic profile selector/decision flow. This change keeps that interaction and adds only the language selector. It does not introduce carousels, modal dialogs, animation-heavy transitions, or new product claims.

## Accessibility

- The language trigger is a real button with `aria-expanded`, `aria-haspopup`, and an accessible name.
- The options are real buttons with selected-state semantics.
- Focus remains visible.
- Locale changes are reflected in document language and direction for assistive technology.
- Decorative flags have empty alternative text; language names remain text.
- The phone preview retains an English accessibility label in Sorani mode because its content is intentionally English.

## Validation

- Tests prove the default English state, Sorani switching, document `lang`/`dir`, persistence, return to English, and the unchanged English phone UI.
- Existing profile interaction tests continue to pass.
- Lint and production build pass.
- Desktop and mobile renders are inspected in both directions.
- A final terminology review compares every Sorani technical term with the established Android resources and checks fluency in context.
