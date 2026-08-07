# Route-Bound Motion Design

## Goal

Make the website feel interactive and authored without making it busier. Motion must explain profile selection, route changes, trust decisions, and temporary navigation state.

## Motion thesis

- **Focal moment:** Selecting a synthetic profile moves one persistent teal marker, changes the signed ticket through a matte route wipe, and reconfigures the background Routeweave as one coordinated transition.
- **Continuity:** Language and mobile navigation surfaces open from their triggers and retain a short closing phase instead of appearing or disappearing abruptly.
- **Feedback:** Confirming trust draws a compact verification mark and reveals the result. Dismissing uses the same structure with a quiet neutral mark.
- **Budget:** Use CSS transforms, opacity, `clip-path`, bounded blur, SVG stroke motion, and one short React closing phase. Add no dependency and no new ambient loop.

## Profile interaction

The selected profile rows share one active marker. It travels between the three fixed rows over `320ms` with `cubic-bezier(0.16, 1, 0.3, 1)`. The ticket stays in place while a keyed content layer performs a `340ms` low-opacity mask sweep. The existing profile Routeweave remains non-looping, but its path transforms, stroke widths, and opacity transition over `360ms` when route style changes.

The initial page remains fully visible without JavaScript animation setup. Profile selection still resets a prior trust decision.

## Trust feedback

Decision buttons receive a `120ms` press response. The feedback shell expands over `220ms`; confirmed feedback draws a teal check path once, while dismissed feedback uses a restrained neutral line. The animation never implies a real security event because the demonstration remains explicitly synthetic.

## Navigation continuity

The language menu remains mounted but inaccessible while closed. It transitions from its trigger using opacity, a small scale change, and a bounded inset mask over `180ms`, with a faster exit. Its flag and short label crossfade when locale changes.

On mobile, the navigation panel opens from the header edge over `240ms` and closes over `140ms`. The hamburger uses the same three SVG strokes throughout and morphs into a close icon. Desktop navigation behavior remains unchanged.

## Accessibility and performance

- Preserve current labels, focus outlines, keyboard behavior, and English phone mockup.
- `prefers-reduced-motion: reduce` collapses all new transitions and keyframes to the existing near-instant behavior.
- Closed temporary surfaces cannot receive pointer or keyboard interaction.
- No parallax, hero choreography, section reveals, bouncing, floating phone, or repeated pulse effects.
- Validate at desktop, 390px mobile, and the 320px supported floor in English and Sorani.

## Acceptance criteria

- The active profile marker tracks the selected row.
- The ticket and Routeweave transition without layout overflow.
- Confirm and dismiss outcomes remain visible, resettable, and semantically announced.
- Language and mobile navigation state remains accessible throughout opening and closing.
- Tests, lint, production build, Impeccable motion scan, and live desktop/mobile checks pass.
