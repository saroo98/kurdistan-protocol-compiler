# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React with Vite. The website will be a richer app-style public surface while remaining suitable for static hosting through the repository's existing GitHub Pages destination.

## Users

The primary audience is everyday Android VPN users who need a clear, trustworthy explanation of Kurdistan VPN and its current availability. The secondary audience is self-hosting operators and technical early adopters who want to understand the decentralized authority, signed-profile, and owner-controlled node model.

## Product Purpose

Kurdistan is a profile-driven, self-hosted relay transport system and Android VPN project for censorship-resilient networking. The website should make the product understandable to non-specialists, build confidence through specific evidence, and create anticipation for the Android release without implying that a public production data plane exists today.

## Positioning

Kurdistan compiles bounded transport behavior from signed profiles instead of shipping one fixed transport. Each deployment owner controls their own VPS, authority, profiles, backups, and data without a mandatory Kurdistan account, central relay directory, analytics service, or product-wide shutdown authority.

## Operating Context

Everyday users will encounter Kurdistan as an Android VPN application that imports an explicit `kurd://` profile and asks them to confirm a deployment fingerprint before trust. Technical operators use `kurdctl` and `kurd-node` to create deployment-local authority, issue and rotate profiles, generate QR artifacts, recover backups, and administer an owner-controlled VPS.

## Capabilities and Constraints

- The compiler, authenticated transport/runtime components, native profile tooling, self-hosted node administration, Android foundation, and controlled conformance paths exist in the repository.
- The public non-loopback relay and unrestricted Internet-egress path are not part of a released production build.
- The primary website action is “Download Android app,” visibly presented as coming soon with no live download.
- The website must not claim guaranteed censorship bypass, undetectability, anonymity, production readiness, a released public relay, or unrestricted production Internet egress.
- Sensitive profiles, QR codes, recovery artifacts, keys, credentials, payloads, destinations, and private device data must never appear in public examples or diagnostics.
- The public product name is “Kurdistan VPN”; “Kurdistan Protocol Compiler” remains the technical project name where relevant.

## Brand Commitments

The existing Android identity uses a geometric hexagonal K mark and an indigo-led palette with teal and saffron support colors. The project voice is direct, technically precise, privacy-respecting, and candid about boundaries. English is the website's initial language; the product already supports Sorani Kurdish, Kurmanji, Persian, and Arabic resources, including right-to-left validation.

## Evidence on Hand

- Real project architecture, capabilities, commands, and release boundaries in `README.md`.
- Existing brand mark in `docs/assets/kurdistan-mark.svg` and Android app icon in `android/app/src/main/res/drawable/ic_kurdistan_vpn.xml`.
- Existing Android color, typography, shape, high-contrast, and reduced-motion behavior in `android/core/ui/src/main/kotlin/org/kurdistanvpn/core/ui/KurdistanTheme.kt`.
- Self-hosting workflow in `docs/self-hosting/QUICKSTART.md`.
- No customer testimonials, production benchmarks, public download artifact, pricing, or field-proven censorship-resistance evidence is available and none may be fabricated.

## Product Principles

1. Tell the truth before asking for trust.
2. Make advanced transport architecture understandable to everyday Android users.
3. Keep authority and user data decentralized by design.
4. Demonstrate the mechanism with real product evidence instead of generic privacy claims.
5. Treat accessibility, localization, and recovery as core product behavior.

## Accessibility & Inclusion

The website should meet WCAG 2.2 AA expectations, support keyboard navigation and visible focus, honor reduced-motion and contrast preferences, and remain structurally compatible with future Sorani Kurdish, Kurmanji, Persian, and Arabic localization and right-to-left layouts.
