/** The website version is unrelated to the unreleased Android product. */
export const config = Object.freeze({
  name: 'Kurdistan VPN',
  siteUrl: process.env.SITE_URL || 'https://saroo98.github.io/kurdistan-protocol-compiler/',
  source: 'https://github.com/saroo98/kurdistan-protocol-compiler',
  revision: 'b86f475cfaa77ee2a2596ed2a29914f031bff506',
  branch: 'phase18/android-product-surface',
  reviewed: '2026-09-16',
  sourceDate: '2026-09-03',
  release: { status: 'Pre-release', artifacts: [], evidence: 'GitHub releases API returned an empty array on the review date.' },
  websiteVersion: '3.0.0',
});
