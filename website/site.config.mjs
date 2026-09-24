/** The website version is unrelated to the unreleased Android product. */
export const config = Object.freeze({
  name: 'Kurdistan VPN',
  siteUrl: process.env.SITE_URL || 'https://saroo98.github.io/kurdistan-protocol-compiler/',
  source: 'https://github.com/saroo98/kurdistan-protocol-compiler',
  revision: '2e3877913bb52421409bedf37ee41183344a1eae',
  branch: 'publication/product-update-20260924',
  reviewed: '2026-09-24',
  sourceDate: '2026-09-24',
  release: { status: 'Pre-release', artifacts: [], evidence: 'GitHub releases API returned an empty array on the review date.' },
  websiteVersion: '3.0.0',
});
