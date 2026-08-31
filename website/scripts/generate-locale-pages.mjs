import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalBase, siteLocales } from './site-metadata.mjs'

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const localeEntries = Object.entries(siteLocales)
const socialImageUrl = new URL('og-kurdistan-vpn.png', canonicalBase).href
const themeBootstrap =
  '!function(){try{var e=localStorage.getItem("kurdistan-vpn-theme"),t="dark"===e||"light"===e?e:matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";document.documentElement.dataset.theme=t,document.documentElement.style.colorScheme=t}catch(e){}}();'

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function canonicalFor(locale) {
  return new URL(siteLocales[locale].path, canonicalBase).href
}

function alternateLinks() {
  const localized = localeEntries
    .map(
      ([locale]) =>
        `<link rel="alternate" hreflang="${locale}" href="${canonicalFor(locale)}" />`,
    )
    .join('\n    ')

  return `${localized}
    <link rel="alternate" hreflang="x-default" href="${canonicalBase}" />`
}

function openGraphAlternates(activeLocale) {
  return localeEntries
    .filter(([locale]) => locale !== activeLocale)
    .map(
      ([, metadata]) =>
        `<meta property="og:locale:alternate" content="${metadata.ogLocale}" />`,
    )
    .join('\n    ')
}

function renderPage(locale) {
  const metadata = siteLocales[locale]
  const canonical = canonicalFor(locale)
  const structuredData = JSON.stringify(
    {
      '@context': 'https://schema.org',
      '@type': 'WebSite',
      name: 'Kurdistan VPN',
      url: canonicalBase,
      description: metadata.description,
      inLanguage: ['en', 'ckb', 'kmr'],
    },
    null,
    2,
  ).replaceAll('<', '\\u003c')

  return `<!doctype html>
<html lang="${metadata.lang}" dir="${metadata.dir}" data-locale="${locale}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="icon" type="image/svg+xml" href="/kurdistan-mark.svg" />
    <link rel="canonical" href="${canonical}" />
    ${alternateLinks()}
    <meta id="theme-color" name="theme-color" content="#090a19" />
    <meta name="robots" content="index, follow, max-image-preview:large" />
    <meta name="description" content="${escapeHtml(metadata.description)}" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Kurdistan VPN" />
    <meta property="og:title" content="${escapeHtml(metadata.title)}" />
    <meta property="og:description" content="${escapeHtml(metadata.description)}" />
    <meta property="og:url" content="${canonical}" />
    <meta property="og:locale" content="${metadata.ogLocale}" />
    ${openGraphAlternates(locale)}
    <meta property="og:image" content="${socialImageUrl}" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="${escapeHtml(metadata.imageAlt)}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${escapeHtml(metadata.title)}" />
    <meta name="twitter:description" content="${escapeHtml(metadata.description)}" />
    <meta name="twitter:image" content="${socialImageUrl}" />
    <meta name="twitter:image:alt" content="${escapeHtml(metadata.imageAlt)}" />
    <title>${escapeHtml(metadata.title)}</title>
    <script data-theme-bootstrap>${themeBootstrap}</script>
    <script type="application/ld+json">${structuredData}</script>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
`
}

for (const [locale, metadata] of localeEntries) {
  const outputFile =
    locale === 'en'
      ? resolve(projectRoot, 'index.html')
      : resolve(projectRoot, metadata.path, 'index.html')

  mkdirSync(dirname(outputFile), { recursive: true })
  writeFileSync(outputFile, renderPage(locale))
}

const generatedMetadata = `export const localeMetadata = ${JSON.stringify(
  siteLocales,
  null,
  2,
)} as const
`

writeFileSync(
  resolve(projectRoot, 'src/i18n/generatedMetadata.ts'),
  generatedMetadata,
)

const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${localeEntries
  .map(
    ([locale]) => `  <url>
    <loc>${canonicalFor(locale)}</loc>
  </url>`,
  )
  .join('\n')}
</urlset>
`

writeFileSync(resolve(projectRoot, 'public/sitemap.xml'), sitemap)
