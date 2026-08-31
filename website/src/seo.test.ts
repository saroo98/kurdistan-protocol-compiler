import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const canonicalBase =
  'https://saroo98.github.io/kurdistan-protocol-compiler/'

const pages = [
  {
    file: 'index.html',
    locale: 'en',
    direction: 'ltr',
    canonical: canonicalBase,
    title: 'Kurdistan VPN · Your internet. Your route.',
  },
  {
    file: 'ckb/index.html',
    locale: 'ckb',
    direction: 'rtl',
    canonical: `${canonicalBase}ckb/`,
    title: 'VPNی کوردستان · ئینتەرنێتی تۆ. ڕێگای تۆ.',
  },
  {
    file: 'kmr/index.html',
    locale: 'kmr',
    direction: 'ltr',
    canonical: `${canonicalBase}kmr/`,
    title: 'Kurdistan VPN · Înterneta te. Rêya te.',
  },
] as const

function readDocument(path: string) {
  const html = readFileSync(resolve(path), 'utf8')
  return new DOMParser().parseFromString(html, 'text/html')
}

describe('localized static search and sharing metadata', () => {
  it.each(pages)(
    'publishes complete static metadata for $locale',
    ({ file, locale, direction, canonical, title }) => {
      const page = readDocument(file)
      const structuredData = JSON.parse(
        page.querySelector<HTMLScriptElement>(
          'script[type="application/ld+json"]',
        )?.textContent ?? '{}',
      ) as Record<string, unknown>

      expect(page.documentElement.lang).toBe(locale)
      expect(page.documentElement.dir).toBe(direction)
      expect(page.documentElement.dataset.locale).toBe(locale)
      expect(page.title).toBe(title)

      expect(
        page.querySelector<HTMLLinkElement>('link[rel="canonical"]')?.href,
      ).toBe(canonical)

      for (const alternate of pages) {
        expect(
          page.querySelector<HTMLLinkElement>(
            `link[rel="alternate"][hreflang="${alternate.locale}"]`,
          )?.href,
        ).toBe(alternate.canonical)
      }

      expect(
        page.querySelector<HTMLMetaElement>('meta[property="og:url"]')
          ?.content,
      ).toBe(canonical)

      expect(
        page.querySelector<HTMLMetaElement>('meta[name="description"]')
          ?.content,
      ).not.toHaveLength(0)

      expect(structuredData).toMatchObject({
        '@context': 'https://schema.org',
        '@type': 'WebSite',
        name: 'Kurdistan VPN',
        inLanguage: ['en', 'ckb', 'kmr'],
      })
    },
  )

  it('publishes all locale URLs in the sitemap', () => {
    expect(existsSync(resolve('public/sitemap.xml'))).toBe(true)

    const document = new DOMParser().parseFromString(
      readFileSync(resolve('public/sitemap.xml'), 'utf8'),
      'application/xml',
    )

    const locations = Array.from(document.querySelectorAll('loc')).map(
      (node) => node.textContent,
    )

    expect(locations).toEqual(pages.map((page) => page.canonical))
  })

  it.each(pages)(
    'adds a production content security policy for $locale',
    ({ file }) => {
      const productionHtml = readFileSync(
        resolve('dist', file),
        'utf8',
      )

      expect(productionHtml).toContain(
        'http-equiv="Content-Security-Policy"',
      )
      expect(productionHtml).toContain("object-src 'none'")
      expect(productionHtml).toContain("base-uri 'self'")
      expect(productionHtml).toContain(
        'name="referrer" content="strict-origin-when-cross-origin"',
      )
      expect(productionHtml).toMatch(
        /script-src 'self' 'sha256-[A-Za-z0-9+/=]+';/,
      )
    },
  )
})
