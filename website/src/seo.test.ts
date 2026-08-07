import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const canonicalUrl = 'https://saroo98.github.io/kurdistan-protocol-compiler/'
const socialImageUrl = `${canonicalUrl}og-kurdistan-vpn.png`

function readDocument() {
  const html = readFileSync(resolve('index.html'), 'utf8')
  return new DOMParser().parseFromString(html, 'text/html')
}

describe('static search and sharing metadata', () => {
  it('publishes canonical, crawler, social, and structured metadata without React', () => {
    const page = readDocument()
    const robots = page.querySelector<HTMLMetaElement>('meta[name="robots"]')
    const graph = (property: string) =>
      page.querySelector<HTMLMetaElement>(`meta[property="${property}"]`)?.content
    const twitter = (name: string) =>
      page.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content
    const structuredData = JSON.parse(
      page.querySelector<HTMLScriptElement>('script[type="application/ld+json"]')
        ?.textContent ?? '{}',
    ) as Record<string, unknown>

    expect(page.querySelector<HTMLLinkElement>('link[rel="canonical"]')?.href).toBe(
      canonicalUrl,
    )
    expect(robots?.content).toContain('index')
    expect(robots?.content).toContain('follow')
    expect(robots?.content).toContain('max-image-preview:large')

    expect(graph('og:type')).toBe('website')
    expect(graph('og:site_name')).toBe('Kurdistan VPN')
    expect(graph('og:title')).toBe('Kurdistan VPN · Your internet. Your route.')
    expect(graph('og:description')).toMatch(/profile-driven Android VPN/i)
    expect(graph('og:url')).toBe(canonicalUrl)
    expect(graph('og:locale')).toBe('en_GB')
    expect(graph('og:locale:alternate')).toBe('ckb_IQ')
    expect(graph('og:image')).toBe(socialImageUrl)

    expect(twitter('twitter:card')).toBe('summary_large_image')
    expect(twitter('twitter:title')).toBe(graph('og:title'))
    expect(twitter('twitter:description')).toBe(graph('og:description'))
    expect(twitter('twitter:image')).toBe(socialImageUrl)

    expect(structuredData).toMatchObject({
      '@context': 'https://schema.org',
      '@type': 'WebSite',
      name: 'Kurdistan VPN',
      url: canonicalUrl,
      inLanguage: ['en', 'ckb'],
    })
    expect(JSON.stringify(structuredData)).not.toMatch(
      /released|downloadable|production-ready|undetectable|bypass/i,
    )
  })

  it('ships crawl files and the social image referenced by the document', () => {
    const robotsPath = resolve('public/robots.txt')
    const sitemapPath = resolve('public/sitemap.xml')
    const socialImagePath = resolve('public/og-kurdistan-vpn.png')

    expect(existsSync(robotsPath)).toBe(true)
    expect(existsSync(sitemapPath)).toBe(true)
    expect(existsSync(socialImagePath)).toBe(true)

    expect(readFileSync(robotsPath, 'utf8')).toContain(
      `${canonicalUrl}sitemap.xml`,
    )

    const sitemap = new DOMParser().parseFromString(
      readFileSync(sitemapPath, 'utf8'),
      'application/xml',
    )
    expect(sitemap.querySelector('loc')?.textContent).toBe(canonicalUrl)
  })
})
