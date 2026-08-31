import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import App from './App'

describe('Kurdistan VPN public page', () => {
  beforeEach(() => {
    window.localStorage.clear()
    document.documentElement.dataset.locale = 'en'
    document.documentElement.lang = 'en'
    document.documentElement.dir = 'ltr'
  })

  it('explains the trust mechanism in the first viewport without presenting a download', () => {
    render(<App />)

    expect(screen.getByText('A profile-driven VPN for Android')).toBeVisible()
    expect(screen.getByText('Private test phase')).toBeVisible()

    expect(
      screen.getByRole('link', { name: 'Try the trust demo' }),
    ).toHaveAttribute('href', '#profile-demo')

    expect(
      screen.getByRole('figure', {
        name: 'How a connection earns trust',
      }),
    ).toBeVisible()

    expect(screen.getByText('Signed profile')).toBeVisible()
    expect(screen.getByText('Verified fingerprint')).toBeVisible()
    expect(screen.getByText('Bounded route')).toBeVisible()

    expect(
      screen.queryByRole('button', { name: /download/i }),
    ).not.toBeInTheDocument()
  })

  it('keeps the Android preview free of a visible illustrative badge', () => {
    render(<App />)

    const preview = screen.getByRole('figure', {
      name: 'Illustrative Android app preview',
    })

    expect(preview.querySelector('figcaption')).not.toBeInTheDocument()
  })

  it('shows the operator workflow before revealing technical details', async () => {
    const user = userEvent.setup()
    render(<App />)

    const responsibilities = screen.getByRole('list', {
      name: /operator responsibilities/i,
    })
    expect(responsibilities).toBeVisible()
    expect(
      within(responsibilities).getByText('Create local authority'),
    ).toBeVisible()
    expect(screen.getByText(/kurdctl init/i)).not.toBeVisible()

    const disclosure = screen.getByText(/explore the operator setup/i)
    await user.click(disclosure)

    expect(screen.getByText(/kurdctl init/i)).toBeVisible()
    expect(
      screen.getByRole('link', { name: /read the self-hosting guide/i }),
    ).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('renders command names as semantic inline code without Markdown punctuation', () => {
    const { container } = render(<App />)
    const factPanel = container.querySelector('.self-host-facts')
    const commandTokens = Array.from(
      factPanel?.querySelectorAll('code') ?? [],
      (token) => token.textContent,
    )

    expect(commandTokens).toEqual(['kurdctl', 'kurd-node'])
    expect(factPanel?.textContent).not.toContain('`')
  })

  it('presents the trust journey as an ordered process and named contract', () => {
    render(<App />)

    const section = screen
      .getByRole('heading', {
        level: 2,
        name: /trust starts with a profile/i,
      })
      .closest('section')

    expect(section?.querySelector('ol')).toBeInTheDocument()

    expect(
      screen.getByRole('complementary', {
        name: /what the profile binds/i,
      }),
    ).toBeVisible()

    expect(screen.getByText('Deployment identity')).toBeVisible()
    expect(screen.getByText('Signed policy')).toBeVisible()
    expect(screen.getByText('Expiry')).toBeVisible()
  })

  it('describes the signed deployment without implying a known individual', () => {
    render(<App />)

    expect(
      screen.getByRole('heading', {
        level: 2,
        name: 'Know which deployment you trust.',
      }),
    ).toBeVisible()
    expect(screen.getByText('Deployment authority')).toBeVisible()
    expect(screen.queryByText(/operator you know/i)).not.toBeInTheDocument()
    expect(
      screen.queryByRole('heading', {
        name: /know who runs the connection/i,
      }),
    ).not.toBeInTheDocument()
  })

  it('distinguishes architectural privacy boundaries from outcome guarantees', () => {
    render(<App />)

    expect(screen.getByText('Architecture boundary')).toBeVisible()
    expect(
      screen.getByText(
        /do not guarantee anonymity, censorship resistance, or immunity from blocking/i,
      ),
    ).toBeVisible()
    expect(
      screen.getByRole('list', {
        name: /decentralization boundaries/i,
      }),
    ).toBeVisible()
  })

  it('shows implementation, validation, and release as a dated release status', () => {
    render(<App />)

    const statusSection = screen
      .getByRole('heading', { level: 2, name: 'What exists today.' })
      .closest('section')
    expect(statusSection).not.toBeNull()
    const status = within(statusSection as HTMLElement)

    expect(status.getByText('Current phase')).toBeVisible()
    expect(status.getByText('Controlled testing')).toBeVisible()
    expect(
      status.getByRole('list', {
        name: /release readiness/i,
      }),
    ).toBeVisible()
    expect(status.getByText('Foundation')).toBeVisible()
    expect(status.getByText('Field validation')).toBeVisible()
    expect(status.getByText('Public release')).toBeVisible()
    expect(status.getByText('2026-08-31')).toBeVisible()
    expect(statusSection?.querySelector('.status-boundary')).not.toBeInTheDocument()
    expect(screen.queryByText(/\d+% complete/i)).not.toBeInTheDocument()
  })

  it('keeps milestone summaries visible while progressively disclosing technical lists', async () => {
    const user = userEvent.setup()
    render(<App />)

    const statusSection = screen
      .getByRole('heading', { level: 2, name: 'What exists today.' })
      .closest('section')
    expect(statusSection).not.toBeNull()
    const status = within(statusSection as HTMLElement)
    const firstItem = status.getByText(
      'Profile-driven protocol compiler and generated transport modules',
    )
    const showDetails = status.getAllByText('Show milestone details')

    expect(showDetails).toHaveLength(3)
    expect(firstItem).not.toBeVisible()

    await user.click(showDetails[0])

    expect(firstItem).toBeVisible()
    expect(
      within(showDetails[0].closest('details') as HTMLElement).getByText(
        'Hide milestone details',
      ),
    ).toBeVisible()
  })

  it('finishes with current legal metadata and a return path', () => {
    render(<App />)

    expect(
      screen.getByRole('link', { name: /back to top/i }),
    ).toHaveAttribute('href', '#top')
    expect(
      screen.getByText(`© ${new Date().getUTCFullYear()} Saro`),
    ).toBeVisible()

    const githubLink = screen.getAllByRole('link', {
      name: /view on github/i,
    })[0]
    expect(githubLink).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('offers the real repository without making prohibited claims', () => {
    render(<App />)

    expect(screen.getAllByRole('link', { name: /view on github/i })[0]).toHaveAttribute(
      'href',
      'https://github.com/saroo98/kurdistan-protocol-compiler',
    )
    expect(
      screen.queryByText(/guaranteed bypass|undetectable|anonymous by default/i),
    ).not.toBeInTheDocument()
  })

  it('exposes landmarks and the primary navigation', () => {
    render(<App />)

    expect(screen.getByRole('banner')).toBeVisible()
    expect(screen.getByRole('main')).toBeVisible()
    expect(screen.getByRole('contentinfo')).toBeVisible()
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeVisible()
    expect(screen.getByRole('link', { name: /skip to main content/i })).toHaveAttribute(
      'href',
      '#main-content',
    )
  })

  it('serves responsive mobile and desktop hero formats with an explicit fallback', () => {
    const { container } = render(<App />)
    const heroImage = container.querySelector<HTMLImageElement>('.hero-texture')
    const picture = heroImage?.parentElement
    const sources = picture?.querySelectorAll('source')

    expect(picture?.tagName).toBe('PICTURE')
    expect(sources).toHaveLength(4)
    expect(sources?.[0]).toHaveAttribute('media', '(max-width: 560px)')
    expect(sources?.[0]).toHaveAttribute('type', 'image/avif')
    expect(sources?.[1]).toHaveAttribute('type', 'image/webp')
    expect(sources?.[0].getAttribute('srcset')).toMatch(/480w.*640w/)
    expect(sources?.[2].getAttribute('srcset')).toMatch(/960w.*1280w.*1536w/)
    expect(sources?.[2]).toHaveAttribute('sizes', '(max-width: 900px) 100vw, 62vw')
    expect(heroImage).toHaveAttribute('width', '1280')
    expect(heroImage).toHaveAttribute('height', '853')
    expect(heroImage).toHaveAttribute('decoding', 'async')
    expect(heroImage).toHaveAttribute('fetchpriority', 'high')
  })

  it('presents the dedication in the active static-page language', () => {
    document.documentElement.dataset.locale = 'ckb'
    render(<App />)

    expect(screen.getByText(/سارۆ خزرنژاد/)).toBeVisible()
    expect(screen.getByText('ڕۆژهەڵات')).toBeVisible()
    expect(screen.queryByText(/Saro Xizirnijad/)).not.toBeInTheDocument()
  })
})
