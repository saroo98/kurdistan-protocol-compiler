import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import App from './App'

describe('Kurdistan VPN public page', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  it('keeps the Android release action visibly unavailable', () => {
    render(<App />)

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /your internet\. your route\./i,
      }),
    ).toBeVisible()
    expect(
      screen.getAllByRole('button', { name: /download for android/i })[0],
    ).toBeDisabled()
    expect(
      screen.getByText(/public relay access is not released/i),
    ).toBeVisible()
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
  })

  it('serves a compact mobile hero image without weakening the desktop fallback', () => {
    const { container } = render(<App />)
    const heroImage = container.querySelector<HTMLImageElement>('.hero-texture')
    const picture = heroImage?.parentElement
    const mobileSource = picture?.querySelector('source')

    expect(picture?.tagName).toBe('PICTURE')
    expect(mobileSource).toHaveAttribute('media', '(max-width: 560px)')
    expect(mobileSource?.getAttribute('srcset')).toMatch(/routeweave-hero-mobile\.webp/)
    expect(heroImage).toHaveAttribute('width', '1536')
    expect(heroImage).toHaveAttribute('height', '1024')
    expect(heroImage).toHaveAttribute('decoding', 'async')
    expect(heroImage).toHaveAttribute('fetchpriority', 'high')
  })

  it('presents the dedication in the active language', async () => {
    const user = userEvent.setup()
    render(<App />)

    expect(screen.getByText(/made with immense/i)).toBeVisible()
    expect(screen.getByText('Rojhelat')).toBeVisible()

    await user.click(screen.getByRole('button', { name: /change language/i }))
    await user.click(screen.getByRole('menuitemradio', { name: /کوردی/i }))

    expect(screen.getByText(/سارۆ خزرنژاد/)).toBeVisible()
    expect(screen.getByText('ڕۆژهەڵات')).toBeVisible()
    expect(screen.queryByText(/Saro Xizirnijad/)).not.toBeInTheDocument()
  })
})
