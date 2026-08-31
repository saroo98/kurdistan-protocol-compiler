import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import App from '../App'

describe('website locale', () => {
  beforeEach(() => {
    window.localStorage.clear()
    document.documentElement.dataset.locale = 'en'
    document.documentElement.lang = 'en'
    document.documentElement.dir = 'ltr'
  })

  it('links to shareable Sorani and Kurmanji pages and remembers the choice', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /open preferences/i }))

    const sorani = screen.getByRole('link', { name: /کوردی/i })
    const kurmanji = screen.getByRole('link', {
      name: 'Kurdî (Kurmancî)',
    })

    expect(sorani).toHaveAttribute('href', '/ckb/')
    expect(kurmanji).toHaveAttribute('href', '/kmr/')
    expect(kurmanji.querySelector('img')).toHaveAttribute(
      'src',
      '/kurdistan-flag.svg',
    )

    sorani.addEventListener('click', (event) => event.preventDefault())
    await user.click(sorani)

    expect(window.localStorage.getItem('kurdistan-vpn-locale')).toBe('ckb')
  })

  it('hydrates the Sorani page as RTL while keeping the phone preview in English', () => {
    document.documentElement.dataset.locale = 'ckb'
    render(<App />)

    expect(document.documentElement).toHaveAttribute('lang', 'ckb')
    expect(document.documentElement).toHaveAttribute('dir', 'rtl')
    expect(document.title).toBe('VPNی کوردستان · ئینتەرنێتی تۆ. ڕێگای تۆ.')
    expect(document.querySelector('meta[name="description"]')).toHaveAttribute(
      'content',
      expect.stringContaining('پرۆفایلی واژۆکراو'),
    )
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'ئینتەرنێتی تۆ. ڕێگای تۆ.',
      }),
    ).toBeVisible()
    expect(screen.getByText('Profile verified')).toBeVisible()
    expect(screen.getByText(/سارۆ خزرنژاد/)).toBeVisible()
  })

  it('hydrates the Kurmanji page as LTR', () => {
    document.documentElement.dataset.locale = 'kmr'
    render(<App />)

    expect(document.documentElement).toHaveAttribute('lang', 'kmr')
    expect(document.documentElement).toHaveAttribute('dir', 'ltr')
    expect(document.title).toBe('Kurdistan VPN · Înterneta te. Rêya te.')
    expect(document.querySelector('meta[name="description"]')).toHaveAttribute(
      'content',
      expect.stringContaining('profîlên îmzekirî'),
    )
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Înterneta te. Rêya te.',
      }),
    ).toBeVisible()
    expect(screen.getByText('Profile verified')).toBeVisible()
  })

  it('prefers the static page locale over a stale stored preference', () => {
    window.localStorage.setItem('kurdistan-vpn-locale', 'kmr')
    document.documentElement.dataset.locale = 'ckb'
    render(<App />)

    expect(document.documentElement).toHaveAttribute('lang', 'ckb')
    expect(document.documentElement).toHaveAttribute('dir', 'rtl')
  })
})
