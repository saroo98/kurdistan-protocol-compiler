import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import App from '../App'

describe('website locale', () => {
  beforeEach(() => {
    window.localStorage.clear()
    document.documentElement.lang = 'en'
    document.documentElement.dir = 'ltr'
  })

  it('switches the website to Sorani RTL while keeping the phone preview in English', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /change language/i }))
    expect(screen.getByRole('menu', { name: /language options/i })).toHaveAttribute(
      'data-state',
      'open',
    )
    await user.click(screen.getByRole('menuitemradio', { name: /کوردی/i }))

    expect(document.documentElement).toHaveAttribute('lang', 'ckb')
    expect(document.documentElement).toHaveAttribute('dir', 'rtl')
    expect(document.title).toBe('VPNی کوردستان · ئینتەرنێتی تۆ. ڕێگای تۆ.')
    expect(document.querySelector('meta[name="description"]')).toHaveAttribute(
      'content',
      expect.stringContaining('پرۆفایلی واژۆکراو'),
    )
    expect(
      screen.getByRole('heading', { level: 1, name: 'ئینتەرنێتی تۆ. ڕێگای تۆ.' }),
    ).toBeVisible()
    expect(screen.getByText('Profile verified')).toBeVisible()
    expect(window.localStorage.getItem('kurdistan-vpn-locale')).toBe('ckb')
    expect(screen.getByRole('menu', { hidden: true })).toHaveAttribute(
      'data-state',
      'closed',
    )
    expect(screen.getByRole('menu', { hidden: true })).toHaveAttribute(
      'aria-hidden',
      'true',
    )
  })

  it('restores a saved locale and can return to English LTR', async () => {
    window.localStorage.setItem('kurdistan-vpn-locale', 'ckb')
    const user = userEvent.setup()
    render(<App />)

    expect(document.documentElement).toHaveAttribute('lang', 'ckb')
    expect(document.documentElement).toHaveAttribute('dir', 'rtl')

    await user.click(screen.getByRole('button', { name: /گۆڕینی زمان/i }))
    await user.click(screen.getByRole('menuitemradio', { name: /english/i }))

    expect(document.documentElement).toHaveAttribute('lang', 'en')
    expect(document.documentElement).toHaveAttribute('dir', 'ltr')
    expect(
      screen.getByRole('heading', { level: 1, name: 'Your internet. Your route.' }),
    ).toBeVisible()
  })
})
