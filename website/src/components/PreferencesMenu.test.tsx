import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App'

describe('preferences panel', () => {
  beforeEach(() => {
    window.localStorage.clear()
    document.documentElement.dataset.locale = 'en'

    vi.stubGlobal(
      'matchMedia',
      vi.fn().mockImplementation((query: string) => ({
        matches: query === '(prefers-color-scheme: dark)',
        media: query,
        onchange: null,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    )
  })

  it('groups language and appearance settings in one named panel', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(
      screen.getByRole('button', { name: /open preferences/i }),
    )

    expect(
      screen.getByRole('dialog', {
        name: /language and appearance/i,
      }),
    ).toBeVisible()

    expect(
      screen.getByRole('group', { name: /language/i }),
    ).toBeVisible()

    expect(
      screen.getByRole('group', { name: /appearance/i }),
    ).toBeVisible()

    expect(
      screen.getByRole('radio', { name: /system/i }),
    ).toBeChecked()
  })

  it('changes theme and returns focus on Escape', async () => {
    const user = userEvent.setup()
    render(<App />)

    const trigger = screen.getByRole('button', {
      name: /open preferences/i,
    })

    await user.click(trigger)
    await user.click(screen.getByRole('radio', { name: /light/i }))

    expect(document.documentElement).toHaveAttribute('data-theme', 'light')

    await user.keyboard('{Escape}')

    expect(trigger).toHaveFocus()
    expect(
      screen.queryByRole('dialog', {
        name: /language and appearance/i,
      }),
    ).not.toBeInTheDocument()
  })

  it('uses real locale links rather than in-place metadata mismatches', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(
      screen.getByRole('button', { name: /open preferences/i }),
    )

    expect(
      screen.getByRole('link', { name: 'کوردی (سۆرانی)' }),
    ).toHaveAttribute('href', expect.stringMatching(/ckb\/$/))

    expect(
      screen.getByRole('link', { name: 'Kurdî (Kurmancî)' }),
    ).toHaveAttribute('href', expect.stringMatching(/kmr\/$/))
  })
})
