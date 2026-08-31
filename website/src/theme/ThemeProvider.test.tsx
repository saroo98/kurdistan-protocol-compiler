import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeProvider } from './ThemeProvider'
import { useTheme } from './ThemeContext'

function ThemeProbe() {
  const { preference, resolvedTheme, setPreference } = useTheme()

  return (
    <>
      <output aria-label="theme preference">{preference}</output>
      <output aria-label="resolved theme">{resolvedTheme}</output>
      <button type="button" onClick={() => setPreference('light')}>
        Use light
      </button>
    </>
  )
}

describe('ThemeProvider', () => {
  beforeEach(() => {
    window.localStorage.clear()

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

  it('follows the operating system until the user chooses an override', async () => {
    const user = userEvent.setup()

    render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    )

    expect(screen.getByLabelText('theme preference')).toHaveTextContent(
      'system',
    )
    expect(screen.getByLabelText('resolved theme')).toHaveTextContent('dark')
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')

    await user.click(screen.getByRole('button', { name: 'Use light' }))

    expect(screen.getByLabelText('theme preference')).toHaveTextContent(
      'light',
    )
    expect(screen.getByLabelText('resolved theme')).toHaveTextContent('light')
    expect(document.documentElement).toHaveAttribute('data-theme', 'light')
    expect(window.localStorage.getItem('kurdistan-vpn-theme')).toBe('light')
  })

  it('ignores corrupt stored values', () => {
    window.localStorage.setItem('kurdistan-vpn-theme', 'purple')

    render(
      <ThemeProvider>
        <ThemeProbe />
      </ThemeProvider>,
    )

    expect(screen.getByLabelText('theme preference')).toHaveTextContent(
      'system',
    )
  })
})
