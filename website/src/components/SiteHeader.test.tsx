import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import App from '../App'

describe('site navigation motion states', () => {
  it('keeps the mobile navigation mounted through its closing phase', async () => {
    const user = userEvent.setup()
    render(<App />)

    const trigger = screen.getByRole('button', { name: /open navigation menu/i })
    const navigation = screen.getByRole('navigation', { name: /primary/i })

    await user.click(trigger)

    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(navigation).toHaveAttribute('data-state', 'open')

    await user.click(screen.getByRole('button', { name: /close navigation menu/i }))

    expect(navigation).toHaveAttribute('data-state', 'closing')
    expect(navigation).toHaveAttribute('aria-hidden', 'true')

    await waitFor(() => expect(navigation).toHaveAttribute('data-state', 'closed'))
    expect(navigation).not.toHaveAttribute('aria-hidden')
  })

  it('closes the mobile navigation with Escape and returns focus to its trigger', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)

    const trigger = screen.getByRole('button', { name: /open navigation menu/i })
    await user.click(trigger)
    await user.keyboard('{Escape}')

    expect(trigger).toHaveFocus()
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(container.querySelector('#primary-navigation')).toHaveAttribute(
      'data-state',
      'closing',
    )
  })

  it('moves focus to the first navigation link when the mobile menu opens', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(
      screen.getByRole('button', { name: /open navigation menu/i }),
    )

    await waitFor(() =>
      expect(
        screen.getByRole('link', { name: /how it works/i }),
      ).toHaveFocus(),
    )
  })

  it('closes the mobile navigation when focus moves to preferences', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)

    await user.click(
      screen.getByRole('button', { name: /open navigation menu/i }),
    )
    await user.click(
      screen.getByRole('button', { name: /open preferences/i }),
    )

    expect(container.querySelector('#primary-navigation')).toHaveAttribute(
      'data-state',
      'closing',
    )
    expect(
      screen.getByRole('dialog', { name: /language and appearance/i }),
    ).toBeVisible()
  })

  it('closes the mobile navigation after an outside pointer interaction', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)

    await user.click(
      screen.getByRole('button', { name: /open navigation menu/i }),
    )
    await user.click(
      screen.getByRole('heading', {
        level: 1,
        name: /your internet\. your route\./i,
      }),
    )

    expect(container.querySelector('#primary-navigation')).toHaveAttribute(
      'data-state',
      'closing',
    )
  })

  it('does not mark an off-screen section as the current location', () => {
    render(<App />)

    expect(
      screen.getByRole('link', { name: /how it works/i }),
    ).not.toHaveAttribute('aria-current')
  })

  it('keeps visible labels inside the accessible names of labeled controls', () => {
    render(<App />)

    expect(
      screen.getByRole('button', { name: /open preferences/i }),
    ).toBeVisible()
    expect(
      screen.getByRole('tab', { name: /city thread.*verified/i }),
    ).toBeVisible()
  })
})
