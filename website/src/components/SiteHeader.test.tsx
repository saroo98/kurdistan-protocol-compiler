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
})
