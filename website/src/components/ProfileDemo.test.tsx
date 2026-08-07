import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import App from '../App'

describe('synthetic profile demonstration', () => {
  it('updates the visible trust decision when a different demo profile is selected', async () => {
    const user = userEvent.setup()
    render(<App />)

    expect(screen.getByText('KURD · 7A31 · D9C4 · DEMO')).toBeVisible()
    const activeMarker = document.querySelector('.profile-active-marker')
    expect(activeMarker).toHaveAttribute('data-profile-index', '0')

    await user.click(
      screen.getByRole('button', { name: /select mountain route profile/i }),
    )

    expect(activeMarker).toHaveAttribute('data-profile-index', '1')
    expect(screen.getByText('KURD · B204 · 8E12 · DEMO')).toBeVisible()
    expect(screen.getByText(/expires in 2 days/i)).toBeVisible()
    expect(screen.getByText(/review before trusting/i)).toBeVisible()
    expect(screen.getByText(/synthetic demonstration/i)).toBeVisible()
  })

  it('makes profile decisions visible and resettable', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /confirm this deployment/i }))

    const confirmedStatus = screen.getByRole('status')
    expect(confirmedStatus).toHaveTextContent(
      /city thread marked as trusted for this demonstration/i,
    )
    expect(confirmedStatus.closest('.profile-ticket__feedback')).toHaveAttribute(
      'data-decision',
      'confirmed',
    )
    expect(
      confirmedStatus.closest('.profile-ticket__feedback')?.querySelector('.decision-mark'),
    ).toBeVisible()

    await user.click(screen.getByRole('button', { name: /reset decision/i }))

    expect(screen.queryByText(/marked as trusted for this demonstration/i)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /not now/i }))

    const dismissedStatus = screen.getByRole('status')
    expect(dismissedStatus).toHaveTextContent(/no trust decision was saved/i)
    expect(dismissedStatus.closest('.profile-ticket__feedback')).toHaveAttribute(
      'data-decision',
      'dismissed',
    )
  })
})
