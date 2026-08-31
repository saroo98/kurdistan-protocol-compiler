import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import App from '../App'

describe('profile trust demonstration', () => {
  beforeEach(() => {
    window.localStorage.clear()
    document.documentElement.dataset.locale = 'en'
    document.documentElement.lang = 'en'
    document.documentElement.dir = 'ltr'
  })

  it('implements profile choices as a keyboard-operable vertical tab set', async () => {
    const user = userEvent.setup()
    render(<App />)

    const tabList = screen.getByRole('tablist', { name: /synthetic profiles/i })
    const tabs = screen.getAllByRole('tab')

    expect(tabList).toHaveAttribute('aria-orientation', 'vertical')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveAttribute('tabindex', '0')
    expect(tabs[1]).toHaveAttribute('tabindex', '-1')

    tabs[0].focus()
    await user.keyboard('{ArrowDown}')
    expect(tabs[1]).toHaveFocus()
    expect(tabs[1]).toHaveAttribute('aria-selected', 'true')

    await user.keyboard('{End}')
    expect(tabs[2]).toHaveFocus()

    await user.keyboard('{Home}')
    expect(tabs[0]).toHaveFocus()
    expect(screen.getByRole('tabpanel')).toHaveAttribute(
      'aria-labelledby',
      tabs[0].id,
    )
  })

  it('announces only the resulting decision', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(
      screen.getByRole('button', { name: /confirm this deployment/i }),
    )

    const status = screen.getByRole('status')
    expect(status).toHaveTextContent(
      /city thread marked as trusted for this demonstration/i,
    )
    expect(status).not.toHaveTextContent(/deployment owner/i)
  })

  it('resets a decision when another synthetic profile is selected', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(
      screen.getByRole('button', { name: /confirm this deployment/i }),
    )
    expect(screen.getByRole('status')).toHaveTextContent(/marked as trusted/i)

    await user.click(screen.getAllByRole('tab')[1])

    expect(
      screen.getByRole('button', { name: /confirm this deployment/i }),
    ).toBeVisible()
    expect(screen.getByRole('status')).toBeEmptyDOMElement()
  })
})
