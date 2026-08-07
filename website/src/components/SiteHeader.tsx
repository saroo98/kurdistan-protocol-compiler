import { useEffect, useState } from 'react'
import { useLocale } from '../i18n/LocaleContext'
import { LanguageSwitcher } from './LanguageSwitcher'

export function SiteHeader() {
  const [open, setOpen] = useState(false)
  const [closing, setClosing] = useState(false)
  const { copy } = useLocale()
  const navigationState = open ? 'open' : closing ? 'closing' : 'closed'

  useEffect(() => {
    if (!closing) return

    const timeout = window.setTimeout(() => setClosing(false), 160)
    return () => window.clearTimeout(timeout)
  }, [closing])

  const closeNavigation = () => {
    if (!open) return
    setOpen(false)
    setClosing(true)
  }

  const toggleNavigation = () => {
    if (open) {
      closeNavigation()
      return
    }

    setClosing(false)
    setOpen(true)
  }

  return (
    <header className="site-header">
      <div className="nav-shell">
        <a className="brand" href="#top" aria-label={copy.header.home}>
          <img src="/kurdistan-mark.svg" alt="" width="36" height="36" />
          <span>
            Kurdistan <strong>VPN</strong>
          </span>
        </a>

        <nav
          id="primary-navigation"
          className={`primary-nav${open ? ' is-open' : ''}${closing ? ' is-closing' : ''}`}
          aria-label={copy.header.primaryNavigation}
          aria-hidden={closing || undefined}
          data-state={navigationState}
        >
          {copy.header.navigation.map((item) => (
            <a key={item.href} href={item.href} onClick={closeNavigation}>
              {item.label}
            </a>
          ))}
          <button type="button" className="nav-download" disabled>
            {copy.header.androidSoon}
          </button>
        </nav>

        <div className="header-actions">
          <LanguageSwitcher />
          <button
            className="menu-toggle"
            type="button"
            aria-expanded={open}
            aria-controls="primary-navigation"
            aria-label={open ? copy.header.closeMenu : copy.header.openMenu}
            onClick={toggleNavigation}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path className="menu-toggle__line menu-toggle__line--top" d="M4 7h16" />
              <path className="menu-toggle__line menu-toggle__line--middle" d="M4 12h16" />
              <path className="menu-toggle__line menu-toggle__line--bottom" d="M4 17h16" />
            </svg>
          </button>
        </div>
      </div>
    </header>
  )
}
