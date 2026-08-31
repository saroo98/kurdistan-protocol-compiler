import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import {
  type NavSectionId,
  useActiveSection,
} from '../hooks/useActiveSection'
import { useScrollProgress } from '../hooks/useScrollProgress'
import { useLocale } from '../i18n/LocaleContext'
import { publicPath } from '../lib/publicPath'
import { PreferencesMenu } from './PreferencesMenu'

export function SiteHeader() {
  const [open, setOpen] = useState(false)
  const [closing, setClosing] = useState(false)
  const [preferencesOpen, setPreferencesOpen] = useState(false)
  const menuTriggerRef = useRef<HTMLButtonElement>(null)
  const navigationRef = useRef<HTMLElement>(null)
  const { copy } = useLocale()
  const navigationState = open ? 'open' : closing ? 'closing' : 'closed'
  const sectionIds = useMemo(
    () =>
      ['how-it-works', 'privacy', 'self-host', 'status'] as const,
    [],
  )
  const activeSection = useActiveSection(sectionIds)
  const scrollProgress = useScrollProgress()

  const closeNavigation = useCallback(() => {
    if (!open) return
    setOpen(false)
    setClosing(true)
  }, [open])

  useEffect(() => {
    if (!closing) return

    const timeout = window.setTimeout(() => setClosing(false), 160)
    return () => window.clearTimeout(timeout)
  }, [closing])

  useEffect(() => {
    if (!open) return

    const focusFrame = window.requestAnimationFrame(() => {
      navigationRef.current?.querySelector<HTMLElement>('a[href]')?.focus()
    })

    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.preventDefault()
      window.cancelAnimationFrame(focusFrame)
      closeNavigation()
      menuTriggerRef.current?.focus()
    }

    const closeOnPointerDown = (event: PointerEvent) => {
      const target = event.target as Node

      if (
        navigationRef.current?.contains(target) ||
        menuTriggerRef.current?.contains(target)
      ) {
        return
      }

      closeNavigation()
    }

    document.addEventListener('keydown', closeOnEscape)
    document.addEventListener('pointerdown', closeOnPointerDown)

    return () => {
      window.cancelAnimationFrame(focusFrame)
      document.removeEventListener('keydown', closeOnEscape)
      document.removeEventListener('pointerdown', closeOnPointerDown)
    }
  }, [closeNavigation, open])

  const toggleNavigation = () => {
    if (open) {
      closeNavigation()
      return
    }

    setPreferencesOpen(false)
    setClosing(false)
    setOpen(true)
  }

  const handlePreferencesOpenChange = (nextOpen: boolean) => {
    if (nextOpen) closeNavigation()
    setPreferencesOpen(nextOpen)
  }

  return (
    <header className="site-header">
      <div className="nav-shell">
        <a className="brand" href="#top" aria-label={copy.header.home}>
          <img
            src={publicPath('kurdistan-mark.svg')}
            alt=""
            width="36"
            height="36"
          />
          <span>
            Kurdistan <strong>VPN</strong>
          </span>
        </a>

        <nav
          ref={navigationRef}
          id="primary-navigation"
          className={`primary-nav${open ? ' is-open' : ''}${closing ? ' is-closing' : ''}`}
          aria-label={copy.header.primaryNavigation}
          aria-hidden={closing || undefined}
          data-state={navigationState}
        >
          {copy.header.navigation.map((item) => {
            const sectionId = item.href.slice(1) as NavSectionId

            return (
              <a
                key={item.href}
                href={item.href}
                aria-current={
                  activeSection === sectionId ? 'location' : undefined
                }
                tabIndex={closing ? -1 : undefined}
                onClick={closeNavigation}
              >
                {item.label}
              </a>
            )
          })}

          <a
            className="nav-download"
            href="#status"
            tabIndex={closing ? -1 : undefined}
            onClick={closeNavigation}
          >
            {copy.header.androidSoon}
          </a>
        </nav>

        <div className="header-actions">
          <PreferencesMenu
            open={preferencesOpen}
            onOpenChange={handlePreferencesOpenChange}
          />
          <button
            ref={menuTriggerRef}
            className="menu-toggle"
            type="button"
            aria-expanded={open}
            aria-controls="primary-navigation"
            aria-label={open ? copy.header.closeMenu : copy.header.openMenu}
            onClick={toggleNavigation}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                className="menu-toggle__line menu-toggle__line--top"
                d="M4 7h16"
              />
              <path
                className="menu-toggle__line menu-toggle__line--middle"
                d="M4 12h16"
              />
              <path
                className="menu-toggle__line menu-toggle__line--bottom"
                d="M4 17h16"
              />
            </svg>
          </button>
        </div>
      </div>

      <progress
        className="header-progress"
        max={1}
        value={scrollProgress}
        aria-hidden="true"
      />
    </header>
  )
}
