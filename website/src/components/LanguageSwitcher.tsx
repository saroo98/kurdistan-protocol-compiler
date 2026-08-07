import { useEffect, useRef, useState } from 'react'
import { useLocale } from '../i18n/LocaleContext'
import type { Locale } from '../i18n/translations'

const options: readonly { locale: Locale; flag: string }[] = [
  { locale: 'ckb', flag: '/kurdistan-flag.svg' },
  { locale: 'en', flag: '/united-kingdom-flag.svg' },
]

export function LanguageSwitcher() {
  const { locale, setLocale, copy } = useLocale()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const active = options.find((option) => option.locale === locale) ?? options[1]

  useEffect(() => {
    if (!open) return

    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }

    document.addEventListener('pointerdown', closeOnOutsidePointer)
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsidePointer)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  const languageName = (optionLocale: Locale) =>
    optionLocale === 'ckb' ? copy.language.sorani : copy.language.english

  const shortLabel =
    locale === 'ckb' ? copy.language.soraniShort : copy.language.englishShort

  return (
    <div className="language-switcher" ref={rootRef}>
      <button
        className="language-trigger"
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="language-options"
        aria-label={copy.language.change}
        onClick={() => setOpen((current) => !current)}
      >
        <img
          key={active.flag}
          className="language-trigger__flag"
          src={active.flag}
          alt=""
          width="22"
          height="15"
        />
        <span key={locale} className="language-trigger__label">
          {shortLabel}
        </span>
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="m4 6 4 4 4-4" />
        </svg>
      </button>

      <div
        className="language-menu"
        id="language-options"
        role="menu"
        aria-label={copy.language.options}
        aria-hidden={!open}
        data-state={open ? 'open' : 'closed'}
      >
        {options.map((option) => (
          <button
            key={option.locale}
            type="button"
            role="menuitemradio"
            aria-checked={option.locale === locale}
            tabIndex={open ? 0 : -1}
            onClick={() => {
              setLocale(option.locale)
              setOpen(false)
            }}
          >
            <img src={option.flag} alt="" width="24" height="16" />
            <span>{languageName(option.locale)}</span>
            {option.locale === locale && (
              <svg viewBox="0 0 16 16" aria-hidden="true">
                <path d="m3 8 3 3 7-7" />
              </svg>
            )}
          </button>
        ))}
      </div>
    </div>
  )
}
