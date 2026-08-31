import { useEffect, useRef } from 'react'
import { useLocale } from '../i18n/LocaleContext'
import type { Locale } from '../i18n/translations'
import { useTheme } from '../theme/ThemeContext'
import type { ThemePreference } from '../theme/theme'
import { publicPath } from '../lib/publicPath'

const localeOptions: readonly {
  locale: Locale
  flag: string
}[] = [
  { locale: 'ckb', flag: publicPath('kurdistan-flag.svg') },
  { locale: 'kmr', flag: publicPath('kurdistan-flag.svg') },
  { locale: 'en', flag: publicPath('united-kingdom-flag.svg') },
]

const themeOptions: readonly ThemePreference[] = [
  'system',
  'dark',
  'light',
]

type PreferencesMenuProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function PreferencesMenu({
  open,
  onOpenChange,
}: PreferencesMenuProps) {
  const { locale, copy, localeHref, rememberLocale } = useLocale()
  const { preference, setPreference } = useTheme()
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)

  const languageNames: Record<Locale, string> = {
    en: copy.language.english,
    ckb: copy.language.sorani,
    kmr: copy.language.kurmanji,
  }

  const shortLabels: Record<Locale, string> = {
    en: copy.language.englishShort,
    ckb: copy.language.soraniShort,
    kmr: copy.language.kurmanjiShort,
  }

  const themeLabels: Record<ThemePreference, string> = {
    system: copy.preferences.system,
    dark: copy.preferences.dark,
    light: copy.preferences.light,
  }

  const activeLocale =
    localeOptions.find((option) => option.locale === locale) ?? localeOptions[2]

  useEffect(() => {
    if (!open) return

    const firstSelected = panelRef.current?.querySelector<HTMLElement>(
      '[aria-current="true"], input:checked',
    )

    window.requestAnimationFrame(() => firstSelected?.focus())

    const handlePointer = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        onOpenChange(false)
      }
    }

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return

      event.preventDefault()
      onOpenChange(false)
      triggerRef.current?.focus()
    }

    document.addEventListener('pointerdown', handlePointer)
    document.addEventListener('keydown', handleEscape)

    return () => {
      document.removeEventListener('pointerdown', handlePointer)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [onOpenChange, open])

  return (
    <div className="preferences" ref={rootRef}>
      <button
        ref={triggerRef}
        className="preferences__trigger"
        type="button"
        aria-expanded={open}
        aria-controls="preferences-panel"
        aria-haspopup="dialog"
        aria-label={open ? copy.preferences.close : copy.preferences.open}
        onClick={() => onOpenChange(!open)}
      >
        <img src={activeLocale.flag} alt="" width="22" height="15" />
        <span>{shortLabels[locale]}</span>
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="m4 6 4 4 4-4" />
        </svg>
      </button>

      {open && (
        <div
          ref={panelRef}
          className="preferences__panel"
          id="preferences-panel"
          role="dialog"
          aria-label={copy.preferences.panel}
        >
          <fieldset className="preferences__group">
            <legend>{copy.preferences.language}</legend>

            <div className="preferences__options">
              {localeOptions.map((option) => (
                <a
                  key={option.locale}
                  href={localeHref(option.locale)}
                  aria-current={
                    option.locale === locale ? 'true' : undefined
                  }
                  onClick={() => rememberLocale(option.locale)}
                >
                  <img
                    src={option.flag}
                    alt=""
                    width="24"
                    height="16"
                  />
                  <span>{languageNames[option.locale]}</span>
                  <svg viewBox="0 0 16 16" aria-hidden="true">
                    <path d="m3 8 3 3 7-7" />
                  </svg>
                </a>
              ))}
            </div>
          </fieldset>

          <fieldset className="preferences__group">
            <legend>{copy.preferences.appearance}</legend>

            <div className="preferences__theme-options">
              {themeOptions.map((option) => (
                <label key={option}>
                  <input
                    type="radio"
                    name="theme"
                    value={option}
                    checked={preference === option}
                    onChange={() => setPreference(option)}
                  />
                  <span aria-hidden="true" data-theme-preview={option} />
                  <strong>{themeLabels[option]}</strong>
                </label>
              ))}
            </div>
          </fieldset>
        </div>
      )}
    </div>
  )
}
