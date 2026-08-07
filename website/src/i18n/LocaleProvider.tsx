import {
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { LocaleContext } from './LocaleContext'
import { translations, type Locale } from './translations'

const STORAGE_KEY = 'kurdistan-vpn-locale'

function readStoredLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    return stored === 'ckb' ? 'ckb' : 'en'
  } catch {
    return 'en'
  }
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>(readStoredLocale)
  const copy = translations[locale]

  useEffect(() => {
    document.documentElement.lang = locale
    document.documentElement.dir = locale === 'ckb' ? 'rtl' : 'ltr'
    document.title = copy.meta.title

    let description = document.querySelector<HTMLMetaElement>('meta[name="description"]')
    if (!description) {
      description = document.createElement('meta')
      description.name = 'description'
      document.head.append(description)
    }
    description.content = copy.meta.description

    try {
      window.localStorage.setItem(STORAGE_KEY, locale)
    } catch {
      // Locale switching still works when storage is unavailable.
    }
  }, [copy.meta.description, copy.meta.title, locale])

  const value = useMemo(
    () => ({ locale, setLocale, copy }),
    [copy, locale],
  )

  return <LocaleContext value={value}>{children}</LocaleContext>
}
