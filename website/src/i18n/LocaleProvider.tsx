import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { localeMetadata } from './generatedMetadata'
import { LocaleContext } from './LocaleContext'
import { translations, type Locale } from './translations'
import { publicPath } from '../lib/publicPath'

const STORAGE_KEY = 'kurdistan-vpn-locale'

function isLocale(value: unknown): value is Locale {
  return value === 'en' || value === 'ckb' || value === 'kmr'
}

function readInitialLocale(): Locale {
  const documentLocale = document.documentElement.dataset.locale
  if (isLocale(documentLocale)) return documentLocale

  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    return isLocale(stored) ? stored : 'en'
  } catch {
    return 'en'
  }
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale] = useState<Locale>(readInitialLocale)
  const copy = translations[locale]

  useEffect(() => {
    document.documentElement.lang = locale
    document.documentElement.dir = localeMetadata[locale].dir
    document.documentElement.dataset.locale = locale
    document.title = copy.meta.title

    let description =
      document.querySelector<HTMLMetaElement>('meta[name="description"]')

    if (!description) {
      description = document.createElement('meta')
      description.name = 'description'
      document.head.append(description)
    }

    description.content = copy.meta.description
  }, [copy.meta.description, copy.meta.title, locale])

  const value = useMemo(
    () => ({
      locale,
      copy,
      localeHref: (target: Locale) =>
        publicPath(localeMetadata[target].path),
      rememberLocale: (target: Locale) => {
        try {
          window.localStorage.setItem(STORAGE_KEY, target)
        } catch {
          // Navigation remains functional when storage is unavailable.
        }
      },
    }),
    [copy, locale],
  )

  return <LocaleContext value={value}>{children}</LocaleContext>
}
