import { createContext, useContext } from 'react'
import type { Locale, SiteCopy } from './translations'

export type LocaleContextValue = {
  locale: Locale
  copy: SiteCopy
  localeHref: (target: Locale) => string
  rememberLocale: (target: Locale) => void
}

export const LocaleContext = createContext<LocaleContextValue | null>(null)

export function useLocale() {
  const context = useContext(LocaleContext)

  if (!context) {
    throw new Error('useLocale must be used within LocaleProvider')
  }

  return context
}
