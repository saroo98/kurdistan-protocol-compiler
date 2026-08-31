import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useMediaQuery } from '../hooks/useMediaQuery'
import { ThemeContext } from './ThemeContext'
import {
  applyResolvedTheme,
  readThemePreference,
  resolveTheme,
  THEME_STORAGE_KEY,
  type ThemePreference,
} from './theme'

export function ThemeProvider({ children }: { children: ReactNode }) {
  const systemPrefersDark = useMediaQuery('(prefers-color-scheme: dark)')
  const [preference, setPreference] =
    useState<ThemePreference>(readThemePreference)

  const resolvedTheme = resolveTheme(preference, systemPrefersDark)

  useEffect(() => {
    applyResolvedTheme(resolvedTheme)
  }, [resolvedTheme])

  useEffect(() => {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, preference)
    } catch {
      // The in-memory theme remains usable when storage is unavailable.
    }
  }, [preference])

  const value = useMemo(
    () => ({ preference, resolvedTheme, setPreference }),
    [preference, resolvedTheme],
  )

  return <ThemeContext value={value}>{children}</ThemeContext>
}
