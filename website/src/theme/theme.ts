export type ThemePreference = 'system' | 'dark' | 'light'
export type ResolvedTheme = Exclude<ThemePreference, 'system'>

export const THEME_STORAGE_KEY = 'kurdistan-vpn-theme'

export function isThemePreference(
  value: unknown,
): value is ThemePreference {
  return value === 'system' || value === 'dark' || value === 'light'
}

export function readThemePreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    return isThemePreference(stored) ? stored : 'system'
  } catch {
    return 'system'
  }
}

export function resolveTheme(
  preference: ThemePreference,
  systemPrefersDark: boolean,
): ResolvedTheme {
  if (preference === 'system') {
    return systemPrefersDark ? 'dark' : 'light'
  }

  return preference
}

export function applyResolvedTheme(theme: ResolvedTheme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme

  const themeColor =
    document.querySelector<HTMLMetaElement>('#theme-color')

  if (themeColor) {
    themeColor.content = theme === 'dark' ? '#090a19' : '#f2eee5'
  }
}
