import { useSyncExternalStore } from 'react'

export function useMediaQuery(query: string, serverValue = false) {
  const subscribe = (callback: () => void) => {
    if (typeof window === 'undefined' || !window.matchMedia) {
      return () => undefined
    }

    const media = window.matchMedia(query)
    media.addEventListener('change', callback)

    return () => media.removeEventListener('change', callback)
  }

  const getSnapshot = () =>
    typeof window !== 'undefined' && window.matchMedia
      ? window.matchMedia(query).matches
      : serverValue

  return useSyncExternalStore(subscribe, getSnapshot, () => serverValue)
}
