import { useSyncExternalStore } from 'react'

const query = '(prefers-reduced-motion: reduce)'

function subscribe(callback: () => void) {
  if (typeof window === 'undefined' || !window.matchMedia) {
    return () => undefined
  }

  const media = window.matchMedia(query)
  media.addEventListener('change', callback)
  return () => media.removeEventListener('change', callback)
}

function getSnapshot() {
  return typeof window !== 'undefined' && window.matchMedia
    ? window.matchMedia(query).matches
    : false
}

export function useReducedMotion() {
  return useSyncExternalStore(subscribe, getSnapshot, () => false)
}
