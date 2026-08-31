import { useEffect, useState } from 'react'

export type NavSectionId =
  | 'how-it-works'
  | 'privacy'
  | 'self-host'
  | 'status'

export function useActiveSection(
  sectionIds: readonly NavSectionId[],
): NavSectionId | null {
  const [activeSection, setActiveSection] = useState<NavSectionId | null>(
    null,
  )

  useEffect(() => {
    const sections = sectionIds
      .map((id) => document.getElementById(id))
      .filter((section): section is HTMLElement => Boolean(section))

    if (!sections.length || !('IntersectionObserver' in window)) {
      return undefined
    }

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort(
            (left, right) =>
              Math.abs(left.boundingClientRect.top) -
              Math.abs(right.boundingClientRect.top),
          )[0]

        if (
          visible &&
          sectionIds.includes(visible.target.id as NavSectionId)
        ) {
          setActiveSection(visible.target.id as NavSectionId)
        }
      },
      {
        rootMargin: '-35% 0px -55% 0px',
        threshold: [0, 0.1, 0.5],
      },
    )

    sections.forEach((section) => observer.observe(section))

    return () => observer.disconnect()
  }, [sectionIds])

  return activeSection
}
