import { useLocale } from '../i18n/LocaleContext'

export function PrivacySection() {
  const { copy } = useLocale()

  return (
    <section className="privacy-section page-shell" id="privacy" aria-labelledby="privacy-title">
      <div className="privacy-statement">
        <h2 id="privacy-title">{copy.privacy.title}</h2>
        <p>{copy.privacy.intro}</p>
      </div>

      <div className="privacy-ledger">
        {copy.privacy.facts.map(([title, factCopy]) => (
          <article key={title}>
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M5 12.5l4.1 4L19 6.8" />
            </svg>
            <div>
              <h3>{title}</h3>
              <p>{factCopy}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}
