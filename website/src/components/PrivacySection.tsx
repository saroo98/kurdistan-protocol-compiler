import { useLocale } from '../i18n/LocaleContext'

export function PrivacySection() {
  const { copy } = useLocale()

  return (
    <section
      className="privacy-section page-shell"
      id="privacy"
      aria-labelledby="privacy-title"
    >
      <div className="privacy-statement">
        <p className="section-kicker">{copy.privacy.kicker}</p>
        <h2 id="privacy-title">{copy.privacy.title}</h2>
        <p>{copy.privacy.intro}</p>
        <p className="privacy-caveat">{copy.privacy.caveat}</p>
      </div>

      <ul
        className="privacy-ledger"
        aria-label={`${copy.privacy.title} decentralization boundaries`}
      >
        {copy.privacy.facts.map(([title, factCopy], index) => (
          <li key={title}>
            <span className="privacy-ledger__number">
              {String(index + 1).padStart(2, '0')}
            </span>
            <div>
              <h3>{title}</h3>
              <p>{factCopy}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
