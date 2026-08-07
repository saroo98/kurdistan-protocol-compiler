import { links } from '../content/siteContent'
import { useLocale } from '../i18n/LocaleContext'

export function SelfHostSection() {
  const { copy } = useLocale()

  return (
    <section className="self-host-section" id="self-host" aria-labelledby="self-host-title">
      <div className="self-host-layout page-shell">
        <div className="self-host-copy">
          <h2 id="self-host-title">{copy.selfHost.title}</h2>
          <p>{copy.selfHost.intro}</p>
          <a href={links.selfHosting} target="_blank" rel="noreferrer">
            {copy.selfHost.guide}
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M4 10h11M11 5l5 5-5 5" />
            </svg>
          </a>
        </div>

        <div className="operator-console" aria-label={copy.selfHost.workflowLabel}>
          <div className="operator-console__bar">
            <span />
            <span />
            <span />
            <strong>{copy.selfHost.consoleTitle}</strong>
          </div>
          <code>
            <span>$</span> kurdctl init --name owner-node
          </code>
          <code>
            <span>$</span> kurdctl profile create --name phone
          </code>
          <code>
            <span>$</span> kurdctl doctor
          </code>
          <div className="operator-console__result">
            {copy.selfHost.consoleLabels.map(([label, value]) => (
              <div className="operator-console__result-row" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="self-host-facts">
          {copy.selfHost.facts.map(([title, factCopy]) => (
            <article key={title}>
              <h3>{title}</h3>
              <p>{factCopy}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
