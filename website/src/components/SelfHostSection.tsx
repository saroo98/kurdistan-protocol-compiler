import { links } from '../content/siteContent'
import { useLocale } from '../i18n/LocaleContext'

function renderInlineCode(text: string) {
  return text.split(/(`[^`]+`)/g).map((segment, index) => {
    if (segment.startsWith('`') && segment.endsWith('`')) {
      return <code key={`${segment}-${index}`}>{segment.slice(1, -1)}</code>
    }

    return segment
  })
}

export function SelfHostSection() {
  const { copy } = useLocale()

  return (
    <section
      className="self-host-section"
      id="self-host"
      aria-labelledby="self-host-title"
    >
      <div className="self-host-layout page-shell">
        <div className="self-host-copy">
          <p className="section-kicker">{copy.selfHost.kicker}</p>
          <h2 id="self-host-title">{copy.selfHost.title}</h2>
          <p>{copy.selfHost.intro}</p>

          <ol
            className="operator-flow"
            aria-label={copy.selfHost.responsibilitiesLabel}
          >
            {copy.selfHost.facts.map(([title], index) => (
              <li key={title}>
                <span>{String(index + 1).padStart(2, '0')}</span>
                <strong>{title}</strong>
              </li>
            ))}
          </ol>
        </div>

        <details className="operator-disclosure">
          <summary>
            <span className="operator-disclosure__closed">
              {copy.selfHost.showDetails}
            </span>
            <span className="operator-disclosure__open">
              {copy.selfHost.hideDetails}
            </span>
            <svg
              className="directional-icon directional-icon--disclosure"
              viewBox="0 0 20 20"
              aria-hidden="true"
            >
              <path d="M4 10h11M11 5l5 5-5 5" />
            </svg>
          </summary>

          <div className="operator-details">
            <div
              className="operator-console"
              aria-label={copy.selfHost.workflowLabel}
            >
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
                  <p>{renderInlineCode(factCopy)}</p>
                </article>
              ))}
            </div>

            <a
              className="operator-guide"
              href={links.selfHosting}
              target="_blank"
              rel="noopener noreferrer"
            >
              {copy.selfHost.guide}
              <svg
                className="directional-icon"
                viewBox="0 0 20 20"
                aria-hidden="true"
              >
                <path d="M4 10h11M11 5l5 5-5 5" />
              </svg>
            </a>
          </div>
        </details>
      </div>
    </section>
  )
}
