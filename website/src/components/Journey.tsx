import { useLocale } from '../i18n/LocaleContext'
import { RouteWeave } from './RouteWeave'

export function Journey() {
  const { copy } = useLocale()

  return (
    <section
      className="journey-section page-shell"
      id="how-it-works"
      aria-labelledby="journey-title"
    >
      <div className="section-intro section-intro--wide">
        <p className="section-kicker">{copy.hero.trustRouteLabel}</p>
        <h2 id="journey-title">{copy.journey.title}</h2>
        <p>{copy.journey.intro}</p>
      </div>

      <div className="journey-composition">
        <div className="journey-track-wrap">
          <RouteWeave variant="journey" />

          <ol className="journey-track">
            {copy.journey.steps.map((step, index) => (
              <li className="journey-step" key={step.title}>
                <div className="journey-knot" aria-hidden="true">
                  <span>{index + 1}</span>
                </div>
                <h3>{step.title}</h3>
                <p>{step.copy}</p>
              </li>
            ))}
          </ol>
        </div>

        <aside
          className="trust-contract"
          aria-label={copy.journey.contractTitle}
        >
          <h3>{copy.journey.contractTitle}</h3>

          <dl>
            {copy.journey.contractItems.map((item) => (
              <div key={item.label}>
                <dt>{item.label}</dt>
                <dd>{item.value}</dd>
              </div>
            ))}
          </dl>
        </aside>
      </div>
    </section>
  )
}
