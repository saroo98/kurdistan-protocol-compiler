import { useLocale } from '../i18n/LocaleContext'
import { RouteWeave } from './RouteWeave'

export function Journey() {
  const { copy } = useLocale()

  return (
    <section className="journey-section page-shell" id="how-it-works" aria-labelledby="journey-title">
      <div className="section-intro section-intro--wide">
        <h2 id="journey-title">{copy.journey.title}</h2>
        <p>{copy.journey.intro}</p>
      </div>

      <div className="journey-track">
        <RouteWeave variant="journey" />
        {copy.journey.steps.map((step, index) => (
          <article className="journey-step" key={step.title}>
            <div className="journey-knot" aria-hidden="true">
              <span>{index + 1}</span>
            </div>
            <h3>{step.title}</h3>
            <p>{step.copy}</p>
          </article>
        ))}
      </div>
    </section>
  )
}
