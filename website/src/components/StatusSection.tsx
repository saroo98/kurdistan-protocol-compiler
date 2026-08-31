import {
  RELEASE_REVIEW_DATE,
  releaseMilestones,
} from '../content/releaseStatus'
import { useLocale } from '../i18n/LocaleContext'

export function StatusSection() {
  const { copy } = useLocale()

  return (
    <section
      className="status-section page-shell"
      id="status"
      aria-labelledby="status-title"
    >
      <div className="status-heading">
        <div>
          <p className="section-kicker">{copy.status.kicker}</p>
          <h2 id="status-title">{copy.status.title}</h2>
        </div>

        <div className="status-summary">
          <p>{copy.status.intro}</p>

          <dl>
            <div>
              <dt>{copy.status.currentPhaseLabel}</dt>
              <dd>{copy.status.currentPhase}</dd>
            </div>
            <div>
              <dt>{copy.status.reviewedLabel}</dt>
              <dd>
                <time dateTime={RELEASE_REVIEW_DATE}>
                  {RELEASE_REVIEW_DATE}
                </time>
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <ol className="release-status-list" aria-label={copy.status.readinessLabel}>
        {releaseMilestones.map((milestone, index) => {
          const milestoneCopy = copy.status.milestones[milestone.id]

          return (
            <li key={milestone.id} data-state={milestone.state}>
              <div className="release-status-list__marker">
                <span>{String(index + 1).padStart(2, '0')}</span>
              </div>

              <div className="release-status-list__content">
                <p className="release-status-list__state">
                  {copy.status.stateLabels[milestone.state]}
                </p>
                <h3>{milestoneCopy.title}</h3>
                <p>{milestoneCopy.summary}</p>

                <details className="release-status-list__details">
                  <summary>
                    <span className="release-status-list__details-closed">
                      {copy.status.showMilestoneDetails}
                    </span>
                    <span className="release-status-list__details-open">
                      {copy.status.hideMilestoneDetails}
                    </span>
                    <svg
                      className="directional-icon directional-icon--disclosure"
                      viewBox="0 0 20 20"
                      aria-hidden="true"
                    >
                      <path d="M4 10h11M11 5l5 5-5 5" />
                    </svg>
                  </summary>

                  <ul>
                    {milestone.itemIds.map((itemId) => (
                      <li key={itemId}>{copy.status.items[itemId]}</li>
                    ))}
                  </ul>
                </details>
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
