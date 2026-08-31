import { useRef, useState, type KeyboardEvent } from 'react'
import { useLocale } from '../i18n/LocaleContext'
import { RouteWeave } from './RouteWeave'

export type ProfileDecision = 'pending' | 'confirmed' | 'dismissed'

export function ProfileDemo() {
  const { copy } = useLocale()
  const profiles = copy.profile.profiles
  const [selectedProfileId, setSelectedProfileId] = useState(profiles[0].id)
  const [decision, setDecision] = useState<ProfileDecision>('pending')
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([])
  const selectedProfile =
    profiles.find((profile) => profile.id === selectedProfileId) ?? profiles[0]

  const selectProfile = (index: number, focus = false) => {
    const normalizedIndex = (index + profiles.length) % profiles.length
    setSelectedProfileId(profiles[normalizedIndex].id)
    setDecision('pending')

    if (focus) {
      tabRefs.current[normalizedIndex]?.focus()
    }
  }

  const handleTabKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    let nextIndex: number | undefined

    switch (event.key) {
      case 'ArrowDown':
        nextIndex = index + 1
        break
      case 'ArrowUp':
        nextIndex = index - 1
        break
      case 'Home':
        nextIndex = 0
        break
      case 'End':
        nextIndex = profiles.length - 1
        break
      default:
        return
    }

    event.preventDefault()
    selectProfile(nextIndex, true)
  }

  const statusMessage =
    decision === 'confirmed'
      ? copy.profile.trustedFeedback(selectedProfile.name)
      : decision === 'dismissed'
        ? copy.profile.dismissedFeedback
        : ''

  return (
    <section
      className="profile-section"
      id="profile-demo"
      aria-labelledby="profile-title"
    >
      <RouteWeave
        variant="profile"
        routeStyle={selectedProfile.routeStyle}
        className="profile-route-transition"
      />
      <div className="profile-layout page-shell">
        <div className="profile-copy">
          <h2 id="profile-title">{copy.profile.title}</h2>
          <p>{copy.profile.intro}</p>
          <span className="synthetic-label">{copy.profile.synthetic}</span>
          <div
            className="profile-tabs"
            role="tablist"
            aria-label={copy.profile.tabsLabel}
            aria-orientation="vertical"
          >
            {profiles.map((profile, index) => {
              const isSelected = profile.id === selectedProfile.id
              const stateLabel =
                profile.state === 'verified'
                  ? copy.profile.verified
                  : copy.profile.needsReview

              return (
                <button
                  key={profile.id}
                  ref={(node) => {
                    tabRefs.current[index] = node
                  }}
                  id={`profile-tab-${profile.id}`}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  aria-controls={`profile-panel-${profile.id}`}
                  tabIndex={isSelected ? 0 : -1}
                  onClick={() => selectProfile(index)}
                  onKeyDown={(event) => handleTabKeyDown(event, index)}
                >
                  <span>{profile.name}</span>
                  <small>{stateLabel}</small>
                </button>
              )
            })}
          </div>
        </div>

        <div
          id={`profile-panel-${selectedProfile.id}`}
          className={`profile-ticket profile-ticket--${selectedProfile.state} profile-ticket--${decision}`}
          role="tabpanel"
          aria-labelledby={`profile-tab-${selectedProfile.id}`}
          tabIndex={0}
          data-decision={decision}
          data-route-style={selectedProfile.routeStyle}
        >
          <div className="profile-ticket__content">
            <span
              key={selectedProfile.id}
              className="profile-ticket__route-sweep"
              aria-hidden="true"
            />
            <div className="profile-ticket__header">
              <div>
                <span>
                  {decision === 'confirmed'
                    ? copy.profile.reviewedLabel
                    : decision === 'dismissed'
                      ? copy.profile.deferredReviewLabel
                      : copy.profile.reviewLabel}
                </span>
                <strong>{selectedProfile.name}</strong>
              </div>
              <span className="profile-state">
                {decision === 'confirmed'
                  ? copy.profile.trustedState
                  : decision === 'dismissed'
                    ? copy.profile.deferredState
                    : selectedProfile.trustLabel}
              </span>
            </div>
            <dl>
              <div>
                <dt>{copy.profile.deploymentOwner}</dt>
                <dd>{selectedProfile.owner}</dd>
              </div>
              <div>
                <dt>{copy.profile.fingerprint}</dt>
                <dd>
                  <code>{selectedProfile.fingerprint}</code>
                </dd>
              </div>
              <div>
                <dt>{copy.profile.validity}</dt>
                <dd>{selectedProfile.expires}</dd>
              </div>
            </dl>
            <p>{selectedProfile.description}</p>
            {decision === 'pending' && (
              <div className="profile-ticket__decision">
                <button type="button" onClick={() => setDecision('confirmed')}>
                  {copy.profile.confirm}
                </button>
                <button type="button" onClick={() => setDecision('dismissed')}>
                  {copy.profile.notNow}
                </button>
              </div>
            )}
          </div>

          <div
            className="profile-ticket__feedback-shell"
            data-open={decision !== 'pending'}
          >
            <div>
              {decision !== 'pending' && (
                <div
                  className={`profile-ticket__feedback profile-ticket__feedback--${decision}`}
                  data-decision={decision}
                >
                  <svg className="decision-mark" viewBox="0 0 20 20" aria-hidden="true">
                    <path
                      d={decision === 'confirmed' ? 'M4 10.5 8 14l8-9' : 'M5 10h10'}
                    />
                  </svg>
                  <p aria-hidden="true">{statusMessage}</p>
                  <button type="button" onClick={() => setDecision('pending')}>
                    {copy.profile.reset}
                  </button>
                </div>
              )}
            </div>
          </div>

          <p
            className="profile-ticket__announcement"
            role="status"
            aria-live="polite"
            aria-atomic="true"
          >
            {statusMessage}
          </p>
          <small className="profile-ticket__disclaimer">
            {copy.profile.disclaimer}
          </small>
        </div>
      </div>
    </section>
  )
}
