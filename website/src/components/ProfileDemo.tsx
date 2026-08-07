import { useState } from 'react'
import { useLocale } from '../i18n/LocaleContext'
import { RouteWeave } from './RouteWeave'

export function ProfileDemo() {
  const { copy } = useLocale()
  const profiles = copy.profile.profiles
  const [selectedProfileId, setSelectedProfileId] = useState(profiles[0].id)
  const [decision, setDecision] = useState<'pending' | 'confirmed' | 'dismissed'>('pending')
  const selectedProfile =
    profiles.find((profile) => profile.id === selectedProfileId) ?? profiles[0]
  const selectedProfileIndex = Math.max(
    profiles.findIndex((profile) => profile.id === selectedProfile.id),
    0,
  )

  return (
    <section className="profile-section" aria-labelledby="profile-title">
      <RouteWeave
        key={selectedProfile.id}
        variant="profile"
        routeStyle={selectedProfile.routeStyle}
        className="is-static profile-route-transition"
      />
      <div className="profile-layout page-shell">
        <div className="profile-copy">
          <h2 id="profile-title">{copy.profile.title}</h2>
          <p>{copy.profile.intro}</p>
          <span className="synthetic-label">{copy.profile.synthetic}</span>
          <div
            className="profile-tabs"
            aria-label={copy.profile.tabsLabel}
          >
            <span
              className="profile-active-marker"
              data-profile-index={selectedProfileIndex}
              aria-hidden="true"
              style={{ top: `${26.5 + selectedProfileIndex * 66}px` }}
            />
            {profiles.map((profile) => (
              <button
                key={profile.id}
                type="button"
                aria-pressed={profile.id === selectedProfile.id}
                aria-label={copy.profile.selectLabel(profile.name)}
                onClick={() => {
                  setSelectedProfileId(profile.id)
                  setDecision('pending')
                }}
              >
                <span>{profile.name}</span>
                <small>
                  {profile.state === 'verified'
                    ? copy.profile.verified
                    : copy.profile.needsReview}
                </small>
              </button>
            ))}
          </div>
        </div>

        <div
          className={`profile-ticket profile-ticket--${selectedProfile.state}`}
          aria-live="polite"
          aria-label={copy.profile.detailsLabel}
          data-decision={decision}
          data-route-style={selectedProfile.routeStyle}
        >
          <div className="profile-ticket__content" key={selectedProfile.id}>
            <span className="profile-ticket__route-sweep" aria-hidden="true" />
            <div className="profile-ticket__header">
              <div>
                <span>{copy.profile.reviewLabel}</span>
                <strong>{selectedProfile.name}</strong>
              </div>
              <span className="profile-state">{selectedProfile.trustLabel}</span>
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
            <div className="profile-ticket__decision">
              <button type="button" onClick={() => setDecision('confirmed')}>
                {copy.profile.confirm}
              </button>
              <button type="button" onClick={() => setDecision('dismissed')}>
                {copy.profile.notNow}
              </button>
            </div>
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
                  <p role="status">
                    {decision === 'confirmed'
                      ? copy.profile.trustedFeedback(selectedProfile.name)
                      : copy.profile.dismissedFeedback}
                  </p>
                  <button type="button" onClick={() => setDecision('pending')}>
                    {copy.profile.reset}
                  </button>
                </div>
              )}
            </div>
          </div>
          <small>{copy.profile.disclaimer}</small>
        </div>
      </div>
    </section>
  )
}
