import { links } from '../content/siteContent'
import { useLocale } from '../i18n/LocaleContext'
import { RouteWeave } from './RouteWeave'

export function SiteFooter() {
  const { copy } = useLocale()

  return (
    <footer className="site-footer">
      <RouteWeave variant="journey" routeStyle="quiet" className="is-static" />
      <div className="footer-layout page-shell">
        <div className="footer-mark" aria-hidden="true">
          <img src="/kurdistan-mark.svg" alt="" width="68" height="68" />
        </div>
        <div className="footer-copy">
          <h2>{copy.footer.title}</h2>
          <p>{copy.footer.intro}</p>
          <div className="footer-actions">
            <button type="button" className="button button--primary" disabled>
              <span>{copy.hero.download}</span>
              <small>{copy.hero.comingSoon}</small>
            </button>
            <a
              className="button button--secondary"
              href={links.repository}
              target="_blank"
              rel="noreferrer"
            >
              {copy.hero.github}
              <svg viewBox="0 0 20 20" aria-hidden="true">
                <path d="M4 10h11M11 5l5 5-5 5" />
              </svg>
            </a>
          </div>
        </div>
        <p className="footer-dedication">
          {copy.footer.dedicationBefore}
          <em>{copy.footer.dedicationPlace}</em>
          {copy.footer.dedicationAfter}
        </p>
        <div className="footer-meta">
          <span>{copy.footer.noAccount}</span>
          <a href={links.license} target="_blank" rel="noreferrer">
            AGPL-3.0-or-later
          </a>
          <span>© 2026 Saro</span>
        </div>
      </div>
    </footer>
  )
}
