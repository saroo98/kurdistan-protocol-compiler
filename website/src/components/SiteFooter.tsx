import { links } from '../content/siteContent'
import { useLocale } from '../i18n/LocaleContext'
import { publicPath } from '../lib/publicPath'
import { RouteWeave } from './RouteWeave'

export function SiteFooter() {
  const { copy } = useLocale()
  const currentYear = new Date().getUTCFullYear()

  return (
    <footer className="site-footer" aria-labelledby="site-footer-title">
      <RouteWeave
        variant="journey"
        routeStyle="quiet"
        className="is-static"
      />

      <div className="footer-layout page-shell">
        <div className="footer-mark" aria-hidden="true">
          <img
            src={publicPath('kurdistan-mark.svg')}
            alt=""
            width="68"
            height="68"
          />
        </div>

        <div className="footer-copy">
          <p className="section-kicker">{copy.status.currentPhase}</p>
          <h2 id="site-footer-title">{copy.footer.title}</h2>
          <p>{copy.footer.intro}</p>

          <div className="footer-actions">
            <a className="button button--primary" href="#status">
              {copy.hero.viewStatus}
              <svg
                className="directional-icon"
                viewBox="0 0 20 20"
                aria-hidden="true"
              >
                <path d="M4 10h11M11 5l5 5-5 5" />
              </svg>
            </a>

            <a
              className="button button--secondary"
              href={links.repository}
              target="_blank"
              rel="noopener noreferrer"
            >
              {copy.hero.github}
              <svg
                className="directional-icon"
                viewBox="0 0 20 20"
                aria-hidden="true"
              >
                <path d="M4 10h11M11 5l5 5-5 5" />
              </svg>
            </a>
          </div>
        </div>

        <p className="footer-dedication">
          <strong>{copy.footer.dedicationProduct}</strong>
          {copy.footer.dedicationBeforeCreator}
          <strong>{copy.footer.dedicationCreator}</strong>
          {copy.footer.dedicationBeforePlace}
          <a
            className="footer-dedication__place"
            href={copy.footer.dedicationPlaceHref}
            target="_blank"
            rel="noopener noreferrer"
          >
            <em>{copy.footer.dedicationPlace}</em>
          </a>
          {copy.footer.dedicationAfterPlace}
        </p>

        <div className="footer-meta">
          <span>{copy.footer.noAccount}</span>
          <a
            href={links.license}
            target="_blank"
            rel="noopener noreferrer"
          >
            AGPL-3.0-or-later
          </a>
          <a href="#top">{copy.footer.backToTop}</a>
          <span>© {currentYear} Saro</span>
        </div>
      </div>
    </footer>
  )
}
