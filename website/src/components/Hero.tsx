import heroTexture from '../assets/routeweave-hero.webp'
import heroTextureMobile from '../assets/routeweave-hero-mobile.webp'
import { links } from '../content/siteContent'
import { useLocale } from '../i18n/LocaleContext'

function ArrowIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M4 10h11M11 5l5 5-5 5" />
    </svg>
  )
}

export function Hero() {
  const { copy } = useLocale()

  return (
    <section className="hero-section" id="top" aria-labelledby="hero-title">
      <picture>
        <source media="(max-width: 560px)" srcSet={heroTextureMobile} />
        <img
          className="hero-texture"
          src={heroTexture}
          width="1536"
          height="1024"
          alt=""
          decoding="async"
          fetchPriority="high"
        />
      </picture>

      <div className="hero-layout page-shell">
        <div className="hero-copy">
          <h1 id="hero-title">{copy.hero.title}</h1>
          <p className="hero-lede">{copy.hero.lede}</p>
          <div className="hero-actions">
            <button type="button" className="button button--primary" disabled>
              <span>{copy.hero.download}</span>
              <small>{copy.hero.comingSoon}</small>
            </button>
            <a className="text-link text-link--emphasis" href="#how-it-works">
              {copy.hero.howItWorks}
              <ArrowIcon />
            </a>
            <a
              className="text-link"
              href={links.repository}
              target="_blank"
              rel="noreferrer"
            >
              {copy.hero.github}
              <ArrowIcon />
            </a>
          </div>
          <p className="hero-boundary">{copy.hero.boundary}</p>
        </div>

        <div className="device-stage" aria-label="Illustrative Android app preview">
          <div className="android-device">
            <div className="device-speaker" aria-hidden="true" />
            <div className="device-screen" lang="en" dir="ltr">
              <div className="device-topline">
                <img src="/kurdistan-mark.svg" alt="" width="30" height="30" />
                <span>Kurdistan VPN</span>
                <i aria-hidden="true" />
              </div>
              <div className="device-orbit" aria-hidden="true">
                <span className="orbit orbit--one" />
                <span className="orbit orbit--two" />
                <span className="orbit orbit--three" />
                <div className="device-core">K</div>
              </div>
              <div className="device-state">
                <span>Profile verified</span>
                <strong>City Thread</strong>
                <code>7A31 · D9C4</code>
              </div>
              <div className="device-action" aria-hidden="true">
                <span />
                Android release coming soon
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
