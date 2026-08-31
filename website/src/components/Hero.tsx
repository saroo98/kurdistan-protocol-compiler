import hero960Avif from '../assets/hero/routeweave-960.avif'
import hero1280Avif from '../assets/hero/routeweave-1280.avif'
import hero1536Avif from '../assets/hero/routeweave-1536.avif'
import hero960Webp from '../assets/hero/routeweave-960.webp'
import hero1280Webp from '../assets/hero/routeweave-1280.webp'
import hero1536Webp from '../assets/hero/routeweave-1536.webp'
import heroMobile480Avif from '../assets/hero/routeweave-mobile-480.avif'
import heroMobile640Avif from '../assets/hero/routeweave-mobile-640.avif'
import heroMobile480Webp from '../assets/hero/routeweave-mobile-480.webp'
import heroMobile640Webp from '../assets/hero/routeweave-mobile-640.webp'
import { useLocale } from '../i18n/LocaleContext'
import { DevicePreview } from './DevicePreview'
import { HeroTrustRoute } from './HeroTrustRoute'

function ArrowIcon() {
  return (
    <svg className="directional-icon" viewBox="0 0 20 20" aria-hidden="true">
      <path d="M4 10h11M11 5l5 5-5 5" />
    </svg>
  )
}

export function Hero() {
  const { copy } = useLocale()

  return (
    <section
      className="hero-section"
      id="top"
      aria-labelledby="hero-title"
    >
      <picture>
        <source
          media="(max-width: 560px)"
          type="image/avif"
          srcSet={`${heroMobile480Avif} 480w, ${heroMobile640Avif} 640w`}
          sizes="100vw"
        />
        <source
          media="(max-width: 560px)"
          type="image/webp"
          srcSet={`${heroMobile480Webp} 480w, ${heroMobile640Webp} 640w`}
          sizes="100vw"
        />
        <source
          type="image/avif"
          srcSet={`${hero960Avif} 960w, ${hero1280Avif} 1280w, ${hero1536Avif} 1536w`}
          sizes="(max-width: 900px) 100vw, 62vw"
        />
        <source
          type="image/webp"
          srcSet={`${hero960Webp} 960w, ${hero1280Webp} 1280w, ${hero1536Webp} 1536w`}
          sizes="(max-width: 900px) 100vw, 62vw"
        />
        <img
          className="hero-texture"
          src={hero1280Webp}
          width="1280"
          height="853"
          alt=""
          decoding="async"
          fetchPriority="high"
        />
      </picture>

      <div className="hero-layout page-shell">
        <div className="hero-copy">
          <div className="hero-eyebrow-row">
            <p className="section-kicker">{copy.hero.eyebrow}</p>
            <span className="release-phase">
              <i aria-hidden="true" />
              {copy.hero.phase}
            </span>
          </div>

          <h1 id="hero-title">{copy.hero.title}</h1>
          <p className="hero-lede">{copy.hero.lede}</p>

          <div className="hero-actions">
            <a className="button button--primary" href="#profile-demo">
              {copy.hero.primaryCta}
              <ArrowIcon />
            </a>

            <a className="button button--secondary" href="#status">
              {copy.hero.viewStatus}
              <ArrowIcon />
            </a>
          </div>

          <p className="hero-boundary">{copy.hero.boundary}</p>

          <HeroTrustRoute
            label={copy.hero.trustRouteLabel}
            steps={copy.hero.trustRouteSteps}
          />
        </div>

        <DevicePreview label={copy.hero.devicePreviewLabel} />
      </div>
    </section>
  )
}
