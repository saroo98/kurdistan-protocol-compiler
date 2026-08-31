import { Hero } from './components/Hero'
import { Journey } from './components/Journey'
import { PrivacySection } from './components/PrivacySection'
import { ProfileDemo } from './components/ProfileDemo'
import { SelfHostSection } from './components/SelfHostSection'
import { SiteFooter } from './components/SiteFooter'
import { SiteHeader } from './components/SiteHeader'
import { StatusSection } from './components/StatusSection'
import { useLocale } from './i18n/LocaleContext'
import { LocaleProvider } from './i18n/LocaleProvider'
import { ThemeProvider } from './theme/ThemeProvider'

function AppContent() {
  const { copy } = useLocale()

  return (
    <div className="site-frame">
      <a className="skip-link" href="#main-content">
        {copy.skipToContent}
      </a>
      <SiteHeader />
      <main id="main-content" tabIndex={-1}>
        <Hero />
        <Journey />
        <ProfileDemo />
        <PrivacySection />
        <SelfHostSection />
        <StatusSection />
      </main>
      <SiteFooter />
    </div>
  )
}

function App() {
  return (
    <LocaleProvider>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
    </LocaleProvider>
  )
}

export default App
