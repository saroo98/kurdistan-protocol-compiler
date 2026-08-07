import { Hero } from './components/Hero'
import { Journey } from './components/Journey'
import { PrivacySection } from './components/PrivacySection'
import { ProfileDemo } from './components/ProfileDemo'
import { SelfHostSection } from './components/SelfHostSection'
import { SiteFooter } from './components/SiteFooter'
import { SiteHeader } from './components/SiteHeader'
import { StatusSection } from './components/StatusSection'
import { LocaleProvider } from './i18n/LocaleProvider'

function AppContent() {
  return (
    <div className="site-frame">
      <SiteHeader />
      <main>
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
      <AppContent />
    </LocaleProvider>
  )
}

export default App
