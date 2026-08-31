import { localeMetadata } from './generatedMetadata'
import type {
  ReleaseItemId,
  ReleaseMilestoneId,
  ReleaseState,
} from '../content/releaseStatus'

export type Locale = 'en' | 'ckb' | 'kmr'

export type LocalizedProfile = {
  id: 'city-thread' | 'mountain-route' | 'quiet-current'
  name: string
  owner: string
  fingerprint: string
  expires: string
  routeStyle: 'woven' | 'split' | 'quiet'
  state: 'verified' | 'expiring'
  trustLabel: string
  description: string
}

export type SiteCopy = {
  skipToContent: string
  meta: {
    title: string
    description: string
  }
  language: {
    change: string
    options: string
    english: string
    sorani: string
    kurmanji: string
    englishShort: string
    soraniShort: string
    kurmanjiShort: string
  }
  preferences: {
    open: string
    close: string
    panel: string
    language: string
    appearance: string
    system: string
    dark: string
    light: string
  }
  header: {
    home: string
    primaryNavigation: string
    openMenu: string
    closeMenu: string
    navigation: readonly { label: string; href: string }[]
    androidSoon: string
  }
  hero: {
    eyebrow: string
    phase: string
    title: string
    lede: string
    primaryCta: string
    viewStatus: string
    github: string
    boundary: string
    devicePreviewLabel: string
    trustRouteLabel: string
    trustRouteSteps: readonly {
      title: string
      copy: string
    }[]
  }
  journey: {
    title: string
    intro: string
    contractTitle: string
    contractItems: readonly {
      label: string
      value: string
    }[]
    steps: readonly { title: string; copy: string }[]
  }
  profile: {
    title: string
    intro: string
    synthetic: string
    tabsLabel: string
    verified: string
    needsReview: string
    trustedState: string
    deferredState: string
    detailsLabel: string
    reviewLabel: string
    reviewedLabel: string
    deferredReviewLabel: string
    deploymentOwner: string
    fingerprint: string
    validity: string
    confirm: string
    notNow: string
    trustedFeedback: (name: string) => string
    dismissedFeedback: string
    reset: string
    disclaimer: string
    profiles: readonly LocalizedProfile[]
  }
  privacy: {
    kicker: string
    title: string
    intro: string
    caveat: string
    facts: readonly (readonly [string, string])[]
  }
  selfHost: {
    kicker: string
    responsibilitiesLabel: string
    title: string
    intro: string
    guide: string
    showDetails: string
    hideDetails: string
    workflowLabel: string
    consoleTitle: string
    consoleLabels: readonly (readonly [string, string])[]
    facts: readonly (readonly [string, string])[]
  }
  status: {
    kicker: string
    title: string
    intro: string
    currentPhaseLabel: string
    currentPhase: string
    reviewedLabel: string
    readinessLabel: string
    showMilestoneDetails: string
    hideMilestoneDetails: string
    stateLabels: Record<ReleaseState, string>
    milestones: Record<
      ReleaseMilestoneId,
      {
        title: string
        summary: string
      }
    >
    items: Record<ReleaseItemId, string>
  }
  footer: {
    title: string
    intro: string
    dedicationBefore: string
    dedicationPlace: string
    dedicationAfter: string
    noAccount: string
    backToTop: string
  }
}

const english: SiteCopy = {
  skipToContent: 'Skip to main content',
  meta: localeMetadata.en,
  language: {
    change: 'Change language',
    options: 'Language options',
    english: 'English',
    sorani: 'کوردی (سۆرانی)',
    kurmanji: 'Kurdî (Kurmancî)',
    englishShort: 'EN',
    soraniShort: 'کوردی',
    kurmanjiShort: 'KMR',
  },
  preferences: {
    open: 'Open preferences',
    close: 'Close preferences',
    panel: 'Language and appearance',
    language: 'Language',
    appearance: 'Appearance',
    system: 'System',
    dark: 'Dark',
    light: 'Light',
  },
  header: {
    home: 'Kurdistan VPN home',
    primaryNavigation: 'Primary navigation',
    openMenu: 'Open navigation menu',
    closeMenu: 'Close navigation menu',
    navigation: [
      { label: 'How it works', href: '#how-it-works' },
      { label: 'Privacy', href: '#privacy' },
      { label: 'Self-host', href: '#self-host' },
      { label: 'Status', href: '#status' },
    ],
    androidSoon: 'Android · soon',
  },
  hero: {
    eyebrow: 'A profile-driven VPN for Android',
    phase: 'Private test phase',
    title: 'Your internet. Your route.',
    lede:
      'Choose an independently operated deployment, verify its fingerprint, and connect only within the policy signed into its profile.',
    primaryCta: 'Try the trust demo',
    viewStatus: 'See release readiness',
    github: 'View on GitHub',
    boundary:
      'The Android foundation is implemented and under controlled testing. The app, public relay access, and general Internet egress are not released.',
    devicePreviewLabel: 'Illustrative Android app preview',
    trustRouteLabel: 'How a connection earns trust',
    trustRouteSteps: [
      {
        title: 'Signed profile',
        copy: 'Names the deployment and its policy.',
      },
      {
        title: 'Verified fingerprint',
        copy: 'Confirms the deployment you chose.',
      },
      {
        title: 'Bounded route',
        copy: 'Allows only signed transport choices.',
      },
    ],
  },
  journey: {
    title: 'Trust starts with a profile.',
    intro:
      'A Kurd profile identifies the deployment, shows a fingerprint for you to verify, and limits the routes the app may use.',
    contractTitle: 'What the profile binds',
    contractItems: [
      {
        label: 'Deployment identity',
        value: 'Which authority signed it',
      },
      {
        label: 'Fingerprint',
        value: 'What the user verifies',
      },
      {
        label: 'Signed policy',
        value: 'Which routes and fallbacks are allowed',
      },
      {
        label: 'Expiry',
        value: 'When trust must be reviewed',
      },
    ],
    steps: [
      {
        title: 'Receive a profile',
        copy: 'You receive a signed Kurd profile for a specific deployment.',
      },
      {
        title: 'Verify the deployment',
        copy: 'Check the fingerprint before adding the profile to your device.',
      },
      {
        title: 'Use its bounded route',
        copy: 'After release, the signed profile will limit the transport and fallback options the app may use.',
      },
    ],
  },
  profile: {
    title: 'Know which deployment you trust.',
    intro:
      'Before you trust a profile, review its deployment identity, fingerprint, expiry, and signed policy.',
    synthetic: 'Synthetic demonstration',
    tabsLabel: 'Synthetic profiles',
    verified: 'verified',
    needsReview: 'needs review',
    trustedState: 'Trusted for this demo',
    deferredState: 'Decision deferred',
    detailsLabel: 'Synthetic profile details',
    reviewLabel: 'Profile to review',
    reviewedLabel: 'Reviewed profile',
    deferredReviewLabel: 'Review deferred',
    deploymentOwner: 'Deployment authority',
    fingerprint: 'Fingerprint',
    validity: 'Validity',
    confirm: 'Confirm this deployment',
    notNow: 'Not now',
    trustedFeedback: (name) => `${name} marked as trusted for this demonstration.`,
    dismissedFeedback: 'No trust decision was saved.',
    reset: 'Reset decision',
    disclaimer: 'No real profile, endpoint, or credential is shown.',
    profiles: [
      {
        id: 'city-thread',
        name: 'City Thread',
        owner: 'Independent deployment A',
        fingerprint: 'KURD · 7A31 · D9C4 · DEMO',
        expires: 'Expires in 6 days',
        routeStyle: 'woven',
        state: 'verified',
        trustLabel: 'Fingerprint verified',
        description:
          'A balanced synthetic profile showing a signed owner boundary and bounded fallback.',
      },
      {
        id: 'mountain-route',
        name: 'Mountain Route',
        owner: 'Independent deployment B',
        fingerprint: 'KURD · B204 · 8E12 · DEMO',
        expires: 'Expires in 2 days',
        routeStyle: 'split',
        state: 'expiring',
        trustLabel: 'Review before trusting',
        description:
          'A synthetic profile near expiry. The app should make that state impossible to overlook.',
      },
      {
        id: 'quiet-current',
        name: 'Quiet Current',
        owner: 'Independent deployment C',
        fingerprint: 'KURD · 4F81 · A610 · DEMO',
        expires: 'Expires in 12 days',
        routeStyle: 'quiet',
        state: 'verified',
        trustLabel: 'Fingerprint verified',
        description: 'A restrained synthetic profile with no authority outside its signed policy.',
      },
    ],
  },
  privacy: {
    kicker: 'Architecture boundary',
    title: 'No central gatekeeper.',
    intro:
      'Each operator controls their own deployment. The app trusts the fingerprint you approve, without a central Kurdistan service in the middle.',
    caveat:
      'These boundaries reduce central product control. They do not guarantee anonymity, censorship resistance, or immunity from blocking.',
    facts: [
      [
        'No mandatory Kurdistan account',
        'Trust begins with the deployment fingerprint you confirm, not a central product login.',
      ],
      [
        'No central relay directory',
        'Independent operators control their own VPS, authority, profiles, backups, and data.',
      ],
      [
        'No required product analytics',
        'The architecture does not depend on advertising, remote crash reporting, or central traffic logs.',
      ],
      [
        'No global off switch',
        'One independent deployment cannot revoke or disable another deployment.',
      ],
    ],
  },
  selfHost: {
    kicker: 'Owner-operated',
    responsibilitiesLabel: 'Operator responsibilities',
    title: 'Run the other end yourself.',
    intro: 'Your authority, profiles, node, backups, and recovery stay under your control.',
    guide: 'Read the self-hosting guide',
    showDetails: 'Explore the operator setup',
    hideDetails: 'Hide operator details',
    workflowLabel: 'Illustrative self-hosting workflow',
    consoleTitle: 'deployment-local authority',
    consoleLabels: [
      ['authority', 'owner-controlled'],
      ['recovery', 'offline'],
      ['profile', 'signed'],
    ],
    facts: [
      [
        'Create local authority',
        '`kurdctl` initializes deployment-local identity and recovery material.',
      ],
      [
        'Issue signed profiles',
        'Create bounded profiles, QR artifacts, expiry, rotation, and revocation under your authority.',
      ],
      [
        'Run your own node',
        '`kurd-node` installs as a hardened, non-root service on an owner-controlled VPS.',
      ],
      [
        'Keep recovery offline',
        'Encrypted backups and recovery material stay outside the VPS and under the owner’s control.',
      ],
    ],
  },
  status: {
    kicker: 'Release readiness',
    title: 'What exists today.',
    intro:
      'The foundation is implemented and under controlled testing. Public Android distribution and public relay access remain separate release gates.',
    currentPhaseLabel: 'Current phase',
    currentPhase: 'Controlled testing',
    reviewedLabel: 'Status reviewed',
    readinessLabel: 'Release readiness',
    showMilestoneDetails: 'Show milestone details',
    hideMilestoneDetails: 'Hide milestone details',
    stateLabels: {
      implemented: 'Implemented',
      validating: 'Validating',
      unreleased: 'Not released',
    },
    milestones: {
      foundation: {
        title: 'Foundation',
        summary: 'Implemented and under controlled testing',
      },
      'field-validation': {
        title: 'Field validation',
        summary: 'Required before public release',
      },
      'public-release': {
        title: 'Public release',
        summary: 'Distribution and public access remain closed',
      },
    },
    items: {
      compiler:
        'Profile-driven protocol compiler and generated transport modules',
      profiles: 'Signed and recipient-sealed Kurd profile artifacts',
      'android-foundation':
        'Android profile import, fingerprint confirmation, and protected storage',
      'operator-control':
        'Deployment-local authority, backup, recovery, and node administration',
      'audit-foundation':
        'Adversarial, mutation, parity, runtime, and security audit foundations',
      'relay-egress':
        'Public non-loopback Kurd relay and unrestricted Internet egress',
      'android-release':
        'Public Android release artifact and distribution signing',
      'field-validation':
        'Broad physical-device and hosting-provider field validation',
    },
  },
  footer: {
    title: 'Follow the build.',
    intro:
      'The Android app is still in development. Until release, explore the source and implementation status on GitHub.',
    dedicationBefore:
      'Made with immense ❤️ by Saro Xizirnijad for the Kurdish people, with love and solidarity for all who have endured oppression, loss, and suffering under the Iranian government’s repression in ',
    dedicationPlace: 'Rojhelat',
    dedicationAfter: '. May their stories and courage never be forgotten.',
    noAccount: 'No mandatory account. No required analytics.',
    backToTop: 'Back to top',
  },
}

const sorani: SiteCopy = {
  skipToContent: 'بازدان بۆ ناوەڕۆکی سەرەکی',
  meta: localeMetadata.ckb,
  language: {
    change: 'گۆڕینی زمان',
    options: 'هەڵبژاردەکانی زمان',
    english: 'English',
    sorani: 'کوردی (سۆرانی)',
    kurmanji: 'Kurdî (Kurmancî)',
    englishShort: 'EN',
    soraniShort: 'کوردی',
    kurmanjiShort: 'KMR',
  },
  preferences: {
    open: 'کردنەوەی هەڵبژاردەکان',
    close: 'داخستنی هەڵبژاردەکان',
    panel: 'زمان و ڕووکار',
    language: 'زمان',
    appearance: 'ڕووکار',
    system: 'سیستەم',
    dark: 'تاریک',
    light: 'ڕوون',
  },
  header: {
    home: 'ماڵپەڕی سەرەکیی VPNی کوردستان',
    primaryNavigation: 'ڕێنیشاندەری سەرەکی',
    openMenu: 'کردنەوەی پێڕستی ڕێنیشاندان',
    closeMenu: 'داخستنی پێڕستی ڕێنیشاندان',
    navigation: [
      { label: 'چۆن کار دەکات', href: '#how-it-works' },
      { label: 'تایبەتی', href: '#privacy' },
      { label: 'خۆمیوانداری', href: '#self-host' },
      { label: 'دۆخ', href: '#status' },
    ],
    androidSoon: 'ئەندرۆید · بەزوویی',
  },
  hero: {
    eyebrow: 'VPNێکی ئەندرۆیدی بەڕێوەبراو بە پرۆفایل',
    phase: 'قۆناغی تاقیکردنەوەی تایبەت',
    title: 'ئینتەرنێتی تۆ. ڕێگای تۆ.',
    lede:
      'دامەزراندنێکی سەربەخۆ هەڵبژێرە، پەنجەمۆری دیجیتاڵی (fingerprint) ئەو دامەزراندنە پشتڕاست بکەرەوە، و تەنها لە سنووری سیاسەتی واژۆکراوی پرۆفایلەکەدا پەیوەندی بکە.',
    primaryCta: 'دیمۆی متمانە تاقی بکەرەوە',
    viewStatus: 'ئامادەیی بۆ بڵاوکردنەوە ببینە',
    github: 'لە GitHub ببینە',
    boundary:
      'بناغەی ئەندرۆید جێبەجێ کراوە و لە ژێر تاقیکردنەوەی کۆنترۆڵکراودایە. ئەپ، دەستگەیشتنی گشتی بە گرێی ناوبەینکار (relay) و دەرچوونی گشتی بۆ ئینتەرنێت بڵاونەکراونەتەوە.',
    devicePreviewLabel: 'پێشبینینی وێنەیی ئەپی ئەندرۆید',
    trustRouteLabel: 'پەیوەندییەک چۆن متمانە بەدەست دەهێنێت',
    trustRouteSteps: [
      {
        title: 'پرۆفایلی واژۆکراو',
        copy: 'دامەزراندنەکە و سیاسەتەکەی دیاری دەکات.',
      },
      {
        title: 'پەنجەمۆری پشتڕاستکراو',
        copy: 'دامەزراندنە هەڵبژێردراوەکە پشتڕاست دەکات.',
      },
      {
        title: 'ڕێگای سنووردار',
        copy: 'تەنها هەڵبژاردە واژۆکراوەکانی گواستنەوە ڕێگە پێدەدات.',
      },
    ],
  },
  journey: {
    title: 'متمانە بە پرۆفایلێک دەست پێ دەکات.',
    intro:
      'پرۆفایلێکی کورد ناسنامەی دامەزراندنەکە دیاری دەکات، پەنجەمۆری دیجیتاڵ (fingerprint) پیشان دەدات تا پشتڕاستی بکەیتەوە، و ڕێگاکانی بەردەست بۆ ئەپەکە سنووردار دەکات.',
    contractTitle: 'پرۆفایلەکە چی سنووردار دەکات',
    contractItems: [
      {
        label: 'ناسنامەی دامەزراندن',
        value: 'کام دەسەڵات واژۆی کردووە',
      },
      {
        label: 'پەنجەمۆر',
        value: 'بەکارهێنەر چی پشتڕاست دەکاتەوە',
      },
      {
        label: 'سیاسەتی واژۆکراو',
        value: 'کام ڕێگا و جێگرەوەیەک ڕێگەپێدراوە',
      },
      {
        label: 'بەسەرچوون',
        value: 'کەی متمانە پێویستی بە پێداچوونەوە هەیە',
      },
    ],
    steps: [
      {
        title: 'پرۆفایلێک وەربگرە',
        copy: 'پرۆفایلێکی واژۆکراوی کورد بۆ دامەزراندنێکی دیاریکراو وەردەگریت.',
      },
      {
        title: 'دامەزراندنەکە پشتڕاست بکەوە',
        copy: 'پێش زیادکردنی پرۆفایلەکە بۆ ئامێرەکەت، پەنجەمۆرەکە بپشکنە.',
      },
      {
        title: 'ڕێگای سنووردارکراوی بەکاربهێنە',
        copy: 'دوای بڵاوکردنەوە، پرۆفایلە واژۆکراوەکە گواستنەوە و ڕێگا جێگرەوەکان کە ئەپەکە دەتوانێت بەکاریان بهێنێت، سنووردار دەکات.',
      },
    ],
  },
  profile: {
    title: 'بزانە متمانە بە کام دامەزراندن دەکەیت.',
    intro:
      'پێش متمانەکردن بە پرۆفایلێک، ناسنامەی دامەزراندن، پەنجەمۆر، بەسەرچوون و سیاسەتی واژۆکراوی بپشکنە.',
    synthetic: 'پیشاندانی نموونەیی',
    tabsLabel: 'پرۆفایلە تاقیکردنەوەییەکان',
    verified: 'پشتڕاستکراو',
    needsReview: 'پێویستی بە پشکنینەوە هەیە',
    trustedState: 'بۆ ئەم پیشاندانە متمانەپێکراوە',
    deferredState: 'بڕیارەکە دواخرا',
    detailsLabel: 'وردەکاریی پرۆفایلی تاقیکردنەوەیی',
    reviewLabel: 'پرۆفایل بۆ پشکنین',
    reviewedLabel: 'پرۆفایلی پشکنراوە',
    deferredReviewLabel: 'پشکنین دواخرا',
    deploymentOwner: 'دەسەڵاتی دامەزراندن',
    fingerprint: 'پەنجەمۆر',
    validity: 'ماوەی دروستی',
    confirm: 'ئەم دامەزراندنە پشتڕاست بکەوە',
    notNow: 'ئێستا نا',
    trustedFeedback: (name) => `${name} بۆ ئەم پیشاندانە وەک متمانەپێکراو دیاری کرا.`,
    dismissedFeedback: 'هیچ بڕیارێکی متمانە پاشەکەوت نەکرا.',
    reset: 'بڕیارەکە ڕێک بخەرەوە',
    disclaimer: 'هیچ پرۆفایل، خاڵی کۆتایی یان زانیاریی نهێنیی دەستگەیشتنی ڕاستەقینە پیشان نەدراوە.',
    profiles: [
      {
        id: 'city-thread',
        name: 'تۆڕی شار',
        owner: 'دامەزراندنی سەربەخۆ A',
        fingerprint: 'KURD · 7A31 · D9C4 · DEMO',
        expires: 'لە ٦ ڕۆژی داهاتوودا بەسەر دەچێت',
        routeStyle: 'woven',
        state: 'verified',
        trustLabel: 'پەنجەمۆر پشتڕاست کراوەتەوە',
        description: 'پرۆفایلێکی تاقیکردنەوەیی و هاوسەنگ کە سنووری واژۆکراوی خاوەن و ڕێگای جێگرەوەی سنووردار پیشان دەدات.',
      },
      {
        id: 'mountain-route',
        name: 'ڕێگای چیا',
        owner: 'دامەزراندنی سەربەخۆ B',
        fingerprint: 'KURD · B204 · 8E12 · DEMO',
        expires: 'لە ٢ ڕۆژی داهاتوودا بەسەر دەچێت',
        routeStyle: 'split',
        state: 'expiring',
        trustLabel: 'پێش متمانەکردن پشکنینی بکە',
        description: 'پرۆفایلێکی تاقیکردنەوەییە کە ماوەی دروستییەکەی بەرەو کۆتایی دەچێت. ئەپەکە دەبێت ئەم دۆخە بە ڕوونی پیشان بدات.',
      },
      {
        id: 'quiet-current',
        name: 'ڕەوتی هێمن',
        owner: 'دامەزراندنی سەربەخۆ C',
        fingerprint: 'KURD · 4F81 · A610 · DEMO',
        expires: 'لە ١٢ ڕۆژی داهاتوودا بەسەر دەچێت',
        routeStyle: 'quiet',
        state: 'verified',
        trustLabel: 'پەنجەمۆر پشتڕاست کراوەتەوە',
        description: 'پرۆفایلێکی تاقیکردنەوەیی و هێمن کە لە دەرەوەی سیاسەتی واژۆکراوی خۆی هیچ دەسەڵاتێکی نییە.',
      },
    ],
  },
  privacy: {
    kicker: 'سنووری تەلارسازی',
    title: 'هیچ دەروازەوانێکی ناوەندی نییە.',
    intro: 'هەر بەڕێوەبەرێک دامەزراندنی خۆی کۆنترۆڵ دەکات. ئەپەکە بەو پەنجەمۆرە متمانە دەکات کە تۆ پشتڕاستت کردووەتەوە، بەبێ خزمەتگوزارییەکی ناوەندیی کوردستان لە نێواندا.',
    caveat:
      'ئەم سنوورانە کۆنترۆڵی ناوەندی بەرهەم کەم دەکەنەوە. بەڵام بێ‌ناسنامەیی، بەرگری لە سانسۆر یان پارێزراوی لە بلۆککردن گەرەنتی ناکەن.',
    facts: [
      [
        'هەژماری ناچاریی کوردستان نییە',
        'متمانە بە پەنجەمۆری دامەزراندنەکە دەست پێ دەکات کە تۆ پشتڕاستی دەکەیتەوە، نەک بە چوونەژوورەوەی بەرهەمێکی ناوەندی.',
      ],
      [
        'پێڕستی ناوەندیی ڕێلەکان نییە',
        'بەڕێوەبەرە سەربەخۆکان VPS، دەسەڵات، پرۆفایل، پاڵپشت و داتای خۆیان کۆنترۆڵ دەکەن.',
      ],
      [
        'شیکاریی ناچاریی بەرهەم نییە',
        'تەلارسازییەکە پشت بە ڕیکلام، ڕاپۆرتی دوورەوەی هەڵە یان تۆماری ناوەندیی هاتووچۆ نابەستێت.',
      ],
      [
        'دوگمەی کوژاندنەوەی گشتی نییە',
        'هیچ دامەزراندنێکی سەربەخۆ ناتوانێت دامەزراندنێکی تر هەڵبوەشێنێتەوە یان ناچالاکی بکات.',
      ],
    ],
  },
  selfHost: {
    kicker: 'بەڕێوەبردراو لەلایەن خاوەنەکەوە',
    responsibilitiesLabel: 'بەرپرسیارێتییەکانی بەڕێوەبەر',
    title: 'لایەنی بەرامبەری پەیوەندییەکە خۆت بەڕێوە ببە.',
    intro: 'دەسەڵات، پرۆفایلەکان، گرێی تۆڕ (node)، پاڵپشت و گەڕاندنەوەت لە ژێر کۆنترۆڵی خۆتدا دەمێننەوە.',
    guide: 'ڕێبەری خۆمیوانداری بخوێنەوە',
    showDetails: 'ڕێکخستنی بەڕێوەبەر ببینە',
    hideDetails: 'وردەکاریی بەڕێوەبەر بشارەوە',
    workflowLabel: 'ڕەوتی نموونەیی خۆمیوانداری',
    consoleTitle: 'دەسەڵاتی تایبەت بە دامەزراندن',
    consoleLabels: [
      ['دەسەڵات', 'لە ژێر کۆنترۆڵی خاوەن'],
      ['گەڕاندنەوە', 'بەبێ هێڵ'],
      ['پرۆفایل', 'واژۆکراو'],
    ],
    facts: [
      [
        'دەسەڵاتی ناوخۆ دروست بکە',
        '`kurdctl` ناسنامە و کەرەستەی گەڕاندنەوەی تایبەت بە دامەزراندن ئامادە دەکات.',
      ],
      [
        'پرۆفایلی واژۆکراو دروست بکە',
        'پرۆفایلە سنووردارەکان، فایلەکانی QR، ماوەی بەسەرچوون، گۆڕینی کلیل و هەڵوەشاندنەوە لە ژێر دەسەڵاتی خۆتدا دروست بکە.',
      ],
      [
        'گرێی تۆڕی خۆت بەڕێوە ببە',
        '`kurd-node` وەک خزمەتگوزارییەکی بەهێزکراو و بەبێ دەسەڵاتی root (non-root) لەسەر VPSێکی لە ژێر کۆنترۆڵی خاوەن دادەمەزرێت.',
      ],
      [
        'کەرەستەی گەڕاندنەوە بەبێ هێڵ بپارێزە',
        'پاڵپشتە نهێنیکراوەکان و کەرەستەی گەڕاندنەوە لە دەرەوەی VPS و لە ژێر کۆنترۆڵی خاوەن دەمێننەوە.',
      ],
    ],
  },
  status: {
    kicker: 'ئامادەیی بۆ بڵاوکردنەوە',
    title: 'ئەمڕۆ چی بەردەستە؟',
    intro: 'بناغەکە جێبەجێکراوە و لە ژێر تاقیکردنەوەی کۆنترۆڵکراودایە. دابەشکردنی گشتی ئەپی ئەندرۆید و دەستگەیشتن بە گرێی ناوبەینکاری گشتی (relay) دوو دەروازەی جیاوازی بڵاوکردنەوەن.',
    currentPhaseLabel: 'قۆناغی ئێستا',
    currentPhase: 'تاقیکردنەوەی کۆنترۆڵکراو',
    reviewedLabel: 'دۆخ پشکنراوەتەوە',
    readinessLabel: 'ئامادەیی بۆ بڵاوکردنەوە',
    showMilestoneDetails: 'وردەکاریی قۆناغەکە پیشان بدە',
    hideMilestoneDetails: 'وردەکاریی قۆناغەکە بشارەوە',
    stateLabels: {
      implemented: 'جێبەجێکراوە',
      validating: 'لە ژێر پشتڕاستکردنەوەدایە',
      unreleased: 'بڵاونەکراوەتەوە',
    },
    milestones: {
      foundation: {
        title: 'بناغە',
        summary: 'جێبەجێکراوە و لە ژێر تاقیکردنەوەی کۆنترۆڵکراودایە',
      },
      'field-validation': {
        title: 'پشتڕاستکردنەوەی مەیدانی',
        summary: 'پێش بڵاوکردنەوەی گشتی پێویستە',
      },
      'public-release': {
        title: 'بڵاوکردنەوەی گشتی',
        summary: 'دابەشکردن و دەستگەیشتنی گشتی هێشتا داخراون',
      },
    },
    items: {
      compiler: 'کۆمپایلەری پرۆتۆکۆلی بەڕێوەبراو بە پرۆفایل و مۆدیوڵە دروستکراوەکانی گواستنەوە',
      profiles: 'فایلە واژۆکراو و بۆ وەرگر نهێنیکراوەکانی پرۆفایلی کورد',
      'android-foundation': 'هاوردەکردنی پرۆفایل لە ئەندرۆید، پشتڕاستکردنەوەی پەنجەمۆر و هەڵگرتنی پارێزراو',
      'operator-control': 'دەسەڵاتی تایبەت بە دامەزراندن، پاڵپشت، گەڕاندنەوە و بەڕێوەبردنی گرێی تۆڕ',
      'audit-foundation': 'بناغەکانی تاقیکردنەوەی هێرشکارانە، گۆڕانکاری، هاوتایی، کاتی جێبەجێکردن (runtime) و پشکنینی ئاسایش',
      'relay-egress': 'گرێی ناوبەینکاری گشتیی کورد لە دەرەوەی ڕووکاری تۆڕی ناوخۆ (loopback) و دەرچوونی بێسنووری ئینتەرنێت',
      'android-release': 'فایلی بڵاوکراوەی ئەندرۆید و واژۆکردنی دابەشکردن',
      'field-validation': 'پشتڕاستکردنەوەی فراوان لە ئامێرە فیزیکییەکان و دابینکەرانی میوانداری',
    },
  },
  footer: {
    title: 'گەشەپێدانەکە بەدواداچوون بکە.',
    intro: 'ئەپی ئەندرۆید هێشتا لە ژێر گەشەپێدانە. تا بڵاوکردنەوە، سەرچاوە و دۆخی جێبەجێکردن لە GitHub ببینە.',
    dedicationBefore:
      'سارۆ خزرنژاد بە خۆشەویستییەکی بێ‌سنوورەوە ❤️ بۆ گەلی کورد دروستی کردووە، بە خۆشەویستی و هاوپشتی بۆ هەموو ئەوانەی لە ',
    dedicationPlace: 'ڕۆژهەڵات',
    dedicationAfter:
      ' لە ژێر سەرکوتکاریی حکومەتی ئێران، ستەم و لەدەستدان و ئازاریان چەشتووە. چیرۆک و بوێرییان هەرگیز لەبیر نەچێتەوە.',
    noAccount: 'هەژماری ناچاری نییە. شیکاریی پێویست نییە.',
    backToTop: 'گەڕانەوە بۆ سەرەوە',
  },
}

const kurmanji: SiteCopy = {
  skipToContent: 'Derbasî naveroka sereke bibe',
  meta: localeMetadata.kmr,
  language: {
    change: 'Ziman biguherîne',
    options: 'Vebijarkên ziman',
    english: 'English',
    sorani: 'کوردی (سۆرانی)',
    kurmanji: 'Kurdî (Kurmancî)',
    englishShort: 'EN',
    soraniShort: 'کوردی',
    kurmanjiShort: 'KMR',
  },
  preferences: {
    open: 'Vebijarkan veke',
    close: 'Vebijarkan bigire',
    panel: 'Ziman û xuyang',
    language: 'Ziman',
    appearance: 'Xuyang',
    system: 'Pergal',
    dark: 'Tarî',
    light: 'Ronahî',
  },
  header: {
    home: 'Rûpela sereke ya Kurdistan VPN',
    primaryNavigation: 'Rêberiya sereke',
    openMenu: 'Menuya rêberiyê veke',
    closeMenu: 'Menuya rêberiyê bigire',
    navigation: [
      { label: 'Çawa dixebite', href: '#how-it-works' },
      { label: 'Parastina daneyan', href: '#privacy' },
      { label: 'Li ser pêşkêşkera xwe', href: '#self-host' },
      { label: 'Rewş', href: '#status' },
    ],
    androidSoon: 'Android · di demeke nêzîk de',
  },
  hero: {
    eyebrow: 'VPN-eke Androidê ku bi profîlê tê rêvebirin',
    phase: 'Qonaxa ceribandina taybet',
    title: 'Înterneta te. Rêya te.',
    lede:
      'Bicîkirineke serbixwe hilbijêre, nîşana taybet a nasnameyê (fingerprint) ya wê piştrast bike û tenê di nav polîtîkaya îmzekirî ya profîlê de girê bide.',
    primaryCta: 'Demoya baweriyê biceribîne',
    viewStatus: 'Amadekariya weşanê bibîne',
    github: 'Li GitHubê bibîne',
    boundary:
      'Bingeha Androidê hatiye bicîkirin û di ceribandina kontrolkirî de ye. Sepan, gihîştina giştî ya girêka navbeynkar (relay) û derketina giştî ya înternetê nehatine weşandin.',
    devicePreviewLabel: 'Pêşdîtina wêneyî ya sepana Androidê',
    trustRouteLabel: 'Girêdanek çawa baweriyê bi dest dixe',
    trustRouteSteps: [
      {
        title: 'Profîla îmzekirî',
        copy: 'Bicîkirin û polîtîkaya wê nav dike.',
      },
      {
        title: 'Nîşana nasnameyê ya piştrastkirî',
        copy: 'Bicîkirina ku te hilbijartiye piştrast dike.',
      },
      {
        title: 'Rêya sînorkirî',
        copy: 'Tenê hilbijartinên veguhastinê yên îmzekirî destûr dide.',
      },
    ],
  },
  journey: {
    title: 'Pêbawerî bi profîlekê dest pê dike.',
    intro:
      'Profîleke Kurd bicîkirinê dide nasîn, nîşana taybet a nasnameyê (fingerprint) ji bo piştrastkirinê nîşan dide û rêyên ku sepan dikare bi kar bîne sînordar dike.',
    contractTitle: 'Profîl çi sînordar dike',
    contractItems: [
      {
        label: 'Nasnameya bicîkirinê',
        value: 'Kîjan desthilatê îmze kiriye',
      },
      {
        label: 'Nîşana nasnameyê',
        value: 'Bikarhêner çi piştrast dike',
      },
      {
        label: 'Polîtîkaya îmzekirî',
        value: 'Kîjan rê û veger destûrkirî ne',
      },
      {
        label: 'Dema qedandinê',
        value: 'Kengê bawerî divê ji nû ve were dîtin',
      },
    ],
    steps: [
      {
        title: 'Profîlekê werbigire',
        copy: 'Tu profîleke Kurd a îmzekirî ji bo bicîkirineke diyarkirî werdigirî.',
      },
      {
        title: 'Bicîkirinê piştrast bike',
        copy: 'Berî ku profîlê li amûra xwe zêde bikî, nîşana nasnameyê kontrol bike.',
      },
      {
        title: 'Rêya wê ya sînordar bi kar bîne',
        copy: 'Piştî berdanê, profîla îmzekirî dê vebijarkên veguhastinê û vebijarkên cîgir ên ku sepan dikare bi kar bîne sînordar bike.',
      },
    ],
  },
  profile: {
    title: 'Bizane ka tu bi kîjan bicîkirinê bawer dikî.',
    intro:
      'Berî ku tu bi profîlekê pê bawer bibî, nasnameya bicîkirinê, nîşana taybet a nasnameyê (fingerprint), dema qedandinê û polîtîkaya wê ya îmzekirî binirxîne.',
    synthetic: 'Pêşandana nimûneyî',
    tabsLabel: 'Profîlên nimûneyî',
    verified: 'hatiye piştrastkirin',
    needsReview: 'pêdiviya vekolînê heye',
    trustedState: 'Ji bo vê pêşandanê pêbawer e',
    deferredState: 'Biryar hate paşxistin',
    detailsLabel: 'Hûragahiyên profîla nimûneyî',
    reviewLabel: 'Profîla ji bo vekolînê',
    reviewedLabel: 'Profîla nirxandî',
    deferredReviewLabel: 'Vekolîn hate paşxistin',
    deploymentOwner: 'Desthilata bicîkirinê',
    fingerprint: 'Nîşana nasnameyê',
    validity: 'Derbasdarî',
    confirm: 'Vê bicîkirinê bipejirîne',
    notNow: 'Niha na',
    trustedFeedback: (name) => `${name} ji bo vê pêşandanê wekî pêbawer hat destnîşankirin.`,
    dismissedFeedback: 'Ti biryara pêbaweriyê nehat tomarkirin.',
    reset: 'Biryara xwe vegerîne',
    disclaimer: 'Ti profîl, xalê dawî an agahiya destgihîştinê ya rastîn nayê nîşandan.',
    profiles: [
      {
        id: 'city-thread',
        name: 'Tevnê Bajarê',
        owner: 'Bicîkirina serbixwe A',
        fingerprint: 'KURD · 7A31 · D9C4 · DEMO',
        expires: 'Piştî 6 rojan derbasdariya wê bi dawî dibe',
        routeStyle: 'woven',
        state: 'verified',
        trustLabel: 'Nîşana nasnameyê hatiye piştrastkirin',
        description:
          'Profîleke nimûneyî ya hevseng ku sînorê îmzekirî yê xwediyê bicîkirinê û vebijarkên cîgir ên sînordar nîşan dide.',
      },
      {
        id: 'mountain-route',
        name: 'Rêya Çiyayê',
        owner: 'Bicîkirina serbixwe B',
        fingerprint: 'KURD · B204 · 8E12 · DEMO',
        expires: 'Piştî 2 rojan derbasdariya wê bi dawî dibe',
        routeStyle: 'split',
        state: 'expiring',
        trustLabel: 'Berî pêbaweriyê binirxîne',
        description:
          'Profîleke nimûneyî ye ku derbasdariya wê ber bi dawiyê ve diçe. Divê sepan vê rewşê bi rengekî ku neyê paşguhkirin nîşan bide.',
      },
      {
        id: 'quiet-current',
        name: 'Herikîna Aram',
        owner: 'Bicîkirina serbixwe C',
        fingerprint: 'KURD · 4F81 · A610 · DEMO',
        expires: 'Piştî 12 rojan derbasdariya wê bi dawî dibe',
        routeStyle: 'quiet',
        state: 'verified',
        trustLabel: 'Nîşana nasnameyê hatiye piştrastkirin',
        description: 'Profîleke nimûneyî ya bi sînor ku li derveyî siyaseta xwe ya îmzekirî tu desthilatê nade.',
      },
    ],
  },
  privacy: {
    kicker: 'Sînorê avahiyê',
    title: 'Kontrolkerekî navendî tune.',
    intro:
      'Her rêveber bicîkirina xwe kontrol dike. Sepan bi nîşana nasnameyê ya ku tu dipejirînî bawer dike, bêyî ku xizmeteke navendî ya Kurdistanê di navberê de hebe.',
    caveat:
      'Ev sînor kontrola navendî ya berhemê kêm dikin. Ew anonîmbûn, berxwedana sansûrê an parastina ji astengkirinê garantî nakin.',
    facts: [
      [
        'Hesabê Kurdistanê yê mecbûrî tune',
        'Pêbawerî bi nîşana nasnameyê ya bicîkirinê ku tu piştrast dikî dest pê dike, ne bi têketina berhemeke navendî.',
      ],
      [
        'Lîsteya navendî ya girêkên navbeynkar tune',
        'Rêveberên serbixwe VPS, desthilat, profîl, kopiyên ewlehiyê û daneyên xwe kontrol dikin.',
      ],
      [
        'Analîtîka berhemê ya mecbûrî tune',
        'Mîmarî li reklam, raporkirina dûr a têkçûnê an tomarên navendî yên trafîkê ne girêdayî ye.',
      ],
      [
        'Dugmeya gerdûnî ya neçalakirinê tune',
        'Tu bicîkirineke serbixwe nikare bicîkirineke din betal an neçalak bike.',
      ],
    ],
  },
  selfHost: {
    kicker: 'Ji aliyê xwedî ve tê rêvebirin',
    responsibilitiesLabel: 'Berpirsiyariyên rêveber',
    title: 'Aliyê din ê girêdanê bi xwe bi rê ve bibe.',
    intro: 'Desthilat, profîl, girêka torê (node), kopiyên ewlehiyê û vegerandina te di bin kontrola te de dimînin.',
    guide: 'Rêberiya bicîkirina li ser pêşkêşkera xwe bixwîne',
    showDetails: 'Sazkirina rêveber bibîne',
    hideDetails: 'Hûragahiyên rêveber veşêre',
    workflowLabel: 'Herikîna karê nimûneyî ya bicîkirina li ser pêşkêşkera xwe',
    consoleTitle: 'desthilata taybet a bicîkirinê',
    consoleLabels: [
      ['desthilat', 'di bin kontrola xwediyê de'],
      ['vegerandin', 'derveyî torê'],
      ['profîl', 'îmzekirî'],
    ],
    facts: [
      [
        'Desthilateke taybet a bicîkirinê biafirîne',
        '`kurdctl` nasnameya taybet a bicîkirinê û materyalên vegerandinê amade dike.',
      ],
      [
        'Profîlên îmzekirî biafirîne',
        'Profîlên sînordar, berhemên QR, dema bidawîbûnê, zivirandina mifteyan û betalkirinê di bin desthilata xwe de biafirîne.',
      ],
      [
        'Girêka xwe ya torê bi rê ve bibe',
        '`kurd-node` li ser VPSeke di bin kontrola xwediyê de wekî xizmeteke bihêzkirî û bê desthilata root (non-root) tê sazkirin.',
      ],
      [
        'Materyalên vegerandinê derveyî torê biparêze',
        'Kopiyên ewlehiyê yên şîfrekirî û materyalên vegerandinê li derveyî VPSê û di bin kontrola xwediyê de dimînin.',
      ],
    ],
  },
  status: {
    kicker: 'Amadekariya berdanê',
    title: 'Îro çi heye.',
    intro:
      'Bingeh hatiye bicîkirin û di bin ceribandina kontrolkirî de ye. Belavkirina giştî ya sepana Androidê û gihîştina giştî ya girêka navbeynkar (relay) du deriyên cuda yên berdanê ne.',
    currentPhaseLabel: 'Qonaxa niha',
    currentPhase: 'Ceribandina kontrolkirî',
    reviewedLabel: 'Rewş hate nirxandin',
    readinessLabel: 'Amadekariya berdanê',
    showMilestoneDetails: 'Hûragahiyên qonaxê nîşan bide',
    hideMilestoneDetails: 'Hûragahiyên qonaxê veşêre',
    stateLabels: {
      implemented: 'Hatiye bicîkirin',
      validating: 'Tê piştrastkirin',
      unreleased: 'Nehatiye berdan',
    },
    milestones: {
      foundation: {
        title: 'Bingeh',
        summary: 'Hatiye bicîkirin û di bin ceribandina kontrolkirî de ye',
      },
      'field-validation': {
        title: 'Piştrastkirina meydanê',
        summary: 'Berî berdana giştî pêdivî ye',
      },
      'public-release': {
        title: 'Berdana giştî',
        summary: 'Belavkirin û gihîştina giştî hîn girtî ne',
      },
    },
    items: {
      compiler: 'Kompîlerê protokolê yê bi profîlan tê rêvebirin û modulên veguhastinê yên hatine çêkirin',
      profiles: 'Berhemên profîlên Kurd ên îmzekirî û ji bo wergir bi şîfre hatine girtin',
      'android-foundation': 'Anîna profîlê li Androidê, piştrastkirina nîşana nasnameyê û depokirina parastî',
      'operator-control': 'Desthilata taybet a bicîkirinê, kopiya ewlehiyê, vegerandin û rêveberiya girêka torê',
      'audit-foundation': 'Bingehên ceribandina dijberane, guhertinê, wekheviyê, dema xebitandinê (runtime) û kontrola ewlehiyê',
      'relay-egress': 'Girêka navbeynkar a giştî ya Kurd li derveyî navrûya torê ya hundirîn (loopback) û derketina înternetê ya bêsînor',
      'android-release': 'Berhema berdana giştî ya Androidê û îmzekirina belavkirinê',
      'field-validation': 'Piştrastkirina berfireh a li ser amûrên fizîkî û pêşkêşkerên mêvandariyê',
    },
  },
  footer: {
    title: 'Pêşkeftina projeyê bişopîne.',
    intro:
      'Sepana Androidê hîn di pêşxistinê de ye. Heta ku were berdan, li GitHubê koda çavkaniyê û rewşa bicîkirinê bibîne.',
    dedicationBefore:
      'Bi evîneke bêdawî ❤️ ji aliyê Saro Xizirnijad ve ji bo gelê Kurd hatiye çêkirin, bi evîn û piştgirî ji bo hemû kesên ku li ',
    dedicationPlace: 'Rojhelat',
    dedicationAfter:
      'ê di bin serkutkirina hukûmeta Îranê de zilm, windahî û êş kişandine. Bila çîrok û wêrekiya wan tu carî neyên jibîrkirin.',
    noAccount: 'Hesabê mecbûrî tune. Analîtîka mecbûrî tune.',
    backToTop: 'Vegere serî',
  },
}

export const translations: Record<Locale, SiteCopy> = {
  en: english,
  ckb: sorani,
  kmr: kurmanji,
}
