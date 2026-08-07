export type Locale = 'en' | 'ckb'

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
  meta: {
    title: string
    description: string
  }
  language: {
    change: string
    options: string
    english: string
    sorani: string
    englishShort: string
    soraniShort: string
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
    title: string
    lede: string
    download: string
    comingSoon: string
    howItWorks: string
    github: string
    boundary: string
  }
  journey: {
    title: string
    intro: string
    steps: readonly { title: string; copy: string }[]
  }
  profile: {
    title: string
    intro: string
    synthetic: string
    tabsLabel: string
    selectLabel: (name: string) => string
    verified: string
    needsReview: string
    detailsLabel: string
    reviewLabel: string
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
    title: string
    intro: string
    facts: readonly (readonly [string, string])[]
  }
  selfHost: {
    title: string
    intro: string
    guide: string
    workflowLabel: string
    consoleTitle: string
    consoleLabels: readonly (readonly [string, string])[]
    facts: readonly (readonly [string, string])[]
  }
  status: {
    title: string
    intro: string
    available: string
    unreleased: string
    implemented: readonly string[]
    notReleased: readonly string[]
  }
  footer: {
    title: string
    intro: string
    dedicationBefore: string
    dedicationPlace: string
    dedicationAfter: string
    noAccount: string
  }
}

const english: SiteCopy = {
  meta: {
    title: 'Kurdistan VPN · Your internet. Your route.',
    description:
      'Kurdistan VPN is an Android VPN in development, built around signed profiles, independently operated deployments, and explicit trust boundaries.',
  },
  language: {
    change: 'Change language',
    options: 'Language options',
    english: 'English',
    sorani: 'کوردی',
    englishShort: 'EN',
    soraniShort: 'کوردی',
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
    title: 'Your internet. Your route.',
    lede:
      'Kurdistan VPN for Android is in development. It uses a signed profile from an operator you choose, so you can verify who runs the other end.',
    download: 'Download for Android',
    comingSoon: 'Coming soon',
    howItWorks: 'How it works',
    github: 'View on GitHub',
    boundary:
      'The Android foundation is implemented and under controlled testing. Public relay access is not released.',
  },
  journey: {
    title: 'Trust starts with a profile.',
    intro:
      'A Kurd profile identifies the operator, shows a fingerprint for you to verify, and limits the routes the app may use.',
    steps: [
      {
        title: 'Receive a profile',
        copy: 'An operator you know shares a signed Kurd profile with you.',
      },
      {
        title: 'Verify who you trust',
        copy: 'Check the fingerprint before adding the profile to your device.',
      },
      {
        title: 'Use its bounded route',
        copy: 'After release, the signed profile will limit the transport and fallback options the app may use.',
      },
    ],
  },
  profile: {
    title: 'Know who runs the connection.',
    intro:
      'Before you trust a profile, review its operator, fingerprint, expiry, and signed policy.',
    synthetic: 'Synthetic demonstration',
    tabsLabel: 'Synthetic profiles',
    selectLabel: (name) => `Select ${name} profile`,
    verified: 'verified',
    needsReview: 'needs review',
    detailsLabel: 'Synthetic profile details',
    reviewLabel: 'Profile to review',
    deploymentOwner: 'Deployment owner',
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
    title: 'No central gatekeeper.',
    intro:
      'Each operator controls their own deployment. The app trusts the fingerprint you approve, without a central Kurdistan service in the middle.',
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
    title: 'Run the other end yourself.',
    intro: 'Your authority, profiles, node, backups, and recovery stay under your control.',
    guide: 'Read the self-hosting guide',
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
    title: 'What exists today.',
    intro:
      'Kurdistan has substantial implemented foundations, but it is still pre-release. The boundary below separates working foundations from unreleased capabilities.',
    available: 'Available foundation',
    unreleased: 'Not released yet',
    implemented: [
      'Profile-driven protocol compiler and generated transport modules',
      'Signed and recipient-sealed Kurd profile artifacts',
      'Android profile import, fingerprint confirmation, and protected storage',
      'Deployment-local authority, backup, recovery, and node administration',
      'Adversarial, mutation, parity, runtime, and security audit foundations',
    ],
    notReleased: [
      'Public non-loopback Kurd relay and unrestricted Internet egress',
      'Public Android release artifact and distribution signing',
      'Broad physical-device and hosting-provider field validation',
      'Any guarantee of censorship bypass, anonymity, or immunity from blocking',
    ],
  },
  footer: {
    title: 'Follow the build.',
    intro:
      'The Android app is still in development. Until release, explore the source and implementation status on GitHub.',
    dedicationBefore:
      'Made with immense ❤️ by Saro Xizirnijad, for the Kurdish people and in honor of all they have endured in ',
    dedicationPlace: 'Rojhelat',
    dedicationAfter: '.',
    noAccount: 'No mandatory account. No required analytics.',
  },
}

const sorani: SiteCopy = {
  meta: {
    title: 'VPNی کوردستان · ئینتەرنێتی تۆ. ڕێگای تۆ.',
    description:
      'VPNی کوردستان VPNێکی ئەندرۆیدی لە ژێر گەشەپێدانە کە لەسەر پرۆفایلی واژۆکراو، دامەزراندنی سەربەخۆ و سنووری ڕوونی متمانە بنیات نراوە.',
  },
  language: {
    change: 'گۆڕینی زمان',
    options: 'هەڵبژاردەکانی زمان',
    english: 'English',
    sorani: 'کوردی',
    englishShort: 'EN',
    soraniShort: 'کوردی',
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
    title: 'ئینتەرنێتی تۆ. ڕێگای تۆ.',
    lede:
      'VPNی کوردستان بۆ ئەندرۆید لە ژێر گەشەپێدانە. پرۆفایلێکی واژۆکراو لە بەڕێوەبەرێکی هەڵبژێردراوی تۆ بەکاردەهێنێت، بۆ ئەوەی بتوانیت پشتڕاست بکەیتەوە کێ لایەنی بەرامبەری پەیوەندییەکە بەڕێوە دەبات.',
    download: 'داگرتن بۆ ئەندرۆید',
    comingSoon: 'بەزوویی',
    howItWorks: 'چۆن کار دەکات',
    github: 'لە GitHub ببینە',
    boundary:
      'بناغەی ئەندرۆید جێبەجێ کراوە و لە ژێر تاقیکردنەوەی کۆنترۆڵکراودایە. دەستگەیشتن بە ڕێلەی گشتی هێشتا بڵاونەکراوەتەوە.',
  },
  journey: {
    title: 'متمانە بە پرۆفایلێک دەست پێ دەکات.',
    intro:
      'پرۆفایلێکی کورد ناسنامەی بەڕێوەبەر دیاری دەکات، پەنجەمۆرێکت پیشان دەدات تا پشتڕاستی بکەیتەوە، و ڕێگاکانی بەردەست بۆ ئەپەکە سنووردار دەکات.',
    steps: [
      {
        title: 'پرۆفایلێک وەربگرە',
        copy: 'بەڕێوەبەرێک کە دەیناسیت پرۆفایلێکی واژۆکراوی کوردت بۆ دەنێرێت.',
      },
      {
        title: 'پشتڕاستی بکەوە بە کێ متمانە دەکەیت',
        copy: 'پێش زیادکردنی پرۆفایلەکە بۆ ئامێرەکەت، پەنجەمۆرەکە بپشکنە.',
      },
      {
        title: 'ڕێگای سنووردارکراوی بەکاربهێنە',
        copy: 'دوای بڵاوکردنەوە، پرۆفایلە واژۆکراوەکە گواستنەوە و ڕێگا جێگرەوەکان کە ئەپەکە دەتوانێت بەکاریان بهێنێت، سنووردار دەکات.',
      },
    ],
  },
  profile: {
    title: 'بزانە کێ پەیوەندییەکە بەڕێوە دەبات.',
    intro:
      'پێش ئەوەی بە پرۆفایلێک متمانە بکەیت، بەڕێوەبەر، پەنجەمۆر، بەسەرچوون و سیاسەتی واژۆکراوی بپشکنە.',
    synthetic: 'پیشاندانی نموونەیی',
    tabsLabel: 'پرۆفایلە تاقیکردنەوەییەکان',
    selectLabel: (name) => `پرۆفایلی ${name} هەڵبژێرە`,
    verified: 'پشتڕاستکراو',
    needsReview: 'پێویستی بە پشکنینەوە هەیە',
    detailsLabel: 'وردەکاریی پرۆفایلی تاقیکردنەوەیی',
    reviewLabel: 'پرۆفایل بۆ پشکنین',
    deploymentOwner: 'خاوەنی دامەزراندن',
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
    title: 'هیچ دەروازەوانێکی ناوەندی نییە.',
    intro: 'هەر بەڕێوەبەرێک دامەزراندنی خۆی کۆنترۆڵ دەکات. ئەپەکە بەو پەنجەمۆرە متمانە دەکات کە تۆ پشتڕاستت کردووەتەوە، بەبێ خزمەتگوزارییەکی ناوەندیی کوردستان لە نێواندا.',
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
    title: 'لایەنی بەرامبەری پەیوەندییەکە خۆت بەڕێوە ببە.',
    intro: 'دەسەڵات، پرۆفایلەکان، نۆد، پاڵپشت و گەڕاندنەوەت لە ژێر کۆنترۆڵی خۆتدا دەمێننەوە.',
    guide: 'ڕێبەری خۆمیوانداری بخوێنەوە',
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
        'نۆدی خۆت بەڕێوە ببە',
        '`kurd-node` وەک خزمەتگوزارییەکی بەهێزکراو و non-root لەسەر VPSێکی لە ژێر کۆنترۆڵی خاوەن دادەمەزرێت.',
      ],
      [
        'کەرەستەی گەڕاندنەوە بەبێ هێڵ بپارێزە',
        'پاڵپشتە نهێنیکراوەکان و کەرەستەی گەڕاندنەوە لە دەرەوەی VPS و لە ژێر کۆنترۆڵی خاوەن دەمێننەوە.',
      ],
    ],
  },
  status: {
    title: 'ئەمڕۆ چی بەردەستە؟',
    intro: 'کوردستان بناغەیەکی جێبەجێکراوی بەرچاوی هەیە، بەڵام هێشتا پێش بڵاوکردنەوەیە. سنووری خوارەوە بناغە کاراکان لە تواناکانی بڵاونەکراوە جیا دەکاتەوە.',
    available: 'بناغەی بەردەست',
    unreleased: 'هێشتا بڵاونەکراوەتەوە',
    implemented: [
      'کۆمپایلەری پرۆتۆکۆلی بەڕێوەبراو بە پرۆفایل و مۆدیوڵە دروستکراوەکانی گواستنەوە',
      'فایلە واژۆکراو و بۆ وەرگر نهێنیکراوەکانی پرۆفایلی کورد',
      'هاوردەکردنی پرۆفایل لە ئەندرۆید، پشتڕاستکردنەوەی پەنجەمۆر و هەڵگرتنی پارێزراو',
      'دەسەڵاتی تایبەت بە دامەزراندن، پاڵپشت، گەڕاندنەوە و بەڕێوەبردنی نۆد',
      'بناغەکانی تاقیکردنەوەی هێرشکارانە، گۆڕانکاری، هاوتایی، ڕانتایم و پشکنینی ئاسایش',
    ],
    notReleased: [
      'ڕێلەی گشتیی کورد لە دەرەوەی loopback و دەرچوونی بێسنووری ئینتەرنێت',
      'فایلی بڵاوکراوەی ئەندرۆید و واژۆکردنی دابەشکردن',
      'پشتڕاستکردنەوەی فراوان لە ئامێرە فیزیکییەکان و دابینکەرانی میوانداری',
      'هەر جۆرە دڵنیاییەک سەبارەت بە تێپەڕاندنی سانسۆر، نەناسراوی یان بەرگری لە بلۆککردن',
    ],
  },
  footer: {
    title: 'گەشەپێدانەکە بەدواداچوون بکە.',
    intro: 'ئەپی ئەندرۆید هێشتا لە ژێر گەشەپێدانە. تا بڵاوکردنەوە، سەرچاوە و دۆخی جێبەجێکردن لە GitHub ببینە.',
    dedicationBefore:
      'سارۆ خزرنژاد بە خۆشەویستییەکی بێ‌سنوورەوە ❤️ بۆ گەلی کورد دروستی کردووە؛ بە ڕێزگرتن لە هەموو ئەو ئازارەی لە ',
    dedicationPlace: 'ڕۆژهەڵات',
    dedicationAfter: ' بەسەریان هاتووە.',
    noAccount: 'هەژماری ناچاری نییە. شیکاریی پێویست نییە.',
  },
}

export const translations: Record<Locale, SiteCopy> = {
  en: english,
  ckb: sorani,
}
