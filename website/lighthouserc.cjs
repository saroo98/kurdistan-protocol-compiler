const ciCollectOptions = process.env.CI
  ? {
      puppeteerLaunchOptions: {
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      },
    }
  : {}

module.exports = {
  ci: {
    collect: {
      ...ciCollectOptions,
      staticDistDir: './dist',
      puppeteerScript: './scripts/lighthouse-puppeteer.cjs',
      url: [
        'http://localhost/',
        'http://localhost/ckb/',
        'http://localhost/kmr/',
      ],
      numberOfRuns: 3,
      settings: {
        preset: 'desktop',
        onlyCategories: [
          'performance',
          'accessibility',
          'best-practices',
          'seo',
        ],
      },
    },
    assert: {
      assertions: {
        'categories:performance': ['error', { minScore: 0.9 }],
        'categories:accessibility': ['error', { minScore: 0.98 }],
        'categories:best-practices': ['error', { minScore: 0.95 }],
        'categories:seo': ['error', { minScore: 1 }],
        'largest-contentful-paint': [
          'error',
          { maxNumericValue: 2500 },
        ],
        'cumulative-layout-shift': ['error', { maxNumericValue: 0.1 }],
        'total-blocking-time': ['error', { maxNumericValue: 200 }],
      },
    },
  },
}
