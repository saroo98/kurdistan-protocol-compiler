import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

type PackageJson = {
  scripts?: Record<string, string>
  devDependencies?: Record<string, string>
}

describe('website quality tooling', () => {
  it('declares reproducible unit, browser, and aggregate quality commands', () => {
    const packageJson = JSON.parse(
      readFileSync(resolve('package.json'), 'utf8'),
    ) as PackageJson

    expect(packageJson.scripts).toMatchObject({
      'test:run': 'vitest run',
      'test:e2e': 'playwright test',
      'test:e2e:update': 'playwright test --update-snapshots=all',
      'audit:dependencies': 'npm audit --omit=dev',
      check:
        'npm run lint && npm run audit:dependencies && npm run build && npm run test:run && npm run test:e2e && npm run audit:bundle',
    })

    expect(packageJson.devDependencies).toHaveProperty('@playwright/test')
    expect(packageJson.devDependencies).toHaveProperty('@axe-core/playwright')
  })

  it('uses sandbox fallbacks only on the CI runner', () => {
    const lighthouseConfig = readFileSync(resolve('lighthouserc.cjs'), 'utf8')

    expect(lighthouseConfig).toContain('process.env.CI')
    expect(lighthouseConfig).toContain('puppeteerLaunchOptions')
    expect(lighthouseConfig).toContain('--no-sandbox')
    expect(lighthouseConfig).toContain('--disable-setuid-sandbox')
  })
})
