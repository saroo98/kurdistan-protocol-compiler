import { expect, test, type Page } from '@playwright/test'

const locales = [
  { name: 'en', path: '/' },
  { name: 'ckb', path: '/ckb/' },
  { name: 'kmr', path: '/kmr/' },
] as const

const themes = ['dark', 'light'] as const

const viewports = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'mobile', width: 390, height: 844 },
] as const

async function prepareStablePage(page: Page, theme: (typeof themes)[number]) {
  await page.clock.setFixedTime(new Date('2026-08-31T12:00:00Z'))
  await page.addInitScript((selectedTheme) => {
    window.localStorage.setItem('kurdistan-vpn-theme', selectedTheme)
  }, theme)
  await page.emulateMedia({ reducedMotion: 'reduce' })
}

async function waitForVisualAssets(page: Page) {
  await page.waitForLoadState('networkidle')
  await page.evaluate(() => document.fonts.ready)
  await page.locator('img').evaluateAll(async (images) => {
    await Promise.all(
      images.map((image) =>
        image.complete
          ? Promise.resolve()
          : new Promise<void>((resolve) => {
              image.addEventListener('load', () => resolve(), { once: true })
              image.addEventListener('error', () => resolve(), { once: true })
            }),
      ),
    )
  })
}

for (const locale of locales) {
  for (const theme of themes) {
    for (const viewport of viewports) {
      test(`${locale.name}-${theme}-${viewport.name}`, async ({ page }) => {
        await prepareStablePage(page, theme)
        await page.setViewportSize({
          width: viewport.width,
          height: viewport.height,
        })
        await page.goto(locale.path)
        await waitForVisualAssets(page)

        await expect(page).toHaveScreenshot(
          `${locale.name}-${theme}-${viewport.name}.png`,
          {
            fullPage: true,
            animations: 'disabled',
            caret: 'hide',
            scale: 'css',
          },
        )
      })
    }
  }
}

test('interaction state baselines', async ({ page }) => {
  await prepareStablePage(page, 'dark')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')
  await waitForVisualAssets(page)

  await page.getByRole('button', { name: /open navigation menu/i }).click()
  await expect(page).toHaveScreenshot('mobile-navigation-open.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  })

  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: /open preferences/i }).click()
  await expect(page).toHaveScreenshot('preferences-open.png', {
    animations: 'disabled',
    caret: 'hide',
    scale: 'css',
  })

  await page.keyboard.press('Escape')
  await page.addStyleTag({
    content: '.site-header, .skip-link { visibility: hidden !important; }',
  })
  await page.getByRole('link', { name: 'Try the trust demo' }).click()
  await page.getByRole('button', {
    name: /confirm this deployment/i,
  }).click()
  await expect(page.locator('#profile-demo')).toHaveScreenshot(
    'profile-confirmed.png',
    {
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
    },
  )

  const operatorDetails = page.locator('details.operator-disclosure')
  await operatorDetails.locator('summary').click()
  await expect(page.locator('#self-host')).toHaveScreenshot(
    'self-host-expanded.png',
    {
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
    },
  )

  const firstMilestone = page.locator('.release-status-list__details').first()
  await firstMilestone.locator('summary').click()
  await expect(page.locator('#status')).toHaveScreenshot(
    'status-milestone-expanded.png',
    {
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
    },
  )
})

for (const locale of [locales[0], locales[1]]) {
  test(`${locale.name}-light mobile header states`, async ({ page }) => {
    await prepareStablePage(page, 'light')
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(locale.path)
    await waitForVisualAssets(page)

    await page.locator('.menu-toggle').click()
    await expect(page).toHaveScreenshot(
      `${locale.name}-light-mobile-navigation-open.png`,
      {
        animations: 'disabled',
        caret: 'hide',
        scale: 'css',
      },
    )

    await page.locator('.preferences__trigger').click()
    await expect(page).toHaveScreenshot(
      `${locale.name}-light-mobile-preferences-open.png`,
      {
        animations: 'disabled',
        caret: 'hide',
        scale: 'css',
      },
    )
  })
}
