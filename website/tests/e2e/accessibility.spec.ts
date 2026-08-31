import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const locales = ['/', '/ckb/', '/kmr/'] as const
const themes = ['dark', 'light'] as const

for (const localePath of locales) {
  for (const theme of themes) {
    test(`${localePath} passes axe in ${theme} theme`, async ({ page }) => {
      await page.addInitScript((selectedTheme) => {
        window.localStorage.setItem(
          'kurdistan-vpn-theme',
          selectedTheme,
        )
      }, theme)

      await page.goto(localePath)
      await page.waitForLoadState('networkidle')

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
        .analyze()

      expect(results.violations).toEqual([])
    })
  }
}

for (const localePath of locales) {
  test(`${localePath} opened mobile navigation passes axe in light theme`, async ({
    page,
  }) => {
    await page.addInitScript(() => {
      window.localStorage.setItem('kurdistan-vpn-theme', 'light')
    })
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(localePath)
    await page.locator('.menu-toggle').click()

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
      .analyze()

    expect(results.violations).toEqual([])
  })
}

test('visible custom controls retain 44px targets', async ({ page }) => {
  const undersizedTargets = () =>
    page
      .locator('a[href], button, summary, label:has(input)')
      .evaluateAll((elements) =>
        elements.flatMap((element) => {
          const rectangle = element.getBoundingClientRect()
          const style = getComputedStyle(element)
          const visible =
            style.display !== 'none' &&
            style.visibility !== 'hidden' &&
            rectangle.width > 0 &&
            rectangle.height > 0

          if (
            !visible ||
            (rectangle.width >= 44 && rectangle.height >= 44)
          ) {
            return []
          }

          return [
            {
              tag: element.tagName.toLowerCase(),
              text: element.textContent?.trim() ?? '',
              width: rectangle.width,
              height: rectangle.height,
            },
          ]
        }),
      )

  for (const localePath of locales) {
    for (const width of [390, 1440]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto(localePath)

      expect(await undersizedTargets()).toEqual([])

      await page.locator('.preferences__trigger').click()
      expect(await undersizedTargets()).toEqual([])
      await page.keyboard.press('Escape')

      if (width === 390) {
        await page.locator('.menu-toggle').click()
        expect(await undersizedTargets()).toEqual([])
        await page.keyboard.press('Escape')
      }
    }
  }
})
