import { expect, test } from '@playwright/test'

test('all current interactive states remain reachable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')

  const menuButton = page.getByRole('button', {
    name: /open navigation menu/i,
  })

  await menuButton.click()
  await expect(
    page.getByRole('navigation', { name: /primary/i }),
  ).toHaveAttribute('data-state', 'open')

  await page.keyboard.press('Escape')
  await expect(menuButton).toBeFocused()

  const preferences = page.getByRole('button', {
    name: /open preferences/i,
  })

  await preferences.click()
  const preferencesPanel = page.getByRole('dialog', {
    name: /language and appearance/i,
  })
  const panelBounds = await preferencesPanel.boundingBox()

  expect(panelBounds).not.toBeNull()
  expect(panelBounds?.x ?? -1).toBeGreaterThanOrEqual(0)
  expect((panelBounds?.x ?? 0) + (panelBounds?.width ?? 0)).toBeLessThanOrEqual(
    390,
  )

  const lightTheme = page.getByRole('radio', { name: 'Light' })
  await lightTheme.focus()
  await page.keyboard.press('Space')
  await expect(lightTheme).toBeChecked()

  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    'light',
  )

  await page.keyboard.press('Escape')
  await expect(preferences).toBeFocused()

  await page.getByRole('link', { name: 'Try the trust demo' }).click()

  const tabs = page.getByRole('tab')
  await tabs.nth(0).focus()
  await page.keyboard.press('ArrowDown')

  await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true')

  await page.getByRole('button', {
    name: /confirm this deployment/i,
  }).click()

  await expect(page.getByRole('status')).toContainText(
    /marked as trusted/i,
  )

  await page.getByRole('button', { name: /reset decision/i }).click()
  await expect(page.getByRole('status')).toBeEmpty()

  await page.getByRole('button', {
    name: /not now/i,
  }).click()
  await expect(page.getByRole('status')).toContainText(
    /no trust decision was saved/i,
  )

  await page.getByRole('button', { name: /reset decision/i }).click()

  const operatorDetails = page.locator('details.operator-disclosure')
  await operatorDetails.locator('summary').click()
  await expect(operatorDetails).toHaveAttribute('open', '')
  await expect(
    operatorDetails.locator('.operator-console > code').first(),
  ).toContainText(/kurdctl init/i)

  await operatorDetails.locator('summary').click()
  await expect(operatorDetails).not.toHaveAttribute('open', '')
})

test('opening the mobile navigation moves keyboard focus into its links', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')

  const menuButton = page.getByRole('button', {
    name: /open navigation menu/i,
  })
  await menuButton.focus()
  await page.keyboard.press('Enter')

  await expect(
    page.getByRole('link', { name: 'How it works', exact: true }),
  ).toBeFocused()
})

test('locale controls navigate to the selected localized page', async ({
  page,
}) => {
  await page.goto('/')
  await page.getByRole('button', { name: /open preferences/i }).click()
  await page.getByRole('link', { name: 'کوردی (سۆرانی)' }).click()

  await expect(page).toHaveURL(/\/ckb\/$/)
  await expect(page.locator('html')).toHaveAttribute('lang', 'ckb')
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl')

  await page.getByRole('button', {
    name: /کردنەوەی هەڵبژاردەکان/i,
  }).click()
  await page.getByRole('link', { name: 'Kurdî (Kurmancî)' }).click()

  await expect(page).toHaveURL(/\/kmr\/$/)
  await expect(page.locator('html')).toHaveAttribute('lang', 'kmr')
  await expect(page.locator('html')).toHaveAttribute('dir', 'ltr')
})

test('Sorani mirrors forward icons while opened disclosures point down', async ({
  page,
}) => {
  await page.goto('/ckb/')

  const linkIcons = page.locator('a .directional-icon')
  await expect(linkIcons).toHaveCount(5)

  const mirroredScales = await linkIcons.evaluateAll((icons) =>
    icons.map(
      (icon) => new DOMMatrix(getComputedStyle(icon).transform).a,
    ),
  )
  expect(mirroredScales.every((scale) => scale < -0.99)).toBe(true)

  const firstMilestone = page.locator('.release-status-list__details').first()
  const disclosureIcon = firstMilestone.locator('.directional-icon')

  await expect
    .poll(() =>
      disclosureIcon.evaluate(
        (icon) => new DOMMatrix(getComputedStyle(icon).transform).a,
      ),
    )
    .toBeLessThan(-0.99)

  await firstMilestone.locator('summary').click()

  await expect
    .poll(() =>
      disclosureIcon.evaluate((icon) => {
        const matrix = new DOMMatrix(getComputedStyle(icon).transform)
        return { horizontalScale: matrix.a, verticalSkew: matrix.b }
      }),
    )
    .toEqual({ horizontalScale: 0, verticalSkew: 1 })
})

test('all internal navigation targets exist and land below the fixed header', async ({
  page,
}) => {
  await page.goto('/')

  const hrefs = await page.locator('a[href^="#"]').evaluateAll((links) =>
    Array.from(
      new Set(
        links
          .map((link) => link.getAttribute('href'))
          .filter(
            (href): href is string => Boolean(href && href.length > 1),
          ),
      ),
    ),
  )

  for (const href of hrefs) {
    const target = page.locator(href)
    await expect(target, `missing target for ${href}`).toHaveCount(1)
    const link = page.locator(`a[href="${href}"]`).first()

    if (href === '#main-content') {
      await link.focus()
      await expect(link).toBeVisible()
      await page.keyboard.press('Enter')
      await expect(target).toBeFocused()
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0)
      continue
    } else {
      await link.click()
    }

    if (href === '#top') {
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0)
      continue
    }

    await expect
      .poll(() => target.evaluate((element) => element.getBoundingClientRect().top))
      .toBeGreaterThanOrEqual(65)
    await expect
      .poll(() => target.evaluate((element) => element.getBoundingClientRect().top))
      .toBeLessThan(150)
  }
})
