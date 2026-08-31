import { expect, test } from '@playwright/test'

test('the production experience boots without browser errors', async ({
  page,
}) => {
  const browserErrors: string[] = []

  page.on('console', (message) => {
    if (message.type() === 'error') browserErrors.push(message.text())
  })
  page.on('pageerror', (error) => browserErrors.push(error.message))

  await page.goto('/')
  await page.waitForLoadState('networkidle')

  await expect(
    page.getByRole('heading', {
      level: 1,
      name: 'Your internet. Your route.',
    }),
  ).toBeVisible()

  await expect(page.getByRole('banner')).toBeVisible()
  await expect(page.getByRole('main')).toBeVisible()
  await expect(page.getByRole('contentinfo')).toBeVisible()
  await expect(page.locator('#status')).toBeAttached()

  expect(browserErrors).toEqual([])
})

test('static content never opts into editing or caret focus', async ({
  page,
}) => {
  for (const localePath of ['/', '/ckb/', '/kmr/']) {
    await page.goto(localePath)

    const state = await page.evaluate(() => {
      const staticText = Array.from(
        document.querySelectorAll<HTMLElement>(
          'h1, h2, h3, p, span, small, dt, dd, li',
        ),
      )

      return {
        activeElement: document.activeElement?.tagName ?? null,
        editableElements: document.querySelectorAll(
          '[contenteditable]:not([contenteditable="false"])',
        ).length,
        focusableStaticText: staticText
          .filter((element) => element.tabIndex >= 0)
          .map((element) => element.tagName),
      }
    })

    expect(state.activeElement).toBe('BODY')
    expect(state.editableElements).toBe(0)
    expect(state.focusableStaticText).toEqual([])
  }
})

test('runtime resources remain first-party', async ({ page }) => {
  const requestedOrigins = new Set<string>()

  page.on('request', (request) => {
    requestedOrigins.add(new URL(request.url()).origin)
  })

  for (const localePath of ['/', '/ckb/', '/kmr/']) {
    await page.goto(localePath)
    await page.waitForLoadState('networkidle')
  }

  expect([...requestedOrigins]).toEqual(['http://127.0.0.1:4174'])
})
