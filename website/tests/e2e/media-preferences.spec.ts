import { expect, test } from '@playwright/test'

test('reduced motion removes every non-essential animation', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/')

  const animatedElements = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .map((element) => {
        const style = getComputedStyle(element)

        return {
          className:
            typeof element.className === 'string'
              ? element.className
              : element.getAttribute('class') ?? '',
          animationName: style.animationName,
          transitionDuration: style.transitionDuration,
        }
      })
      .filter(
        ({ animationName, transitionDuration }) =>
          animationName !== 'none' ||
          transitionDuration
            .split(',')
            .some((duration) => Number.parseFloat(duration) > 0),
      ),
  )

  expect(animatedElements).toEqual([])
})

test('forced colors preserves controls and content', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' })
  await page.goto('/')

  await expect(
    page.getByRole('heading', {
      level: 1,
      name: 'Your internet. Your route.',
    }),
  ).toBeVisible()
  await expect(
    page.getByRole('link', { name: 'Try the trust demo' }),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: /open preferences/i }),
  ).toBeVisible()
})
