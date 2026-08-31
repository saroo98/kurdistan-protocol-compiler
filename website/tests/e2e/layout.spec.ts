import { expect, test, type Page } from '@playwright/test'

const viewportWidths = [
  320, 360, 390, 560, 768, 819, 820, 821, 900, 1024, 1440, 1920, 2560,
]

async function documentMetrics(page: Page) {
  return page.evaluate(() => {
    const elements = Array.from(
      document.querySelectorAll<HTMLElement>('body *'),
    )

    const protruding = elements
      .map((element) => {
        const rectangle = element.getBoundingClientRect()

        return {
          tag: element.tagName.toLowerCase(),
          className:
            typeof element.className === 'string' ? element.className : '',
          left: rectangle.left,
          right: rectangle.right,
        }
      })
      .filter(
        ({ left, right }) =>
          left < -1 || right > window.innerWidth + 1,
      )

    return {
      innerWidth: window.innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
      heroHeight:
        document.querySelector<HTMLElement>('#top')?.offsetHeight ?? 0,
      protruding,
    }
  })
}

async function visibleContentMetrics(page: Page) {
  return page.evaluate(() => {
    const selectors = [
      'header a',
      'header button',
      'main h1',
      'main h2',
      'main h3',
      'main p',
      'main li',
      'main dt',
      'main dd',
      'main button',
      'main a',
      'main summary',
      'footer p',
      'footer a',
    ].join(',')

    const elements = Array.from(
      document.querySelectorAll<HTMLElement>(selectors),
    )

    const protruding = elements.flatMap((element) => {
      if (
        element.closest('.device-stage') ||
        element.closest('details:not([open])') ||
        element.matches('.skip-link:not(:focus)')
      ) {
        return []
      }

      const styles = getComputedStyle(element)
      const rectangle = element.getBoundingClientRect()

      if (
        styles.display === 'none' ||
        styles.visibility === 'hidden' ||
        Number(styles.opacity) === 0 ||
        rectangle.width === 0 ||
        rectangle.height === 0
      ) {
        return []
      }

      const range = document.createRange()
      range.selectNodeContents(element)
      const textRectangles = Array.from(range.getClientRects()).filter(
        ({ width, height }) => width > 0 && height > 0,
      )
      range.detach()

      const left = Math.min(
        rectangle.left,
        ...textRectangles.map((textRectangle) => textRectangle.left),
      )
      const right = Math.max(
        rectangle.right,
        ...textRectangles.map((textRectangle) => textRectangle.right),
      )

      if (left >= -1 && right <= window.innerWidth + 1) {
        return []
      }

      return [
        {
          tag: element.tagName.toLowerCase(),
          className:
            typeof element.className === 'string' ? element.className : '',
          text: element.textContent?.trim().slice(0, 90) ?? '',
          left,
          right,
        },
      ]
    })

    return {
      innerWidth: window.innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
      protruding,
    }
  })
}

test('the page has no concealed horizontal overflow', async ({ page }) => {
  for (const width of viewportWidths) {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/')

    const metrics = await documentMetrics(page)

    expect(
      metrics.scrollWidth,
      `document overflow at ${width}px`,
    ).toBeLessThanOrEqual(metrics.innerWidth)

    expect(
      metrics.protruding,
      `elements protruding at ${width}px`,
    ).toEqual([])
  }
})

test('the layout changes continuously around the former breakpoint', async ({
  page,
}) => {
  const heights: number[] = []

  for (const width of [819, 820, 821, 822]) {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/')

    heights.push((await documentMetrics(page)).heroHeight)
  }

  for (let index = 1; index < heights.length; index += 1) {
    const larger = Math.max(heights[index - 1], heights[index])
    const difference = Math.abs(heights[index - 1] - heights[index])

    expect(difference / larger).toBeLessThan(0.12)
  }
})

test('two-hundred-percent text scaling still reflows', async ({ page }) => {
  for (const localePath of ['/', '/ckb/', '/kmr/']) {
    for (const scale of [150, 175, 200]) {
      await page.setViewportSize({ width: 320, height: 900 })
      await page.goto(localePath)

      await page.evaluate((fontScale) => {
        document.documentElement.style.fontSize = `${fontScale}%`
      }, scale)

      const metrics = await visibleContentMetrics(page)

      expect(
        metrics.scrollWidth,
        `${localePath} document overflow at ${scale}% text`,
      ).toBeLessThanOrEqual(metrics.innerWidth)
      expect(
        metrics.protruding,
        `${localePath} visible content overflow at ${scale}% text`,
      ).toEqual([])
    }
  }
})

test('mobile header overlays remain reachable at two-hundred-percent text', async ({
  page,
}) => {
  for (const localePath of ['/', '/ckb/', '/kmr/']) {
    await page.setViewportSize({ width: 320, height: 900 })
    await page.goto(localePath)
    await page.evaluate(() => {
      document.documentElement.style.fontSize = '200%'
    })

    const menuToggle = page.locator('.menu-toggle')
    const preferencesTrigger = page.locator('.preferences__trigger')

    await menuToggle.click()
    await expect(page.locator('#primary-navigation')).toBeInViewport()
    expect(await visibleContentMetrics(page)).toMatchObject({
      innerWidth: 320,
      protruding: [],
    })

    await preferencesTrigger.click()
    await expect(page.locator('.preferences__panel')).toBeInViewport()
    expect(await visibleContentMetrics(page)).toMatchObject({
      innerWidth: 320,
      protruding: [],
    })
  }
})

test('mobile page shells preserve a readable viewport gutter', async ({
  page,
}) => {
  for (const localePath of ['/', '/ckb/', '/kmr/']) {
    for (const width of [320, 390]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto(localePath)

      const bounds = await page.locator('.page-shell').evaluateAll((shells) =>
        shells.map((shell) => {
          const rectangle = shell.getBoundingClientRect()

          return {
            left: rectangle.left,
            right: window.innerWidth - rectangle.right,
          }
        }),
      )

      for (const gutter of bounds) {
        expect(gutter.left, `${localePath} left gutter at ${width}px`).toBeGreaterThanOrEqual(16)
        expect(gutter.right, `${localePath} right gutter at ${width}px`).toBeGreaterThanOrEqual(16)
      }
    }
  }
})

test('desktop trust-route connectors stay above the step copy', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')

  const steps = await page.locator('.hero-trust-route li').evaluateAll((items) =>
    items.map((item) => {
      const node = item.querySelector<HTMLElement>('.hero-trust-route__node')
      const copy = item.querySelector<HTMLElement>('.hero-trust-route__copy')

      if (!node || !copy) {
        return null
      }

      const nodeRectangle = node.getBoundingClientRect()
      const copyRectangle = copy.getBoundingClientRect()

      return {
        nodeBottom: nodeRectangle.bottom,
        copyTop: copyRectangle.top,
      }
    }),
  )

  expect(steps).not.toContain(null)
  for (const step of steps) {
    expect(step?.copyTop).toBeGreaterThanOrEqual((step?.nodeBottom ?? 0) + 8)
  }
})

test('mobile release-readiness link is compact and centered', async ({
  page,
}) => {
  for (const localePath of ['/', '/ckb/', '/kmr/']) {
    await page.setViewportSize({ width: 430, height: 932 })
    await page.goto(localePath)

    const metrics = await page
      .locator('.hero-actions .button--secondary')
      .evaluate((link) => {
        const rectangle = link.getBoundingClientRect()

        return {
          center: rectangle.left + rectangle.width / 2,
          height: rectangle.height,
          viewportCenter: window.innerWidth / 2,
          width: rectangle.width,
        }
      })

    expect(
      Math.abs(metrics.center - metrics.viewportCenter),
      `${localePath} secondary action alignment`,
    ).toBeLessThanOrEqual(1)
    expect(metrics.width).toBeLessThan(260)
    expect(metrics.height).toBeGreaterThanOrEqual(44)
  }
})

test('profile ticket edges stay visually continuous', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')

  const edgeContent = await page.locator('.profile-ticket').evaluate((ticket) => ({
    after: getComputedStyle(ticket, '::after').content,
    before: getComputedStyle(ticket, '::before').content,
  }))

  expect(edgeContent).toEqual({
    after: 'none',
    before: 'none',
  })
})

test('phone layouts omit stretched route decoration while desktop keeps it', async ({
  page,
}) => {
  const selectors = [
    '.journey-track-wrap > .route-weave',
    '.site-footer > .route-weave',
  ]

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')

  for (const selector of selectors) {
    await expect(page.locator(selector)).toBeHidden()
  }

  await page.setViewportSize({ width: 1440, height: 900 })
  await page.reload()

  for (const selector of selectors) {
    await expect(page.locator(selector)).toBeVisible()
  }
})

test('light release-status cards keep small status copy at enhanced contrast', async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem('kurdistan-vpn-theme', 'light')
  })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')

  const contrastRatios = await page.locator('.release-status-list > li').evaluateAll((cards) => {
    const relativeLuminance = (value: string) => {
      const channels = value
        .match(/[\d.]+/g)
        ?.slice(0, 3)
        .map((channel) => Number(channel) / 255)

      if (!channels || channels.length !== 3) {
        throw new Error(`Unable to parse colour: ${value}`)
      }

      const linearChannels = channels.map((channel) =>
        channel <= 0.04045
          ? channel / 12.92
          : ((channel + 0.055) / 1.055) ** 2.4,
      )

      return (
        0.2126 * linearChannels[0] +
        0.7152 * linearChannels[1] +
        0.0722 * linearChannels[2]
      )
    }

    const contrast = (foreground: string, background: string) => {
      const foregroundLuminance = relativeLuminance(foreground)
      const backgroundLuminance = relativeLuminance(background)
      const lighter = Math.max(foregroundLuminance, backgroundLuminance)
      const darker = Math.min(foregroundLuminance, backgroundLuminance)

      return (lighter + 0.05) / (darker + 0.05)
    }

    return cards.map((card) => {
      const background = getComputedStyle(card).backgroundColor
      const marker = card.querySelector<HTMLElement>('.release-status-list__marker')
      const state = card.querySelector<HTMLElement>('.release-status-list__state')
      const summary = card.querySelector<HTMLElement>(
        '.release-status-list__content > p:not(.release-status-list__state)',
      )

      if (!marker || !state || !summary) {
        throw new Error('Release-status card content is incomplete')
      }

      return {
        marker: contrast(getComputedStyle(marker).color, background),
        state: contrast(getComputedStyle(state).color, background),
        summary: contrast(getComputedStyle(summary).color, background),
      }
    })
  })

  for (const ratios of contrastRatios) {
    expect(ratios.marker).toBeGreaterThanOrEqual(7)
    expect(ratios.state).toBeGreaterThanOrEqual(7)
    expect(ratios.summary).toBeGreaterThanOrEqual(7)
  }
})
