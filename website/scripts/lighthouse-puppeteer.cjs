/**
 * Keep Lighthouse attached to a Puppeteer-managed browser.
 *
 * LHCI invokes this hook before each URL. The hook does not mutate the page;
 * enabling it makes LHCI launch one reusable browser and pass its debugging
 * port to Lighthouse, which avoids flaky per-run Chrome profile cleanup on
 * Windows. Chromium can report its WebSocket endpoint a moment before the
 * HTTP discovery endpoint is ready, so wait for that endpoint explicitly.
 */
module.exports = async function lighthouseBrowserHook(browser) {
  const debuggingPort = new URL(browser.wsEndpoint()).port
  const versionUrl = `http://127.0.0.1:${debuggingPort}/json/version`

  for (let attempt = 0; attempt < 25; attempt += 1) {
    try {
      const response = await fetch(versionUrl)

      if (response.ok) return
    } catch {
      // Chromium is still bringing up its local debugging endpoint.
    }

    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  throw new Error(
    `Chromium debugging endpoint did not become ready at ${versionUrl}`,
  )
}
