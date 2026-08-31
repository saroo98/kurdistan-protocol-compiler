import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { chromium } from '@playwright/test'

const chromePath = chromium.executablePath()

if (!existsSync(chromePath)) {
  throw new Error(
    'Playwright Chromium is not installed. Run "npx playwright install chromium" before the Lighthouse audit.',
  )
}

const lhciCli = resolve('node_modules/@lhci/cli/src/cli.js')
const result = spawnSync(
  process.execPath,
  [lhciCli, 'autorun', ...process.argv.slice(2)],
  {
    env: {
      ...process.env,
      CHROME_PATH: chromePath,
    },
    stdio: 'inherit',
  },
)

if (result.error) {
  throw result.error
}

if (result.signal) {
  throw new Error(`Lighthouse terminated by signal ${result.signal}`)
}

process.exitCode = result.status ?? 1
