import { createHash, randomBytes } from 'node:crypto'
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import sharp from 'sharp'

const websiteRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(websiteRoot, '..')
const canonicalRoot = resolve(repositoryRoot, 'brand/kurdistan-vpn/v1')

const expectedArchive = {
  sha256: '1dd0df382a6a78450ef3460d2c1d08ca4960596369a36750dca580c014996384',
  bytes: 140452,
  entries: 18,
}

const expectedAssets = {
  'symbol-only.svg': {
    bytes: 440,
    sha256: 'd0d96c8b73e790d0d53586a5340d662f19af9b6468267c58fedd44b698367007',
    viewBox: '0 0 256 256',
  },
  'primary.svg': {
    bytes: 1120,
    sha256: 'ac9fa81dfd2a63955bd28744f8c8c67f456d88c34a5b9fa76e161a733f37fcea',
    viewBox: '0 0 920 256',
  },
  'reverse.svg': {
    bytes: 1120,
    sha256: '43232050c5aaade53b86f55bc3ac0ef955450214eb027a843f2d3fd5b113002c',
    viewBox: '0 0 920 256',
  },
  'compact-transparent.png': {
    bytes: 7501,
    sha256: '1c28d1e34706f6d86e930436f3411927e69587a627b0e96a399d9c38a3aaf24e',
  },
  '16.png': {
    bytes: 289,
    sha256: '8371cae2da56de66a0947346af0433355e5759531eedc1f3e87b676263dc5970',
  },
  '32.png': {
    bytes: 459,
    sha256: 'c4e76aba239f583f778f2303b2eb3e775e382b805a0cfa3fe2526c7e668b514e',
  },
  '64.png': {
    bytes: 827,
    sha256: '365d1cf3c0ad7127b7d5d999a47f684baaa1307cad22fd4370e8a57c8a54c99e',
  },
}

const allowedSourceFiles = new Set([
  'manifest.json',
  ...Object.keys(expectedAssets),
])

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message)
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function validateSvg(name, bytes, expectedViewBox) {
  const svg = bytes.toString('utf8')
  const forbiddenElement = /<\s*(?:script|foreignObject|iframe|object|embed|audio|video)\b/i
  const eventHandler = /\son[a-z][\w:-]*\s*=/i
  const externalReference = /(?:href|xlink:href|src)\s*=\s*["'](?!#)[^"']+["']/i
  const externalCssUrl = /url\(\s*["']?(?!#)[^)"']+["']?\s*\)/i
  const declaration = /<!DOCTYPE|<!ENTITY/i
  const localPath = /(?:^|[\s"'(])(?:[A-Za-z]:[\\/]|\\\\)|file:/i

  invariant(svg.startsWith('<svg '), `unsafe SVG ${name}: missing root element`)
  invariant(
    svg.includes(`viewBox="${expectedViewBox}"`),
    `unsafe SVG ${name}: unexpected viewBox`,
  )
  invariant(!forbiddenElement.test(svg), `unsafe SVG ${name}: forbidden element`)
  invariant(!eventHandler.test(svg), `unsafe SVG ${name}: event handler`)
  invariant(!externalReference.test(svg), `unsafe SVG ${name}: external reference`)
  invariant(!externalCssUrl.test(svg), `unsafe SVG ${name}: external CSS URL`)
  invariant(!declaration.test(svg), `unsafe SVG ${name}: XML declaration`)
  invariant(!localPath.test(svg), `unsafe SVG ${name}: local path`)
}

function readManifest(sourceRoot) {
  const path = resolve(sourceRoot, 'manifest.json')
  const stat = lstatSync(path)
  invariant(stat.isFile() && !stat.isSymbolicLink(), 'manifest must be a regular file')

  let manifest
  try {
    manifest = JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    throw new Error(`invalid brand manifest: ${error.message}`, { cause: error })
  }

  invariant(manifest.schemaVersion === 1, 'unexpected brand manifest schema')
  invariant(
    manifest.trademarkClearance === 'not-assessed',
    'trademark clearance must remain not-assessed',
  )
  invariant(
    manifest.sourceArchive?.sha256 === expectedArchive.sha256 &&
      manifest.sourceArchive?.bytes === expectedArchive.bytes &&
      manifest.sourceArchive?.entries === expectedArchive.entries,
    'source archive identity mismatch',
  )
  invariant(
    manifest.assets && typeof manifest.assets === 'object',
    'brand manifest assets are missing',
  )

  return manifest
}

function validateSource(sourceRoot) {
  const rootStat = lstatSync(sourceRoot)
  invariant(rootStat.isDirectory() && !rootStat.isSymbolicLink(), 'source root must be a directory')

  const entries = readdirSync(sourceRoot, { withFileTypes: true })
  invariant(entries.length === allowedSourceFiles.size, 'unexpected brand source entry count')

  for (const entry of entries) {
    invariant(allowedSourceFiles.has(entry.name), `unexpected brand source entry: ${entry.name}`)
    invariant(entry.isFile() && !entry.isSymbolicLink(), `brand source entry is not a regular file: ${entry.name}`)
  }

  const manifest = readManifest(sourceRoot)
  invariant(
    Object.keys(manifest.assets).length === Object.keys(expectedAssets).length,
    'unexpected manifest asset count',
  )

  for (const [name, expected] of Object.entries(expectedAssets)) {
    const path = resolve(sourceRoot, name)
    const bytes = readFileSync(path)
    const recorded = manifest.assets[name]

    invariant(recorded, `manifest asset missing: ${name}`)

    if (expected.viewBox) {
      validateSvg(name, bytes, expected.viewBox)
      invariant(recorded.svgSafety === 'passed', `SVG safety result missing: ${name}`)
      invariant(recorded.viewBox === expected.viewBox, `manifest viewBox mismatch: ${name}`)
    }

    invariant(bytes.byteLength === expected.bytes, `approved length mismatch: ${name}`)
    invariant(sha256(bytes) === expected.sha256, `approved digest mismatch: ${name}`)
    invariant(recorded.bytes === expected.bytes, `manifest length mismatch: ${name}`)
    invariant(recorded.sha256 === expected.sha256, `manifest digest mismatch: ${name}`)
    invariant(recorded.sourceEntry === `assets/${name}`, `manifest source entry mismatch: ${name}`)
  }

  return manifest
}

function atomicWrite(path, bytes) {
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`

  try {
    writeFileSync(temporary, bytes, { flag: 'wx' })
    renameSync(temporary, path)
  } finally {
    rmSync(temporary, { force: true })
  }
}

async function atomicRenderPng(path, svg) {
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`

  try {
    await sharp(Buffer.from(svg))
      .png({ compressionLevel: 9, palette: false })
      .toFile(temporary)
    renameSync(temporary, path)
  } finally {
    rmSync(temporary, { force: true })
  }
}

function renderSocialSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="ground" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#090a19"/>
      <stop offset="1" stop-color="#17102e"/>
    </linearGradient>
    <linearGradient id="route" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#147f79"/>
      <stop offset="0.52" stop-color="#48bdb3"/>
      <stop offset="1" stop-color="#8278b8"/>
    </linearGradient>
    <filter id="route-shadow" x="-20%" y="-30%" width="140%" height="160%">
      <feDropShadow dx="0" dy="18" stdDeviation="20" flood-color="#000000" flood-opacity="0.34"/>
    </filter>
  </defs>
  <rect width="1200" height="630" fill="url(#ground)"/>
  <path d="M-80 515 C185 408 322 590 562 482 C777 386 905 470 1280 316" fill="none" stroke="#102f46" stroke-width="74" stroke-linecap="round" opacity="0.9" filter="url(#route-shadow)"/>
  <path d="M-70 477 C208 352 358 567 590 430 C826 292 972 384 1270 252" fill="none" stroke="url(#route)" stroke-width="31" stroke-linecap="round"/>
  <path d="M-80 555 C226 464 374 616 610 526 C858 431 1010 502 1270 394" fill="none" stroke="#d6a04d" stroke-width="14" stroke-linecap="round" opacity="0.86"/>
  <path d="M650 -60 C778 144 925 149 1286 89" fill="none" stroke="#173f55" stroke-width="86" stroke-linecap="round" opacity="0.64"/>
  <image href="../public/brand/kurdistan-vpn-reverse.svg" x="72" y="62" width="552" height="154"/>
  <text x="76" y="316" fill="#f3efe5" font-family="Arial, sans-serif" font-size="78" font-weight="700" letter-spacing="-3">Your internet.</text>
  <text x="76" y="400" fill="#f3efe5" font-family="Arial, sans-serif" font-size="78" font-weight="700" letter-spacing="-3">Your route.</text>
  <text x="79" y="438" fill="#aaa8b6" font-family="Arial, sans-serif" font-size="25">Signed profiles. Owner-controlled nodes. Android coming soon.</text>
  <g transform="translate(918 510)">
    <rect width="206" height="54" rx="27" fill="#11132b" stroke="#48bdb3" stroke-opacity="0.45"/>
    <circle cx="29" cy="27" r="6" fill="#d6a04d"/>
    <text x="50" y="35" fill="#c9c6d2" font-family="Arial, sans-serif" font-size="17" font-weight="700">PROFILE-DRIVEN</text>
  </g>
</svg>
`
}

async function syncWebsite(sourceRoot) {
  validateSource(sourceRoot)

  const symbol = readFileSync(resolve(sourceRoot, 'symbol-only.svg'), 'utf8')
  const primary = readFileSync(resolve(sourceRoot, 'primary.svg'))
  const reverse = readFileSync(resolve(sourceRoot, 'reverse.svg'))
  const publicSymbol = symbol.replace('fill="#0B1220"', 'fill="#16BFAE"')
  invariant(publicSymbol !== symbol, 'canonical symbol color token was not found')

  atomicWrite(resolve(websiteRoot, 'public/brand/kurdistan-vpn-primary.svg'), primary)
  atomicWrite(resolve(websiteRoot, 'public/brand/kurdistan-vpn-reverse.svg'), reverse)
  atomicWrite(resolve(websiteRoot, 'public/kurdistan-mark.svg'), publicSymbol)

  for (const size of [16, 32, 64]) {
    atomicWrite(
      resolve(websiteRoot, `public/favicon-${size}.png`),
      readFileSync(resolve(sourceRoot, `${size}.png`)),
    )
  }

  const socialSvg = renderSocialSvg()
  const socialSource = resolve(websiteRoot, 'artifacts/og-kurdistan-vpn.svg')
  atomicWrite(socialSource, socialSvg)

  const embeddedReverse = `data:image/svg+xml;base64,${reverse.toString('base64')}`
  const renderedSocialSvg = socialSvg.replace(
    '../public/brand/kurdistan-vpn-reverse.svg',
    embeddedReverse,
  )
  await atomicRenderPng(
    resolve(websiteRoot, 'public/og-kurdistan-vpn.png'),
    renderedSocialSvg,
  )
}

function parseArguments(argv) {
  let mode
  let sourceRoot = canonicalRoot

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]

    if (argument === '--check' || argument === '--website') {
      invariant(!mode, 'exactly one brand operation is required')
      mode = argument.slice(2)
      continue
    }

    if (argument === '--source-root') {
      invariant(index + 1 < argv.length, '--source-root requires a value')
      sourceRoot = resolve(argv[index + 1])
      index += 1
      continue
    }

    throw new Error(`unknown argument: ${argument}`)
  }

  invariant(mode === 'check' || mode === 'website', 'use --check or --website')
  return { mode, sourceRoot }
}

async function main() {
  const { mode, sourceRoot } = parseArguments(process.argv.slice(2))

  if (mode === 'check') {
    validateSource(sourceRoot)
    console.log('BRAND_SOURCE=VALID')
    return
  }

  await syncWebsite(sourceRoot)
  console.log('BRAND_WEBSITE=SYNCED')
}

main().catch((error) => {
  console.error(`BRAND_ERROR=${error.message}`)
  process.exitCode = 1
})
