import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import sharp from 'sharp'
import { afterEach, describe, expect, it } from 'vitest'

const websiteRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(websiteRoot, '..')
const canonicalRoot = resolve(repositoryRoot, 'brand/kurdistan-vpn/v1')
const generator = resolve(websiteRoot, 'scripts/sync-brand-assets.mjs')
const temporaryRoots: string[] = []

const expectedArchiveSha256 =
  '1dd0df382a6a78450ef3460d2c1d08ca4960596369a36750dca580c014996384'

const expectedAssets = {
  'symbol-only.svg':
    'd0d96c8b73e790d0d53586a5340d662f19af9b6468267c58fedd44b698367007',
  'primary.svg':
    'ac9fa81dfd2a63955bd28744f8c8c67f456d88c34a5b9fa76e161a733f37fcea',
  'reverse.svg':
    '43232050c5aaade53b86f55bc3ac0ef955450214eb027a843f2d3fd5b113002c',
  'compact-transparent.png':
    '1c28d1e34706f6d86e930436f3411927e69587a627b0e96a399d9c38a3aaf24e',
  '16.png':
    '8371cae2da56de66a0947346af0433355e5759531eedc1f3e87b676263dc5970',
  '32.png':
    'c4e76aba239f583f778f2303b2eb3e775e382b805a0cfa3fe2526c7e668b514e',
  '64.png':
    '365d1cf3c0ad7127b7d5d999a47f684baaa1307cad22fd4370e8a57c8a54c99e',
} as const

function sha256(path: string) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function newFixture() {
  const root = mkdtempSync(resolve(tmpdir(), 'kurdistan-brand-'))
  temporaryRoots.push(root)
  cpSync(canonicalRoot, root, { recursive: true })
  return root
}

function runCheck(sourceRoot: string) {
  return spawnSync(
    process.execPath,
    [generator, '--check', '--source-root', sourceRoot],
    { encoding: 'utf8' },
  )
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { force: true, recursive: true })
  }
})

describe('canonical Kurdistan VPN brand assets', () => {
  it('binds the approved archive and every canonical master by digest', () => {
    const manifestPath = resolve(canonicalRoot, 'manifest.json')
    expect(existsSync(manifestPath), 'canonical manifest must exist').toBe(true)
    if (!existsSync(manifestPath)) return

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    expect(manifest.sourceArchive.sha256).toBe(expectedArchiveSha256)
    expect(manifest.sourceArchive.bytes).toBe(140_452)
    expect(manifest.sourceArchive.entries).toBe(18)
    expect(manifest.trademarkClearance).toBe('not-assessed')
    expect(JSON.stringify(manifest)).not.toMatch(/[A-Za-z]:[\\/]/)

    for (const [name, digest] of Object.entries(expectedAssets)) {
      const path = resolve(canonicalRoot, name)
      expect(existsSync(path), `${name} must exist`).toBe(true)
      if (!existsSync(path)) continue
      expect(sha256(path), `${name} must retain its approved bytes`).toBe(
        digest,
      )
      expect(manifest.assets[name].sha256).toBe(digest)
      expect(manifest.assets[name].bytes).toBe(readFileSync(path).byteLength)
    }
  })

  it('keeps every canonical SVG self-contained and inert', () => {
    for (const name of ['symbol-only.svg', 'primary.svg', 'reverse.svg']) {
      const path = resolve(canonicalRoot, name)
      expect(existsSync(path), `${name} must exist`).toBe(true)
      if (!existsSync(path)) continue
      const svg = readFileSync(path, 'utf8')
      expect(svg).toMatch(/viewBox="[^"]+"/)
      expect(svg).not.toMatch(
        /<script|<foreignObject|\son[a-z]+\s*=|(?:href|src)\s*=\s*["'](?:https?:|data:|file:|[A-Za-z]:[\\/])/i,
      )
    }
  })

  it.each([
    ['16.png', 16],
    ['32.png', 32],
    ['64.png', 64],
  ])('retains the exact %s favicon dimensions', async (name, size) => {
    const metadata = await sharp(resolve(canonicalRoot, name)).metadata()
    expect(metadata.width).toBe(size)
    expect(metadata.height).toBe(size)
  })

  it('derives the public mark and social artwork from the canonical masters', async () => {
    const publicMark = resolve(websiteRoot, 'public/kurdistan-mark.svg')
    const canonicalSymbol = readFileSync(
      resolve(canonicalRoot, 'symbol-only.svg'),
      'utf8',
    )
    const publicSymbol = readFileSync(publicMark, 'utf8')
    const canonicalPaths = canonicalSymbol.match(/\sd="[^"]+"/g)

    expect(publicSymbol.match(/\sd="[^"]+"/g)).toEqual(canonicalPaths)
    expect(publicSymbol).toContain('#16BFAE')
    expect(
      readFileSync(resolve(websiteRoot, 'public/brand/kurdistan-vpn-primary.svg')),
    ).toEqual(readFileSync(resolve(canonicalRoot, 'primary.svg')))
    expect(
      readFileSync(resolve(websiteRoot, 'public/brand/kurdistan-vpn-reverse.svg')),
    ).toEqual(readFileSync(resolve(canonicalRoot, 'reverse.svg')))

    for (const size of [16, 32, 64]) {
      expect(readFileSync(resolve(websiteRoot, `public/favicon-${size}.png`))).toEqual(
        readFileSync(resolve(canonicalRoot, `${size}.png`)),
      )
    }

    expect(readFileSync(resolve(websiteRoot, 'artifacts/og-kurdistan-vpn.svg'), 'utf8')).toContain(
      'kurdistan-vpn-reverse.svg',
    )

    const social = await sharp(
      resolve(websiteRoot, 'public/og-kurdistan-vpn.png'),
    ).metadata()
    expect(social.width).toBe(1200)
    expect(social.height).toBe(630)
  })

  it('validates the checked-in canonical source without rewriting it', () => {
    const result = runCheck(canonicalRoot)
    expect(result.status, result.stderr).toBe(0)
    expect(result.stdout).toContain('BRAND_SOURCE=VALID')
  })

  it('rejects changed bytes, unexpected files, and unsafe SVG content', () => {
    const changed = newFixture()
    writeFileSync(resolve(changed, '16.png'), 'changed')
    expect(runCheck(changed).status).not.toBe(0)

    const unexpected = newFixture()
    writeFileSync(resolve(unexpected, 'unexpected.txt'), 'not allowlisted')
    expect(runCheck(unexpected).status).not.toBe(0)

    const unsafe = newFixture()
    const unsafePath = resolve(unsafe, 'symbol-only.svg')
    writeFileSync(
      unsafePath,
      readFileSync(unsafePath, 'utf8').replace('</svg>', '<script>0</script></svg>'),
    )
    const unsafeManifestPath = resolve(unsafe, 'manifest.json')
    const unsafeManifest = JSON.parse(readFileSync(unsafeManifestPath, 'utf8'))
    unsafeManifest.assets['symbol-only.svg'].sha256 = sha256(unsafePath)
    unsafeManifest.assets['symbol-only.svg'].bytes = readFileSync(unsafePath).byteLength
    writeFileSync(unsafeManifestPath, `${JSON.stringify(unsafeManifest, null, 2)}\n`)
    const unsafeResult = runCheck(unsafe)
    expect(unsafeResult.status).not.toBe(0)
    expect(unsafeResult.stderr).toMatch(/unsafe svg/i)
  })
})
