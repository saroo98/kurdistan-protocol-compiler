import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { translations } from '../i18n/translations'

const prohibitedPatterns = [
  /guaranteed censorship bypass/i,
  /guaranteed anonymity/i,
  /anonymous by default/i,
  /undetectable/i,
  /unblock everything/i,
  /production[- ]ready/i,
  /military[- ]grade/i,
]

function flatten(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (typeof value === 'function') return []
  if (Array.isArray(value)) return value.flatMap(flatten)

  if (value && typeof value === 'object') {
    return Object.values(value).flatMap(flatten)
  }

  return []
}

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry)

    if (statSync(path).isDirectory()) return sourceFiles(path)

    return /\.(tsx?|html)$/.test(path) && !/\.test\.[jt]sx?$/.test(path)
      ? [path]
      : []
  })
}

function applicationSource() {
  return sourceFiles(resolve('src'))
    .map((path) => readFileSync(path, 'utf8'))
    .join('\n')
}

describe('public claim integrity', () => {
  it('contains none of the prohibited marketing claims', () => {
    const publicCopy = flatten(translations).join('\n')

    for (const pattern of prohibitedPatterns) {
      expect(publicCopy).not.toMatch(pattern)
    }
  })

  it('contains no inline JSX style attributes', () => {
    expect(applicationSource()).not.toMatch(/\bstyle\s*=\s*\{\{/)
  })

  it('protects every external blank-target link', () => {
    const externalLinks =
      applicationSource().match(
        /<a\b(?:(?!<\/a>)[\s\S])*?target="_blank"(?:(?!<\/a>)[\s\S])*?<\/a>/g,
      ) ?? []

    expect(externalLinks.length).toBeGreaterThan(0)

    for (const link of externalLinks) {
      expect(link).toContain('rel="noopener noreferrer"')
    }
  })
})
