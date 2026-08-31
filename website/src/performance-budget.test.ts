import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('hero delivery', () => {
  it('ships responsive AVIF and WebP sources with explicit sizes', () => {
    const source = readFileSync(
      resolve('src/components/Hero.tsx'),
      'utf8',
    )

    expect(source).toContain('type="image/avif"')
    expect(source).toContain('type="image/webp"')
    expect(source).toContain('sizes=')
    expect(source).toContain('640w')
    expect(source).toContain('960w')
    expect(source).toContain('1280w')
  })
})
