import { describe, expect, it } from 'vitest'
import { publicPath } from './publicPath'

describe('publicPath', () => {
  it('keeps public assets and locale routes inside a deployment base', () => {
    expect(publicPath('/kurdistan-mark.svg', '/project/')).toBe(
      '/project/kurdistan-mark.svg',
    )
    expect(publicPath('ckb/', '/project/')).toBe('/project/ckb/')
    expect(publicPath('', '/project/')).toBe('/project/')
  })

  it('preserves root hosting without duplicate slashes', () => {
    expect(publicPath('/kurdistan-mark.svg', '/')).toBe(
      '/kurdistan-mark.svg',
    )
  })
})
