import { readFileSync, readdirSync, statSync } from 'node:fs'
import { extname, join, resolve } from 'node:path'
import { gzipSync } from 'node:zlib'

const budgets = {
  javascriptGzip: 90 * 1024,
  cssGzip: 24 * 1024,
  largestHeroImage: 260 * 1024,
  totalBuild: 1_600 * 1024,
}

function filesRecursively(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry)
    return statSync(path).isDirectory() ? filesRecursively(path) : [path]
  })
}

const distDirectory = resolve('dist')
const files = filesRecursively(distDirectory)

const javascriptGzip = files
  .filter((file) => extname(file) === '.js')
  .reduce(
    (total, file) => total + gzipSync(readFileSync(file)).byteLength,
    0,
  )

const cssGzip = files
  .filter((file) => extname(file) === '.css')
  .reduce(
    (total, file) => total + gzipSync(readFileSync(file)).byteLength,
    0,
  )

const heroImages = files.filter(
  (file) =>
    file.includes('routeweave') &&
    ['.avif', '.webp'].includes(extname(file)),
)

const largestHeroImage = Math.max(
  0,
  ...heroImages.map((file) => statSync(file).size),
)

const totalBuild = files.reduce(
  (total, file) => total + statSync(file).size,
  0,
)

const measured = {
  javascriptGzip,
  cssGzip,
  largestHeroImage,
  totalBuild,
}

for (const [name, limit] of Object.entries(budgets)) {
  const value = measured[name]

  if (value > limit) {
    throw new Error(
      `${name} exceeded its budget: ${value} bytes > ${limit} bytes`,
    )
  }
}

console.table(measured)
