import { mkdirSync } from 'node:fs'
import { resolve } from 'node:path'
import sharp from 'sharp'

const outputDirectory = resolve('src/assets/hero')
mkdirSync(outputDirectory, { recursive: true })

const jobs = [
  {
    source: resolve('src/assets/routeweave-hero-mobile.webp'),
    widths: [480, 640],
    prefix: 'routeweave-mobile',
  },
  {
    source: resolve('src/assets/routeweave-hero.webp'),
    widths: [960, 1280, 1536],
    prefix: 'routeweave',
  },
]

for (const job of jobs) {
  for (const width of job.widths) {
    const base = sharp(job.source)
      .resize({
        width,
        withoutEnlargement: true,
      })
      .withMetadata({ orientation: undefined })

    await base
      .clone()
      .avif({ quality: 52, effort: 6 })
      .toFile(resolve(outputDirectory, `${job.prefix}-${width}.avif`))

    await base
      .clone()
      .webp({ quality: 72, effort: 6 })
      .toFile(resolve(outputDirectory, `${job.prefix}-${width}.webp`))
  }
}
