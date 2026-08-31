import { createHash } from 'node:crypto'
import {
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'

function htmlFiles(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry)

    if (statSync(path).isDirectory()) {
      return htmlFiles(path)
    }

    return path.endsWith('.html') ? [path] : []
  })
}

for (const file of htmlFiles(resolve('dist'))) {
  const html = readFileSync(file, 'utf8')
  const bootstrapMatch = html.match(
    /<script data-theme-bootstrap>([\s\S]*?)<\/script>/,
  )

  if (!bootstrapMatch) {
    throw new Error(`Theme bootstrap missing from ${file}`)
  }

  if (html.includes('http-equiv="Content-Security-Policy"')) {
    throw new Error(`CSP already exists in ${file}`)
  }

  const hash = createHash('sha256')
    .update(bootstrapMatch[1])
    .digest('base64')

  const policy = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "form-action 'none'",
    "frame-src 'none'",
    "worker-src 'none'",
    "img-src 'self' data:",
    "font-src 'self'",
    "style-src 'self'",
    `script-src 'self' 'sha256-${hash}'`,
    "connect-src 'self'",
    'upgrade-insecure-requests',
  ].join('; ')

  const securityMetadata = `
    <meta http-equiv="Content-Security-Policy" content="${policy}" />
    <meta name="referrer" content="strict-origin-when-cross-origin" />`

  writeFileSync(
    file,
    html.replace('</head>', `${securityMetadata}\n  </head>`),
  )
}
