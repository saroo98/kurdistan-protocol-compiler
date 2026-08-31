export function publicPath(
  path: string,
  base = import.meta.env.BASE_URL,
) {
  const normalizedBase = base.endsWith('/') ? base : `${base}/`
  const normalizedPath = path.replace(/^\/+/, '')

  return `${normalizedBase}${normalizedPath}`
}
