import type { RouteStyle } from '../content/siteContent'
import { useReducedMotion } from '../hooks/useReducedMotion'

type RouteWeaveProps = {
  variant?: 'hero' | 'journey' | 'profile'
  routeStyle?: RouteStyle
  className?: string
}

const paths = [
  'M-30 108 C150 12 276 194 438 104 S710 4 930 110 S1190 214 1470 80',
  'M-40 196 C160 302 276 76 470 186 S760 316 972 176 S1202 48 1470 210',
  'M-24 276 C154 174 318 352 510 264 S826 152 1048 272 S1260 362 1474 244',
  'M-10 40 C190 154 322 -8 536 84 S842 214 1072 96 S1282 -8 1478 60',
]

export function RouteWeave({
  variant = 'hero',
  routeStyle = 'woven',
  className = '',
}: RouteWeaveProps) {
  const reducedMotion = useReducedMotion()
  const classes = [
    'route-weave',
    `route-weave--${variant}`,
    `route-weave--${routeStyle}`,
    reducedMotion ? 'is-static' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <svg
      className={classes}
      viewBox="-50 0 1540 360"
      preserveAspectRatio="none"
      aria-hidden="true"
      focusable="false"
    >
      <g className="route-weave__shadow">
        {paths.map((path) => (
          <path key={`shadow-${path}`} d={path} />
        ))}
      </g>
      <g className="route-weave__threads">
        {paths.map((path, index) => (
          <path
            key={path}
            className={`route-weave__thread route-weave__thread--${index + 1}`}
            d={path}
          />
        ))}
      </g>
      <g className="route-weave__stitches">
        <path d={paths[0]} />
        <path d={paths[2]} />
      </g>
      <g className="route-weave__register">
        <circle cx="438" cy="104" r="6" />
        <circle cx="972" cy="176" r="6" />
        <path d="M1052 70h36M1070 52v36" />
      </g>
    </svg>
  )
}
