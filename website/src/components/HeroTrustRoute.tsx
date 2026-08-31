import { useId } from 'react'

type TrustRouteStep = {
  title: string
  copy: string
}

type HeroTrustRouteProps = {
  label: string
  steps: readonly TrustRouteStep[]
}

export function HeroTrustRoute({
  label,
  steps,
}: HeroTrustRouteProps) {
  const captionId = useId()

  return (
    <figure className="hero-trust-route" aria-labelledby={captionId}>
      <figcaption id={captionId}>{label}</figcaption>

      <ol>
        {steps.map((step, index) => (
          <li key={step.title}>
            <span className="hero-trust-route__node">{index + 1}</span>
            <div className="hero-trust-route__copy">
              <strong>{step.title}</strong>
              <p>{step.copy}</p>
            </div>
          </li>
        ))}
      </ol>
    </figure>
  )
}
