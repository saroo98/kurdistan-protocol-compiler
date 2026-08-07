import { useLocale } from '../i18n/LocaleContext'

type StatusListProps = {
  title: string
  items: readonly string[]
  state: 'available' | 'unreleased'
}

function StatusList({ title, items, state }: StatusListProps) {
  return (
    <div className={`status-list status-list--${state}`}>
      <div className="status-list__heading">
        <span aria-hidden="true" />
        <h3>{title}</h3>
      </div>
      <ul>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  )
}

export function StatusSection() {
  const { copy } = useLocale()

  return (
    <section className="status-section page-shell" id="status" aria-labelledby="status-title">
      <div className="status-heading">
        <h2 id="status-title">{copy.status.title}</h2>
        <p>{copy.status.intro}</p>
      </div>
      <div className="status-grid">
        <StatusList
          title={copy.status.available}
          items={copy.status.implemented}
          state="available"
        />
        <StatusList
          title={copy.status.unreleased}
          items={copy.status.notReleased}
          state="unreleased"
        />
      </div>
    </section>
  )
}
