import { publicPath } from '../lib/publicPath'

type DevicePreviewProps = {
  label: string
}

export function DevicePreview({ label }: DevicePreviewProps) {
  return (
    <figure className="device-stage" aria-label={label}>
      <div className="android-device" aria-hidden="true">
        <div className="device-speaker" />
        <div className="device-screen" lang="en" dir="ltr">
          <div className="device-topline">
            <img
              src={publicPath('kurdistan-mark.svg')}
              alt=""
              width="30"
              height="30"
            />
            <span>Kurdistan VPN</span>
            <i />
          </div>

          <div className="device-orbit">
            <span className="orbit orbit--one" />
            <span className="orbit orbit--two" />
            <span className="orbit orbit--three" />
            <div className="device-core">K</div>
          </div>

          <div className="device-state">
            <span>Profile verified</span>
            <strong>City Thread</strong>
            <code>7A31 · D9C4</code>
          </div>

          <div className="device-action">
            <span />
            Android release coming soon
          </div>
        </div>
      </div>
    </figure>
  )
}
