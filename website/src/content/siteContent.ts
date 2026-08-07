export type RouteStyle = 'woven' | 'split' | 'quiet'

export type SyntheticProfile = {
  id: string
  name: string
  owner: string
  fingerprint: string
  expires: string
  routeStyle: RouteStyle
  state: 'verified' | 'expiring'
  trustLabel: string
  description: string
}

export const links = {
  repository: 'https://github.com/saroo98/kurdistan-protocol-compiler',
  selfHosting:
    'https://github.com/saroo98/kurdistan-protocol-compiler/blob/product/phase16-production-trust/docs/self-hosting/QUICKSTART.md',
  license:
    'https://github.com/saroo98/kurdistan-protocol-compiler/blob/product/phase16-production-trust/LICENSE',
} as const

export const navigation = [
  { label: 'How it works', href: '#how-it-works' },
  { label: 'Privacy', href: '#privacy' },
  { label: 'Self-host', href: '#self-host' },
  { label: 'Status', href: '#status' },
] as const

export const journey = [
  {
    title: 'Receive a profile',
    copy: 'An operator you know shares a signed Kurd profile with you.',
  },
  {
    title: 'Verify who you trust',
    copy: 'Check the fingerprint before adding the profile to your device.',
  },
  {
    title: 'Use its bounded route',
    copy: 'After release, the signed profile will limit the transport and fallback options the app may use.',
  },
] as const

export const syntheticProfiles: readonly SyntheticProfile[] = [
  {
    id: 'city-thread',
    name: 'City Thread',
    owner: 'Independent deployment A',
    fingerprint: 'KURD · 7A31 · D9C4 · DEMO',
    expires: 'Expires in 6 days',
    routeStyle: 'woven',
    state: 'verified',
    trustLabel: 'Fingerprint verified',
    description: 'A balanced synthetic profile showing a signed owner boundary and bounded fallback.',
  },
  {
    id: 'mountain-route',
    name: 'Mountain Route',
    owner: 'Independent deployment B',
    fingerprint: 'KURD · B204 · 8E12 · DEMO',
    expires: 'Expires in 2 days',
    routeStyle: 'split',
    state: 'expiring',
    trustLabel: 'Review before trusting',
    description: 'A synthetic profile near expiry. The app should make that state impossible to overlook.',
  },
  {
    id: 'quiet-current',
    name: 'Quiet Current',
    owner: 'Independent deployment C',
    fingerprint: 'KURD · 4F81 · A610 · DEMO',
    expires: 'Expires in 12 days',
    routeStyle: 'quiet',
    state: 'verified',
    trustLabel: 'Fingerprint verified',
    description: 'A restrained synthetic profile with no authority outside its signed policy.',
  },
] as const

export const privacyFacts = [
  ['No mandatory Kurdistan account', 'Trust begins with the deployment fingerprint you confirm, not a central product login.'],
  ['No central relay directory', 'Independent operators control their own VPS, authority, profiles, backups, and data.'],
  ['No required product analytics', 'The architecture does not depend on advertising, remote crash reporting, or central traffic logs.'],
  ['No global off switch', 'One independent deployment cannot revoke or disable another deployment.'],
] as const

export const selfHostFacts = [
  ['Create local authority', '`kurdctl` initializes deployment-local identity and recovery material.'],
  ['Issue signed profiles', 'Create bounded profiles, QR artifacts, expiry, rotation, and revocation under your authority.'],
  ['Run your own node', '`kurd-node` installs as a hardened, non-root service on an owner-controlled VPS.'],
  ['Keep recovery offline', 'Encrypted backups and recovery material stay outside the VPS and under the owner’s control.'],
] as const

export const implementedCapabilities = [
  'Profile-driven protocol compiler and generated transport modules',
  'Signed and recipient-sealed Kurd profile artifacts',
  'Android profile import, fingerprint confirmation, and protected storage',
  'Deployment-local authority, backup, recovery, and node administration',
  'Adversarial, mutation, parity, runtime, and security audit foundations',
] as const

export const unreleasedCapabilities = [
  'Public non-loopback Kurd relay and unrestricted Internet egress',
  'Public Android release artifact and distribution signing',
  'Broad physical-device and hosting-provider field validation',
  'Any guarantee of censorship bypass, anonymity, or immunity from blocking',
] as const
