export type ReleaseMilestoneId =
  | 'foundation'
  | 'field-validation'
  | 'public-release'

export type ReleaseItemId =
  | 'compiler'
  | 'profiles'
  | 'android-foundation'
  | 'operator-control'
  | 'audit-foundation'
  | 'relay-egress'
  | 'android-release'
  | 'field-validation'

export type ReleaseState = 'implemented' | 'validating' | 'unreleased'

export const RELEASE_REVIEW_DATE = '2026-08-31'

export const releaseMilestones: readonly {
  id: ReleaseMilestoneId
  state: ReleaseState
  itemIds: readonly ReleaseItemId[]
}[] = [
  {
    id: 'foundation',
    state: 'implemented',
    itemIds: [
      'compiler',
      'profiles',
      'android-foundation',
      'operator-control',
      'audit-foundation',
    ],
  },
  {
    id: 'field-validation',
    state: 'validating',
    itemIds: ['field-validation'],
  },
  {
    id: 'public-release',
    state: 'unreleased',
    itemIds: ['relay-egress', 'android-release'],
  },
]
