# Phase 18 feature coverage

## Status

This is a planning-completeness contract for [the Task 0 production contract](PHASE18_ANDROID_PRODUCTION_CONTRACT.md#capability-gated-feature-ledger). It does not claim implementation, execution, installation, qualification, or release.

- Current implementation state: `NOT_STARTED`
- Phase 18 decision: `NO_GO`
- Release authorization: `NO_GO`
- Frozen legacy-coverage digest: `8f1235653f1e3367f164660cd805921279282177bf8c35faaaef196fc149bbb4`
- Legacy scope: `D0-D28`; inspiration inventory reconciled: `true`.
- Canonical control count: `311`
- Canonical control-set SHA-256: `b922c3411014eb680b2aeef0bb75c3c35a6872734c92e8a14faab4a485c401c7`

## Feature ledger

| Feature | Capability | Frozen disposition | Target disposition | Capability admission | Owning tasks | Current state |
| --- | --- | --- | --- | --- | --- | --- |
| P18-F001 | Three-area navigation | Phase 18 | delivered-production | NOT_APPLICABLE | 14,27 | planned |
| P18-F002 | Large daily connection control | Phase 18 | delivered-production | NOT_APPLICABLE | 16 | planned |
| P18-F003 | Current provider/server card | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 16,17 | planned |
| P18-F004 | Live latency, speed, duration, counters | Phase 18 | delivered-production | NOT_APPLICABLE | 16,19,30 | planned |
| P18-F005 | Exit country/region | Capability-gated | inapplicable-final | NOT_ADMITTED | 16,30 | planned |
| P18-F006 | Favorites, recent use, search, filter, sort | Phase 18 | delivered-production | NOT_APPLICABLE | 17 | planned |
| P18-F007 | Provider/subscription groups | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 17,18 | planned |
| P18-F008 | Provider quota/HWID/install ID/user-agent | Rejected | rejected-final | NOT_APPLICABLE | 3,17,31 | planned |
| P18-F009 | QR/file/clipboard/share/`kurd://` import | Phase 18 | delivered-production | NOT_APPLICABLE | 15 | planned |
| P18-F010 | Direct remote subscription URL | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 18 | planned |
| P18-F011 | Arbitrary VLESS/VMess/Trojan/Shadowsocks import | Rejected for v1 | rejected-final | NOT_APPLICABLE | 15,31 | planned |
| P18-F012 | Manual endpoint/protocol editor | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 17,22 | planned |
| P18-F013 | TLS/REALITY/fingerprint/Allow Insecure editor | Rejected | rejected-final | NOT_APPLICABLE | 22,31 | planned |
| P18-F014 | Native strategy taxonomy | Capability-gated | delivered-production | ADMITTED | 17 | planned |
| P18-F015 | Manual strategy choice | Capability-gated | delivered-production | ADMITTED | 17 | planned |
| P18-F016 | Fragmentation, padding, noise, Mux, cover streams | Capability-gated | inapplicable-final | NOT_ADMITTED | 22 | planned |
| P18-F017 | Profile share/copy URL/copy JSON | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 24 | planned |
| P18-F018 | Send to TV/device | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 24 | planned |
| P18-F019 | Per-app include/exclude | Phase 18 | delivered-production | NOT_APPLICABLE | 10,21,29,30 | planned |
| P18-F020 | App categories | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 21 | planned |
| P18-F021 | Auto-connect on app launch | Phase 18 | delivered-production | NOT_APPLICABLE | 11,20 | planned |
| P18-F022 | Auto-connect at boot | Capability-gated | delivered-production | ADMITTED | 11,20 | planned |
| P18-F023 | Kill switch toggle | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 11,20 | planned |
| P18-F024 | Trusted network rules | Phase 18 | delivered-production | NOT_APPLICABLE | 20 | planned |
| P18-F025 | Allow LAN | Capability-gated | inapplicable-final | NOT_ADMITTED | 10,21,30 | planned |
| P18-F026 | Public hotspot proxy | Later gate | rejected-final | NOT_APPLICABLE | 12,21,31 | planned |
| P18-F027 | TUN only | Phase 18 | delivered-production | NOT_APPLICABLE | 9,10,30 | planned |
| P18-F028 | TUN plus local proxy | Phase 18 | delivered-production | NOT_APPLICABLE | 12,21,30 | planned |
| P18-F029 | Local proxy only | Capability-gated | inapplicable-final | NOT_ADMITTED | 12,21 | planned |
| P18-F030 | Hide notification/icon | Rejected | rejected-final | NOT_APPLICABLE | 9,22,31 | planned |
| P18-F031 | SOCKS5/HTTP credentials | Phase 18 | delivered-production | NOT_APPLICABLE | 12,23 | planned |
| P18-F032 | External/open proxy logging | Rejected | rejected-final | NOT_APPLICABLE | 12,25,31 | planned |
| P18-F033 | IPv4, IPv6, dual stack, auto | Capability-gated | delivered-production | ADMITTED | 10,21,30 | planned |
| P18-F034 | Internal in-tunnel DNS | Phase 18 | delivered-production | NOT_APPLICABLE | 10,21,30 | planned |
| P18-F035 | Public DNS presets | Capability-gated | inapplicable-final | NOT_ADMITTED | 10,21,30 | planned |
| P18-F036 | Custom DNS | Phase 18 | delivered-production | NOT_APPLICABLE | 10,21,30 | planned |
| P18-F037 | DNS leak test | Phase 18 | delivered-production | NOT_APPLICABLE | 21,30 | planned |
| P18-F038 | WebRTC leak test | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 25 | planned |
| P18-F039 | Probe method selection | Capability-gated | inapplicable-final | NOT_ADMITTED | 19 | planned |
| P18-F040 | Ping history/jitter/loss/stability | Phase 18 | delivered-production | NOT_APPLICABLE | 19 | planned |
| P18-F041 | “Fastest” selection | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 19 | planned |
| P18-F042 | Profile auto-update | Phase 18 | delivered-production | NOT_APPLICABLE | 18,30 | planned |
| P18-F043 | Theme/language/app icon | Phase 18 | delivered-production | NOT_APPLICABLE | 22,27,30 | planned |
| P18-F044 | Multiple decorative color themes | Rejected for v1 | rejected-final | NOT_APPLICABLE | 22,31 | planned |
| P18-F045 | About/version/licenses/privacy | Phase 18 | delivered-production | NOT_APPLICABLE | 26 | planned |
| P18-F046 | Rate/share app | Capability-gated | inapplicable-final | NOT_ADMITTED | 26 | planned |
| P18-F047 | URL/deep-link automation | Capability-gated | inapplicable-final | NOT_ADMITTED | 26,29 | planned |
| P18-F048 | Backup and selective restore | Phase 18 | delivered-production | NOT_APPLICABLE | 24,30 | planned |
| P18-F049 | Backup QR/copy link | Capability-gated | delivered-production | ADMITTED | 24 | planned |
| P18-F050 | Performance presets | Capability-gated | inapplicable-final | NOT_ADMITTED | 22,28,30 | planned |
| P18-F051 | CPU/memory/battery/thermal status | Phase 18 | delivered-production | NOT_APPLICABLE | 22,28,30 | planned |
| P18-F052 | Crash counter and safe restart | Phase 18 | delivered-production | NOT_APPLICABLE | 28,30 | planned |
| P18-F053 | Expert MTU/limits/routes/UDP | Capability-gated | inapplicable-final | NOT_ADMITTED | 21,22,29 | planned |
| P18-F054 | Traffic sniffing | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 25,31 | planned |
| P18-F055 | Diagnostic level/retention | Phase 18 | delivered-production | NOT_APPLICABLE | 25 | planned |
| P18-F056 | Tunnel logs as raw text | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 25 | planned |
| P18-F057 | Scoped reset | Phase 18 | delivered-production | NOT_APPLICABLE | 24,30 | planned |
| P18-F058 | Privacy dashboard | Phase 18 | delivered-production | NOT_APPLICABLE | 23,26 | planned |
| P18-F059 | App lock/biometric | Phase 18 | delivered-production | NOT_APPLICABLE | 23 | planned |
| P18-F060 | Usage statistics | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 23 | planned |
| P18-F061 | Multi-provider priority/failover | Safely replaced | safely-replaced-final | NOT_APPLICABLE | 11,17,30 | planned |
| P18-F062 | Smart reconnect | Phase 18 | delivered-production | NOT_APPLICABLE | 11,30 | planned |
| P18-F063 | Captive portal guidance | Phase 18 | delivered-production | NOT_APPLICABLE | 11,20,25,30 | planned |
| P18-F064 | OEM/battery/autostart guidance | Phase 18 | delivered-production | NOT_APPLICABLE | 20,25,27 | planned |
| P18-F065 | Accessibility and RTL | Phase 18 | delivered-production | NOT_APPLICABLE | 27,30 | planned |
| P18-F066 | Phones, tablets, foldables | Phase 18 | delivered-production | NOT_APPLICABLE | 14,27,30 | planned |
| P18-F067 | Guaranteed bypass, anonymity, undetectability, “uncensorable” | Rejected | rejected-final | NOT_APPLICABLE | 26,31 | planned |

## Screen ledger

| Screen | Route | Planned owner file | Planned owner symbol | Planned state owner | Navigation root |
| --- | --- | --- | --- | --- | --- |
| P18-S01 | `Welcome` | `android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/WelcomeScreen.kt` | `WelcomeScreen` | `OnboardingViewModel, OnboardingState` | true |
| P18-S02 | `ImportSource` | `android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/ImportSourceScreen.kt` | `ImportSourceScreen` | `OnboardingViewModel, ImportCoordinator` | false |
| P18-S03 | `FirstTrust(importId)` | `android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/FirstTrustScreen.kt` | `FirstTrustScreen` | `OnboardingViewModel, ProfileRepository` | false |
| P18-S04 | `VpnPermissionEducation` | `android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/VpnPermissionScreen.kt` | `VpnPermissionScreen` | `OnboardingViewModel, SystemPolicyRepository` | false |
| P18-S05 | `Home` | `android/feature/home/src/main/kotlin/org/kurdistanvpn/feature/home/HomeScreen.kt` | `HomeScreen` | `ConnectionViewModel, ConnectionState` | true |
| P18-S06 | `RouteDetail(sessionAlias)` | `android/feature/home/src/main/kotlin/org/kurdistanvpn/feature/home/RouteDetailScreen.kt` | `RouteDetailScreen` | `ConnectionViewModel, VerifiedRouteSnapshot` | false |
| P18-S07 | `Profiles` | `android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/ProfilesScreen.kt` | `ProfilesScreen` | `ProfilesViewModel, DeploymentListState` | true |
| P18-S08 | `DeploymentDetail(deploymentId)` | `android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/DeploymentDetailScreen.kt` | `DeploymentDetailScreen` | `ProfilesViewModel, DeploymentDetailState` | false |
| P18-S09 | `ProfileDetail(profileId)` | `android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/ProfileDetailScreen.kt` | `ProfileDetailScreen` | `ProfilesViewModel, ProfileDetailState` | false |
| P18-S10 | `StrategyMatrix(profileId)` | `android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/StrategyMatrixScreen.kt` | `StrategyMatrixScreen` | `ProfilesViewModel, StrategyMatrixState` | false |
| P18-S11 | `ProbeHistory(profileId)` | `android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/ProbeHistoryScreen.kt` | `ProbeHistoryScreen` | `ProfilesViewModel, ProbeHistoryState` | false |
| P18-S12 | `Settings` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/SettingsIndexScreen.kt` | `SettingsIndexScreen` | `SettingsViewModel, SettingsIndexState` | true |
| P18-S13 | `ConnectionPermissions` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ConnectionPermissionsScreen.kt` | `ConnectionPermissionsScreen` | `SettingsViewModel, SystemPolicyRepository` | false |
| P18-S14 | `TrustedNetworks` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/TrustedNetworksScreen.kt` | `TrustedNetworksScreen` | `SettingsViewModel, TrustedNetworkRepository` | false |
| P18-S15 | `PerAppRouting` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/PerAppRoutingScreen.kt` | `PerAppRoutingScreen` | `SettingsViewModel, InstalledAppRepository` | false |
| P18-S16 | `ExcludedRoutes` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ExcludedRoutesScreen.kt` | `ExcludedRoutesScreen` | `SettingsViewModel, RuntimePlanAuthorizer` | false |
| P18-S17 | `TunnelDns` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/TunnelDnsScreen.kt` | `TunnelDnsScreen` | `SettingsViewModel, RuntimePlanAuthorizer` | false |
| P18-S18 | `LocalProxy` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/LocalProxyScreen.kt` | `LocalProxyScreen` | `SettingsViewModel, ProxyCredentialController` | false |
| P18-S19 | `UpdatesProbes` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/UpdatesProbesScreen.kt` | `UpdatesProbesScreen` | `SettingsViewModel, NodeMaintenanceRepository` | false |
| P18-S20 | `AppearanceAccessibility` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/AppearanceAccessibilityScreen.kt` | `AppearanceAccessibilityScreen` | `SettingsViewModel, LocaleController` | false |
| P18-S21 | `PrivacyAppLock` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/PrivacyAppLockScreen.kt` | `PrivacyAppLockScreen` | `PrivacyRecoveryViewModel, PrivacyState` | false |
| P18-S22 | `BackupCreation` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/BackupCreationScreen.kt` | `BackupCreationScreen` | `PrivacyRecoveryViewModel, BackupState` | false |
| P18-S23 | `RestorePreview(operationId)` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/RestorePreviewScreen.kt` | `RestorePreviewScreen` | `PrivacyRecoveryViewModel, RestoreState` | false |
| P18-S24 | `TransferExport(profileId)` | `android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/TransferExportScreen.kt` | `TransferExportScreen` | `ProfilesViewModel, TransferState` | false |
| P18-S25 | `RecoveryCenter` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/RecoveryCenterScreen.kt` | `RecoveryCenterScreen` | `PrivacyRecoveryViewModel, RecoveryState` | false |
| P18-S26 | `ScopedReset` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ScopedResetScreen.kt` | `ScopedResetScreen` | `PrivacyRecoveryViewModel, ResetState` | false |
| P18-S27 | `Diagnostics` | `android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/DiagnosticsExplorerScreen.kt` | `DiagnosticsExplorerScreen` | `DiagnosticsViewModel, DiagnosticsState` | false |
| P18-S28 | `DiagnosticExport(operationId)` | `android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/DiagnosticExportPreviewScreen.kt` | `DiagnosticExportPreviewScreen` | `DiagnosticsViewModel, DiagnosticExportState` | false |
| P18-S29 | `Troubleshooting` | `android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/TroubleshootingScreen.kt` | `TroubleshootingScreen` | `DiagnosticsViewModel, TroubleshootingState` | false |
| P18-S30 | `NotificationsPerformance` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/NotificationsPerformanceScreen.kt` | `NotificationsPerformanceScreen` | `SettingsViewModel, LocalPerformanceState` | false |
| P18-S31 | `ExpertControls` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ExpertControlsScreen.kt` | `ExpertControlsScreen` | `SettingsViewModel, EffectiveExpertState` | false |
| P18-S32 | `Automation` | `android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/AutomationScreen.kt` | `AutomationScreen` | `SettingsViewModel, AutomationState` | false |
| P18-S33 | `About` | `android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/AboutScreen.kt` | `AboutScreen` | `DiagnosticsViewModel, BuildInfoState` | false |
| P18-S34 | `Legal` | `android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/LegalScreen.kt` | `LegalScreen` | `DiagnosticsViewModel, LegalDocumentState` | false |

## Planning boundary

All 67 features and 311 controls remain planned. Device, qualification, candidate, Stress, soak, publication, and release evidence remain unexecuted.
