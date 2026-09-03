// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	manifestPath    = "android/config/phase18-every-control.json"
	budgetsPath     = "android/config/phase18-performance-budgets.json"
	ownedFilesPath  = "android/config/phase18-owned-files.txt"
	deviceTestsPath = "android/config/phase18-required-device-tests.txt"
	acceptancePath  = "testdata/evidence/phase18/acceptance-status.json"
	coveragePath    = "docs/PHASE18_FEATURE_COVERAGE.md"
	evidencePath    = "docs/PHASE18_EVIDENCE_INDEX.md"
	task0Path       = "docs/PHASE18_ANDROID_PRODUCTION_CONTRACT.md"

	manifestSchema   = "phase18-every-control-planning-v1"
	budgetSchema     = "phase18-performance-budgets-v1"
	legacyTitle      = "Phase 18 inspiration and product-feature disposition matrix"
	legacySHA256     = "8f1235653f1e3367f164660cd805921279282177bf8c35faaaef196fc149bbb4"
	controlSetSHA256 = "b922c3411014eb680b2aeef0bb75c3c35a6872734c92e8a14faab4a485c401c7"

	maxJSONBytes      = 4 << 20
	maxMarkdownBytes  = 1 << 20
	maxTextBytes      = 256
	maxControls       = 512
	exactControlCount = 311
)

var expectedScreenControlCounts = []int{
	3, 7, 8, 5, 12, 8, 9, 8, 9, 6, 4, 14, 14, 7, 11, 5, 14,
	16, 12, 11, 13, 10, 7, 8, 7, 10, 10, 5, 17, 10, 13, 7, 6, 5,
}

var navigationRoots = map[string]bool{
	"P18-S01": true,
	"P18-S05": true,
	"P18-S07": true,
	"P18-S12": true,
}

var terminalDispositions = []string{
	"delivered-production",
	"safely-replaced-final",
	"rejected-final",
	"inapplicable-final",
}

var productFailureCodes = []string{
	"INVALID_INPUT",
	"SIZE_LIMIT",
	"PROFILE_UNTRUSTED",
	"PROFILE_EXPIRED",
	"PROFILE_REVOKED",
	"PROFILE_ROLLBACK",
	"PROFILE_WRONG_DEVICE",
	"PROFILE_INCOMPATIBLE",
	"STORAGE_LOCKED",
	"STORAGE_KEY_INVALIDATED",
	"STORAGE_DEGRADED",
	"MIGRATION_REQUIRED",
	"VPN_CONSENT_REQUIRED",
	"VPN_CONSENT_DENIED",
	"NETWORK_UNAVAILABLE",
	"NETWORK_IDENTITY_UNAVAILABLE",
	"CAPTIVE_PORTAL",
	"NODE_UNREACHABLE",
	"SESSION_AUTHENTICATION_FAILED",
	"NO_PERMITTED_STRATEGY",
	"SOCKET_PROTECTION_FAILED",
	"TUN_ESTABLISH_FAILED",
	"ROUTE_POLICY_REJECTED",
	"DNS_POLICY_REJECTED",
	"DNS_HEALTH_FAILED",
	"APP_POLICY_DRIFT",
	"FOREGROUND_START_BLOCKED",
	"RECONNECT_EXHAUSTED",
	"UPDATE_SIGNATURE_INVALID",
	"UPDATE_ROLLBACK",
	"UPDATE_INCOMPATIBLE",
	"PROXY_BIND_FAILED",
	"PROXY_AUTHENTICATION_FAILED",
	"LOW_MEMORY",
	"THERMAL_LIMIT",
	"CANCELLED",
	"INTERNAL_FAILURE",
}

var expectedOwnedFiles = []string{
	"android/app/build.gradle.kts",
	"android/app/gradle.lockfile",
	"android/benchmark/build.gradle.kts",
	"android/benchmark/gradle.lockfile",
	"android/build.gradle.kts",
	"android/config/phase18-every-control.json",
	"android/config/phase18-owned-files.txt",
	"android/config/phase18-performance-budgets.json",
	"android/config/phase18-required-device-tests.txt",
	"android/data/node/build.gradle.kts",
	"android/data/node/gradle.lockfile",
	"android/feature/onboarding/build.gradle.kts",
	"android/feature/onboarding/gradle.lockfile",
	"android/gradle/libs.versions.toml",
	"android/gradle/verification-metadata.xml",
	"android/platform/system/build.gradle.kts",
	"android/platform/system/gradle.lockfile",
	"android/settings.gradle.kts",
	"cmd/phase18verify/main.go",
	"cmd/phase18verify/main_test.go",
	"docs/PHASE18_ANDROID_PRODUCTION_CONTRACT.md",
	"docs/PHASE18_EVIDENCE_INDEX.md",
	"docs/PHASE18_FEATURE_COVERAGE.md",
}

var expectedGeneratedEvidenceFiles = []string{
	"testdata/evidence/phase9/android-licenses.spdx.json",
	"testdata/evidence/phase9/android-sbom.cdx.json",
}

var expectedDeviceTests = []string{
	"org.kurdistanvpn.app.Phase18AccessibilityDeviceTest#talkBackSwitchKeyboardAndDpadTraverse",
	"org.kurdistanvpn.app.Phase18AccessibilityDeviceTest#twoHundredPercentTextKeepsActions",
	"org.kurdistanvpn.app.Phase18AdaptiveDeviceTest#allWindowClassesPreserveState",
	"org.kurdistanvpn.app.Phase18AutomationDeviceTest#externalAutomationAlwaysConfirms",
	"org.kurdistanvpn.app.Phase18ConnectionDeviceTest#alwaysOnColdStartRevalidatesBootstrap",
	"org.kurdistanvpn.app.Phase18ConnectionDeviceTest#connectedRequiresNativeTunRouteAndDns",
	"org.kurdistanvpn.app.Phase18ConnectionDeviceTest#handoverUpdatesUnderlyingNetwork",
	"org.kurdistanvpn.app.Phase18ConnectionDeviceTest#revokeStopsTrafficAndReconnect",
	"org.kurdistanvpn.app.Phase18ControlManifestDeviceTest#everyControlMatchesManifest",
	"org.kurdistanvpn.app.Phase18LocaleDeviceTest#allFiveLocalesHaveParity",
	"org.kurdistanvpn.app.Phase18LocaleDeviceTest#rtlAndBidiValuesRemainSafe",
	"org.kurdistanvpn.app.Phase18OnboardingDeviceTest#allIngressSourcesRequireVerifiedPreview",
	"org.kurdistanvpn.app.Phase18OnboardingDeviceTest#vpnConsentDenialIsRecoverable",
	"org.kurdistanvpn.app.Phase18PersistenceRecoveryDeviceTest#allStoreMigrationsRecover",
	"org.kurdistanvpn.app.Phase18PersistenceRecoveryDeviceTest#backupRestoreAndResetAreTransactional",
	"org.kurdistanvpn.app.Phase18PrivacyDeviceTest#appLockNeverBlocksEmergencyActions",
	"org.kurdistanvpn.app.Phase18PrivacyDeviceTest#secretCanariesNeverEscape",
	"org.kurdistanvpn.app.Phase18ProductSurfaceDeviceTest#allThirtyFourRoutesReachable",
	"org.kurdistanvpn.app.Phase18ProxyDeviceTest#proxyRequiresAuthAndBindsOnlyLoopback",
	"org.kurdistanvpn.app.Phase18ProxyDeviceTest#proxyStopsWithSession",
	"org.kurdistanvpn.app.Phase18ResilienceDeviceTest#safeModeIsDeterministic",
	"org.kurdistanvpn.app.Phase18RoutingDnsDeviceTest#dualStackAndInternalDnsApplyExactly",
	"org.kurdistanvpn.app.Phase18RoutingDnsDeviceTest#excludedRoutesNeverWidenAuthority",
	"org.kurdistanvpn.app.Phase18RoutingDnsDeviceTest#perAppIncludeExcludeUseSeparateUids",
}

type planningManifest struct {
	SchemaVersion            string           `json:"schemaVersion"`
	PlanningStatus           string           `json:"planningStatus"`
	ControlCount             int              `json:"controlCount"`
	ControlSetSHA256         string           `json:"controlSetSHA256"`
	LegacyCoverageProvenance legacyProvenance `json:"legacyCoverageProvenance"`
	TerminalDispositions     []string         `json:"terminalDispositions"`
	Features                 []feature        `json:"features"`
	Screens                  []screen         `json:"screens"`
}

type legacyProvenance struct {
	SourceTitle                    string   `json:"sourceTitle"`
	SHA256                         string   `json:"sha256"`
	ReconcilesLegacyItems          string   `json:"reconcilesLegacyItems"`
	ReconcilesInspirationInventory bool     `json:"reconcilesInspirationInventory"`
	FeatureIDs                     []string `json:"featureIds"`
}

type feature struct {
	FeatureID              string   `json:"featureId"`
	CapabilityKey          string   `json:"capabilityKey"`
	FrozenDisposition      string   `json:"frozenDisposition"`
	TargetDisposition      string   `json:"targetDisposition"`
	ImplementationState    string   `json:"implementationState"`
	OwnerTasks             []int    `json:"ownerTasks"`
	CapabilityAdmission    string   `json:"capabilityAdmission"`
	PublicContractEvidence []string `json:"publicContractEvidence"`
	ControlIDs             []string `json:"controlIds"`
}

type screen struct {
	ScreenID       string    `json:"screenId"`
	RouteKey       string    `json:"routeKey"`
	OwnerFile      string    `json:"ownerFile"`
	OwnerSymbol    string    `json:"ownerSymbol"`
	StateOwner     string    `json:"stateOwner"`
	NavigationRoot bool      `json:"navigationRoot"`
	Controls       []control `json:"controls"`
}

type control struct {
	ControlID                 string               `json:"controlId"`
	FeatureIDs                []string             `json:"featureIds"`
	FeatureDispositions       []featureDisposition `json:"featureDispositions"`
	ControlType               string               `json:"controlType"`
	LabelKey                  string               `json:"labelKey"`
	PlannedComposable         string               `json:"plannedComposable"`
	SemanticsTestTag          string               `json:"semanticsTestTag"`
	StateProperty             string               `json:"stateProperty"`
	ActionSymbol              string               `json:"actionSymbol"`
	NavigationDestination     string               `json:"navigationDestination"`
	Enabled                   bool                 `json:"enabled"`
	EnabledCondition          string               `json:"enabledCondition"`
	UnavailableReasonKey      string               `json:"unavailableReasonKey"`
	ValidationSymbol          string               `json:"validationSymbol"`
	BoundedInputs             string               `json:"boundedInputs"`
	PersistenceOwner          string               `json:"persistenceOwner"`
	ObservableEffect          string               `json:"observableEffect"`
	FailureExplanationKey     string               `json:"failureExplanationKey"`
	FailureCode               string               `json:"failureCode"`
	UserRecoveryAction        string               `json:"userRecoveryAction"`
	ReversalAction            string               `json:"reversalAction"`
	AccessibilityContract     string               `json:"accessibilityContract"`
	LocalizationOwner         string               `json:"localizationOwner"`
	MigrationContract         string               `json:"migrationContract"`
	RecoveryContract          string               `json:"recoveryContract"`
	ProcessRecreationBehavior string               `json:"processRecreationBehavior"`
	TestIDs                   []string             `json:"testIds"`
	EvidenceKeys              []string             `json:"evidenceKeys"`
	ImplementationState       string               `json:"implementationState"`
}

type featureDisposition struct {
	FeatureID           string `json:"featureId"`
	TerminalDisposition string `json:"terminalDisposition"`
	LegacyProvenanceKey string `json:"legacyProvenanceKey"`
}

type featureSpec struct {
	ID, Key, Frozen, Target, Admission string
	Owners                             []int
}

type screenSpec struct {
	ID, Route, OwnerFile, OwnerSymbol, StateOwner string
}

type performanceBudgets struct {
	SchemaVersion string         `json:"schemaVersion"`
	Decision      string         `json:"decision"`
	Metrics       []budgetMetric `json:"metrics"`
}

type budgetMetric struct {
	MetricID                           string   `json:"metricId"`
	MedianMilliseconds                 *float64 `json:"medianMilliseconds,omitempty"`
	P95Milliseconds                    *float64 `json:"p95Milliseconds,omitempty"`
	P99Milliseconds                    *float64 `json:"p99Milliseconds,omitempty"`
	MaximumMilliseconds                *float64 `json:"maximumMilliseconds,omitempty"`
	Iterations                         *int     `json:"iterations,omitempty"`
	ProfileCount                       *int     `json:"profileCount,omitempty"`
	Transitions                        *int     `json:"transitions,omitempty"`
	P95MiB                             *float64 `json:"p95MiB,omitempty"`
	MaximumMiB                         *float64 `json:"maximumMiB,omitempty"`
	Cycles                             *int     `json:"cycles,omitempty"`
	P95Percent                         *float64 `json:"p95Percent,omitempty"`
	DurationMinutes                    *int     `json:"durationMinutes,omitempty"`
	MaximumPercentagePointsPerHour     *float64 `json:"maximumPercentagePointsPerHour,omitempty"`
	DurationHours                      *int     `json:"durationHours,omitempty"`
	Runs                               *int     `json:"runs,omitempty"`
	MaximumCategory                    *string  `json:"maximumCategory,omitempty"`
	MaximumSeconds                     *float64 `json:"maximumSeconds,omitempty"`
	MaximumActivePerDeployment         *int     `json:"maximumActivePerDeployment,omitempty"`
	FirstConnectMaximumMilliseconds    *float64 `json:"firstConnectMaximumMilliseconds,omitempty"`
	OverLimitRejectMaximumMilliseconds *float64 `json:"overLimitRejectMaximumMilliseconds,omitempty"`
	ConnectStopCycles                  *int     `json:"connectStopCycles,omitempty"`
	NavigationCycles                   *int     `json:"navigationCycles,omitempty"`
	MaximumFailures                    *int     `json:"maximumFailures,omitempty"`
	Actions                            []string `json:"actions,omitempty"`
	VisibleStates                      []string `json:"visibleStates,omitempty"`
	TransitionDirections               []string `json:"transitionDirections,omitempty"`
	ProcessScope                       string   `json:"processScope,omitempty"`
	Conditions                         []string `json:"conditions,omitempty"`
	CausalFailureRule                  string   `json:"causalFailureRule,omitempty"`
	TerminalOutcomes                   []string `json:"terminalOutcomes,omitempty"`
	ProtocolOperation                  string   `json:"protocolOperation,omitempty"`
	AuthenticationRequired             *bool    `json:"authenticationRequired,omitempty"`
	ZeroFailureCategories              []string `json:"zeroFailureCategories,omitempty"`
	FirstUsableStates                  []string `json:"firstUsableStates,omitempty"`
	FullyDrawnRequired                 *bool    `json:"fullyDrawnRequired,omitempty"`
	Measurement                        string   `json:"measurement"`
}

type acceptanceStatus struct {
	SchemaVersion        string `json:"schemaVersion"`
	EvidenceKind         string `json:"evidenceKind"`
	ControlSetSHA256     string `json:"controlSetSHA256"`
	ImplementationStatus string `json:"implementationStatus"`
	Phase18Decision      string `json:"phase18Decision"`
	ReleaseAuthorization string `json:"releaseAuthorization"`
}

type evidenceRecord struct {
	SchemaVersion  string          `json:"schemaVersion"`
	EvidenceKind   string          `json:"evidenceKind"`
	SubjectCommit  string          `json:"subjectCommit"`
	SubjectTree    string          `json:"subjectTree"`
	Result         string          `json:"result"`
	EvidenceSHA256 string          `json:"evidenceSHA256"`
	Checks         []evidenceCheck `json:"checks"`
}

type evidenceCheck struct {
	CheckID        string `json:"checkId"`
	Result         string `json:"result"`
	EvidenceSHA256 string `json:"evidenceSHA256"`
}

var evidenceKinds = []string{
	"acceptance-status",
	"complete-v1-feature-map",
	"every-control-results",
	"human-review",
	"performance-results",
	"production-android-e2e",
	"release-surface-scan",
}

var evidenceCheckIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,127}$`)
var gitObjectIDPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var expectedFeatureRows = []string{
	"P18-F001|Three-area navigation|Phase 18|delivered-production|14,27|NOT_APPLICABLE",
	"P18-F002|Large daily connection control|Phase 18|delivered-production|16|NOT_APPLICABLE",
	"P18-F003|Current provider/server card|Safely replaced|safely-replaced-final|16,17|NOT_APPLICABLE",
	"P18-F004|Live latency, speed, duration, counters|Phase 18|delivered-production|16,19,30|NOT_APPLICABLE",
	"P18-F005|Exit country/region|Capability-gated|inapplicable-final|16,30|NOT_ADMITTED",
	"P18-F006|Favorites, recent use, search, filter, sort|Phase 18|delivered-production|17|NOT_APPLICABLE",
	"P18-F007|Provider/subscription groups|Safely replaced|safely-replaced-final|17,18|NOT_APPLICABLE",
	"P18-F008|Provider quota/HWID/install ID/user-agent|Rejected|rejected-final|3,17,31|NOT_APPLICABLE",
	"P18-F009|QR/file/clipboard/share/`kurd://` import|Phase 18|delivered-production|15|NOT_APPLICABLE",
	"P18-F010|Direct remote subscription URL|Safely replaced|safely-replaced-final|18|NOT_APPLICABLE",
	"P18-F011|Arbitrary VLESS/VMess/Trojan/Shadowsocks import|Rejected for v1|rejected-final|15,31|NOT_APPLICABLE",
	"P18-F012|Manual endpoint/protocol editor|Safely replaced|safely-replaced-final|17,22|NOT_APPLICABLE",
	"P18-F013|TLS/REALITY/fingerprint/Allow Insecure editor|Rejected|rejected-final|22,31|NOT_APPLICABLE",
	"P18-F014|Native strategy taxonomy|Capability-gated|delivered-production|17|ADMITTED",
	"P18-F015|Manual strategy choice|Capability-gated|delivered-production|17|ADMITTED",
	"P18-F016|Fragmentation, padding, noise, Mux, cover streams|Capability-gated|inapplicable-final|22|NOT_ADMITTED",
	"P18-F017|Profile share/copy URL/copy JSON|Safely replaced|safely-replaced-final|24|NOT_APPLICABLE",
	"P18-F018|Send to TV/device|Safely replaced|safely-replaced-final|24|NOT_APPLICABLE",
	"P18-F019|Per-app include/exclude|Phase 18|delivered-production|10,21,29,30|NOT_APPLICABLE",
	"P18-F020|App categories|Safely replaced|safely-replaced-final|21|NOT_APPLICABLE",
	"P18-F021|Auto-connect on app launch|Phase 18|delivered-production|11,20|NOT_APPLICABLE",
	"P18-F022|Auto-connect at boot|Capability-gated|delivered-production|11,20|ADMITTED",
	"P18-F023|Kill switch toggle|Safely replaced|safely-replaced-final|11,20|NOT_APPLICABLE",
	"P18-F024|Trusted network rules|Phase 18|delivered-production|20|NOT_APPLICABLE",
	"P18-F025|Allow LAN|Capability-gated|inapplicable-final|10,21,30|NOT_ADMITTED",
	"P18-F026|Public hotspot proxy|Later gate|rejected-final|12,21,31|NOT_APPLICABLE",
	"P18-F027|TUN only|Phase 18|delivered-production|9,10,30|NOT_APPLICABLE",
	"P18-F028|TUN plus local proxy|Phase 18|delivered-production|12,21,30|NOT_APPLICABLE",
	"P18-F029|Local proxy only|Capability-gated|inapplicable-final|12,21|NOT_ADMITTED",
	"P18-F030|Hide notification/icon|Rejected|rejected-final|9,22,31|NOT_APPLICABLE",
	"P18-F031|SOCKS5/HTTP credentials|Phase 18|delivered-production|12,23|NOT_APPLICABLE",
	"P18-F032|External/open proxy logging|Rejected|rejected-final|12,25,31|NOT_APPLICABLE",
	"P18-F033|IPv4, IPv6, dual stack, auto|Capability-gated|delivered-production|10,21,30|ADMITTED",
	"P18-F034|Internal in-tunnel DNS|Phase 18|delivered-production|10,21,30|NOT_APPLICABLE",
	"P18-F035|Public DNS presets|Capability-gated|inapplicable-final|10,21,30|NOT_ADMITTED",
	"P18-F036|Custom DNS|Phase 18|delivered-production|10,21,30|NOT_APPLICABLE",
	"P18-F037|DNS leak test|Phase 18|delivered-production|21,30|NOT_APPLICABLE",
	"P18-F038|WebRTC leak test|Safely replaced|safely-replaced-final|25|NOT_APPLICABLE",
	"P18-F039|Probe method selection|Capability-gated|inapplicable-final|19|NOT_ADMITTED",
	"P18-F040|Ping history/jitter/loss/stability|Phase 18|delivered-production|19|NOT_APPLICABLE",
	"P18-F041|“Fastest” selection|Safely replaced|safely-replaced-final|19|NOT_APPLICABLE",
	"P18-F042|Profile auto-update|Phase 18|delivered-production|18,30|NOT_APPLICABLE",
	"P18-F043|Theme/language/app icon|Phase 18|delivered-production|22,27,30|NOT_APPLICABLE",
	"P18-F044|Multiple decorative color themes|Rejected for v1|rejected-final|22,31|NOT_APPLICABLE",
	"P18-F045|About/version/licenses/privacy|Phase 18|delivered-production|26|NOT_APPLICABLE",
	"P18-F046|Rate/share app|Capability-gated|inapplicable-final|26|NOT_ADMITTED",
	"P18-F047|URL/deep-link automation|Capability-gated|inapplicable-final|26,29|NOT_ADMITTED",
	"P18-F048|Backup and selective restore|Phase 18|delivered-production|24,30|NOT_APPLICABLE",
	"P18-F049|Backup QR/copy link|Capability-gated|delivered-production|24|ADMITTED",
	"P18-F050|Performance presets|Capability-gated|inapplicable-final|22,28,30|NOT_ADMITTED",
	"P18-F051|CPU/memory/battery/thermal status|Phase 18|delivered-production|22,28,30|NOT_APPLICABLE",
	"P18-F052|Crash counter and safe restart|Phase 18|delivered-production|28,30|NOT_APPLICABLE",
	"P18-F053|Expert MTU/limits/routes/UDP|Capability-gated|inapplicable-final|21,22,29|NOT_ADMITTED",
	"P18-F054|Traffic sniffing|Safely replaced|safely-replaced-final|25,31|NOT_APPLICABLE",
	"P18-F055|Diagnostic level/retention|Phase 18|delivered-production|25|NOT_APPLICABLE",
	"P18-F056|Tunnel logs as raw text|Safely replaced|safely-replaced-final|25|NOT_APPLICABLE",
	"P18-F057|Scoped reset|Phase 18|delivered-production|24,30|NOT_APPLICABLE",
	"P18-F058|Privacy dashboard|Phase 18|delivered-production|23,26|NOT_APPLICABLE",
	"P18-F059|App lock/biometric|Phase 18|delivered-production|23|NOT_APPLICABLE",
	"P18-F060|Usage statistics|Safely replaced|safely-replaced-final|23|NOT_APPLICABLE",
	"P18-F061|Multi-provider priority/failover|Safely replaced|safely-replaced-final|11,17,30|NOT_APPLICABLE",
	"P18-F062|Smart reconnect|Phase 18|delivered-production|11,30|NOT_APPLICABLE",
	"P18-F063|Captive portal guidance|Phase 18|delivered-production|11,20,25,30|NOT_APPLICABLE",
	"P18-F064|OEM/battery/autostart guidance|Phase 18|delivered-production|20,25,27|NOT_APPLICABLE",
	"P18-F065|Accessibility and RTL|Phase 18|delivered-production|27,30|NOT_APPLICABLE",
	"P18-F066|Phones, tablets, foldables|Phase 18|delivered-production|14,27,30|NOT_APPLICABLE",
	"P18-F067|Guaranteed bypass, anonymity, undetectability, “uncensorable”|Rejected|rejected-final|26,31|NOT_APPLICABLE",
}

var expectedScreenRows = []string{
	"P18-S01|Welcome|android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/WelcomeScreen.kt|WelcomeScreen|OnboardingViewModel, OnboardingState",
	"P18-S02|ImportSource|android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/ImportSourceScreen.kt|ImportSourceScreen|OnboardingViewModel, ImportCoordinator",
	"P18-S03|FirstTrust(importId)|android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/FirstTrustScreen.kt|FirstTrustScreen|OnboardingViewModel, ProfileRepository",
	"P18-S04|VpnPermissionEducation|android/feature/onboarding/src/main/kotlin/org/kurdistanvpn/feature/onboarding/VpnPermissionScreen.kt|VpnPermissionScreen|OnboardingViewModel, SystemPolicyRepository",
	"P18-S05|Home|android/feature/home/src/main/kotlin/org/kurdistanvpn/feature/home/HomeScreen.kt|HomeScreen|ConnectionViewModel, ConnectionState",
	"P18-S06|RouteDetail(sessionAlias)|android/feature/home/src/main/kotlin/org/kurdistanvpn/feature/home/RouteDetailScreen.kt|RouteDetailScreen|ConnectionViewModel, VerifiedRouteSnapshot",
	"P18-S07|Profiles|android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/ProfilesScreen.kt|ProfilesScreen|ProfilesViewModel, DeploymentListState",
	"P18-S08|DeploymentDetail(deploymentId)|android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/DeploymentDetailScreen.kt|DeploymentDetailScreen|ProfilesViewModel, DeploymentDetailState",
	"P18-S09|ProfileDetail(profileId)|android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/ProfileDetailScreen.kt|ProfileDetailScreen|ProfilesViewModel, ProfileDetailState",
	"P18-S10|StrategyMatrix(profileId)|android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/StrategyMatrixScreen.kt|StrategyMatrixScreen|ProfilesViewModel, StrategyMatrixState",
	"P18-S11|ProbeHistory(profileId)|android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/ProbeHistoryScreen.kt|ProbeHistoryScreen|ProfilesViewModel, ProbeHistoryState",
	"P18-S12|Settings|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/SettingsIndexScreen.kt|SettingsIndexScreen|SettingsViewModel, SettingsIndexState",
	"P18-S13|ConnectionPermissions|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ConnectionPermissionsScreen.kt|ConnectionPermissionsScreen|SettingsViewModel, SystemPolicyRepository",
	"P18-S14|TrustedNetworks|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/TrustedNetworksScreen.kt|TrustedNetworksScreen|SettingsViewModel, TrustedNetworkRepository",
	"P18-S15|PerAppRouting|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/PerAppRoutingScreen.kt|PerAppRoutingScreen|SettingsViewModel, InstalledAppRepository",
	"P18-S16|ExcludedRoutes|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ExcludedRoutesScreen.kt|ExcludedRoutesScreen|SettingsViewModel, RuntimePlanAuthorizer",
	"P18-S17|TunnelDns|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/TunnelDnsScreen.kt|TunnelDnsScreen|SettingsViewModel, RuntimePlanAuthorizer",
	"P18-S18|LocalProxy|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/LocalProxyScreen.kt|LocalProxyScreen|SettingsViewModel, ProxyCredentialController",
	"P18-S19|UpdatesProbes|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/UpdatesProbesScreen.kt|UpdatesProbesScreen|SettingsViewModel, NodeMaintenanceRepository",
	"P18-S20|AppearanceAccessibility|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/AppearanceAccessibilityScreen.kt|AppearanceAccessibilityScreen|SettingsViewModel, LocaleController",
	"P18-S21|PrivacyAppLock|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/PrivacyAppLockScreen.kt|PrivacyAppLockScreen|PrivacyRecoveryViewModel, PrivacyState",
	"P18-S22|BackupCreation|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/BackupCreationScreen.kt|BackupCreationScreen|PrivacyRecoveryViewModel, BackupState",
	"P18-S23|RestorePreview(operationId)|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/RestorePreviewScreen.kt|RestorePreviewScreen|PrivacyRecoveryViewModel, RestoreState",
	"P18-S24|TransferExport(profileId)|android/feature/profiles/src/main/kotlin/org/kurdistanvpn/feature/profiles/TransferExportScreen.kt|TransferExportScreen|ProfilesViewModel, TransferState",
	"P18-S25|RecoveryCenter|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/RecoveryCenterScreen.kt|RecoveryCenterScreen|PrivacyRecoveryViewModel, RecoveryState",
	"P18-S26|ScopedReset|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ScopedResetScreen.kt|ScopedResetScreen|PrivacyRecoveryViewModel, ResetState",
	"P18-S27|Diagnostics|android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/DiagnosticsExplorerScreen.kt|DiagnosticsExplorerScreen|DiagnosticsViewModel, DiagnosticsState",
	"P18-S28|DiagnosticExport(operationId)|android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/DiagnosticExportPreviewScreen.kt|DiagnosticExportPreviewScreen|DiagnosticsViewModel, DiagnosticExportState",
	"P18-S29|Troubleshooting|android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/TroubleshootingScreen.kt|TroubleshootingScreen|DiagnosticsViewModel, TroubleshootingState",
	"P18-S30|NotificationsPerformance|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/NotificationsPerformanceScreen.kt|NotificationsPerformanceScreen|SettingsViewModel, LocalPerformanceState",
	"P18-S31|ExpertControls|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/ExpertControlsScreen.kt|ExpertControlsScreen|SettingsViewModel, EffectiveExpertState",
	"P18-S32|Automation|android/feature/settings-recovery/src/main/kotlin/org/kurdistanvpn/feature/settingsrecovery/AutomationScreen.kt|AutomationScreen|SettingsViewModel, AutomationState",
	"P18-S33|About|android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/AboutScreen.kt|AboutScreen|DiagnosticsViewModel, BuildInfoState",
	"P18-S34|Legal|android/feature/diagnostics-about/src/main/kotlin/org/kurdistanvpn/feature/diagnosticsabout/LegalScreen.kt|LegalScreen|DiagnosticsViewModel, LegalDocumentState",
}

func main() {
	root := flag.String("root", ".", "repository root")
	mode := flag.String("mode", "planning", "verification mode")
	flag.Parse()
	if *mode != "planning" {
		fmt.Fprintf(os.Stderr, "phase18verify: unsupported mode %q\n", *mode)
		os.Exit(2)
	}
	if err := verifyPlanning(*root); err != nil {
		fmt.Fprintf(os.Stderr, "phase18verify: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("phase18verify: planning contract valid (67 features, 34 screens, 15 capability decisions; implementation NOT_STARTED; release NO_GO)")
}

func verifyPlanning(root string, suppliedChanged ...[]string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("repository root: %w", err)
	}
	manifestRaw, err := readBounded(absRoot, manifestPath, maxJSONBytes)
	if err != nil {
		return err
	}
	var manifest planningManifest
	if err := decodeStrictJSON(manifestRaw, &manifest); err != nil {
		return fmt.Errorf("every-control manifest: %w", err)
	}
	task0Raw, err := readBounded(absRoot, task0Path, maxMarkdownBytes)
	if err != nil {
		return err
	}
	capabilities, err := validateTask0Capabilities(task0Raw)
	if err != nil {
		return err
	}
	if err := validateManifest(manifest, capabilities); err != nil {
		return err
	}
	if err := validateBudgets(absRoot); err != nil {
		return err
	}
	if err := validateCanonicalTextFile(absRoot, deviceTestsPath, expectedDeviceTests, "required device tests"); err != nil {
		return err
	}
	if len(suppliedChanged) > 1 {
		return errors.New("changed-path input may be supplied at most once")
	}
	if err := validateOwnedFiles(absRoot, len(suppliedChanged) == 0); err != nil {
		return err
	}
	acceptance, err := validateAcceptance(absRoot)
	if err != nil {
		return err
	}
	if err := validateMarkdownFiles(absRoot, manifest, acceptance); err != nil {
		return err
	}
	changed := []string(nil)
	if len(suppliedChanged) == 1 {
		changed = append(changed, suppliedChanged[0]...)
	} else {
		changed, err = gitChangedPaths(absRoot)
		if err != nil {
			return err
		}
	}
	if err := validateChangedPaths(changed); err != nil {
		return err
	}
	if err := validatePublicSafety(absRoot); err != nil {
		return err
	}
	return nil
}

func expectedFeatures() ([]featureSpec, error) {
	result := make([]featureSpec, 0, len(expectedFeatureRows))
	for _, row := range expectedFeatureRows {
		parts := strings.Split(row, "|")
		if len(parts) != 6 {
			return nil, fmt.Errorf("internal feature specification malformed: %q", row)
		}
		owners := make([]int, 0, 4)
		for _, raw := range strings.Split(parts[4], ",") {
			value, err := strconv.Atoi(raw)
			if err != nil {
				return nil, fmt.Errorf("internal owner task %q: %w", raw, err)
			}
			owners = append(owners, value)
		}
		result = append(result, featureSpec{
			ID: parts[0], Key: parts[1], Frozen: parts[2], Target: parts[3], Owners: owners, Admission: parts[5],
		})
	}
	return result, nil
}

func expectedScreens() ([]screenSpec, error) {
	result := make([]screenSpec, 0, len(expectedScreenRows))
	for _, row := range expectedScreenRows {
		parts := strings.Split(row, "|")
		if len(parts) != 5 {
			return nil, fmt.Errorf("internal screen specification malformed: %q", row)
		}
		result = append(result, screenSpec{
			ID: parts[0], Route: parts[1], OwnerFile: parts[2], OwnerSymbol: parts[3], StateOwner: parts[4],
		})
	}
	return result, nil
}

var capabilityRowPattern = regexp.MustCompile("(?m)^\\| (P18-F[0-9]{3}) \\| `?(ADMITTED|NOT_ADMITTED)`? \\|")

func validateTask0Capabilities(raw []byte) (map[string]string, error) {
	const heading = "## Capability-gated feature ledger"
	text := string(raw)
	if strings.Count(text, heading) != 1 {
		return nil, errors.New("Task 0 capability-gated feature ledger section must occur exactly once")
	}
	start := strings.Index(text, heading) + len(heading)
	section := text[start:]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	matches := capabilityRowPattern.FindAllSubmatch([]byte(section), -1)
	if len(matches) != 15 {
		return nil, fmt.Errorf("Task 0 capability ledger has %d rows, want 15", len(matches))
	}
	got := make(map[string]string, 15)
	admitted := 0
	for _, match := range matches {
		id, decision := string(match[1]), string(match[2])
		if _, duplicate := got[id]; duplicate {
			return nil, fmt.Errorf("Task 0 capability ledger duplicate %s", id)
		}
		got[id] = decision
		if decision == "ADMITTED" {
			admitted++
		}
	}
	if admitted != 5 || len(got)-admitted != 10 {
		return nil, fmt.Errorf("Task 0 capability ledger split is %d/%d, want 5/10", admitted, len(got)-admitted)
	}
	return got, nil
}

func validateManifest(m planningManifest, task0Capabilities map[string]string) error {
	if err := exactBounded("schemaVersion", m.SchemaVersion, manifestSchema); err != nil {
		return err
	}
	if err := exactBounded("planningStatus", m.PlanningStatus, "NOT_STARTED"); err != nil {
		return err
	}
	if !reflect.DeepEqual(m.TerminalDispositions, terminalDispositions) {
		return fmt.Errorf("terminal target disposition list must be the exact four canonical values")
	}
	if m.ControlCount != exactControlCount {
		return fmt.Errorf("control cardinality is %d, want exactly %d", m.ControlCount, exactControlCount)
	}
	if err := validateLegacyProvenance(m.LegacyCoverageProvenance); err != nil {
		return err
	}
	expected, err := expectedFeatures()
	if err != nil {
		return err
	}
	if len(m.Features) != len(expected) {
		return fmt.Errorf("manifest has %d features, want exactly 67 features", len(m.Features))
	}
	featureByID := make(map[string]feature, len(m.Features))
	for i, actual := range m.Features {
		if _, duplicate := featureByID[actual.FeatureID]; duplicate {
			return fmt.Errorf("duplicate feature ID %q", actual.FeatureID)
		}
		featureByID[actual.FeatureID] = actual
		want := expected[i]
		if actual.FeatureID != want.ID {
			return fmt.Errorf("feature order at row %d is %q, want %q", i+1, actual.FeatureID, want.ID)
		}
		if err := boundedString("feature capability key", actual.CapabilityKey, true); err != nil {
			return err
		}
		if actual.CapabilityKey != want.Key {
			return fmt.Errorf("feature %s capability key is %q, want %q", actual.FeatureID, actual.CapabilityKey, want.Key)
		}
		if actual.FrozenDisposition != want.Frozen {
			return fmt.Errorf("feature %s frozen disposition is %q, want %q", actual.FeatureID, actual.FrozenDisposition, want.Frozen)
		}
		if !contains(terminalDispositions, actual.TargetDisposition) || actual.TargetDisposition != want.Target {
			return fmt.Errorf("feature %s target disposition is %q, want %q", actual.FeatureID, actual.TargetDisposition, want.Target)
		}
		if actual.ImplementationState != "planned" {
			return fmt.Errorf("feature %s implementation state must remain planned", actual.FeatureID)
		}
		if len(actual.OwnerTasks) > 8 {
			return fmt.Errorf("feature %s owner tasks exceed bounded list maximum", actual.FeatureID)
		}
		if !strictlyIncreasingInts(actual.OwnerTasks) || !reflect.DeepEqual(actual.OwnerTasks, want.Owners) {
			return fmt.Errorf("feature %s owner tasks are %v, want %v", actual.FeatureID, actual.OwnerTasks, want.Owners)
		}
		if actual.CapabilityAdmission != want.Admission {
			return fmt.Errorf("feature %s capability admission is %q, want %q", actual.FeatureID, actual.CapabilityAdmission, want.Admission)
		}
		if want.Admission == "ADMITTED" || want.Admission == "NOT_ADMITTED" {
			decision, ok := task0Capabilities[actual.FeatureID]
			if !ok || decision != want.Admission {
				return fmt.Errorf("feature %s capability admission disagrees with Task 0", actual.FeatureID)
			}
			wantEvidence := []string{"docs/PHASE18_ANDROID_PRODUCTION_CONTRACT.md#capability-gated-feature-ledger"}
			if !reflect.DeepEqual(actual.PublicContractEvidence, wantEvidence) {
				return fmt.Errorf("feature %s must cite exact public Task 0 contract evidence", actual.FeatureID)
			}
			if want.Admission == "NOT_ADMITTED" && actual.TargetDisposition != "inapplicable-final" {
				return fmt.Errorf("NOT_ADMITTED feature %s must target inapplicable-final", actual.FeatureID)
			}
		} else {
			if _, found := task0Capabilities[actual.FeatureID]; found {
				return fmt.Errorf("feature %s unexpectedly appears in Task 0 capability ledger", actual.FeatureID)
			}
			if len(actual.PublicContractEvidence) != 0 {
				return fmt.Errorf("feature %s has unexpected capability contract evidence", actual.FeatureID)
			}
		}
		if len(actual.ControlIDs) == 0 || len(actual.ControlIDs) > 64 || !canonicalUniqueStrings(actual.ControlIDs) {
			return fmt.Errorf("feature %s control IDs must be a nonempty canonical bounded list", actual.FeatureID)
		}
	}
	if len(task0Capabilities) != 15 {
		return fmt.Errorf("Task 0 capability admission set has %d entries, want 15", len(task0Capabilities))
	}
	if err := validateScreensAndControls(m.Screens, featureByID); err != nil {
		return err
	}
	digest, err := canonicalControlDigest(m.Screens)
	if err != nil {
		return err
	}
	if m.ControlSetSHA256 != digest {
		return fmt.Errorf("control set digest is %q, recomputed %q", m.ControlSetSHA256, digest)
	}
	if m.ControlSetSHA256 != controlSetSHA256 {
		return fmt.Errorf("control set digest is %q, pinned %q", m.ControlSetSHA256, controlSetSHA256)
	}
	return nil
}

func canonicalControlDigest(screens []screen) (string, error) {
	raw, err := json.Marshal(screens)
	if err != nil {
		return "", fmt.Errorf("canonical control set: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validateLegacyProvenance(p legacyProvenance) error {
	if p.SourceTitle == "" {
		return errors.New("legacy provenance is missing")
	}
	if err := exactBounded("legacy provenance source title", p.SourceTitle, legacyTitle); err != nil {
		return err
	}
	if !validSHA256(p.SHA256) {
		return errors.New("legacy provenance SHA-256 is malformed")
	}
	if p.SHA256 != legacySHA256 {
		return fmt.Errorf("legacy provenance hash is %s, want %s", p.SHA256, legacySHA256)
	}
	if p.ReconcilesLegacyItems != "D0-D28" || !p.ReconcilesInspirationInventory {
		return errors.New("legacy provenance must record D0-D28 and inspiration-inventory reconciliation")
	}
	if len(p.FeatureIDs) != 67 {
		return fmt.Errorf("legacy provenance has %d feature IDs, want 67", len(p.FeatureIDs))
	}
	for i, id := range p.FeatureIDs {
		want := fmt.Sprintf("P18-F%03d", i+1)
		if id != want {
			return fmt.Errorf("legacy provenance feature order at row %d is %q, want %q", i+1, id, want)
		}
	}
	return nil
}

var controlIDPattern = regexp.MustCompile(`^P18-C-S([0-9]{2})-([0-9]{3})$`)

func validateScreensAndControls(screens []screen, features map[string]feature) error {
	expected, err := expectedScreens()
	if err != nil {
		return err
	}
	if len(screens) != len(expected) {
		return fmt.Errorf("manifest has %d screens, want exactly 34 screens", len(screens))
	}
	seenScreens := make(map[string]struct{}, len(screens))
	seenControls := make(map[string]struct{})
	actualControlsByFeature := make(map[string][]string, len(features))
	knownRoutes := make(map[string]struct{}, len(screens))
	for _, candidate := range screens {
		if _, duplicate := knownRoutes[candidate.RouteKey]; duplicate {
			return fmt.Errorf("duplicate screen route %q", candidate.RouteKey)
		}
		knownRoutes[candidate.RouteKey] = struct{}{}
	}
	incomingRoutes := make(map[string][]string, len(screens))
	adjacentRoutes := make(map[string][]string, len(screens))
	totalControls := 0
	for i, actual := range screens {
		if _, duplicate := seenScreens[actual.ScreenID]; duplicate {
			return fmt.Errorf("duplicate screen ID %q", actual.ScreenID)
		}
		seenScreens[actual.ScreenID] = struct{}{}
		want := expected[i]
		if actual.ScreenID != want.ID {
			return fmt.Errorf("screen order at row %d is %q, want %q", i+1, actual.ScreenID, want.ID)
		}
		if actual.RouteKey != want.Route {
			return fmt.Errorf("screen %s route key is %q, want %q", actual.ScreenID, actual.RouteKey, want.Route)
		}
		if actual.OwnerFile != want.OwnerFile {
			return fmt.Errorf("screen %s owner file is %q, want %q", actual.ScreenID, actual.OwnerFile, want.OwnerFile)
		}
		if actual.OwnerSymbol != want.OwnerSymbol || actual.StateOwner != want.StateOwner {
			return fmt.Errorf("screen %s owner symbol/state owner differs from the frozen screen contract", actual.ScreenID)
		}
		if actual.NavigationRoot != navigationRoots[actual.ScreenID] {
			return fmt.Errorf("screen %s navigation root is %t, want %t", actual.ScreenID, actual.NavigationRoot, navigationRoots[actual.ScreenID])
		}
		if len(actual.Controls) == 0 {
			return fmt.Errorf("screen %s has no controls", actual.ScreenID)
		}
		if len(actual.Controls) != expectedScreenControlCounts[i] {
			return fmt.Errorf("control cardinality for screen %s is %d, want %d", actual.ScreenID, len(actual.Controls), expectedScreenControlCounts[i])
		}
		for j, c := range actual.Controls {
			totalControls++
			if totalControls > maxControls {
				return fmt.Errorf("controls exceed bounded list maximum %d", maxControls)
			}
			if _, duplicate := seenControls[c.ControlID]; duplicate {
				return fmt.Errorf("duplicate control ID %q", c.ControlID)
			}
			seenControls[c.ControlID] = struct{}{}
			wantID := fmt.Sprintf("P18-C-S%02d-%03d", i+1, j+1)
			if c.ControlID != wantID {
				return fmt.Errorf("control order for screen %s at row %d is %q, want %q", actual.ScreenID, j+1, c.ControlID, wantID)
			}
			if !controlIDPattern.MatchString(c.ControlID) {
				return fmt.Errorf("control ID %q is malformed", c.ControlID)
			}
			if len(c.FeatureIDs) == 0 || len(c.FeatureIDs) > 8 || !canonicalUniqueStrings(c.FeatureIDs) {
				return fmt.Errorf("control %s feature IDs must be a nonempty canonical bounded list", c.ControlID)
			}
			for _, featureID := range c.FeatureIDs {
				f, ok := features[featureID]
				if !ok {
					return fmt.Errorf("control %s refers to unknown feature %s", c.ControlID, featureID)
				}
				if c.Enabled && f.CapabilityAdmission == "NOT_ADMITTED" {
					return fmt.Errorf("control %s enables NOT_ADMITTED feature %s", c.ControlID, featureID)
				}
				if c.Enabled && f.TargetDisposition == "rejected-final" {
					return fmt.Errorf("control %s enables rejected feature %s", c.ControlID, featureID)
				}
				actualControlsByFeature[featureID] = append(actualControlsByFeature[featureID], c.ControlID)
			}
			if err := validateControl(c); err != nil {
				return err
			}
			for featureIndex, featureID := range c.FeatureIDs {
				if c.FeatureDispositions[featureIndex].TerminalDisposition != features[featureID].TargetDisposition {
					return fmt.Errorf("control %s feature disposition for %s is %q, want %q", c.ControlID, featureID, c.FeatureDispositions[featureIndex].TerminalDisposition, features[featureID].TargetDisposition)
				}
			}
			if c.NavigationDestination != "" {
				if _, ok := knownRoutes[c.NavigationDestination]; !ok {
					return fmt.Errorf("control %s navigation destination %q is not a canonical screen route", c.ControlID, c.NavigationDestination)
				}
				if !c.Enabled {
					return fmt.Errorf("disabled control %s cannot publish a navigation destination", c.ControlID)
				}
				incomingRoutes[c.NavigationDestination] = append(incomingRoutes[c.NavigationDestination], c.ControlID)
				adjacentRoutes[actual.RouteKey] = append(adjacentRoutes[actual.RouteKey], c.NavigationDestination)
			}
		}
	}
	if totalControls != exactControlCount {
		return fmt.Errorf("control cardinality is %d, want exactly %d", totalControls, exactControlCount)
	}
	for _, actual := range screens {
		if !actual.NavigationRoot && len(incomingRoutes[actual.RouteKey]) == 0 {
			return fmt.Errorf("screen %s route %s is not reachable from a planned navigation control", actual.ScreenID, actual.RouteKey)
		}
	}
	reachable := make(map[string]bool, len(screens))
	queue := make([]string, 0, len(navigationRoots))
	for _, actual := range screens {
		if actual.NavigationRoot {
			reachable[actual.RouteKey] = true
			queue = append(queue, actual.RouteKey)
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, destination := range adjacentRoutes[current] {
			if !reachable[destination] {
				reachable[destination] = true
				queue = append(queue, destination)
			}
		}
	}
	for _, actual := range screens {
		if !reachable[actual.RouteKey] {
			return fmt.Errorf("screen %s route %s is not reachable by traversal from a navigation root", actual.ScreenID, actual.RouteKey)
		}
	}
	for id, f := range features {
		got := actualControlsByFeature[id]
		sort.Strings(got)
		if !reflect.DeepEqual(got, f.ControlIDs) {
			return fmt.Errorf("feature %s control ID mapping is %v, want %v", id, f.ControlIDs, got)
		}
	}
	return nil
}

func validateControl(c control) error {
	allowedTypes := []string{"ACTION", "LINK", "SELECTION", "TOGGLE", "EXPLANATORY"}
	if !contains(allowedTypes, c.ControlType) {
		return fmt.Errorf("control %s has unsupported control type %q", c.ControlID, c.ControlType)
	}
	for name, value := range map[string]string{
		"label key":               c.LabelKey,
		"planned composable":      c.PlannedComposable,
		"state property":          c.StateProperty,
		"action symbol":           c.ActionSymbol,
		"enabled condition":       c.EnabledCondition,
		"validation symbol":       c.ValidationSymbol,
		"bounded inputs":          c.BoundedInputs,
		"persistence owner":       c.PersistenceOwner,
		"observable effect":       c.ObservableEffect,
		"failure explanation key": c.FailureExplanationKey,
		"reversal action":         c.ReversalAction,
		"accessibility contract":  c.AccessibilityContract,
		"localization owner":      c.LocalizationOwner,
		"migration contract":      c.MigrationContract,
		"recovery contract":       c.RecoveryContract,
		"semantics test tag":      c.SemanticsTestTag,
		"failure code":            c.FailureCode,
		"user recovery action":    c.UserRecoveryAction,
		"process recreation":      c.ProcessRecreationBehavior,
	} {
		if err := boundedString("control "+c.ControlID+" "+name, value, true); err != nil {
			return err
		}
		if strings.Contains(value, "http"+"://") || strings.Contains(value, "https"+"://") || strings.Contains(value, "file"+"://") || absoluteWindowsPathPattern.MatchString(value) {
			return fmt.Errorf("control %s %s violates the privacy-safe contract", c.ControlID, name)
		}
	}
	if err := boundedString("control "+c.ControlID+" unavailable reason", c.UnavailableReasonKey, false); err != nil {
		return err
	}
	if c.ImplementationState != "planned" {
		return fmt.Errorf("control %s implementation state must remain planned", c.ControlID)
	}
	suffix := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(c.ControlID, "P18-C-"), "-", "_"))
	if c.SemanticsTestTag != "phase18_control_"+suffix {
		return fmt.Errorf("control %s semantics test tag is %q", c.ControlID, c.SemanticsTestTag)
	}
	if !contains(productFailureCodes, c.FailureCode) {
		return fmt.Errorf("control %s failure code %q is outside ProductFailureCode", c.ControlID, c.FailureCode)
	}
	allowedRecovery := []string{
		"correct-the-draft-or-cancel-to-the-last-committed-state",
		"reauthorize-and-re-enter-or-repeat-the-explicit-sensitive-action",
		"reload-authoritative-state-review-failure-and-explicitly-confirm-any-retry",
		"review-localized-failure-and-explicitly-retry-or-reverse",
		"review-localized-unavailable-reason-and-return-without-mutation",
		"review-navigation-failure-and-return-to-the-source-route",
	}
	if !contains(allowedRecovery, c.UserRecoveryAction) {
		return fmt.Errorf("control %s user recovery action is unsupported", c.ControlID)
	}
	allowedRecreation := []string{
		"clear-sensitive-input-and-require-reauthorization-or-re-entry",
		"reload-authoritative-state-without-repeating-action",
		"reload-unavailable-reason-from-admitted-contract-without-enabling-action",
		"restore-nonsensitive-draft-from-authorized-state-without-repeating-action",
		"restore-route-from-opaque-id-without-repeating-action",
	}
	if !contains(allowedRecreation, c.ProcessRecreationBehavior) {
		return fmt.Errorf("control %s process recreation behavior is unsupported", c.ControlID)
	}
	if len(c.FeatureDispositions) != len(c.FeatureIDs) {
		return fmt.Errorf("control %s feature disposition count is %d, want %d", c.ControlID, len(c.FeatureDispositions), len(c.FeatureIDs))
	}
	for i, featureID := range c.FeatureIDs {
		disposition := c.FeatureDispositions[i]
		if disposition.FeatureID != featureID {
			return fmt.Errorf("control %s feature disposition at row %d is for %s, want %s", c.ControlID, i+1, disposition.FeatureID, featureID)
		}
		if !contains(terminalDispositions, disposition.TerminalDisposition) {
			return fmt.Errorf("control %s feature disposition for %s is unsupported", c.ControlID, featureID)
		}
		if disposition.LegacyProvenanceKey != "legacy-coverage:"+featureID {
			return fmt.Errorf("control %s legacy provenance for %s is invalid", c.ControlID, featureID)
		}
	}
	sensitive := strings.ToLower(c.LabelKey + " " + c.ActionSymbol + " " + c.StateProperty)
	if (strings.Contains(sensitive, "credential") || strings.Contains(sensitive, "passphrase") || strings.Contains(sensitive, "reveal") || strings.Contains(sensitive, "paste_clipboard") || strings.Contains(sensitive, "pasteclipboard") || strings.Contains(sensitive, "enter_kurd_link") || strings.Contains(sensitive, "enterkurdlink")) && c.ProcessRecreationBehavior != "clear-sensitive-input-and-require-reauthorization-or-re-entry" {
		return fmt.Errorf("control %s process recreation must clear sensitive input and require reauthorization or re-entry", c.ControlID)
	}
	if len(c.TestIDs) == 0 || len(c.TestIDs) > 32 || !canonicalUniqueStrings(c.TestIDs) {
		return fmt.Errorf("control %s test IDs must be a nonempty canonical bounded list", c.ControlID)
	}
	if len(c.EvidenceKeys) == 0 || len(c.EvidenceKeys) > 32 || !canonicalUniqueStrings(c.EvidenceKeys) {
		return fmt.Errorf("control %s evidence keys must be a nonempty canonical bounded list", c.ControlID)
	}
	for _, value := range append(append([]string(nil), c.TestIDs...), c.EvidenceKeys...) {
		if err := boundedString("control "+c.ControlID+" list value", value, true); err != nil {
			return err
		}
	}
	if c.Enabled {
		if c.ControlType == "EXPLANATORY" || c.ActionSymbol == "NONE" || c.ValidationSymbol == "NONE" || c.ReversalAction == "NONE" {
			return fmt.Errorf("enabled control %s lacks action, validation, or reversal", c.ControlID)
		}
		if c.UnavailableReasonKey != "" {
			return fmt.Errorf("enabled control %s has an unavailable reason", c.ControlID)
		}
	} else {
		if c.ControlType != "EXPLANATORY" || c.ActionSymbol != "NONE" || c.ValidationSymbol != "NONE" || c.ReversalAction != "NONE" || c.UnavailableReasonKey == "" {
			return fmt.Errorf("disabled control %s must be a noninteractive explanatory row with a reason", c.ControlID)
		}
	}
	return nil
}

func expectedBudgets() performanceBudgets {
	return performanceBudgets{
		SchemaVersion: budgetSchema,
		Decision:      "PLANNING_ONLY",
		Metrics: []budgetMetric{
			{MetricID: "cold-start-ttid", MedianMilliseconds: fp(1000), P95Milliseconds: fp(1500), Iterations: ip(20), Measurement: "physical-arm64-api36-release-like"},
			{MetricID: "cold-start-ttfd", P95Milliseconds: fp(2000), FirstUsableStates: []string{"Home", "onboarding"}, FullyDrawnRequired: bp(true), Measurement: "physical-arm64-api36-fully-drawn"},
			{MetricID: "warm-start", P95Milliseconds: fp(750), Iterations: ip(20), Measurement: "physical-arm64-api36"},
			{MetricID: "navigation-settled-frame", P95Milliseconds: fp(100), Measurement: "home-profiles-settings-five-deep-flows"},
			{MetricID: "large-list-scroll", P95Milliseconds: fp(16.7), P99Milliseconds: fp(33.4), ProfileCount: ip(1000), Measurement: "physical-60hz-redacted-fixtures"},
			{MetricID: "connect-to-preparing", P95Milliseconds: fp(100), Measurement: "app-controlled-transition"},
			{MetricID: "route-plan-to-tun", P95Milliseconds: fp(500), Measurement: "remote-handshake-excluded"},
			{MetricID: "stop-to-closed-tun", P95Milliseconds: fp(1000), Actions: []string{"Recover Internet", "Stop"}, Measurement: "proxy-and-socket-teardown-included"},
			{MetricID: "handover-reaction", MaximumMilliseconds: fp(500), Transitions: ip(10), VisibleStates: []string{"FallingBack", "Reconnecting"}, TransitionDirections: []string{"Wi-Fi-to-cellular", "cellular-to-Wi-Fi"}, Measurement: "network-callback-to-visible-recovery-state"},
			{MetricID: "steady-connected-pss", P95MiB: fp(160), ProcessScope: "app+:vpn", Measurement: "ten-minute-idle-and-active-transfer-samples"},
			{MetricID: "memory-growth", MaximumMiB: fp(10), Cycles: ip(100), ProcessScope: "same-process-pair", Measurement: "after-garbage-collection-stabilization"},
			{MetricID: "idle-cpu", P95Percent: fp(2), DurationMinutes: ip(10), ProcessScope: "app+:vpn", Measurement: "screen-off-no-scheduled-probe-or-update"},
			{MetricID: "screen-off-battery", MaximumPercentagePointsPerHour: fp(2), DurationHours: ip(3), Runs: ip(3), Conditions: []string{"stable-power", "stable-Wi-Fi"}, Measurement: "median-of-three-dedicated-runs"},
			{MetricID: "thermal", MaximumCategory: sp("below-severe"), CausalFailureRule: "severe-or-higher-caused-by-app-work", Measurement: "connected-idle-transfer-proxy-probe"},
			{MetricID: "update-worker", MaximumSeconds: fp(30), MaximumActivePerDeployment: ip(1), TerminalOutcomes: []string{"CATEGORICAL_TIMEOUT", "COMPLETED"}, Measurement: "fake-clock-unit-tests-plus-dedicated-network-run"},
			{MetricID: "proxy", FirstConnectMaximumMilliseconds: fp(250), OverLimitRejectMaximumMilliseconds: fp(100), ProtocolOperation: "CONNECT", AuthenticationRequired: bp(true), Measurement: "local-overhead-native-handshake-excluded"},
			{MetricID: "reliability", ConnectStopCycles: ip(100), NavigationCycles: ip(1000), MaximumFailures: ip(0), ZeroFailureCategories: []string{"crash", "deadlock", "leaked-service", "stuck-operation"}, Measurement: "dedicated-phase18-device"},
		},
	}
}

func fp(v float64) *float64 { return &v }
func ip(v int) *int         { return &v }
func sp(v string) *string   { return &v }
func bp(v bool) *bool       { return &v }

func validateBudgets(root string) error {
	raw, err := readBounded(root, budgetsPath, maxJSONBytes)
	if err != nil {
		return err
	}
	var got performanceBudgets
	if err := decodeStrictJSON(raw, &got); err != nil {
		return fmt.Errorf("performance budget JSON: %w", err)
	}
	if len(got.Metrics) > 64 {
		return errors.New("performance budget metrics exceed bounded list maximum")
	}
	for _, metric := range got.Metrics {
		if err := boundedString("performance budget metric ID", metric.MetricID, true); err != nil {
			return err
		}
		if err := boundedString("performance budget measurement", metric.Measurement, true); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(got, expectedBudgets()) {
		return errors.New("performance budget contract differs from the exact accepted values")
	}
	return nil
}

func validateOwnedFiles(root string, requirePublicationMembership bool) error {
	if err := validateCanonicalTextFile(root, ownedFilesPath, expectedOwnedFiles, "owned path set"); err != nil {
		return err
	}
	for _, relative := range expectedOwnedFiles {
		if strings.HasPrefix(relative, "testdata/evidence/phase18/") || strings.HasPrefix(relative, "."+"tools/") {
			return fmt.Errorf("owned path set contains excluded path %s", relative)
		}
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("owned path %s is missing: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("owned path %s is not a regular in-repository file", relative)
		}
	}
	for _, relative := range expectedGeneratedEvidenceFiles {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("generated evidence path %s is missing: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generated evidence path %s is not a regular in-repository file", relative)
		}
	}
	if requirePublicationMembership {
		publicationPaths := append([]string(nil), expectedOwnedFiles...)
		publicationPaths = append(publicationPaths, expectedGeneratedEvidenceFiles...)
		publicationPaths = append(publicationPaths, acceptancePath)
		for _, relative := range publicationPaths {
			tracked, err := gitIndexTracks(root, relative)
			if err != nil {
				return err
			}
			if !tracked {
				return fmt.Errorf("publication path %s must be tracked in the Git index", relative)
			}
		}
	}
	return nil
}

func gitIndexTracks(root, relative string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(root, ".git")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect repository metadata: %w", err)
	}
	cmd := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", filepath.ToSlash(relative))
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("inspect Git index membership for %s: %w", relative, err)
	}
	return true, nil
}

func validateCanonicalTextFile(root, relative string, expected []string, label string) error {
	raw, err := readBounded(root, relative, maxMarkdownBytes)
	if err != nil {
		return err
	}
	if bytes.Contains(raw, []byte{'\r'}) || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return fmt.Errorf("%s must use canonical LF lines and a final newline", label)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if label == "owned path set" {
		expectedSet := make(map[string]struct{}, len(expected))
		for _, line := range expected {
			expectedSet[line] = struct{}{}
		}
		for _, line := range lines {
			if _, ok := expectedSet[line]; !ok {
				return fmt.Errorf("owned path set contains future path %q", line)
			}
		}
	}
	if len(lines) != len(expected) {
		return fmt.Errorf("%s has %d entries, want %d", label, len(lines), len(expected))
	}
	if !canonicalUniqueStrings(lines) {
		return fmt.Errorf("%s is not bytewise sorted and unique", label)
	}
	for _, line := range lines {
		if err := boundedString(label+" entry", line, true); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(lines, expected) {
		return fmt.Errorf("%s differs from the exact current Phase 18 task set", label)
	}
	return nil
}

func validateAcceptance(root string) (acceptanceStatus, error) {
	raw, err := readBounded(root, acceptancePath, maxJSONBytes)
	if err != nil {
		return acceptanceStatus{}, err
	}
	var got acceptanceStatus
	if err := decodeStrictJSON(raw, &got); err != nil {
		return acceptanceStatus{}, fmt.Errorf("acceptance status: %w", err)
	}
	if err := validateAcceptanceValue(got); err != nil {
		return acceptanceStatus{}, err
	}
	canonical, err := canonicalJSON(got)
	if err != nil {
		return acceptanceStatus{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return acceptanceStatus{}, errors.New("acceptance status JSON is not canonical")
	}
	return got, nil
}

func validateAcceptanceValue(got acceptanceStatus) error {
	if got.SchemaVersion != "phase18-acceptance-status-v1" {
		return fmt.Errorf("acceptance schemaVersion must be phase18-acceptance-status-v1, got %q", got.SchemaVersion)
	}
	if got.EvidenceKind != "acceptance-status" {
		return fmt.Errorf("acceptance evidenceKind must be acceptance-status, got %q", got.EvidenceKind)
	}
	if !validSHA256(got.ControlSetSHA256) || got.ControlSetSHA256 != controlSetSHA256 {
		return fmt.Errorf("acceptance controlSetSHA256 must bind the canonical control set")
	}
	if got.ImplementationStatus != "NOT_STARTED" {
		return fmt.Errorf("acceptance implementationStatus must remain NOT_STARTED, got %q", got.ImplementationStatus)
	}
	if got.Phase18Decision != "NO_GO" {
		return fmt.Errorf("acceptance phase18Decision must remain NO_GO, got %q", got.Phase18Decision)
	}
	if got.ReleaseAuthorization != "NO_GO" {
		return fmt.Errorf("acceptance releaseAuthorization must remain NO_GO, got %q", got.ReleaseAuthorization)
	}
	return nil
}

var markdownLinkPattern = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)

func validateMarkdownFiles(root string, manifest planningManifest, acceptance acceptanceStatus) error {
	coverage, err := readBounded(root, coveragePath, maxMarkdownBytes)
	if err != nil {
		return err
	}
	evidence, err := readBounded(root, evidencePath, maxMarkdownBytes)
	if err != nil {
		return err
	}
	for relative, raw := range map[string][]byte{coveragePath: coverage, evidencePath: evidence} {
		if err := validateRelativeMarkdownLinks(root, relative, raw); err != nil {
			return err
		}
	}
	wantCoverage := renderCoverageMarkdown(manifest)
	if !bytes.Equal(coverage, wantCoverage) {
		return errors.New("coverage document differs from the exact deterministic manifest rendering")
	}
	wantEvidence := renderEvidenceMarkdown(acceptance)
	if !bytes.Equal(evidence, wantEvidence) {
		return errors.New("evidence index differs from the exact deterministic contract rendering")
	}
	return nil
}

func renderCoverageMarkdown(m planningManifest) []byte {
	var b strings.Builder
	b.WriteString("# Phase 18 feature coverage\n\n## Status\n\n")
	b.WriteString("This is a planning-completeness contract for [the Task 0 production contract](PHASE18_ANDROID_PRODUCTION_CONTRACT.md#capability-gated-feature-ledger). It does not claim implementation, execution, installation, qualification, or release.\n\n")
	b.WriteString("- Current implementation state: `NOT_STARTED`\n- Phase 18 decision: `NO_GO`\n- Release authorization: `NO_GO`\n")
	fmt.Fprintf(&b, "- Frozen legacy-coverage digest: `%s`\n- Legacy scope: `%s`; inspiration inventory reconciled: `%t`.\n- Canonical control count: `%d`\n- Canonical control-set SHA-256: `%s`\n\n", m.LegacyCoverageProvenance.SHA256, m.LegacyCoverageProvenance.ReconcilesLegacyItems, m.LegacyCoverageProvenance.ReconcilesInspirationInventory, m.ControlCount, m.ControlSetSHA256)
	b.WriteString("## Feature ledger\n\n| Feature | Capability | Frozen disposition | Target disposition | Capability admission | Owning tasks | Current state |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, f := range m.Features {
		owners := make([]string, len(f.OwnerTasks))
		for i, owner := range f.OwnerTasks {
			owners[i] = strconv.Itoa(owner)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", f.FeatureID, f.CapabilityKey, f.FrozenDisposition, f.TargetDisposition, f.CapabilityAdmission, strings.Join(owners, ","), f.ImplementationState)
	}
	b.WriteString("\n## Screen ledger\n\n| Screen | Route | Planned owner file | Planned owner symbol | Planned state owner | Navigation root |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, s := range m.Screens {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | `%s` | `%s` | %t |\n", s.ScreenID, s.RouteKey, s.OwnerFile, s.OwnerSymbol, s.StateOwner, s.NavigationRoot)
	}
	b.WriteString("\n## Planning boundary\n\nAll 67 features and 311 controls remain planned. Device, qualification, candidate, Stress, soak, publication, and release evidence remain unexecuted.\n")
	return []byte(b.String())
}

func renderEvidenceMarkdown(a acceptanceStatus) []byte {
	var b strings.Builder
	b.WriteString("# Phase 18 evidence index\n\n## Current planning evidence\n\n")
	b.WriteString("[The Task 0 production contract](PHASE18_ANDROID_PRODUCTION_CONTRACT.md#capability-gated-feature-ledger) binds capability admission. [Phase 18 feature coverage](PHASE18_FEATURE_COVERAGE.md#feature-ledger) binds the planning ledger.\n\n")
	fmt.Fprintf(&b, "- Implementation status: `%s`\n- Phase 18 decision: `%s`\n- Release authorization: `%s`\n- Canonical control-set SHA-256: `%s`\n\n", a.ImplementationStatus, a.Phase18Decision, a.ReleaseAuthorization, a.ControlSetSHA256)
	b.WriteString("| Record kind | Schema | Present now | Current result |\n| --- | --- | --- | --- |\n")
	b.WriteString("| acceptance-status | phase18-acceptance-status-v1 | yes | `NOT_STARTED`; `NO_GO` |\n")
	for _, kind := range evidenceKinds {
		if kind == "acceptance-status" {
			continue
		}
		fmt.Fprintf(&b, "| %s | phase18-%s-v1 | no | `UNEXECUTED` |\n", kind, kind)
	}
	b.WriteString("\n## Decoder and privacy boundary\n\nFuture evidence is absent. Decoders accept only canonical, versioned, source-bound categorical/hash records. Unknown, duplicate, trailing, malformed, oversized, noncanonical, or privacy-prohibited data is rejected. No future record is created by Task 1.\n")
	b.WriteString("\n## Gate boundary\n\nD01-D08, G03-G04, installed-device qualification, candidate construction, Stress, soak, publication, and release remain unexecuted and `NO_GO`.\n")
	return []byte(b.String())
}

func validateRelativeMarkdownLinks(root, relative string, raw []byte) error {
	for _, match := range markdownLinkPattern.FindAllSubmatch(raw, -1) {
		target := string(match[1])
		if strings.Contains(target, "://") || strings.HasPrefix(target, "/") || filepath.IsAbs(target) {
			return fmt.Errorf("Markdown link in %s is not repository-relative: %q", relative, target)
		}
		parts := strings.SplitN(target, "#", 2)
		pathPart := parts[0]
		if pathPart == "" {
			continue
		}
		targetRelative := filepath.Clean(filepath.Join(filepath.Dir(filepath.FromSlash(relative)), filepath.FromSlash(pathPart)))
		if targetRelative == "." || filepath.IsAbs(targetRelative) || targetRelative == ".." || strings.HasPrefix(targetRelative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("Markdown link in %s escapes repository: %q", relative, target)
		}
		targetRaw, err := readBounded(root, filepath.ToSlash(targetRelative), maxMarkdownBytes)
		if err != nil {
			return fmt.Errorf("Markdown link in %s does not resolve safely: %q: %w", relative, target, err)
		}
		if len(parts) == 2 && parts[1] != "" {
			if !markdownHasAnchor(targetRaw, parts[1]) {
				return fmt.Errorf("Markdown anchor in %s does not resolve: %q", relative, target)
			}
		}
	}
	return nil
}

func markdownHasAnchor(raw []byte, want string) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		heading := strings.TrimSpace(strings.TrimLeft(line, "#"))
		var b strings.Builder
		lastHyphen := false
		for _, r := range strings.ToLower(heading) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				b.WriteRune(r)
				lastHyphen = false
			case r == ' ' || r == '-':
				if b.Len() > 0 && !lastHyphen {
					b.WriteByte('-')
					lastHyphen = true
				}
			}
		}
		if strings.TrimSuffix(b.String(), "-") == want {
			return true
		}
	}
	return false
}

func decodeStrictJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > maxJSONBytes {
		return fmt.Errorf("JSON byte length %d is outside the bounded range", len(raw))
	}
	if bytes.Contains(raw, []byte{'\r'}) {
		return errors.New("JSON must use canonical LF line endings")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := requireJSONEOF(dec); err != nil {
		return err
	}
	return nil
}

func decodeEvidenceRecord(kind string, raw []byte, repositoryRoots ...string) error {
	if len(repositoryRoots) > 1 {
		return errors.New("evidence repository root may be supplied at most once")
	}
	if len(repositoryRoots) == 1 && strings.TrimSpace(repositoryRoots[0]) == "" {
		return errors.New("evidence repository root is empty")
	}
	if !contains(evidenceKinds, kind) {
		return fmt.Errorf("unsupported Phase 18 evidence kind %q", kind)
	}
	if kind == "acceptance-status" {
		var record acceptanceStatus
		if err := decodeStrictJSON(raw, &record); err != nil {
			return err
		}
		if err := validateAcceptanceValue(record); err != nil {
			return err
		}
		return requireCanonicalJSON(raw, record)
	}
	var record evidenceRecord
	if err := decodeStrictJSON(raw, &record); err != nil {
		return err
	}
	if record.SchemaVersion != "phase18-"+kind+"-v1" {
		return fmt.Errorf("evidence schema %q does not match kind %s", record.SchemaVersion, kind)
	}
	if record.EvidenceKind != kind {
		return fmt.Errorf("evidence kind is %q, want %q", record.EvidenceKind, kind)
	}
	if !gitObjectIDPattern.MatchString(record.SubjectCommit) || !gitObjectIDPattern.MatchString(record.SubjectTree) {
		return errors.New("evidence subject commit/tree identity is malformed")
	}
	if len(repositoryRoots) == 1 {
		if err := validateEvidenceSubject(repositoryRoots[0], record.SubjectCommit, record.SubjectTree); err != nil {
			return err
		}
	}
	if !evidenceResultAllowed(record.Result) {
		return fmt.Errorf("evidence result %q is not categorical", record.Result)
	}
	if !validSHA256(record.EvidenceSHA256) {
		return errors.New("evidence SHA-256 is malformed")
	}
	if len(record.Checks) < 1 || len(record.Checks) > 256 {
		return fmt.Errorf("evidence check list has %d entries outside 1..256", len(record.Checks))
	}
	previous := ""
	for _, check := range record.Checks {
		if !evidenceCheckIDPattern.MatchString(check.CheckID) || evidenceValueProhibited(check.CheckID) {
			return fmt.Errorf("evidence check ID %q is outside the privacy allowlist", check.CheckID)
		}
		if previous != "" && check.CheckID <= previous {
			return errors.New("evidence check list is not canonical, strictly ordered, and unique")
		}
		previous = check.CheckID
		if !evidenceResultAllowed(check.Result) {
			return fmt.Errorf("evidence check %s result %q is not categorical", check.CheckID, check.Result)
		}
		if record.Result == "PASS" && check.Result != "PASS" {
			return fmt.Errorf("aggregate PASS conflicts with non-PASS check %s result %s", check.CheckID, check.Result)
		}
		if !validSHA256(check.EvidenceSHA256) {
			return fmt.Errorf("evidence check %s SHA-256 is malformed", check.CheckID)
		}
	}
	return requireCanonicalJSON(raw, record)
}

func validateEvidenceSubject(root, commit, tree string) error {
	typeOf := func(object string) (string, error) {
		cmd := exec.Command("git", "-C", root, "cat-file", "-t", object)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("resolve immutable Git object %s: %w", object, err)
		}
		return strings.TrimSpace(string(output)), nil
	}
	commitType, err := typeOf(commit)
	if err != nil {
		return err
	}
	if commitType != "commit" {
		return fmt.Errorf("evidence subject commit object %s has type %s", commit, commitType)
	}
	treeType, err := typeOf(tree)
	if err != nil {
		return err
	}
	if treeType != "tree" {
		return fmt.Errorf("evidence subject tree object %s has type %s", tree, treeType)
	}
	cmd := exec.Command("git", "-C", root, "rev-parse", commit+"^{tree}")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("resolve evidence subject commit tree: %w", err)
	}
	actualTree := strings.TrimSpace(string(output))
	if actualTree != tree {
		return fmt.Errorf("evidence subject commit %s resolves to tree %s, not %s", commit, actualTree, tree)
	}
	return nil
}

func evidenceResultAllowed(value string) bool {
	return contains([]string{"BLOCKED", "FAIL", "INCOMPLETE", "NO_GO", "NOT_AVAILABLE", "PASS", "UNEXECUTED"}, value)
}

func evidenceValueProhibited(value string) bool {
	lower := strings.ToLower(value)
	if strings.ContainsAny(value, `/\\:`) || strings.Contains(lower, ".") {
		return true
	}
	for _, category := range []string{"authority", "credential", "device_identifier", "dns", "endpoint", "packet", "profile_material", "secret", "token"} {
		if strings.Contains(lower, category) {
			return true
		}
	}
	return false
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	return append(raw, '\n'), nil
}

func requireCanonicalJSON(raw []byte, value any) error {
	want, err := canonicalJSON(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, want) {
		return errors.New("evidence JSON is not in canonical object and list representation")
	}
	return nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var consumeValue func() error
	consumeValue = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := consumeValue(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for dec.More() {
				if err := consumeValue(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := consumeValue(); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return err
	}
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("JSON contains trailing data")
	}
	return err
}

func readBounded(root, relative string, maximum int64) ([]byte, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	resolvedRoot, err = filepath.Abs(resolvedRoot)
	if err != nil {
		return nil, fmt.Errorf("canonicalize repository root: %w", err)
	}
	candidate := filepath.Clean(filepath.Join(resolvedRoot, filepath.FromSlash(relative)))
	if !insideRoot(resolvedRoot, candidate) {
		return nil, fmt.Errorf("path escapes repository: %s", relative)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, fmt.Errorf("resolve required path %s: %w", relative, err)
	}
	resolvedCandidate, err = filepath.Abs(resolvedCandidate)
	if err != nil {
		return nil, fmt.Errorf("canonicalize required path %s: %w", relative, err)
	}
	if !insideRoot(resolvedRoot, resolvedCandidate) {
		return nil, fmt.Errorf("resolved path escapes repository: %s", relative)
	}
	info, err := os.Lstat(resolvedCandidate)
	if err != nil {
		return nil, fmt.Errorf("required path %s: %w", relative, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("required path %s is not a regular file", relative)
	}
	if info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("required path %s has byte length %d outside 1..%d", relative, info.Size(), maximum)
	}
	raw, err := os.ReadFile(resolvedCandidate)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relative, err)
	}
	if int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("read %s changed length during verification", relative)
	}
	return raw, nil
}

func insideRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func gitChangedPaths(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("enumerate changed paths: %w", err)
	}
	return parseGitStatusPaths(raw)
}

func parseGitStatusPaths(raw []byte) ([]string, error) {
	entries := bytes.Split(raw, []byte{0})
	paths := make([]string, 0, len(entries))
	for i := 0; i < len(entries); i++ {
		entry := entries[i]
		if len(entry) == 0 {
			continue
		}
		if len(entry) < 4 || entry[2] != ' ' {
			return nil, fmt.Errorf("malformed git status entry %q", entry)
		}
		paths = append(paths, filepath.ToSlash(string(entry[3:])))
		if entry[0] == 'R' || entry[0] == 'C' || entry[1] == 'R' || entry[1] == 'C' {
			i++
			if i >= len(entries) || len(entries[i]) == 0 {
				return nil, errors.New("malformed rename/copy status entry")
			}
			paths = append(paths, filepath.ToSlash(string(entries[i])))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func validateChangedPaths(paths []string) error {
	allowed := make(map[string]struct{}, len(expectedOwnedFiles)+len(expectedGeneratedEvidenceFiles)+1)
	for _, path := range expectedOwnedFiles {
		allowed[path] = struct{}{}
	}
	for _, path := range expectedGeneratedEvidenceFiles {
		allowed[path] = struct{}{}
	}
	allowed[acceptancePath] = struct{}{}
	seen := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		path := filepath.ToSlash(filepath.Clean(raw))
		if path == "." || filepath.IsAbs(raw) || path == ".." || strings.HasPrefix(path, "../") {
			return fmt.Errorf("unowned changed path %q is invalid", raw)
		}
		if _, duplicate := seen[path]; duplicate {
			return fmt.Errorf("duplicate changed path %q", path)
		}
		seen[path] = struct{}{}
		if _, ok := allowed[path]; !ok {
			return fmt.Errorf("unowned changed path %q", path)
		}
	}
	return nil
}

var absoluteWindowsPathPattern = regexp.MustCompile(`(?i)(^|[[:space:]"'\(])[a-z]:[\\/]`)
var publicURLPattern = regexp.MustCompile(`(?i)https?://[^\x00-\x20"'<>]+`)

func validatePublicSafety(root string) error {
	paths := append([]string(nil), expectedOwnedFiles...)
	paths = append(paths, expectedGeneratedEvidenceFiles...)
	paths = append(paths, acceptancePath)
	for _, relative := range paths {
		raw, err := readBounded(root, relative, maxJSONBytes)
		if err != nil {
			return err
		}
		text := strings.ToLower(string(raw))
		text, err = scrubAuditedGeneratedURLs(relative, text)
		if err != nil {
			return err
		}
		for _, allowed := range publicSafetyAllowedFragments(relative) {
			count := strings.Count(text, allowed)
			if count > 1 {
				return fmt.Errorf("privacy/public-safety rejection in %s: duplicated allowed fragment", relative)
			}
			if count == 1 {
				text = strings.Replace(text, allowed, "", 1)
			}
		}
		for _, forbidden := range publicSafetyForbiddenCategories() {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("privacy/public-safety rejection in %s: forbidden category %q", relative, forbidden)
			}
		}
		if absoluteWindowsPathPattern.Match(raw) {
			return fmt.Errorf("privacy/public-safety rejection in %s: absolute local path", relative)
		}
		if strings.ContainsRune(string(raw), '\x00') {
			return fmt.Errorf("privacy/public-safety rejection in %s: NUL byte", relative)
		}
	}
	return nil
}

func scrubAuditedGeneratedURLs(relative, text string) (string, error) {
	allowedHosts := publicSafetyURLHosts(relative)
	if len(allowedHosts) == 0 {
		return text, nil
	}
	for _, rawURL := range publicURLPattern.FindAllString(text, -1) {
		parsed, err := url.Parse(rawURL)
		if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
			return "", fmt.Errorf("privacy/public-safety rejection in %s: malformed generated URL", relative)
		}
		host := strings.ToLower(parsed.Hostname())
		if parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !allowedHosts[host] {
			return "", fmt.Errorf("privacy/public-safety rejection in %s: unaudited generated URL", relative)
		}
		text = strings.Replace(text, rawURL, "", 1)
	}
	return text, nil
}

func publicSafetyURLHosts(relative string) map[string]bool {
	var hosts []string
	switch relative {
	case "android/gradle/verification-metadata.xml":
		hosts = []string{"schema.gradle.org", "www.w3.org"}
	case "testdata/evidence/phase9/android-licenses.spdx.json":
		hosts = []string{"github.com"}
	case "testdata/evidence/phase9/android-sbom.cdx.json":
		hosts = []string{
			"code.google.com",
			"cs.android.com",
			"github.com",
			"opensource.org",
			"oss.sonatype.org",
			"source.android.com",
			"www.apache.org",
			"www.google.com",
		}
	default:
		return nil
	}
	allowed := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		allowed[host] = true
	}
	return allowed
}

func publicSafetyAllowedFragments(relative string) []string {
	if relative != "android/build.gradle.kts" {
		return nil
	}
	// These exact public Gradle arguments select ignored device-gate output roots.
	// Any other local-output reference remains categorically rejected below.
	return []string{
		`"` + "." + `tools/phase11/device-gate/latest"`,
		`"` + "." + `tools/phase13/device-gate/latest"`,
		`"` + "." + `tools/phase14/device-gate/latest"`,
	}
}

func publicSafetyForbiddenCategories() []string {
	return []string{
		"." + "codex-" + "private",
		"agents." + "override.md",
		"private" + "-planning",
		"master_" + "implementation_plan",
		"private" + " planning",
		"master" + " plan",
		"mini-" + "roadmap",
		"owner-" + "decision",
		"handoff" + " packet",
		"." + "tools/",
		"appdata/" + "local/temp",
		"http" + "://",
		"https" + "://",
	}
}

func exactBounded(label, actual, expected string) error {
	if err := boundedString(label, actual, true); err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%s is %q, want %q", label, actual, expected)
	}
	return nil
}

func boundedString(label, value string, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%s is empty", label)
	}
	if len([]byte(value)) > maxTextBytes {
		return fmt.Errorf("%s exceeds bounded string maximum %d", label, maxTextBytes)
	}
	if strings.ContainsRune(value, '\x00') || !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid bounded UTF-8 text", label)
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func strictlyIncreasingInts(values []int) bool {
	if len(values) == 0 {
		return false
	}
	for i, value := range values {
		if value < 0 || value > 31 || i > 0 && value <= values[i-1] {
			return false
		}
	}
	return true
}

func canonicalUniqueStrings(values []string) bool {
	for i, value := range values {
		if value == "" || i > 0 && value <= values[i-1] {
			return false
		}
	}
	return true
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
