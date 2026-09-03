// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const fixtureLegacyHash = "8f1235653f1e3367f164660cd805921279282177bf8c35faaaef196fc149bbb4"

const expectedControlSetSHA256ForTest = "b922c3411014eb680b2aeef0bb75c3c35a6872734c92e8a14faab4a485c401c7"

var fixtureFeatureSpecs = []string{
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

var fixtureScreenSpecs = []string{
	"P18-S01|Welcome|WelcomeScreen|OnboardingViewModel, OnboardingState",
	"P18-S02|ImportSource|ImportSourceScreen|OnboardingViewModel, ImportCoordinator",
	"P18-S03|FirstTrust(importId)|FirstTrustScreen|OnboardingViewModel, ProfileRepository",
	"P18-S04|VpnPermissionEducation|VpnPermissionScreen|OnboardingViewModel, SystemPolicyRepository",
	"P18-S05|Home|HomeScreen|ConnectionViewModel, ConnectionState",
	"P18-S06|RouteDetail(sessionAlias)|RouteDetailScreen|ConnectionViewModel, VerifiedRouteSnapshot",
	"P18-S07|Profiles|ProfilesScreen|ProfilesViewModel, DeploymentListState",
	"P18-S08|DeploymentDetail(deploymentId)|DeploymentDetailScreen|ProfilesViewModel, DeploymentDetailState",
	"P18-S09|ProfileDetail(profileId)|ProfileDetailScreen|ProfilesViewModel, ProfileDetailState",
	"P18-S10|StrategyMatrix(profileId)|StrategyMatrixScreen|ProfilesViewModel, StrategyMatrixState",
	"P18-S11|ProbeHistory(profileId)|ProbeHistoryScreen|ProfilesViewModel, ProbeHistoryState",
	"P18-S12|Settings|SettingsIndexScreen|SettingsViewModel, SettingsIndexState",
	"P18-S13|ConnectionPermissions|ConnectionPermissionsScreen|SettingsViewModel, SystemPolicyRepository",
	"P18-S14|TrustedNetworks|TrustedNetworksScreen|SettingsViewModel, TrustedNetworkRepository",
	"P18-S15|PerAppRouting|PerAppRoutingScreen|SettingsViewModel, InstalledAppRepository",
	"P18-S16|ExcludedRoutes|ExcludedRoutesScreen|SettingsViewModel, RuntimePlanAuthorizer",
	"P18-S17|TunnelDns|TunnelDnsScreen|SettingsViewModel, RuntimePlanAuthorizer",
	"P18-S18|LocalProxy|LocalProxyScreen|SettingsViewModel, ProxyCredentialController",
	"P18-S19|UpdatesProbes|UpdatesProbesScreen|SettingsViewModel, NodeMaintenanceRepository",
	"P18-S20|AppearanceAccessibility|AppearanceAccessibilityScreen|SettingsViewModel, LocaleController",
	"P18-S21|PrivacyAppLock|PrivacyAppLockScreen|PrivacyRecoveryViewModel, PrivacyState",
	"P18-S22|BackupCreation|BackupCreationScreen|PrivacyRecoveryViewModel, BackupState",
	"P18-S23|RestorePreview(operationId)|RestorePreviewScreen|PrivacyRecoveryViewModel, RestoreState",
	"P18-S24|TransferExport(profileId)|TransferExportScreen|ProfilesViewModel, TransferState",
	"P18-S25|RecoveryCenter|RecoveryCenterScreen|PrivacyRecoveryViewModel, RecoveryState",
	"P18-S26|ScopedReset|ScopedResetScreen|PrivacyRecoveryViewModel, ResetState",
	"P18-S27|Diagnostics|DiagnosticsExplorerScreen|DiagnosticsViewModel, DiagnosticsState",
	"P18-S28|DiagnosticExport(operationId)|DiagnosticExportPreviewScreen|DiagnosticsViewModel, DiagnosticExportState",
	"P18-S29|Troubleshooting|TroubleshootingScreen|DiagnosticsViewModel, TroubleshootingState",
	"P18-S30|NotificationsPerformance|NotificationsPerformanceScreen|SettingsViewModel, LocalPerformanceState",
	"P18-S31|ExpertControls|ExpertControlsScreen|SettingsViewModel, EffectiveExpertState",
	"P18-S32|Automation|AutomationScreen|SettingsViewModel, AutomationState",
	"P18-S33|About|AboutScreen|DiagnosticsViewModel, BuildInfoState",
	"P18-S34|Legal|LegalScreen|DiagnosticsViewModel, LegalDocumentState",
}

var expectedScreenControlCountsForTest = []int{
	3, 7, 8, 5, 12, 8, 9, 8, 9, 6, 4, 14, 14, 7, 11, 5, 14,
	16, 12, 11, 13, 10, 7, 8, 7, 10, 10, 5, 17, 10, 13, 7, 6, 5,
}

type fixtureManifest struct {
	SchemaVersion            string                  `json:"schemaVersion"`
	PlanningStatus           string                  `json:"planningStatus"`
	ControlCount             int                     `json:"controlCount"`
	ControlSetSHA256         string                  `json:"controlSetSHA256"`
	LegacyCoverageProvenance fixtureLegacyProvenance `json:"legacyCoverageProvenance"`
	TerminalDispositions     []string                `json:"terminalDispositions"`
	Features                 []fixtureFeature        `json:"features"`
	Screens                  []fixtureScreen         `json:"screens"`
}

type fixtureLegacyProvenance struct {
	SourceTitle                    string   `json:"sourceTitle"`
	SHA256                         string   `json:"sha256"`
	ReconcilesLegacyItems          string   `json:"reconcilesLegacyItems"`
	ReconcilesInspirationInventory bool     `json:"reconcilesInspirationInventory"`
	FeatureIDs                     []string `json:"featureIds"`
}

type fixtureFeature struct {
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

type fixtureScreen struct {
	ScreenID       string           `json:"screenId"`
	RouteKey       string           `json:"routeKey"`
	OwnerFile      string           `json:"ownerFile"`
	OwnerSymbol    string           `json:"ownerSymbol"`
	StateOwner     string           `json:"stateOwner"`
	NavigationRoot bool             `json:"navigationRoot"`
	Controls       []fixtureControl `json:"controls"`
}

type fixtureFeatureDisposition struct {
	FeatureID           string `json:"featureId"`
	TerminalDisposition string `json:"terminalDisposition"`
	LegacyProvenanceKey string `json:"legacyProvenanceKey"`
}

type fixtureControl struct {
	ControlID                 string                      `json:"controlId"`
	FeatureIDs                []string                    `json:"featureIds"`
	FeatureDispositions       []fixtureFeatureDisposition `json:"featureDispositions"`
	ControlType               string                      `json:"controlType"`
	LabelKey                  string                      `json:"labelKey"`
	PlannedComposable         string                      `json:"plannedComposable"`
	SemanticsTestTag          string                      `json:"semanticsTestTag"`
	StateProperty             string                      `json:"stateProperty"`
	ActionSymbol              string                      `json:"actionSymbol"`
	NavigationDestination     string                      `json:"navigationDestination"`
	Enabled                   bool                        `json:"enabled"`
	EnabledCondition          string                      `json:"enabledCondition"`
	UnavailableReasonKey      string                      `json:"unavailableReasonKey"`
	ValidationSymbol          string                      `json:"validationSymbol"`
	BoundedInputs             string                      `json:"boundedInputs"`
	PersistenceOwner          string                      `json:"persistenceOwner"`
	ObservableEffect          string                      `json:"observableEffect"`
	FailureExplanationKey     string                      `json:"failureExplanationKey"`
	FailureCode               string                      `json:"failureCode"`
	UserRecoveryAction        string                      `json:"userRecoveryAction"`
	ReversalAction            string                      `json:"reversalAction"`
	AccessibilityContract     string                      `json:"accessibilityContract"`
	LocalizationOwner         string                      `json:"localizationOwner"`
	MigrationContract         string                      `json:"migrationContract"`
	RecoveryContract          string                      `json:"recoveryContract"`
	ProcessRecreationBehavior string                      `json:"processRecreationBehavior"`
	TestIDs                   []string                    `json:"testIds"`
	EvidenceKeys              []string                    `json:"evidenceKeys"`
	ImplementationState       string                      `json:"implementationState"`
}

func TestVerifyPlanningAcceptsCompletePlanningFixture(t *testing.T) {
	root, changed := writeValidPlanningFixture(t)
	if err := verifyPlanning(root, changed); err != nil {
		t.Fatalf("complete planning fixture rejected: %v", err)
	}
}

func TestVerifyPlanningRejectsLegacyProvenanceFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"missing", func(v map[string]any) { delete(v, "legacyCoverageProvenance") }, "legacy provenance"},
		{"hash mismatch", func(v map[string]any) {
			v["legacyCoverageProvenance"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		}, "legacy provenance hash"},
		{"invalid digest", func(v map[string]any) { v["legacyCoverageProvenance"].(map[string]any)["sha256"] = "not-a-digest" }, "SHA-256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			mutateJSONFile(t, root, "android/config/phase18-every-control.json", tc.mutate)
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsFeatureCardinalityIdentityAndOrderFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fixtureManifest)
		want   string
	}{
		{"missing feature", func(v *fixtureManifest) { v.Features = v.Features[:len(v.Features)-1] }, "67 features"},
		{"duplicate feature", func(v *fixtureManifest) { v.Features[1].FeatureID = v.Features[0].FeatureID }, "duplicate feature"},
		{"out of order", func(v *fixtureManifest) { v.Features[0], v.Features[1] = v.Features[1], v.Features[0] }, "feature order"},
		{"wrong key", func(v *fixtureManifest) { v.Features[0].CapabilityKey = "Changed key" }, "capability key"},
		{"wrong owner", func(v *fixtureManifest) { v.Features[0].OwnerTasks = []int{31} }, "owner tasks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			mutateManifest(t, root, tc.mutate)
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsScreenAndControlIdentityFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fixtureManifest)
		want   string
	}{
		{"missing screen", func(v *fixtureManifest) { v.Screens = v.Screens[:len(v.Screens)-1] }, "34 screens"},
		{"duplicate screen", func(v *fixtureManifest) { v.Screens[1].ScreenID = v.Screens[0].ScreenID }, "duplicate screen"},
		{"duplicate control", func(v *fixtureManifest) { v.Screens[1].Controls[0].ControlID = v.Screens[0].Controls[0].ControlID }, "duplicate control"},
		{"wrong route", func(v *fixtureManifest) { v.Screens[0].RouteKey = "Wrong" }, "route key"},
		{"wrong owner file", func(v *fixtureManifest) { v.Screens[0].OwnerFile = "wrong.kt" }, "owner file"},
		{"noncanonical control order", func(v *fixtureManifest) {
			v.Screens[0].Controls[0], v.Screens[0].Controls[1] = v.Screens[0].Controls[1], v.Screens[0].Controls[0]
		}, "control order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			mutateManifest(t, root, tc.mutate)
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsDispositionAndCapabilityFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fixtureManifest)
		want   string
	}{
		{"unsupported disposition", func(v *fixtureManifest) { v.Features[0].TargetDisposition = "partial" }, "target disposition"},
		{"capability disagreement", func(v *fixtureManifest) { featureByID(v, "P18-F014").CapabilityAdmission = "NOT_ADMITTED" }, "capability admission"},
		{"not admitted enabling control", func(v *fixtureManifest) {
			c := controlForFeature(v, "P18-F005")
			c.ControlType, c.Enabled, c.ActionSymbol = "ACTION", true, "ExitController.select"
		}, "NOT_ADMITTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			mutateManifest(t, root, tc.mutate)
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsStrictJSONAndBoundsFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(string)
		want   string
	}{
		{"unknown evidence field", func(root string) {
			mutateJSONFile(t, root, "testdata/evidence/phase18/acceptance-status.json", func(v map[string]any) { v["unknown"] = true })
		}, "unknown field"},
		{"duplicate evidence field", func(root string) {
			p := filepath.Join(root, filepath.FromSlash("testdata/evidence/phase18/acceptance-status.json"))
			raw := mustRead(t, p)
			raw = []byte(strings.Replace(string(raw), `"implementationStatus": "NOT_STARTED"`, `"implementationStatus": "NOT_STARTED", "implementationStatus": "NOT_STARTED"`, 1))
			mustWrite(t, p, raw)
		}, "duplicate"},
		{"oversized field", func(root string) {
			mutateManifest(t, root, func(v *fixtureManifest) { v.Features[0].CapabilityKey = strings.Repeat("x", 257) })
		}, "bounded string"},
		{"oversized list", func(root string) {
			mutateManifest(t, root, func(v *fixtureManifest) { v.Features[0].OwnerTasks = make([]int, 33) })
		}, "bounded list"},
		{"privacy value", func(root string) {
			mutateManifest(t, root, func(v *fixtureManifest) {
				v.Screens[0].Controls[0].ObservableEffect = "send credential to " + "https" + "://private.example"
			})
		}, "privacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			tc.mutate(root)
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsOwnedFileBoundaryFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(string)
		changed func([]string) []string
		want    string
	}{
		{"missing owned path", func(root string) {
			p := filepath.Join(root, filepath.FromSlash("android/config/phase18-owned-files.txt"))
			lines := strings.Split(strings.TrimSpace(string(mustRead(t, p))), "\n")
			mustWrite(t, p, []byte(strings.Join(lines[1:], "\n")+"\n"))
		}, nil, "owned path set"},
		{"future path", func(root string) {
			p := filepath.Join(root, filepath.FromSlash("android/config/phase18-owned-files.txt"))
			lines := strings.Split(strings.TrimSpace(string(mustRead(t, p))), "\n")
			lines = append(lines, "android/domain/src/main/kotlin/org/kurdistanvpn/domain/ConnectionRepository.kt")
			sort.Strings(lines)
			mustWrite(t, p, []byte(strings.Join(lines, "\n")+"\n"))
		}, nil, "future path"},
		{"unowned changed path", nil, func(changed []string) []string { return append(changed, "docs/UNOWNED.md") }, "unowned changed path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			if tc.mutate != nil {
				tc.mutate(root)
			}
			if tc.changed != nil {
				changed = tc.changed(changed)
			}
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsAcceptancePromotion(t *testing.T) {
	for _, tc := range []struct {
		name, field, value, want string
	}{
		{"implementation", "implementationStatus", "COMPLETE", "NOT_STARTED"},
		{"phase decision", "phase18Decision", "PASS", "NO_GO"},
		{"release", "releaseAuthorization", "AUTHORIZED", "NO_GO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			mutateJSONFile(t, root, "testdata/evidence/phase18/acceptance-status.json", func(v map[string]any) { v[tc.field] = tc.value })
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestVerifyPlanningRejectsBudgetAndMarkdownDrift(t *testing.T) {
	root, changed := writeValidPlanningFixture(t)
	mutateJSONFile(t, root, "android/config/phase18-performance-budgets.json", func(v map[string]any) {
		v["metrics"].([]any)[0].(map[string]any)["p95Milliseconds"] = float64(1501)
	})
	assertPlanningError(t, root, changed, "performance budget")

	root, changed = writeValidPlanningFixture(t)
	p := filepath.Join(root, filepath.FromSlash("docs/PHASE18_FEATURE_COVERAGE.md"))
	mustWrite(t, p, []byte(strings.Replace(string(mustRead(t, p)), "P18-F067", "P18-F999", 1)))
	assertPlanningError(t, root, changed, "coverage document")
}

func TestVerifyPlanningRejectsExactControlSetDeletionAndReplacement(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		root, changed := writeValidPlanningFixture(t)
		mutateManifest(t, root, func(m *fixtureManifest) {
			m.Screens[0].Controls[0].LabelKey = "phase18.control.replaced_without_authority"
		})
		assertPlanningError(t, root, changed, "control set digest")
	})

	t.Run("deletion", func(t *testing.T) {
		root, changed := writeValidPlanningFixture(t)
		mutateManifest(t, root, func(m *fixtureManifest) {
			screen := &m.Screens[1]
			removed := screen.Controls[len(screen.Controls)-1]
			remaining := &screen.Controls[0]
			for _, featureID := range removed.FeatureIDs {
				remaining.FeatureIDs = append(remaining.FeatureIDs, featureID)
				feature := featureByID(m, featureID)
				feature.ControlIDs = []string{remaining.ControlID}
			}
			sort.Strings(remaining.FeatureIDs)
			screen.Controls = screen.Controls[:len(screen.Controls)-1]
		})
		assertPlanningError(t, root, changed, "control cardinality")
	})
}

func TestVerifyPlanningRejectsSemanticMarkdownDriftAndBrokenAnchors(t *testing.T) {
	t.Run("semantic row drift", func(t *testing.T) {
		root, changed := writeValidPlanningFixture(t)
		path := filepath.Join(root, filepath.FromSlash("docs/PHASE18_FEATURE_COVERAGE.md"))
		raw := string(mustRead(t, path))
		raw = strings.Replace(raw, "Three-area navigation", "Unbound navigation claim", 1)
		mustWrite(t, path, []byte(raw))
		assertPlanningError(t, root, changed, "coverage document")
	})

	t.Run("broken anchor", func(t *testing.T) {
		root, changed := writeValidPlanningFixture(t)
		path := filepath.Join(root, filepath.FromSlash("docs/PHASE18_FEATURE_COVERAGE.md"))
		raw := string(mustRead(t, path))
		raw = strings.Replace(raw, "PHASE18_ANDROID_PRODUCTION_CONTRACT.md#capability-gated-feature-ledger)", "PHASE18_ANDROID_PRODUCTION_CONTRACT.md#missing-contract-anchor)", 1)
		mustWrite(t, path, []byte(raw))
		assertPlanningError(t, root, changed, "Markdown anchor")
	})
}

func TestVerifyPlanningRejectsEveryRenderedCoverageAndEvidenceFieldDrift(t *testing.T) {
	for _, tc := range []struct {
		name, relative, old, replacement, want string
	}{
		{"frozen disposition", coveragePath, "| Phase 18 | delivered-production |", "| Rejected | delivered-production |", "coverage document"},
		{"target disposition", coveragePath, "| delivered-production | NOT_APPLICABLE |", "| rejected-final | NOT_APPLICABLE |", "coverage document"},
		{"capability admission", coveragePath, "| inapplicable-final | NOT_ADMITTED |", "| inapplicable-final | ADMITTED |", "coverage document"},
		{"owner tasks", coveragePath, "| 14,27 | planned |", "| 31 | planned |", "coverage document"},
		{"screen owner", coveragePath, "WelcomeScreen.kt`", "WrongScreen.kt`", "coverage document"},
		{"screen route", coveragePath, "`Welcome`", "`WrongRoute`", "coverage document"},
		{"legacy provenance", coveragePath, fixtureLegacyHash, strings.Repeat("0", 64), "coverage document"},
		{"planning status", coveragePath, "`NOT_STARTED`", "`COMPLETE`", "coverage document"},
		{"evidence status", evidencePath, "`UNEXECUTED`", "`PASS`", "evidence index"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			path := filepath.Join(root, filepath.FromSlash(tc.relative))
			raw := string(mustRead(t, path))
			if !strings.Contains(raw, tc.old) {
				t.Fatalf("fixture %s does not contain %q", tc.relative, tc.old)
			}
			mustWrite(t, path, []byte(strings.Replace(raw, tc.old, tc.replacement, 1)))
			assertPlanningError(t, root, changed, tc.want)
		})
	}

	t.Run("feature row order", func(t *testing.T) {
		root, changed := writeValidPlanningFixture(t)
		path := filepath.Join(root, filepath.FromSlash(coveragePath))
		lines := strings.Split(string(mustRead(t, path)), "\n")
		first, second := -1, -1
		for i, line := range lines {
			if strings.HasPrefix(line, "| P18-F001 |") {
				first = i
			}
			if strings.HasPrefix(line, "| P18-F002 |") {
				second = i
			}
		}
		if first < 0 || second < 0 {
			t.Fatal("fixture is missing the first two feature rows")
		}
		lines[first], lines[second] = lines[second], lines[first]
		mustWrite(t, path, []byte(strings.Join(lines, "\n")))
		assertPlanningError(t, root, changed, "coverage document")
	})
}

func TestVerifyPlanningRejectsControlContractFieldDrift(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fixtureControl)
		want string
	}{
		{"semantics tag", func(c *fixtureControl) { c.SemanticsTestTag = "wrong_tag" }, "semantics test tag"},
		{"failure code", func(c *fixtureControl) { c.FailureCode = "WRONG_FAILURE" }, "failure code"},
		{"recovery action", func(c *fixtureControl) { c.UserRecoveryAction = "silently-ignore" }, "user recovery action"},
		{"recreation", func(c *fixtureControl) { c.ProcessRecreationBehavior = "fabricate-state" }, "process recreation"},
		{"feature disposition", func(c *fixtureControl) { c.FeatureDispositions[0].TerminalDisposition = "rejected-final" }, "feature disposition"},
		{"legacy provenance", func(c *fixtureControl) { c.FeatureDispositions[0].LegacyProvenanceKey = "invented-D-item" }, "legacy provenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, changed := writeValidPlanningFixture(t)
			mutateManifest(t, root, func(m *fixtureManifest) {
				control := &m.Screens[0].Controls[0]
				if len(control.FeatureDispositions) == 0 {
					control.FeatureDispositions = []fixtureFeatureDisposition{{
						FeatureID: control.FeatureIDs[0], TerminalDisposition: "delivered-production", LegacyProvenanceKey: "legacy-coverage:P18-F001",
					}}
				}
				tc.edit(control)
			})
			assertPlanningError(t, root, changed, tc.want)
		})
	}
}

func TestRepositoryManifestHasCompleteControlContractsAndReachableRoutes(t *testing.T) {
	m := readRepositoryFixtureManifest(t)
	roots := map[string]bool{"P18-S01": true, "P18-S05": true, "P18-S07": true, "P18-S12": true}
	knownRoutes := make(map[string]struct{}, len(m.Screens))
	for _, screen := range m.Screens {
		knownRoutes[screen.RouteKey] = struct{}{}
		if screen.NavigationRoot != roots[screen.ScreenID] {
			t.Errorf("screen %s navigationRoot = %v, want %v", screen.ScreenID, screen.NavigationRoot, roots[screen.ScreenID])
		}
	}
	incoming := make(map[string][]string)
	for _, screen := range m.Screens {
		for _, control := range screen.Controls {
			for field, value := range map[string]string{
				"semanticsTestTag":          control.SemanticsTestTag,
				"failureCode":               control.FailureCode,
				"userRecoveryAction":        control.UserRecoveryAction,
				"processRecreationBehavior": control.ProcessRecreationBehavior,
			} {
				if value == "" {
					t.Errorf("control %s is missing %s", control.ControlID, field)
				}
			}
			if len(control.FeatureDispositions) != len(control.FeatureIDs) {
				t.Errorf("control %s has %d feature dispositions for %d feature IDs", control.ControlID, len(control.FeatureDispositions), len(control.FeatureIDs))
			}
			if strings.Contains(control.LabelKey, "adaptive_layout_preview") {
				t.Errorf("control %s exposes adaptive layout as a user control", control.ControlID)
			}
			if control.NavigationDestination != "" {
				if _, ok := knownRoutes[control.NavigationDestination]; !ok {
					t.Errorf("control %s targets unknown route %q", control.ControlID, control.NavigationDestination)
				}
				if !control.Enabled {
					t.Errorf("disabled control %s claims navigation to %s", control.ControlID, control.NavigationDestination)
				}
				incoming[control.NavigationDestination] = append(incoming[control.NavigationDestination], control.ControlID)
			}
		}
	}
	for _, screen := range m.Screens {
		if !screen.NavigationRoot && len(incoming[screen.RouteKey]) == 0 {
			t.Errorf("screen %s route %s has no reachable planned navigation control", screen.ScreenID, screen.RouteKey)
		}
	}
	for _, route := range []string{"ProbeHistory(profileId)", "ExcludedRoutes", "ExpertControls", "Automation"} {
		if len(incoming[route]) == 0 {
			t.Errorf("required route %s has no incoming control", route)
		}
	}

	f054 := featureByID(&m, "P18-F054")
	if f054.TargetDisposition != "safely-replaced-final" {
		t.Fatalf("P18-F054 target = %q", f054.TargetDisposition)
	}
	for _, id := range f054.ControlIDs {
		control := findFixtureControl(t, m, id)
		if strings.Contains(control.LabelKey, "traffic_sniffing") || !strings.Contains(control.LabelKey, "redacted_diagnostics") {
			t.Errorf("P18-F054 control %s does not express the redacted-diagnostics replacement", id)
		}
	}
}

func TestRepositoryControlContractsUseExactFailureTaxonomyAndCriticalBounds(t *testing.T) {
	m := readRepositoryFixtureManifest(t)
	allowedFailures := map[string]bool{
		"INVALID_INPUT": true, "SIZE_LIMIT": true, "PROFILE_UNTRUSTED": true,
		"PROFILE_EXPIRED": true, "PROFILE_REVOKED": true, "PROFILE_ROLLBACK": true,
		"PROFILE_WRONG_DEVICE": true, "PROFILE_INCOMPATIBLE": true, "STORAGE_LOCKED": true,
		"STORAGE_KEY_INVALIDATED": true, "STORAGE_DEGRADED": true, "MIGRATION_REQUIRED": true,
		"VPN_CONSENT_REQUIRED": true, "VPN_CONSENT_DENIED": true, "NETWORK_UNAVAILABLE": true,
		"NETWORK_IDENTITY_UNAVAILABLE": true, "CAPTIVE_PORTAL": true, "NODE_UNREACHABLE": true,
		"SESSION_AUTHENTICATION_FAILED": true, "NO_PERMITTED_STRATEGY": true,
		"SOCKET_PROTECTION_FAILED": true, "TUN_ESTABLISH_FAILED": true,
		"ROUTE_POLICY_REJECTED": true, "DNS_POLICY_REJECTED": true, "DNS_HEALTH_FAILED": true,
		"APP_POLICY_DRIFT": true, "FOREGROUND_START_BLOCKED": true, "RECONNECT_EXHAUSTED": true,
		"UPDATE_SIGNATURE_INVALID": true, "UPDATE_ROLLBACK": true, "UPDATE_INCOMPATIBLE": true,
		"PROXY_BIND_FAILED": true, "PROXY_AUTHENTICATION_FAILED": true, "LOW_MEMORY": true,
		"THERMAL_LIMIT": true, "CANCELLED": true, "INTERNAL_FAILURE": true,
	}
	forbiddenGeneric := []string{
		"Typed arguments only; every string, identifier, count, and selection obeys the owning domain bound",
		"Owning domain repository or no persistence when the action is transient",
		"Publish the validated typed state transition only after its authoritative effect is observable",
		"Versioned state is validated before exposure; unknown versions remain unavailable",
	}
	for _, screen := range m.Screens {
		for _, control := range screen.Controls {
			if !allowedFailures[control.FailureCode] {
				t.Errorf("control %s failureCode = %q, outside ProductFailureCode", control.ControlID, control.FailureCode)
			}
			fields := []string{control.BoundedInputs, control.PersistenceOwner, control.ObservableEffect, control.MigrationContract}
			for _, forbidden := range forbiddenGeneric {
				for _, value := range fields {
					if value == forbidden {
						t.Errorf("control %s retains generic contract %q", control.ControlID, forbidden)
					}
				}
			}
		}
	}

	for id, want := range map[string]struct {
		bounded, persistence, effect, recreation string
	}{
		"P18-C-S18-003": {
			"Integer port 1024..65535; distinct from HTTP CONNECT port; default 10808; loopback only",
			"SettingsViewModel LocalProxyPreferences draft; persist only after both ports validate and explicit Apply",
			"After Apply, the requested SOCKS5 loopback port is effective only after the controlled session restart succeeds",
			"restore-nonsensitive-draft-from-authorized-state-without-repeating-action",
		},
		"P18-C-S18-004": {
			"Integer port 1024..65535; distinct from SOCKS5 port; default 10809; loopback only",
			"SettingsViewModel LocalProxyPreferences draft; persist only after both ports validate and explicit Apply",
			"After Apply, the requested HTTP CONNECT loopback port is effective only after the controlled session restart succeeds",
			"restore-nonsensitive-draft-from-authorized-state-without-repeating-action",
		},
		"P18-C-S02-003": {
			"One explicit user-initiated clipboard read; exact kurd://artifact form; canonical decoded artifact 1..1052763 bytes",
			"OnboardingViewModel retains no raw input; only an encrypted preview operation ID may survive process recreation",
			"Native verification opens one redacted import preview; no profile, trust, key, or storage mutation occurs",
			"clear-sensitive-input-and-require-reauthorization-or-re-entry",
		},
		"P18-C-S02-005": {
			"One exact kurd://artifact value; canonical base64url without padding; decoded artifact 1..1052763 bytes",
			"OnboardingViewModel retains no raw input; only an encrypted preview operation ID may survive process recreation",
			"Native verification opens one redacted import preview; no profile, trust, key, or storage mutation occurs",
			"clear-sensitive-input-and-require-reauthorization-or-re-entry",
		},
	} {
		control := findFixtureControl(t, m, id)
		if control.BoundedInputs != want.bounded || control.PersistenceOwner != want.persistence ||
			control.ObservableEffect != want.effect || control.ProcessRecreationBehavior != want.recreation {
			t.Errorf("control %s critical contract drift: bounded=%q persistence=%q effect=%q recreation=%q", id,
				control.BoundedInputs, control.PersistenceOwner, control.ObservableEffect, control.ProcessRecreationBehavior)
		}
	}
}

func TestRepositoryControlsEncodeEverySourceDefinedSettingsBound(t *testing.T) {
	m := readRepositoryFixtureManifest(t)
	wants := map[string]string{
		"P18-C-S08-004": "Integer interval 1..168 hours; periodic work is off by default and unique per deployment",
		"P18-C-S11-002": "At most 200 samples per profile and 30 days; only categorical method, coarse time, latency, jitter, loss, stability, and result code",
		"P18-C-S13-001": "One of automatic, Kurd-only, or a manual strategy ID; manual ID must be in the signed/native strategy set before persistence",
		"P18-C-S13-002": "Boolean, off by default; effective only from a visible activity with fresh authority when not paused",
		"P18-C-S13-003": "Boolean plus requested maximum 1..10; effective maximum is min(user request, signed maximum, native maximum)",
		"P18-C-S13-005": "One of allow, ask, or wait-for-unmetered; one live user connect may override once, background update obeys the stored rule",
		"P18-C-S14-001": "Current network security type plus protected rule ID; unknown or redacted network identity is untrusted and cannot be enrolled",
		"P18-C-S15-001": "One of all, include-only, or exclude-selected; exactly one Android mode applies to each TUN",
		"P18-C-S15-002": "Include-only with 1..min(native maximum,256) selected launchable app UIDs; empty selection or package drift is rejected",
		"P18-C-S15-003": "Exclude-selected with 0..min(native maximum,256) selected launchable app UIDs; package drift is revalidated",
		"P18-C-S15-006": "One opaque launchable app identity; total selection is bounded by min(native maximum,256) and revalidated for package drift",
		"P18-C-S17-001": "One of TUN-only or TUN-plus-proxy; proxy-only remains unavailable unless separately admitted",
		"P18-C-S17-002": "One of TUN-only or TUN-plus-proxy; proxy-only remains unavailable unless separately admitted",
		"P18-C-S17-004": "One of auto, IPv4, IPv6, or dual; effective family requires signed addresses, routes, DNS, and native support",
		"P18-C-S17-005": "One of auto, IPv4, IPv6, or dual; effective family requires signed addresses, routes, DNS, and native support",
		"P18-C-S17-006": "One of auto, IPv4, IPv6, or dual; effective family requires signed addresses, routes, DNS, and native support",
		"P18-C-S17-007": "One of auto, IPv4, IPv6, or dual; effective family requires signed addresses, routes, DNS, and native support",
		"P18-C-S17-008": "One of internal, profile-defined, admitted preset ID, or one/two numeric custom addresses; no hostname or out-of-tunnel fallback",
		"P18-C-S17-009": "One of internal, profile-defined, admitted preset ID, or one/two numeric custom addresses; no hostname or out-of-tunnel fallback",
		"P18-C-S17-011": "One or two numeric resolver addresses; hostnames and out-of-tunnel fallback are rejected",
		"P18-C-S18-001": "One of TUN-only or TUN-plus-proxy; proxy-only remains unavailable unless separately admitted",
		"P18-C-S18-005": "Integer clients 1..16; effective maximum is min(local request, signed maximum, native maximum)",
		"P18-C-S18-006": "Integer streams 1..64; effective maximum is min(local request, signed maximum, native maximum)",
		"P18-C-S18-007": "Integer idle timeout 30..3600 seconds; effective maximum is min(local request, signed maximum, native maximum)",
		"P18-C-S18-008": "Integer memory budget 16..128 MiB; effective maximum is min(local request, signed maximum, native maximum)",
		"P18-C-S19-003": "Integer interval 1..168 hours; periodic work is off by default and unique per deployment",
		"P18-C-S21-004": "Boolean, off by default; retain at most 30 days of daily bytes and connected duration with no destinations or comparisons",
		"P18-C-S21-006": "Boolean plus allowed authenticators; app lock protects entry and sensitive actions but never disconnect or Recover Internet",
		"P18-C-S27-009": "One of 1 hour, 6 hours, 1 day, or 7 days; oldest-first cap is 4096 categorical events or 2 MiB",
		"P18-C-S30-007": "Boolean, off by default; retain at most 30 days of daily bytes and connected duration with no destinations or comparisons",
		"P18-C-S31-009": "One of none, error, warning, info, or debug; debug remains categorical and never stores free-form exception text",
		"P18-C-S31-010": "One of 1 hour, 6 hours, 1 day, or 7 days; oldest-first cap is 4096 categorical events or 2 MiB",
	}
	for id, want := range wants {
		if got := findFixtureControl(t, m, id).BoundedInputs; got != want {
			t.Errorf("control %s boundedInputs = %q, want exact source-defined bound %q", id, got, want)
		}
	}
}

func TestValidateControlRejectsSyntheticFailureCodeAndSensitiveImportRestoration(t *testing.T) {
	m := readRepositoryPlanningManifest(t)
	t.Run("synthetic failure code", func(t *testing.T) {
		control := m.Screens[0].Controls[0]
		control.FailureCode = "P18_CONTROL_S01_001_FAILED"
		if err := validateControl(control); err == nil {
			t.Fatal("control validator accepted a synthetic failure code outside ProductFailureCode")
		}
	})
	for _, id := range []string{"P18-C-S02-003", "P18-C-S02-005"} {
		t.Run(id, func(t *testing.T) {
			control := findPlanningControl(t, m, id)
			control.ProcessRecreationBehavior = "reload-authoritative-state-without-repeating-action"
			if err := validateControl(control); err == nil {
				t.Fatalf("control %s accepted restoration of transient import input", id)
			}
		})
	}
}

func TestRouteReachabilityRejectsDisconnectedCycles(t *testing.T) {
	m := readRepositoryPlanningManifest(t)
	features := make(map[string]feature, len(m.Features))
	for _, candidate := range m.Features {
		features[candidate.FeatureID] = candidate
	}
	var nonRoots []int
	for i := range m.Screens {
		for j := range m.Screens[i].Controls {
			m.Screens[i].Controls[j].NavigationDestination = ""
		}
		if !m.Screens[i].NavigationRoot {
			nonRoots = append(nonRoots, i)
		}
	}
	type controlLocation struct{ screen, control int }
	var carriers []controlLocation
	for _, screenIndex := range nonRoots {
		for controlIndex := range m.Screens[screenIndex].Controls {
			if m.Screens[screenIndex].Controls[controlIndex].Enabled {
				carriers = append(carriers, controlLocation{screen: screenIndex, control: controlIndex})
			}
		}
	}
	if len(carriers) < len(nonRoots) {
		t.Fatalf("fixture has %d enabled non-root controls, need %d route carriers", len(carriers), len(nonRoots))
	}
	for i, screenIndex := range nonRoots {
		carrier := carriers[i]
		m.Screens[carrier.screen].Controls[carrier.control].NavigationDestination = m.Screens[screenIndex].RouteKey
	}
	if err := validateScreensAndControls(m.Screens, features); err == nil {
		t.Fatal("route validator accepted a disconnected non-root cycle")
	} else if !strings.Contains(strings.ToLower(err.Error()), "navigation root") {
		t.Fatalf("disconnected-cycle error = %q, want navigation-root reachability", err)
	}
}

func TestTask0CapabilityRowsMustBeInsideCapabilitySection(t *testing.T) {
	raw := strings.Replace(fixtureTask0Contract(), "## Capability-gated feature ledger", "## Unrelated ledger", 1)
	if _, err := validateTask0Capabilities([]byte(raw)); err == nil {
		t.Fatal("Task 0 parser accepted capability rows outside the capability-gated section")
	}
}

func TestRepositoryManifestPinsCanonicalControlSet(t *testing.T) {
	m := readRepositoryFixtureManifest(t)
	if m.ControlCount != 311 {
		t.Fatalf("controlCount = %d, want 311", m.ControlCount)
	}
	raw, err := json.Marshal(m.Screens)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(raw))
	if m.ControlSetSHA256 != got {
		t.Fatalf("controlSetSHA256 = %q, independently recomputed %q", m.ControlSetSHA256, got)
	}
	if m.ControlSetSHA256 != expectedControlSetSHA256ForTest {
		t.Fatalf("controlSetSHA256 = %q, pinned test expectation %q", m.ControlSetSHA256, expectedControlSetSHA256ForTest)
	}
	if len(m.Screens) != len(expectedScreenControlCountsForTest) {
		t.Fatalf("screens = %d, want %d", len(m.Screens), len(expectedScreenControlCountsForTest))
	}
	for i, want := range expectedScreenControlCountsForTest {
		if got := len(m.Screens[i].Controls); got != want {
			t.Errorf("screen %s controls = %d, want %d", m.Screens[i].ScreenID, got, want)
		}
	}
}

func TestRepositorySensitiveControlsClearOnRecreationAndRequireReauthorization(t *testing.T) {
	m := readRepositoryFixtureManifest(t)
	matched := 0
	for _, screen := range m.Screens {
		for _, control := range screen.Controls {
			combined := strings.ToLower(strings.Join([]string{control.LabelKey, control.ActionSymbol, control.StateProperty}, " "))
			if !strings.Contains(combined, "credential") && !strings.Contains(combined, "passphrase") &&
				!strings.Contains(combined, "reveal") && !strings.Contains(combined, "paste_clipboard") &&
				!strings.Contains(combined, "enter_kurd_link") {
				continue
			}
			matched++
			behavior := strings.ToLower(control.ProcessRecreationBehavior)
			if !strings.Contains(behavior, "clear") || (!strings.Contains(behavior, "reauthor") && !strings.Contains(behavior, "re-enter")) {
				t.Errorf("sensitive control %s recreation behavior = %q", control.ControlID, control.ProcessRecreationBehavior)
			}
		}
	}
	if matched == 0 {
		t.Fatal("no credential, passphrase, reveal, clipboard-paste, or Kurd-link controls were classified as sensitive")
	}
}

func TestRepositoryBudgetsEncodeAllAcceptedMeasurementSemantics(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal(mustRead(t, filepath.Join("..", "..", filepath.FromSlash("android/config/phase18-performance-budgets.json"))), &root); err != nil {
		t.Fatal(err)
	}
	metrics, ok := root["metrics"].([]any)
	if !ok || len(metrics) != 17 {
		t.Fatalf("metrics = %T/%d, want 17", root["metrics"], len(metrics))
	}
	byID := make(map[string]map[string]any, len(metrics))
	for _, raw := range metrics {
		metric := raw.(map[string]any)
		byID[metric["metricId"].(string)] = metric
	}
	requireExactJSONList(t, byID["stop-to-closed-tun"], "actions", []string{"Recover Internet", "Stop"})
	requireExactJSONList(t, byID["handover-reaction"], "visibleStates", []string{"FallingBack", "Reconnecting"})
	requireExactJSONList(t, byID["handover-reaction"], "transitionDirections", []string{"Wi-Fi-to-cellular", "cellular-to-Wi-Fi"})
	for _, id := range []string{"steady-connected-pss", "memory-growth", "idle-cpu"} {
		if byID[id]["processScope"] == nil {
			t.Errorf("metric %s is missing processScope", id)
		}
	}
	requireExactJSONList(t, byID["screen-off-battery"], "conditions", []string{"stable-power", "stable-Wi-Fi"})
	if byID["thermal"]["causalFailureRule"] != "severe-or-higher-caused-by-app-work" {
		t.Errorf("thermal causal rule = %v", byID["thermal"]["causalFailureRule"])
	}
	requireExactJSONList(t, byID["update-worker"], "terminalOutcomes", []string{"CATEGORICAL_TIMEOUT", "COMPLETED"})
	if byID["proxy"]["protocolOperation"] != "CONNECT" || byID["proxy"]["authenticationRequired"] != true {
		t.Errorf("proxy contract is not authenticated CONNECT: %#v", byID["proxy"])
	}
	requireExactJSONList(t, byID["reliability"], "zeroFailureCategories", []string{"crash", "deadlock", "leaked-service", "stuck-operation"})
	requireExactJSONList(t, byID["cold-start-ttfd"], "firstUsableStates", []string{"Home", "onboarding"})
	if byID["cold-start-ttfd"]["fullyDrawnRequired"] != true {
		t.Errorf("cold-start-ttfd fullyDrawnRequired = %v, want true", byID["cold-start-ttfd"]["fullyDrawnRequired"])
	}
}

func TestRepositoryMarkdownMatchesDeterministicRendering(t *testing.T) {
	m := readRepositoryFixtureManifest(t)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var production planningManifest
	if err := json.Unmarshal(raw, &production); err != nil {
		t.Fatal(err)
	}
	acceptance := acceptanceStatus{
		SchemaVersion: "phase18-acceptance-status-v1", EvidenceKind: "acceptance-status",
		ControlSetSHA256: controlSetSHA256, ImplementationStatus: "NOT_STARTED",
		Phase18Decision: "NO_GO", ReleaseAuthorization: "NO_GO",
	}
	for _, tc := range []struct {
		path string
		want []byte
	}{
		{filepath.Join("..", "..", filepath.FromSlash(coveragePath)), renderCoverageMarkdown(production)},
		{filepath.Join("..", "..", filepath.FromSlash(evidencePath)), renderEvidenceMarkdown(acceptance)},
	} {
		got := mustRead(t, tc.path)
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s differs at %s", tc.path, firstTextDifference(got, tc.want))
		}
	}
}

func firstTextDifference(got, want []byte) string {
	limit := len(got)
	if len(want) < limit {
		limit = len(want)
	}
	for i := 0; i < limit; i++ {
		if got[i] != want[i] {
			start := i - 32
			if start < 0 {
				start = 0
			}
			end := i + 64
			if end > limit {
				end = limit
			}
			return fmt.Sprintf("byte %d: got %q, want %q; got context %q; want context %q", i, got[i], want[i], got[start:end], want[start:end])
		}
	}
	return fmt.Sprintf("length: got %d, want %d", len(got), len(want))
}

func TestEvidenceRecordDecodersRejectNoncanonicalMalformedAndPrivateValues(t *testing.T) {
	kinds := []string{
		"acceptance-status",
		"complete-v1-feature-map",
		"every-control-results",
		"human-review",
		"performance-results",
		"production-android-e2e",
		"release-surface-scan",
	}
	for _, kind := range kinds {
		t.Run(kind+" valid", func(t *testing.T) {
			raw := canonicalEvidenceFixture(t, kind)
			if err := decodeEvidenceRecord(kind, raw); err != nil {
				t.Fatalf("valid %s evidence rejected: %v", kind, err)
			}
		})
		cases := []struct {
			name   string
			mutate func([]byte) []byte
		}{
			{"unknown field", func(raw []byte) []byte {
				return bytes.Replace(raw, []byte("\n}"), []byte(",\n  \"unknown\": true\n}"), 1)
			}},
			{"duplicate field", func(raw []byte) []byte {
				return bytes.Replace(raw, []byte("{\n"), []byte("{\n  \"evidenceKind\": \""+kind+"\",\n"), 1)
			}},
			{"trailing data", func(raw []byte) []byte { return append(raw, []byte("{}\n")...) }},
			{"truncated", func(raw []byte) []byte { return raw[:len(raw)-3] }},
			{"missing field", func(raw []byte) []byte {
				if kind == "acceptance-status" {
					return removeEvidenceField(t, raw, "controlSetSHA256")
				}
				return removeEvidenceField(t, raw, "subjectTree")
			}},
			{"wrong kind", func(raw []byte) []byte { return replaceEvidenceField(t, raw, "evidenceKind", "wrong-kind") }},
			{"wrong schema", func(raw []byte) []byte { return replaceEvidenceField(t, raw, "schemaVersion", "phase18-wrong-v1") }},
			{"unknown result", func(raw []byte) []byte {
				if kind == "acceptance-status" {
					return replaceEvidenceField(t, raw, "phase18Decision", "MAYBE")
				}
				return replaceEvidenceField(t, raw, "result", "MAYBE")
			}},
			{"noncanonical object order", func(raw []byte) []byte { return swapFirstTwoJSONObjectFields(t, raw) }},
			{"invalid digest", func(raw []byte) []byte {
				if kind == "acceptance-status" {
					return replaceEvidenceField(t, raw, "controlSetSHA256", "not-a-digest")
				}
				return bytes.Replace(raw, []byte(strings.Repeat("a", 64)), []byte("not-a-digest"), 1)
			}},
			{"oversized value", func(raw []byte) []byte {
				if kind == "acceptance-status" {
					return replaceEvidenceField(t, raw, "implementationStatus", strings.Repeat("X", 257))
				}
				return bytes.Replace(raw, []byte("CHECK_001"), []byte(strings.Repeat("X", 257)), 1)
			}},
		}
		if kind != "acceptance-status" {
			cases = append(cases,
				struct {
					name   string
					mutate func([]byte) []byte
				}{"oversized list", func(raw []byte) []byte { return setEvidenceCheckCount(t, raw, 257) }},
				struct {
					name   string
					mutate func([]byte) []byte
				}{"noncanonical list order", func(raw []byte) []byte { return bytes.Replace(raw, []byte("CHECK_001"), []byte("CHECK_999"), 1) }},
			)
		}
		for _, tc := range cases {
			t.Run(kind+" "+tc.name, func(t *testing.T) {
				if err := decodeEvidenceRecord(kind, tc.mutate(canonicalEvidenceFixture(t, kind))); err == nil {
					t.Fatalf("%s decoder accepted %s", kind, tc.name)
				}
			})
		}
	}
}

func TestEvidenceRecordDecodersRejectPrivateValueCategories(t *testing.T) {
	for _, value := range []string{
		"/var/tmp/result",
		`\\server\share\result`,
		"file:///tmp/result",
		"ftp://example.invalid/result",
		"https" + "://example.invalid:8443/result",
		"credential_material",
		"authority_bytes",
		"packet_payload",
		"dns_question",
		"device_identifier",
	} {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			raw := replaceEvidenceCheckID(t, canonicalEvidenceFixture(t, "production-android-e2e"), value)
			if err := decodeEvidenceRecord("production-android-e2e", raw); err == nil {
				t.Fatalf("evidence decoder accepted prohibited value category %q", value)
			}
		})
	}
}

func TestEvidenceRecordRejectsAggregatePassWithNonPassCheck(t *testing.T) {
	var record evidenceRecord
	if err := json.Unmarshal(canonicalEvidenceFixture(t, "production-android-e2e"), &record); err != nil {
		t.Fatal(err)
	}
	record.Result = "PASS"
	raw, err := canonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeEvidenceRecord("production-android-e2e", raw); err == nil {
		t.Fatal("evidence decoder accepted aggregate PASS with a non-PASS check")
	}
}

func TestEvidenceRecordBindsRealGitCommitTreeRelationship(t *testing.T) {
	root := t.TempDir()
	initGitFixture(t, root)
	runGitFixture(t, root, "config", "user.name", "Phase 18 verifier test")
	runGitFixture(t, root, "config", "user.email", "phase18-verifier@example.invalid")
	mustWriteRelative(t, root, "subject.txt", []byte("first subject\n"))
	runGitFixture(t, root, "add", "--", "subject.txt")
	runGitFixture(t, root, "commit", "--quiet", "-m", "first subject")
	firstCommit := runGitFixtureOutput(t, root, "rev-parse", "HEAD")
	firstTree := runGitFixtureOutput(t, root, "rev-parse", "HEAD^{tree}")
	firstBlob := runGitFixtureOutput(t, root, "rev-parse", "HEAD:subject.txt")
	mustWriteRelative(t, root, "subject.txt", []byte("second subject\n"))
	runGitFixture(t, root, "add", "--", "subject.txt")
	runGitFixture(t, root, "commit", "--quiet", "-m", "second subject")
	secondTree := runGitFixtureOutput(t, root, "rev-parse", "HEAD^{tree}")

	record := evidenceRecord{
		SchemaVersion: "phase18-production-android-e2e-v1", EvidenceKind: "production-android-e2e",
		SubjectCommit: firstCommit, SubjectTree: firstTree, Result: "PASS", EvidenceSHA256: strings.Repeat("a", 64),
		Checks: []evidenceCheck{{CheckID: "CHECK_001", Result: "PASS", EvidenceSHA256: strings.Repeat("b", 64)}},
	}
	encode := func(record evidenceRecord) []byte {
		t.Helper()
		raw, err := canonicalJSON(record)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if err := decodeEvidenceRecord("production-android-e2e", encode(record), root); err != nil {
		t.Fatalf("real commit/tree relationship rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*evidenceRecord)
	}{
		{"other real tree", func(candidate *evidenceRecord) { candidate.SubjectTree = secondTree }},
		{"missing commit", func(candidate *evidenceRecord) { candidate.SubjectCommit = strings.Repeat("0", 40) }},
		{"blob as commit", func(candidate *evidenceRecord) { candidate.SubjectCommit = firstBlob }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := record
			tc.mutate(&candidate)
			if err := decodeEvidenceRecord("production-android-e2e", encode(candidate), root); err == nil {
				t.Fatalf("evidence decoder accepted %s", tc.name)
			}
		})
	}
}

func TestReadBoundedRejectsIntermediateLinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "escape.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		if err := createDirectoryJunction(link, outside); err != nil {
			t.Fatalf("create deterministic directory link: symlink=%v junction=%v", err, err)
		}
	}
	if _, err := readBounded(root, "linked/escape.json", 1024); err == nil {
		t.Fatal("readBounded accepted an intermediate link that resolves outside the repository root")
	}
}

func TestMarkdownLinksRejectIntermediateLinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target.md"), []byte("# Target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "docs", "linked")
	if err := os.Symlink(outside, link); err != nil {
		if junctionErr := createDirectoryJunction(link, outside); junctionErr != nil {
			t.Fatalf("create deterministic directory link: symlink=%v junction=%v", err, junctionErr)
		}
	}
	raw := []byte("[outside](linked/target.md#target)\n")
	if err := validateRelativeMarkdownLinks(root, "docs/source.md", raw); err == nil {
		t.Fatal("Markdown validator accepted an intermediate link that resolves outside the repository root")
	}
}

func TestGitStatusParserPreservesBothRenameAndCopyPaths(t *testing.T) {
	raw := []byte("R  docs/new.md\x00docs/old.md\x00C  android/new.kt\x00android/old.kt\x00")
	got, err := parseGitStatusPaths(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"android/new.kt", "android/old.kt", "docs/new.md", "docs/old.md"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rename/copy paths = %v, want source and destination %v", got, want)
	}
}

func TestPublicationMembershipRequiresEveryTask1Artifact(t *testing.T) {
	t.Run("explicit generation seam remains verifiable", func(t *testing.T) {
		root, changed := writeValidPlanningFixture(t)
		initGitFixture(t, root)
		if err := verifyPlanning(root, changed); err != nil {
			t.Fatalf("explicit generation fixture rejected: %v", err)
		}
	})

	t.Run("real planning rejects wholly untracked publication", func(t *testing.T) {
		root, _ := writeValidPlanningFixture(t)
		initGitFixture(t, root)
		if err := verifyPlanning(root); err == nil {
			t.Fatal("real repository planning accepted wholly untracked Task 1 publication")
		} else if !strings.Contains(strings.ToLower(err.Error()), "publication") {
			t.Fatalf("untracked publication error = %q, want publication membership", err)
		}
	})

	t.Run("acceptance status is required in publication index", func(t *testing.T) {
		root, _ := writeValidPlanningFixture(t)
		initGitFixture(t, root)
		args := append([]string{"add", "--"}, expectedOwnedFiles...)
		runGitFixture(t, root, args...)
		if err := verifyPlanning(root); err == nil {
			t.Fatal("publication membership accepted an untracked acceptance-status record")
		} else if !strings.Contains(err.Error(), acceptancePath) {
			t.Fatalf("acceptance membership error = %q, want %s", err, acceptancePath)
		}
	})

	t.Run("all publication paths tracked is accepted", func(t *testing.T) {
		root, _ := writeValidPlanningFixture(t)
		initGitFixture(t, root)
		paths := append(append([]string(nil), expectedOwnedFiles...), acceptancePath)
		args := append([]string{"add", "--"}, paths...)
		runGitFixture(t, root, args...)
		if err := verifyPlanning(root); err != nil {
			t.Fatalf("fully tracked owned-file fixture rejected: %v", err)
		}
	})
}

func canonicalEvidenceFixture(t *testing.T, kind string) []byte {
	t.Helper()
	if kind == "acceptance-status" {
		value := acceptanceStatus{
			SchemaVersion: "phase18-acceptance-status-v1", EvidenceKind: kind,
			ControlSetSHA256: controlSetSHA256, ImplementationStatus: "NOT_STARTED",
			Phase18Decision: "NO_GO", ReleaseAuthorization: "NO_GO",
		}
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	value := evidenceRecord{
		SchemaVersion:  "phase18-" + kind + "-v1",
		EvidenceKind:   kind,
		SubjectCommit:  strings.Repeat("1", 40),
		SubjectTree:    strings.Repeat("2", 40),
		Result:         "NOT_AVAILABLE",
		EvidenceSHA256: strings.Repeat("a", 64),
		Checks: []evidenceCheck{
			{CheckID: "CHECK_001", Result: "NOT_AVAILABLE", EvidenceSHA256: strings.Repeat("b", 64)},
			{CheckID: "CHECK_002", Result: "BLOCKED", EvidenceSHA256: strings.Repeat("c", 64)},
		},
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func swapFirstTwoJSONObjectFields(t *testing.T, raw []byte) []byte {
	t.Helper()
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 4 {
		t.Fatal("evidence fixture unexpectedly short")
	}
	lines[1], lines[2] = lines[2], lines[1]
	return []byte(strings.Join(lines, "\n"))
}

func replaceEvidenceCheckID(t *testing.T, raw []byte, value string) []byte {
	t.Helper()
	var record evidenceRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Checks[0].CheckID = value
	updated, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(updated, '\n')
}

func removeEvidenceField(t *testing.T, raw []byte, field string) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	delete(value, field)
	return marshalCanonicalMap(t, value)
}

func replaceEvidenceField(t *testing.T, raw []byte, field string, value any) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object[field] = value
	return marshalCanonicalMap(t, object)
}

func setEvidenceCheckCount(t *testing.T, raw []byte, count int) []byte {
	t.Helper()
	var record evidenceRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Checks = make([]evidenceCheck, count)
	for i := range record.Checks {
		record.Checks[i] = evidenceCheck{CheckID: fmt.Sprintf("CHECK_%03d", i+1), Result: "NOT_AVAILABLE", EvidenceSHA256: strings.Repeat("b", 64)}
	}
	updated, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(updated, '\n')
}

func marshalCanonicalMap(t *testing.T, value map[string]any) []byte {
	t.Helper()
	updated, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(updated, '\n')
}

func createDirectoryJunction(link, target string) error {
	cmd := exec.Command("cmd", "/c", "mklink", "/J", link, target)
	return cmd.Run()
}

func initGitFixture(t *testing.T, root string) {
	t.Helper()
	runGitFixture(t, root, "init", "--quiet")
}

func runGitFixture(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func runGitFixtureOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func readRepositoryFixtureManifest(t *testing.T) fixtureManifest {
	t.Helper()
	var manifest fixtureManifest
	raw := mustRead(t, filepath.Join("..", "..", filepath.FromSlash("android/config/phase18-every-control.json")))
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func readRepositoryPlanningManifest(t *testing.T) planningManifest {
	t.Helper()
	var manifest planningManifest
	raw := mustRead(t, filepath.Join("..", "..", filepath.FromSlash("android/config/phase18-every-control.json")))
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func findPlanningControl(t *testing.T, manifest planningManifest, id string) control {
	t.Helper()
	for _, screen := range manifest.Screens {
		for _, candidate := range screen.Controls {
			if candidate.ControlID == id {
				return candidate
			}
		}
	}
	t.Fatalf("missing control %s", id)
	return control{}
}

func findFixtureControl(t *testing.T, manifest fixtureManifest, id string) fixtureControl {
	t.Helper()
	for _, screen := range manifest.Screens {
		for _, control := range screen.Controls {
			if control.ControlID == id {
				return control
			}
		}
	}
	t.Fatalf("missing control %s", id)
	return fixtureControl{}
}

func requireExactJSONList(t *testing.T, object map[string]any, field string, expected []string) {
	t.Helper()
	raw, ok := object[field].([]any)
	if !ok {
		t.Errorf("%s is missing %s", object["metricId"], field)
		return
	}
	actual := make([]string, 0, len(raw))
	for _, value := range raw {
		actual = append(actual, value.(string))
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("%s %s = %v, want %v", object["metricId"], field, actual, expected)
	}
}

func TestValidatePublicSafetyAcceptsVerifierAndPublicContractSources(t *testing.T) {
	root, _ := writeValidPlanningFixture(t)
	for _, source := range []struct {
		current  string
		relative string
	}{
		{"main.go", "cmd/phase18verify/main.go"},
		{"main_test.go", "cmd/phase18verify/main_test.go"},
		{filepath.Join("..", "..", "docs", "PHASE18_EVIDENCE_INDEX.md"), "docs/PHASE18_EVIDENCE_INDEX.md"},
	} {
		mustWriteRelative(t, root, source.relative, mustRead(t, source.current))
	}
	if err := validatePublicSafety(root); err != nil {
		t.Fatalf("public Task 1 sources rejected by their own safety policy: %v", err)
	}

	forbiddenSentinel := "." + "codex-" + "private"
	mustWriteRelative(t, root, "cmd/phase18verify/main.go", []byte(forbiddenSentinel))
	if err := validatePublicSafety(root); err == nil {
		t.Fatal("public-safety validator accepted a complete forbidden sentinel")
	}
}

func writeValidPlanningFixture(t *testing.T) (string, []string) {
	t.Helper()
	root := t.TempDir()
	manifest := validFixtureManifest(t)
	writeJSON(t, root, "android/config/phase18-every-control.json", manifest)
	writeJSON(t, root, "android/config/phase18-performance-budgets.json", fixtureBudgets())
	writeJSON(t, root, "testdata/evidence/phase18/acceptance-status.json", acceptanceStatus{
		SchemaVersion: "phase18-acceptance-status-v1", EvidenceKind: "acceptance-status",
		ControlSetSHA256: controlSetSHA256, ImplementationStatus: "NOT_STARTED",
		Phase18Decision: "NO_GO", ReleaseAuthorization: "NO_GO",
	})
	owned := []string{
		"android/config/phase18-every-control.json",
		"android/config/phase18-owned-files.txt",
		"android/config/phase18-performance-budgets.json",
		"android/config/phase18-required-device-tests.txt",
		"cmd/phase18verify/main.go",
		"cmd/phase18verify/main_test.go",
		"docs/PHASE18_ANDROID_PRODUCTION_CONTRACT.md",
		"docs/PHASE18_EVIDENCE_INDEX.md",
		"docs/PHASE18_FEATURE_COVERAGE.md",
	}
	mustWriteRelative(t, root, "android/config/phase18-owned-files.txt", []byte(strings.Join(owned, "\n")+"\n"))
	mustWriteRelative(t, root, "android/config/phase18-required-device-tests.txt", []byte(strings.Join(fixtureDeviceTests(), "\n")+"\n"))
	mustWriteRelative(t, root, "docs/PHASE18_ANDROID_PRODUCTION_CONTRACT.md", []byte(fixtureTask0Contract()))
	mustWriteRelative(t, root, "docs/PHASE18_FEATURE_COVERAGE.md", []byte(fixtureCoverageMarkdown(manifest)))
	mustWriteRelative(t, root, "docs/PHASE18_EVIDENCE_INDEX.md", []byte(fixtureEvidenceMarkdown()))
	mustWriteRelative(t, root, "cmd/phase18verify/main.go", []byte("package main\n"))
	mustWriteRelative(t, root, "cmd/phase18verify/main_test.go", []byte("package main\n"))
	changed := append([]string(nil), owned...)
	changed = append(changed, "testdata/evidence/phase18/acceptance-status.json")
	sort.Strings(changed)
	return root, changed
}

func validFixtureManifest(t *testing.T) fixtureManifest {
	t.Helper()
	return readRepositoryFixtureManifest(t)
}

func fixtureScreenOwnerFile(screenID, symbol string) string {
	module := "settings-recovery"
	pkg := "settingsrecovery"
	switch screenID {
	case "P18-S01", "P18-S02", "P18-S03", "P18-S04":
		module, pkg = "onboarding", "onboarding"
	case "P18-S05", "P18-S06":
		module, pkg = "home", "home"
	case "P18-S07", "P18-S08", "P18-S09", "P18-S10", "P18-S11", "P18-S24":
		module, pkg = "profiles", "profiles"
	case "P18-S27", "P18-S28", "P18-S29", "P18-S33", "P18-S34":
		module, pkg = "diagnostics-about", "diagnosticsabout"
	}
	return "android/feature/" + module + "/src/main/kotlin/org/kurdistanvpn/feature/" + pkg + "/" + symbol + ".kt"
}

func fixtureBudgets() map[string]any {
	return map[string]any{
		"schemaVersion": "phase18-performance-budgets-v1",
		"decision":      "PLANNING_ONLY",
		"metrics": []map[string]any{
			{"metricId": "cold-start-ttid", "medianMilliseconds": 1000, "p95Milliseconds": 1500, "iterations": 20, "measurement": "physical-arm64-api36-release-like"},
			{"metricId": "cold-start-ttfd", "p95Milliseconds": 2000, "firstUsableStates": []string{"Home", "onboarding"}, "fullyDrawnRequired": true, "measurement": "physical-arm64-api36-fully-drawn"},
			{"metricId": "warm-start", "p95Milliseconds": 750, "iterations": 20, "measurement": "physical-arm64-api36"},
			{"metricId": "navigation-settled-frame", "p95Milliseconds": 100, "measurement": "home-profiles-settings-five-deep-flows"},
			{"metricId": "large-list-scroll", "p95Milliseconds": 16.7, "p99Milliseconds": 33.4, "profileCount": 1000, "measurement": "physical-60hz-redacted-fixtures"},
			{"metricId": "connect-to-preparing", "p95Milliseconds": 100, "measurement": "app-controlled-transition"},
			{"metricId": "route-plan-to-tun", "p95Milliseconds": 500, "measurement": "remote-handshake-excluded"},
			{"metricId": "stop-to-closed-tun", "p95Milliseconds": 1000, "actions": []string{"Recover Internet", "Stop"}, "measurement": "proxy-and-socket-teardown-included"},
			{"metricId": "handover-reaction", "maximumMilliseconds": 500, "transitions": 10, "visibleStates": []string{"FallingBack", "Reconnecting"}, "transitionDirections": []string{"Wi-Fi-to-cellular", "cellular-to-Wi-Fi"}, "measurement": "network-callback-to-visible-recovery-state"},
			{"metricId": "steady-connected-pss", "p95MiB": 160, "processScope": "app+:vpn", "measurement": "ten-minute-idle-and-active-transfer-samples"},
			{"metricId": "memory-growth", "maximumMiB": 10, "cycles": 100, "processScope": "same-process-pair", "measurement": "after-garbage-collection-stabilization"},
			{"metricId": "idle-cpu", "p95Percent": 2, "durationMinutes": 10, "processScope": "app+:vpn", "measurement": "screen-off-no-scheduled-probe-or-update"},
			{"metricId": "screen-off-battery", "maximumPercentagePointsPerHour": 2, "durationHours": 3, "runs": 3, "conditions": []string{"stable-power", "stable-Wi-Fi"}, "measurement": "median-of-three-dedicated-runs"},
			{"metricId": "thermal", "maximumCategory": "below-severe", "causalFailureRule": "severe-or-higher-caused-by-app-work", "measurement": "connected-idle-transfer-proxy-probe"},
			{"metricId": "update-worker", "maximumSeconds": 30, "maximumActivePerDeployment": 1, "terminalOutcomes": []string{"CATEGORICAL_TIMEOUT", "COMPLETED"}, "measurement": "fake-clock-unit-tests-plus-dedicated-network-run"},
			{"metricId": "proxy", "firstConnectMaximumMilliseconds": 250, "overLimitRejectMaximumMilliseconds": 100, "protocolOperation": "CONNECT", "authenticationRequired": true, "measurement": "local-overhead-native-handshake-excluded"},
			{"metricId": "reliability", "connectStopCycles": 100, "navigationCycles": 1000, "maximumFailures": 0, "zeroFailureCategories": []string{"crash", "deadlock", "leaked-service", "stuck-operation"}, "measurement": "dedicated-phase18-device"},
		},
	}
}

func fixtureDeviceTests() []string {
	return []string{
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
}

func fixtureTask0Contract() string {
	var b strings.Builder
	b.WriteString("# Phase 18 Android production-contract admission\n\n## Capability-gated feature ledger\n\n")
	b.WriteString("| ID | Result | Bound contract evidence | Consequence |\n| --- | --- | --- | --- |\n")
	for _, raw := range fixtureFeatureSpecs {
		parts := strings.Split(raw, "|")
		if parts[5] == "ADMITTED" || parts[5] == "NOT_ADMITTED" {
			fmt.Fprintf(&b, "| %s | `%s` | immutable source | planning consequence |\n", parts[0], parts[5])
		}
	}
	return b.String()
}

func fixtureCoverageMarkdown(m fixtureManifest) string {
	raw, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var production planningManifest
	if err := json.Unmarshal(raw, &production); err != nil {
		panic(err)
	}
	return string(renderCoverageMarkdown(production))
}

func fixtureEvidenceMarkdown() string {
	return string(renderEvidenceMarkdown(acceptanceStatus{
		SchemaVersion: "phase18-acceptance-status-v1", EvidenceKind: "acceptance-status",
		ControlSetSHA256: controlSetSHA256, ImplementationStatus: "NOT_STARTED",
		Phase18Decision: "NO_GO", ReleaseAuthorization: "NO_GO",
	}))
}

func mutateManifest(t *testing.T, root string, mutate func(*fixtureManifest)) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash("android/config/phase18-every-control.json"))
	var value fixtureManifest
	if err := json.Unmarshal(mustRead(t, path), &value); err != nil {
		t.Fatal(err)
	}
	mutate(&value)
	writeJSONPath(t, path, value)
}

func mutateJSONFile(t *testing.T, root, relative string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	var value map[string]any
	if err := json.Unmarshal(mustRead(t, path), &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	writeJSONPath(t, path, value)
}

func featureByID(m *fixtureManifest, id string) *fixtureFeature {
	for i := range m.Features {
		if m.Features[i].FeatureID == id {
			return &m.Features[i]
		}
	}
	panic("fixture feature not found: " + id)
}

func controlForFeature(m *fixtureManifest, id string) *fixtureControl {
	for i := range m.Screens {
		for j := range m.Screens[i].Controls {
			for _, candidate := range m.Screens[i].Controls[j].FeatureIDs {
				if candidate == id {
					return &m.Screens[i].Controls[j]
				}
			}
		}
	}
	panic("fixture control not found: " + id)
}

func assertPlanningError(t *testing.T, root string, changed []string, want string) {
	t.Helper()
	err := verifyPlanning(root, changed)
	if err == nil {
		t.Fatalf("invalid planning fixture accepted; wanted error containing %q", want)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}

func writeJSON(t *testing.T, root, relative string, value any) {
	t.Helper()
	writeJSONPath(t, filepath.Join(root, filepath.FromSlash(relative)), value)
}

func writeJSONPath(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, append(raw, '\n'))
}

func mustWriteRelative(t *testing.T, root, relative string, raw []byte) {
	t.Helper()
	mustWrite(t, filepath.Join(root, filepath.FromSlash(relative)), raw)
}

func mustWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
