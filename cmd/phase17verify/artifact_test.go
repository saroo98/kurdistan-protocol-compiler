// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"kurdistan/internal/androidartifact"
	"kurdistan/internal/audit"
	"kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
	"kurdistan/internal/testkit/evidenceoverlay"
)

func TestHistoricalVerificationCannotQualifyCurrentDevelopment(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	state, err := phase17evidence.VerifyDevelopmentAvailability(root)
	if err != nil {
		t.Fatal(err)
	}
	if state.HistoricalVerification != "VERIFIED" || state.SuccessorEvidence != "NOT_AVAILABLE" {
		t.Fatalf("historical and development evidence were conflated: %+v", state)
	}
	for _, gate := range []string{state.Candidate, state.Readiness, state.Stress, state.Campaign, state.Soak, state.Release} {
		if gate != "BLOCKED" {
			t.Fatalf("historical success opened a development gate: %+v", state)
		}
	}
	missing, err := phase17evidence.VerifyDevelopmentAvailability(t.TempDir())
	if err == nil || missing.SuccessorEvidence != "NOT_AVAILABLE" || missing.Candidate != "BLOCKED" || missing.Release != "BLOCKED" {
		t.Fatalf("missing immutable evidence did not fail closed: %+v, %v", missing, err)
	}
	historical, err := evidenceoverlay.ReadHistoricalFile(root, phase17evidence.AcceptancePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phase17qualification.DecodeCandidateManifest(bytes.NewReader(historical.Content)); err == nil {
		t.Fatal("historical acceptance was accepted as a current candidate manifest")
	}
	if _, err := phase17qualification.DecodeReadinessEvidenceIndex(bytes.NewReader(historical.Content)); err == nil {
		t.Fatal("historical acceptance was accepted as current readiness evidence")
	}
	result := audit.SecurityM0IntegratedEvidenceGate()
	if !result.Passed {
		t.Fatalf("historical audit failed: %+v", result)
	}
	if result.Details["current_development_availability"] != state {
		t.Fatalf("historical audit omitted the explicit closed development gates: %+v", result.Details["current_development_availability"])
	}
}

func TestPhase17ManifestRequiresExactLiveVPNBoundary(t *testing.T) {
	valid := phase17ManifestFixture(t, nil, false)
	if err := verifyPhase17Manifest(valid); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(androidartifact.Manifest) androidartifact.Manifest{
		"missing internet": func(value androidartifact.Manifest) androidartifact.Manifest {
			value.Permissions = removeString(value.Permissions, "android.permission.INTERNET")
			return value
		},
		"unexpected broad permission": func(value androidartifact.Manifest) androidartifact.Manifest {
			value.Permissions = append(value.Permissions, "android.permission.QUERY_ALL_PACKAGES")
			return value
		},
		"cleartext": func(value androidartifact.Manifest) androidartifact.Manifest {
			allowed := true
			value.UsesCleartextTraffic = &allowed
			return value
		},
		"exported vpn service": func(value androidartifact.Manifest) androidartifact.Manifest {
			value.Services[0].Exported = true
			return value
		},
		"wrong vpn permission": func(value androidartifact.Manifest) androidartifact.Manifest {
			value.Services[0].Permission = ""
			return value
		},
		"always-on opt-out": func(value androidartifact.Manifest) androidartifact.Manifest {
			disabled := false
			value.Services[0].SupportsAlwaysOn = &disabled
			return value
		},
		"missing always-on declaration": func(value androidartifact.Manifest) androidartifact.Manifest {
			value.Services[0].SupportsAlwaysOn = nil
			return value
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyPhase17Manifest(mutate(phase17ManifestFixture(t, nil, false))); err == nil {
				t.Fatal("invalid live VPN manifest was accepted")
			}
		})
	}
}

func TestPhase17ManifestRejectsEveryReissueAndTunnelBoundaryMismatch(t *testing.T) {
	truth, falsity := true, false
	for name, mutate := range map[string]func(*androidartifact.Manifest){
		"missing reissue":              func(m *androidartifact.Manifest) { m.Services = m.Services[:1] },
		"exported reissue":             func(m *androidartifact.Manifest) { m.Services[1].Exported = true },
		"direct boot reissue":          func(m *androidartifact.Manifest) { m.Services[1].DirectBootAware = &truth },
		"implicit direct boot reissue": func(m *androidartifact.Manifest) { m.Services[1].DirectBootAware = nil },
		"vpn process reissue": func(m *androidartifact.Manifest) {
			m.Services[1].Process = ":vpn"
			m.Services[1].ProcessDeclared = true
		},
		"inherited alternate process":  func(m *androidartifact.Manifest) { m.ApplicationProcess = ":other" },
		"inherited binding permission": func(m *androidartifact.Manifest) { m.ApplicationPermission = "synthetic.permission.EXTRA" },
		"reissue permission": func(m *androidartifact.Manifest) {
			m.Services[1].Permission = "android.permission.BIND_VPN_SERVICE"
			m.Services[1].PermissionDeclared = true
		},
		"isolated reissue":        func(m *androidartifact.Manifest) { m.Services[1].IsolatedProcess = &truth },
		"external reissue":        func(m *androidartifact.Manifest) { m.Services[1].ExternalService = &truth },
		"disabled reissue":        func(m *androidartifact.Manifest) { m.Services[1].Enabled = &falsity },
		"implicit reissue intent": func(m *androidartifact.Manifest) { m.Services[1].IntentFilterCount = 1 },
		"foreground reissue":      func(m *androidartifact.Manifest) { m.Services[1].ForegroundServiceType = "specialUse" },
		"duplicate reissue":       func(m *androidartifact.Manifest) { m.Services = append(m.Services, m.Services[1]) },
		"foreign reissue class":   func(m *androidartifact.Manifest) { m.Services[1].Name = "example.other.RuntimeAuthorityReissueService" },
		"old handoff": func(m *androidartifact.Manifest) {
			m.Services = append(m.Services, androidartifact.Service{Name: "org.kurdistanvpn.runtime.android.RuntimeAuthorityHandoffService"})
		},
		"direct boot application":      func(m *androidartifact.Manifest) { m.ApplicationDirectBootAware = &truth },
		"device protected application": func(m *androidartifact.Manifest) { m.DefaultToDeviceProtectedStorage = &truth },
		"disabled application":         func(m *androidartifact.Manifest) { m.ApplicationEnabled = &falsity },
		"direct boot vpn":              func(m *androidartifact.Manifest) { m.Services[0].DirectBootAware = &truth },
		"implicit direct boot vpn":     func(m *androidartifact.Manifest) { m.Services[0].DirectBootAware = nil },
		"disabled vpn":                 func(m *androidartifact.Manifest) { m.Services[0].Enabled = &falsity },
		"task bound vpn":               func(m *androidartifact.Manifest) { m.Services[0].StopWithTask = &truth },
		"isolated vpn":                 func(m *androidartifact.Manifest) { m.Services[0].IsolatedProcess = &truth },
		"external vpn":                 func(m *androidartifact.Manifest) { m.Services[0].ExternalService = &truth },
		"missing system action":        func(m *androidartifact.Manifest) { m.Services[0].IntentActions = nil },
		"extra system action": func(m *androidartifact.Manifest) {
			m.Services[0].IntentActions = append(m.Services[0].IntentActions, "synthetic.other")
		},
		"extra category":           func(m *androidartifact.Manifest) { m.Services[0].IntentCategories = []string{"synthetic.category"} },
		"data constraint":          func(m *androidartifact.Manifest) { m.Services[0].IntentDataCount = 1 },
		"missing subtype property": func(m *androidartifact.Manifest) { m.Services[0].SpecialUseSubtype = "" },
		"foreign vpn class":        func(m *androidartifact.Manifest) { m.Services[0].Name = "example.other.KurdVpnService" },
		"second tun owner": func(m *androidartifact.Manifest) {
			extra := m.Services[0]
			extra.Name = "example.other.Vpn"
			m.Services = append(m.Services, extra)
		},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := phase17ManifestFixture(t, nil, false)
			mutate(&manifest)
			if err := verifyPhase17Manifest(manifest); err == nil {
				t.Fatal("unsafe corrected boundary accepted")
			}
		})
	}
}

func TestPhase17NativeJNIInventoryIncludesExactDurableExports(t *testing.T) {
	// This independently checks source declarations, not linked or installed ELF behavior.
	declaration := regexp.MustCompile(`JNIEXPORT\s+\w+\s+JNICALL\s+(\w+)\s*\(`)
	var actual []string
	for _, name := range []string{"kvpn_jni.c", "kvpn_durable_fs_jni.c"} {
		raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "android", "core", "native-jni", "src", "main", "cpp", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range declaration.FindAllSubmatch(raw, -1) {
			actual = append(actual, string(match[1]))
		}
	}
	if err := comparePhase17Symbols(actual, phase17JNISymbols); err != nil {
		t.Fatal(err)
	}
}

func TestPhase17NativeJNIExportPolicyRejectsMissingExtraAndVisibleInternalHelpers(t *testing.T) {
	var symbols []elf.Symbol
	for _, name := range phase17JNISymbols {
		symbols = append(symbols, elf.Symbol{Name: name, Section: 1, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)})
	}
	if err := verifyPhase17JNIExports(symbols, phase17JNISymbols); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"nativeDurableRead", "nativePrepareBorrowedPipe", "nativeDurableOpenChild", "nativeDurableCreateChild", "nativeDurableCloseDirectory", "nativeDurableBootstrap", "nativeDurableList", "nativeDurableOpen", "nativeDurableClose", "nativeDurableMutate", "nativeDurableRestrictExisting", "nativeDurableSyncExisting"} {
		name := "Java_org_kurdistanvpn_core_nativejni_NativeBridge_" + suffix
		var missing []elf.Symbol
		for _, symbol := range symbols {
			if symbol.Name != name {
				missing = append(missing, symbol)
			}
		}
		if len(missing) == len(symbols) {
			t.Fatalf("expected durable JNI symbol absent from inventory: %s", name)
		}
		if err := verifyPhase17JNIExports(missing, phase17JNISymbols); err == nil {
			t.Fatalf("missing JNI symbol accepted: %s", name)
		}
	}
	for _, extra := range []string{"kvpn_fs_mutate", "kvpn_pipe_prepare_borrowed", "Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeUnexpected", "Java_example_Other_nativeUnexpected", "JNI_OnUnload"} {
		if err := verifyPhase17JNIExports(append(append([]elf.Symbol(nil), symbols...), elf.Symbol{Name: extra, Section: 1, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)}), phase17JNISymbols); err == nil {
			t.Fatalf("unexpected export accepted: %s", extra)
		}
	}
	for name, mutate := range map[string]func(*elf.Symbol){
		"undefined": func(symbol *elf.Symbol) { symbol.Section = elf.SHN_UNDEF },
		"object": func(symbol *elf.Symbol) {
			symbol.Info = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT)
		},
		"local": func(symbol *elf.Symbol) {
			symbol.Info = byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FUNC)
		},
		"weak": func(symbol *elf.Symbol) {
			symbol.Info = byte(elf.STB_WEAK)<<4 | byte(elf.STT_FUNC)
		},
		"hidden": func(symbol *elf.Symbol) { symbol.Other = byte(elf.STV_HIDDEN) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := append([]elf.Symbol(nil), symbols...)
			mutate(&invalid[0])
			if err := verifyPhase17JNIExports(invalid, phase17JNISymbols); err == nil {
				t.Fatal("non-callable or non-public JNI symbol accepted")
			}
		})
	}
}

func TestPhase17APKRequiresProtectedLivePathAndRejectsPredecessorMarkers(t *testing.T) {
	valid := phase17APKFixture(t, phase17RequiredAPKMarkers)
	if err := verifyPhase17APKMarkers(valid); err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range phase17ForbiddenAPKMarkers {
		t.Run("reject_"+strings.NewReplacer("/", "_", ".", "_").Replace(forbidden), func(t *testing.T) {
			artifact := phase17APKFixture(t, append(append([]string(nil), phase17RequiredAPKMarkers...), forbidden))
			if err := verifyPhase17APKMarkers(artifact); err == nil {
				t.Fatalf("forbidden APK marker %q was accepted", forbidden)
			}
		})
	}

	for _, missing := range phase17RequiredAPKMarkers {
		t.Run("missing_"+missing, func(t *testing.T) {
			artifact := phase17APKFixture(t, removeString(phase17RequiredAPKMarkers, missing))
			if err := verifyPhase17APKMarkers(artifact); err == nil {
				t.Fatalf("APK without %q was accepted", missing)
			}
		})
	}
}

func TestPhase17NativeSurfaceRejectsMissingBridge(t *testing.T) {
	artifact := phase17APKFixture(t, phase17RequiredAPKMarkers)
	if err := verifyPhase17NativeSurface(artifact, false); err == nil {
		t.Fatal("APK without native bridges was accepted")
	}
}

func TestPhase17InternalAPKRequiresOwnerSocketProtectionBridge(t *testing.T) {
	withBridge := phase17APKFixture(t, []string{phase17InternalSocketProtectionMarker})
	if err := verifyPhase17InternalAPKMarkers(withBridge); err != nil {
		t.Fatal(err)
	}
	withoutBridge := phase17APKFixture(t, nil)
	if err := verifyPhase17InternalAPKMarkers(withoutBridge); err == nil {
		t.Fatal("internal APK without owner socket-protection bridge was accepted")
	}
}

func TestArtifactPathsRequireAllOrNone(t *testing.T) {
	if enabled, err := validateArtifactPaths("", "", ""); err != nil || enabled {
		t.Fatalf("empty artifact paths = %v, %v", enabled, err)
	}
	if enabled, err := validateArtifactPaths("release.apk", "internal.apk", "manifest.xml"); err != nil || !enabled {
		t.Fatalf("complete artifact paths = %v, %v", enabled, err)
	}
	if _, err := validateArtifactPaths("release.apk", "", "manifest.xml"); err == nil {
		t.Fatal("partial artifact paths were accepted")
	}
}

func phase17ManifestFixture(t *testing.T, extraPermissions []string, cleartext bool) androidartifact.Manifest {
	t.Helper()
	permissions := append([]string(nil), phase17RequiredManifestPermissions...)
	permissions = append(permissions, extraPermissions...)
	allowBackup := false
	supportsAlwaysOn := true
	directBootAware := false
	return androidartifact.Manifest{
		PackageName:          "org.kurdistanvpn.app",
		Permissions:          permissions,
		UsesCleartextTraffic: &cleartext,
		AllowBackup:          &allowBackup,
		Services: []androidartifact.Service{{
			Name:                  "org.kurdistanvpn.runtime.android.KurdVpnService",
			Permission:            "android.permission.BIND_VPN_SERVICE",
			Exported:              false,
			Process:               ":vpn",
			ForegroundServiceType: "specialUse",
			SupportsAlwaysOn:      &supportsAlwaysOn,
			DirectBootAware:       &directBootAware,
			PermissionDeclared:    true,
			ProcessDeclared:       true,
			IntentFilterCount:     1,
			IntentActions:         []string{"android.net.VpnService"},
			SpecialUseSubtype:     "synthetic protected VPN transport",
		}, {
			Name:            "org.kurdistanvpn.app.RuntimeAuthorityReissueService",
			DirectBootAware: &directBootAware,
		}},
	}
}

func TestPhase17SourceManifestRejectsAlwaysOnOptOut(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, filepath.FromSlash(phase17RuntimeAndroidManifestPath))
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	appPath := filepath.Join(root, filepath.FromSlash(phase17AppAndroidManifestPath))
	if err := os.MkdirAll(filepath.Dir(appPath), 0o700); err != nil {
		t.Fatal(err)
	}
	app := `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application><service android:name=".RuntimeAuthorityReissueService" android:exported="false" android:directBootAware="false"/></application></manifest>`
	if err := os.WriteFile(appPath, []byte(app), 0o600); err != nil {
		t.Fatal(err)
	}
	writeManifest := func(value string) {
		t.Helper()
		raw := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <service android:name=".KurdVpnService"
      android:permission="android.permission.BIND_VPN_SERVICE"
      android:exported="false"
      android:directBootAware="false"
      android:process=":vpn"
      android:foregroundServiceType="specialUse">
      <intent-filter><action android:name="android.net.VpnService" /></intent-filter>
      <meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="` + value + `" />
      <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="synthetic protected VPN transport" />
    </service>
  </application>
</manifest>`
		if err := os.WriteFile(manifestPath, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeManifest("false")
	if err := verifyPhase17SourceManifest(root); err == nil {
		t.Fatal("source manifest opting out of system-managed always-on VPN was accepted")
	}
	writeManifest("true")
	if err := verifyPhase17SourceManifest(root); err != nil {
		t.Fatalf("source manifest enabling system-managed always-on VPN was rejected: %v", err)
	}
}

func TestPhase17CurrentSourceManifestCorrectionBoundary(t *testing.T) {
	// This is an integration gate over the actual source declarations, not the
	// passing synthetic fixtures above and not merged or installed evidence.
	if err := verifyPhase17SourceManifest(repositoryRoot(t)); err != nil {
		t.Fatalf("current source does not satisfy the corrected service boundary: %v", err)
	}
}

func phase17APKFixture(t *testing.T, markers []string) androidartifact.APK {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(strings.Join(markers, "\x00"))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	artifact, err := androidartifact.ParseAPK(buffer.Bytes(), androidartifact.Limits{MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func removeString(values []string, remove string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			result = append(result, value)
		}
	}
	return result
}
