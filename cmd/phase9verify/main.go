// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase9verify enforces the Android Phase 9 release boundary against
// built artifacts. It intentionally inspects the merged manifest, DEX payloads,
// packaged ABIs, and public native symbols rather than trusting source layout.
package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"kurdistan/internal/androidartifact"
)

const maxReleaseAPKBytes = 40 * 1024 * 1024

const versionControlInfoEntry = "META-INF/version-control-info.textproto"

var bridgeSymbols = []string{
	"kvpn_abi_info",
	"kvpn_activation_next",
	"kvpn_activation_open",
	"kvpn_activation_submit",
	"kvpn_backup_create",
	"kvpn_backup_open_preview",
	"kvpn_backup_restore",
	"kvpn_cancel",
	"kvpn_diagnostic_build",
	"kvpn_diagnostic_confirm",
	"kvpn_diagnostic_prepare",
	"kvpn_diagnostic_preview",
	"kvpn_free",
	"kvpn_phase11_roundtrip",
	"kvpn_runtime_session_open",
	"kvpn_runtime_session_roundtrip",
	"kvpn_verify_preview",
}

var jniSymbols = []string{
	"JNI_OnLoad",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeAbiInfo",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeActivationNext",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeActivationOpen",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeActivationSubmit",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBackupCreate",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBackupOpenPreview",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBackupRestore",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeCancel",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticBuild",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticConfirm",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticPrepare",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticPreview",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeFree",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativePhase11RoundTrip",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionOpen",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionRoundTrip",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeVerifyPreview",
}

var forbiddenManifestValues = []string{
	"android.permission.INTERNET",
	"android.permission.ACCESS_NETWORK_STATE",
	"android.permission.BIND_VPN_SERVICE",
	"android.permission.FOREGROUND_SERVICE",
	"android.net.VpnService",
}

var forbiddenDEXValues = []string{
	"Landroid/net/VpnService;",
	"Ljava/net/HttpURLConnection;",
	"Ljava/net/URLConnection;",
	"Ljava/net/Socket;",
	"Lokhttp3/",
}

var requiredPhase10ManifestValues = []string{
	"android.permission.BIND_VPN_SERVICE",
	"android.permission.FOREGROUND_SERVICE",
	"android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
	"android.permission.POST_NOTIFICATIONS",
	"android.net.VpnService",
	"android:exported=\"false\"",
	"android:foregroundServiceType=\"specialUse\"",
	"android:process=\":vpn\"",
	"android.net.VpnService.SUPPORTS_ALWAYS_ON",
	"android:value=\"false\"",
}

var forbiddenPhase10ManifestValues = []string{
	"android.permission.INTERNET",
	"android.permission.ACCESS_NETWORK_STATE",
	"android:usesCleartextTraffic=\"true\"",
	"android:allowBackup=\"true\"",
}

var forbiddenPhase10DEXValues = []string{
	"allowBypass",
	"Lcom/google/firebase/analytics/",
	"Lcom/google/firebase/crashlytics/",
	"Lio/sentry/",
	"Lokhttp3/",
	"Lretrofit2/",
}

var internalOnlyMarkers = []string{
	"phase9 internal activation",
	"phase9 internal restore",
	"phase9-internal-root",
}

var phase11InternalOnlyMarkers = []string{
	"phase11.android.internal",
	"kurdistan-phase11-android-internal-conformance-v1",
}

var requiredPhase11APKMarkers = []string{
	"ACTIVE_KURD_LOOPBACK",
	"Connected to owned loopback",
}

type apkContents struct {
	dex     [][]byte
	natives map[string][]byte
	all     [][]byte
	entries map[string]struct{}
}

func main() {
	releaseAPK := flag.String("release-apk", "", "path to the unsigned release APK")
	internalAPK := flag.String("internal-apk", "", "path to the internal demonstration APK")
	manifest := flag.String("manifest", "", "path to the merged release manifest")
	phase10 := flag.Bool("phase10", false, "verify the bounded Phase 10 local VPN boundary")
	phase11 := flag.Bool("phase11", false, "verify the bounded Phase 11 Kurd loopback transport boundary")
	flag.Parse()
	if *releaseAPK == "" || *internalAPK == "" || *manifest == "" {
		fmt.Fprintln(os.Stderr, "phase9verify: release-apk, internal-apk, and manifest are required")
		os.Exit(2)
	}
	if *phase10 && *phase11 {
		fmt.Fprintln(os.Stderr, "phase9verify: phase10 and phase11 are mutually exclusive")
		os.Exit(2)
	}
	if err := verify(*releaseAPK, *internalAPK, *manifest, *phase10 || *phase11, *phase11); err != nil {
		fmt.Fprintf(os.Stderr, "ANDROID ARTIFACT VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	if *phase11 {
		fmt.Println("PHASE 11 ARTIFACT VERIFICATION PASSED")
	} else if *phase10 {
		fmt.Println("PHASE 10 ARTIFACT VERIFICATION PASSED")
	} else {
		fmt.Println("PHASE 9 ARTIFACT VERIFICATION PASSED")
	}
}

func verify(releasePath, internalPath, manifestPath string, vpnRuntime, phase11 bool) error {
	info, err := os.Stat(releasePath)
	if err != nil {
		return fmt.Errorf("release APK: %w", err)
	}
	if info.Size() > maxReleaseAPKBytes {
		return fmt.Errorf("release APK is %d bytes, exceeds %d-byte budget", info.Size(), maxReleaseAPKBytes)
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("merged manifest: %w", err)
	}
	if vpnRuntime {
		if err := requireMarkers(manifest, requiredPhase10ManifestValues); err != nil {
			return fmt.Errorf("merged release manifest: %w", err)
		}
		if err := rejectMarkers([][]byte{manifest}, forbiddenPhase10ManifestValues); err != nil {
			return fmt.Errorf("merged release manifest: %w", err)
		}
	} else {
		if err := rejectMarkers([][]byte{manifest}, forbiddenManifestValues); err != nil {
			return fmt.Errorf("merged release manifest: %w", err)
		}
	}

	release, err := readAPK(releasePath)
	if err != nil {
		return fmt.Errorf("release APK: %w", err)
	}
	if err := rejectCommitSensitiveEntries(release); err != nil {
		return fmt.Errorf("release APK: %w", err)
	}
	internal, err := readAPK(internalPath)
	if err != nil {
		return fmt.Errorf("internal APK: %w", err)
	}
	if vpnRuntime {
		if err := rejectMarkers(release.dex, forbiddenPhase10DEXValues); err != nil {
			return fmt.Errorf("release DEX: %w", err)
		}
		for _, required := range []string{
			"198.18.0.0",
			"198.18.0.53",
			"phase10",
			"DNS_REPLIED",
			"org.kurdistanvpn.runtime.action.QUERY_STATUS",
		} {
			if !containsAny(release.all, required) {
				return fmt.Errorf("release APK is missing Phase 10 boundary marker %q", required)
			}
		}
		if phase11 {
			for _, required := range requiredPhase11APKMarkers {
				if !containsAny(release.all, required) {
					return fmt.Errorf("release APK is missing Phase 11 boundary marker %q", required)
				}
			}
		}
	} else {
		if err := rejectMarkers(release.dex, forbiddenDEXValues); err != nil {
			return fmt.Errorf("release DEX: %w", err)
		}
	}
	for _, marker := range internalOnlyMarkers {
		if containsAny(release.all, marker) {
			return fmt.Errorf("release APK contains internal-only trust marker %q", marker)
		}
	}
	if !containsAny(internal.all, internalOnlyMarkers[0]) {
		return errors.New("internal APK does not contain its explicit nonproduction trust marker")
	}
	for _, marker := range phase11InternalOnlyMarkers {
		if containsAny(release.all, marker) {
			return fmt.Errorf("release APK contains Phase 11 internal-only marker %q", marker)
		}
		if phase11 && !containsAny(internal.all, marker) {
			return fmt.Errorf("internal APK is missing Phase 11 conformance marker %q", marker)
		}
	}
	for _, abi := range []string{"arm64-v8a", "x86_64"} {
		for _, library := range []string{"libkurdistan_bridge.so", "libkurdistan_jni.so"} {
			name := fmt.Sprintf("lib/%s/%s", abi, library)
			if _, ok := internal.natives[name]; !ok {
				return fmt.Errorf("internal APK is missing %s native support: %q", abi, name)
			}
		}
	}
	for name := range release.natives {
		if strings.HasPrefix(name, "lib/") && !strings.HasPrefix(name, "lib/arm64-v8a/") {
			return fmt.Errorf("release APK contains unsupported ABI entry %q", name)
		}
	}
	bridge, ok := release.natives["lib/arm64-v8a/libkurdistan_bridge.so"]
	if !ok {
		return errors.New("release APK is missing the Go bridge")
	}
	jni, ok := release.natives["lib/arm64-v8a/libkurdistan_jni.so"]
	if !ok {
		return errors.New("release APK is missing the JNI bridge")
	}
	if err := requireSymbols(bridge, "kvpn_", bridgeSymbols); err != nil {
		return fmt.Errorf("Go bridge symbols: %w", err)
	}
	if err := requireELFIdentity(bridge, "libkurdistan_bridge.so", ""); err != nil {
		return fmt.Errorf("Go bridge identity: %w", err)
	}
	if err := requireJNISymbols(jni, jniSymbols); err != nil {
		return fmt.Errorf("JNI symbols: %w", err)
	}
	if err := requireELFIdentity(jni, "libkurdistan_jni.so", "libkurdistan_bridge.so"); err != nil {
		return fmt.Errorf("JNI identity: %w", err)
	}
	return nil
}

func requireMarkers(value []byte, required []string) error {
	for _, marker := range required {
		if !bytes.Contains(value, []byte(marker)) {
			return fmt.Errorf("missing required %q", marker)
		}
	}
	return nil
}

func readAPK(path string) (apkContents, error) {
	artifact, err := androidartifact.ReadAPK(path, androidartifact.Limits{
		MaxEntryBytes: 64 * 1024 * 1024,
		MaxTotalBytes: 512 * 1024 * 1024,
	})
	if err != nil {
		return apkContents{}, err
	}
	result := apkContents{
		dex:     artifact.DEXContents(),
		all:     artifact.AllContents(),
		natives: make(map[string][]byte),
		entries: make(map[string]struct{}),
	}
	for _, name := range artifact.EntryNames() {
		result.entries[name] = struct{}{}
		if native, ok := artifact.Native(name); ok {
			result.natives[name] = native
		}
	}
	return result, nil
}

func containsAny(values [][]byte, needle string) bool {
	for _, value := range values {
		if bytes.Contains(value, []byte(needle)) {
			return true
		}
	}
	return false
}

func rejectMarkers(values [][]byte, forbidden []string) error {
	for _, marker := range forbidden {
		if containsAny(values, marker) {
			return fmt.Errorf("contains forbidden %q", marker)
		}
	}
	return nil
}

func rejectCommitSensitiveEntries(contents apkContents) error {
	if _, ok := contents.entries[versionControlInfoEntry]; ok {
		return fmt.Errorf("contains commit-sensitive %q", versionControlInfoEntry)
	}
	return nil
}

func requireSymbols(data []byte, prefix string, expected []string) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer file.Close()
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return err
	}
	var actual []string
	for _, symbol := range symbols {
		if symbol.Section != elf.SHN_UNDEF && strings.HasPrefix(symbol.Name, prefix) {
			actual = append(actual, symbol.Name)
		}
	}
	return compareSymbols(actual, expected)
}

func requireJNISymbols(data []byte, expected []string) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer file.Close()
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return err
	}
	var actual []string
	for _, symbol := range symbols {
		if symbol.Section == elf.SHN_UNDEF {
			continue
		}
		if symbol.Name == "JNI_OnLoad" ||
			strings.HasPrefix(symbol.Name, "Java_org_kurdistanvpn_core_nativejni_NativeBridge_") {
			actual = append(actual, symbol.Name)
		}
	}
	return compareSymbols(actual, expected)
}

func requireELFIdentity(data []byte, expectedSONAME, requiredDependency string) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer file.Close()
	for _, section := range []string{".note.go.buildid", ".note.gnu.build-id"} {
		if file.Section(section) != nil {
			return fmt.Errorf("contains host-sensitive build identity section %q", section)
		}
	}
	sonames, err := file.DynString(elf.DT_SONAME)
	if err != nil {
		return err
	}
	if len(sonames) != 1 || sonames[0] != expectedSONAME {
		return fmt.Errorf("SONAME=%v, want [%s]", sonames, expectedSONAME)
	}
	if requiredDependency == "" {
		return nil
	}
	dependencies, err := file.ImportedLibraries()
	if err != nil {
		return err
	}
	for _, dependency := range dependencies {
		if dependency == requiredDependency {
			return nil
		}
	}
	return fmt.Errorf("dependencies=%v, missing %q", dependencies, requiredDependency)
}

func compareSymbols(actual, expected []string) error {
	sort.Strings(actual)
	expected = append([]string(nil), expected...)
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("got %v, want %v", actual, expected)
	}
	return nil
}
