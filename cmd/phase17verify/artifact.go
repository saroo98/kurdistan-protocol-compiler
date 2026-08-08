// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strings"

	"kurdistan/internal/androidartifact"
)

var phase17RequiredManifestPermissions = []string{
	"android.permission.ACCESS_NETWORK_STATE",
	"android.permission.CAMERA",
	"android.permission.FOREGROUND_SERVICE",
	"android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
	"android.permission.INTERNET",
	"android.permission.POST_NOTIFICATIONS",
	"android.permission.USE_BIOMETRIC",
	"android.permission.USE_FINGERPRINT",
}

var phase17RequiredAPKMarkers = []string{
	"KurdVpnService",
	"nativeRuntimeSocketPrepare",
	"nativeRuntimeSocketCommitProtected",
	"nativeRuntimeTunAttach",
	"ENDPOINT_UNAVAILABLE",
	"DNS_UNAVAILABLE",
}

var phase17ForbiddenAPKMarkers = []string{
	"TRUST_UNAVAILABLE",
	"LoopbackOnly=true",
	"TunPacketLoop",
	"dataPlane=false",
	"phase9-internal-root",
	"LiveTunnelInvariantProbe",
	"com/google/firebase/analytics",
	"com/google/firebase/crashlytics",
	"io/sentry/",
	"com/google/android/gms/ads",
}

var phase17BridgeSymbols = []string{
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
	"kvpn_recipient_create",
	"kvpn_recipient_private_export",
	"kvpn_recipient_request",
	"kvpn_recipient_validate",
	"kvpn_runtime_session_open",
	"kvpn_runtime_session_open_v2",
	"kvpn_runtime_session_roundtrip",
	"kvpn_runtime_socket_commit_protected",
	"kvpn_runtime_socket_prepare",
	"kvpn_runtime_status",
	"kvpn_runtime_stop",
	"kvpn_runtime_tun_attach",
	"kvpn_verify_preview",
	"kvpn_verify_preview_with_recipient",
}

var phase17JNISymbols = []string{
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
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientCreate",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientPrivateExport",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientRequest",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientValidate",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionOpen",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionOpenV2",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionRoundTrip",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSocketCommitProtected",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSocketPrepare",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeStatus",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeStop",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeTunAttach",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeVerifyPreview",
	"Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeVerifyPreviewWithRecipient",
}

const phase17MaxReleaseAPKBytes = 40 * 1024 * 1024

func verifyPhase17Artifacts(releasePath, internalPath, manifestPath string) error {
	info, err := os.Stat(releasePath)
	if err != nil {
		return fmt.Errorf("release APK: %w", err)
	}
	if info.Size() > phase17MaxReleaseAPKBytes {
		return fmt.Errorf("release APK is %d bytes, exceeds %d-byte budget", info.Size(), phase17MaxReleaseAPKBytes)
	}
	manifest, err := androidartifact.ReadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("merged release manifest: %w", err)
	}
	if err := verifyPhase17Manifest(manifest); err != nil {
		return fmt.Errorf("merged release manifest: %w", err)
	}
	limits := androidartifact.Limits{MaxEntryBytes: 64 << 20, MaxTotalBytes: 512 << 20}
	release, err := androidartifact.ReadAPK(releasePath, limits)
	if err != nil {
		return fmt.Errorf("release APK: %w", err)
	}
	if err := verifyPhase17APKMarkers(release); err != nil {
		return err
	}
	if err := verifyPhase17NativeSurface(release, false); err != nil {
		return fmt.Errorf("release APK: %w", err)
	}
	internal, err := androidartifact.ReadAPK(internalPath, limits)
	if err != nil {
		return fmt.Errorf("internal APK: %w", err)
	}
	if err := verifyPhase17NativeSurface(internal, true); err != nil {
		return fmt.Errorf("internal APK: %w", err)
	}
	return nil
}

func verifyPhase17Manifest(manifest androidartifact.Manifest) error {
	if manifest.UsesCleartextTraffic == nil || *manifest.UsesCleartextTraffic {
		return fmt.Errorf("release manifest must explicitly disable cleartext traffic")
	}
	if manifest.AllowBackup == nil || *manifest.AllowBackup {
		return fmt.Errorf("release manifest must explicitly disable platform backup")
	}
	permissions := make([]string, 0, len(manifest.Permissions))
	for _, permission := range manifest.Permissions {
		if strings.HasPrefix(permission, "org.kurdistanvpn.app") && strings.HasSuffix(permission, ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION") {
			continue
		}
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	want := append([]string(nil), phase17RequiredManifestPermissions...)
	sort.Strings(want)
	if strings.Join(permissions, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("release permissions = %v, want %v", permissions, want)
	}
	var vpnServices []androidartifact.Service
	for _, service := range manifest.Services {
		if strings.HasSuffix(service.Name, ".KurdVpnService") {
			vpnServices = append(vpnServices, service)
		}
	}
	if len(vpnServices) != 1 {
		return fmt.Errorf("Kurd VpnService declarations = %d, want 1", len(vpnServices))
	}
	vpn := vpnServices[0]
	if vpn.Exported || vpn.Permission != "android.permission.BIND_VPN_SERVICE" || vpn.Process != ":vpn" || vpn.ForegroundServiceType != "specialUse" {
		return fmt.Errorf("invalid Kurd VpnService boundary: %+v", vpn)
	}
	return nil
}

func verifyPhase17APKMarkers(artifact androidartifact.APK) error {
	for _, required := range phase17RequiredAPKMarkers {
		if !artifact.Contains(required) {
			return fmt.Errorf("release APK is missing live-path marker %q", required)
		}
	}
	for _, forbidden := range phase17ForbiddenAPKMarkers {
		if artifact.Contains(forbidden) {
			return fmt.Errorf("release APK contains forbidden predecessor or third-party marker %q", forbidden)
		}
	}
	return nil
}

func verifyPhase17NativeSurface(artifact androidartifact.APK, internal bool) error {
	abis := []string{"arm64-v8a"}
	if internal {
		abis = append(abis, "x86_64")
	}
	allowedLibraries := []string{
		"libandroidx.graphics.path.so",
		"libdatastore_shared_counter.so",
		"libimage_processing_util_jni.so",
		"libkurdistan_bridge.so",
		"libkurdistan_jni.so",
		"libsurface_util_jni.so",
	}
	allowed := make(map[string]struct{}, len(abis)*len(allowedLibraries))
	for _, abi := range abis {
		for _, library := range allowedLibraries {
			allowed[fmt.Sprintf("lib/%s/%s", abi, library)] = struct{}{}
		}
		bridgeName := fmt.Sprintf("lib/%s/libkurdistan_bridge.so", abi)
		jniName := fmt.Sprintf("lib/%s/libkurdistan_jni.so", abi)
		bridge, ok := artifact.Native(bridgeName)
		if !ok {
			return fmt.Errorf("missing native bridge %q", bridgeName)
		}
		if err := requirePhase17Symbols(bridge, "kvpn_", phase17BridgeSymbols); err != nil {
			return fmt.Errorf("%s exports: %w", bridgeName, err)
		}
		if err := requirePhase17ELFIdentity(bridge, "libkurdistan_bridge.so", ""); err != nil {
			return fmt.Errorf("%s identity: %w", bridgeName, err)
		}
		jni, ok := artifact.Native(jniName)
		if !ok {
			return fmt.Errorf("missing JNI bridge %q", jniName)
		}
		if err := requirePhase17JNISymbols(jni, phase17JNISymbols); err != nil {
			return fmt.Errorf("%s exports: %w", jniName, err)
		}
		if err := requirePhase17ELFIdentity(jni, "libkurdistan_jni.so", "libkurdistan_bridge.so"); err != nil {
			return fmt.Errorf("%s identity: %w", jniName, err)
		}
	}
	for _, name := range artifact.EntryNames() {
		if !strings.HasPrefix(name, "lib/") || !strings.HasSuffix(name, ".so") {
			continue
		}
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("unexpected native library %q", name)
		}
	}
	return nil
}

func requirePhase17Symbols(data []byte, prefix string, expected []string) error {
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
	return comparePhase17Symbols(actual, expected)
}

func requirePhase17JNISymbols(data []byte, expected []string) error {
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
		if symbol.Name == "JNI_OnLoad" || strings.HasPrefix(symbol.Name, "Java_org_kurdistanvpn_core_nativejni_NativeBridge_") {
			actual = append(actual, symbol.Name)
		}
	}
	return comparePhase17Symbols(actual, expected)
}

func requirePhase17ELFIdentity(data []byte, expectedSONAME, requiredDependency string) error {
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

func comparePhase17Symbols(actual, expected []string) error {
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if strings.Join(actual, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("got %v, want %v", actual, want)
	}
	return nil
}
