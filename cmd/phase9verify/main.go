// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase9verify enforces the Android Phase 9 release boundary against
// built artifacts. It intentionally inspects the merged manifest, DEX payloads,
// packaged ABIs, and public native symbols rather than trusting source layout.
package main

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
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

var internalOnlyMarkers = []string{
	"phase9 internal activation",
	"phase9 internal restore",
	"phase9-internal-root",
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
	flag.Parse()
	if *releaseAPK == "" || *internalAPK == "" || *manifest == "" {
		fmt.Fprintln(os.Stderr, "phase9verify: release-apk, internal-apk, and manifest are required")
		os.Exit(2)
	}
	if err := verify(*releaseAPK, *internalAPK, *manifest); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 9 ARTIFACT VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 9 ARTIFACT VERIFICATION PASSED")
}

func verify(releasePath, internalPath, manifestPath string) error {
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
	if err := rejectMarkers([][]byte{manifest}, forbiddenManifestValues); err != nil {
		return fmt.Errorf("merged release manifest: %w", err)
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
	if err := rejectMarkers(release.dex, forbiddenDEXValues); err != nil {
		return fmt.Errorf("release DEX: %w", err)
	}
	for _, marker := range internalOnlyMarkers {
		if containsAny(release.all, marker) {
			return fmt.Errorf("release APK contains internal-only trust marker %q", marker)
		}
	}
	if !containsAny(internal.all, internalOnlyMarkers[0]) {
		return errors.New("internal APK does not contain its explicit nonproduction trust marker")
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
	if err := requireJNISymbols(jni, jniSymbols); err != nil {
		return fmt.Errorf("JNI symbols: %w", err)
	}
	return nil
}

func readAPK(path string) (apkContents, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return apkContents{}, err
	}
	defer reader.Close()
	result := apkContents{
		natives: make(map[string][]byte),
		entries: make(map[string]struct{}),
	}
	for _, entry := range reader.File {
		result.entries[entry.Name] = struct{}{}
		if entry.UncompressedSize64 > 64*1024*1024 {
			return apkContents{}, fmt.Errorf("entry %q exceeds inspection bound", entry.Name)
		}
		stream, err := entry.Open()
		if err != nil {
			return apkContents{}, err
		}
		content, readErr := io.ReadAll(io.LimitReader(stream, 64*1024*1024+1))
		closeErr := stream.Close()
		if readErr != nil {
			return apkContents{}, readErr
		}
		if closeErr != nil {
			return apkContents{}, closeErr
		}
		result.all = append(result.all, content)
		if strings.HasPrefix(entry.Name, "classes") && strings.HasSuffix(entry.Name, ".dex") {
			result.dex = append(result.dex, content)
		}
		if strings.HasPrefix(entry.Name, "lib/") && strings.HasSuffix(entry.Name, ".so") {
			result.natives[entry.Name] = content
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

func compareSymbols(actual, expected []string) error {
	sort.Strings(actual)
	expected = append([]string(nil), expected...)
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("got %v, want %v", actual, expected)
	}
	return nil
}
