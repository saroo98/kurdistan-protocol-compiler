// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidartifact

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadAPKIndexesBoundedContents(t *testing.T) {
	path := writeAPKFixture(t, map[string]string{
		"classes.dex":                          "release-marker",
		"lib/arm64-v8a/libkurdistan_bridge.so": "native-marker",
		"assets/config.txt":                    "asset-marker",
	})

	artifact, err := ReadAPK(path, Limits{MaxEntryBytes: 1024, MaxTotalBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.Contains("release-marker") || !artifact.DEXContains("release-marker") {
		t.Fatal("APK marker was not indexed from DEX")
	}
	if artifact.DEXContains("asset-marker") {
		t.Fatal("non-DEX marker was incorrectly indexed as DEX")
	}
	native, ok := artifact.Native("lib/arm64-v8a/libkurdistan_bridge.so")
	if !ok || string(native) != "native-marker" {
		t.Fatalf("native lookup = %q, %v", native, ok)
	}
	wantEntries := []string{
		"assets/config.txt",
		"classes.dex",
		"lib/arm64-v8a/libkurdistan_bridge.so",
	}
	if got := artifact.EntryNames(); !reflect.DeepEqual(got, wantEntries) {
		t.Fatalf("entries = %v, want %v", got, wantEntries)
	}
}

func TestAPKContentAccessorsReturnDefensiveCopies(t *testing.T) {
	path := writeAPKFixture(t, map[string]string{
		"classes.dex": "dex-marker",
		"assets/a":    "asset-marker",
	})
	artifact, err := ReadAPK(path, Limits{MaxEntryBytes: 1024, MaxTotalBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	all := artifact.AllContents()
	dex := artifact.DEXContents()
	all[0][0] ^= 0xff
	dex[0][0] ^= 0xff
	if !artifact.Contains("dex-marker") || !artifact.Contains("asset-marker") || !artifact.DEXContains("dex-marker") {
		t.Fatal("caller mutation changed indexed APK contents")
	}
}

func TestReadAPKRejectsUnsafeOrOversizedEntries(t *testing.T) {
	for name, fixture := range map[string]map[string]string{
		"path traversal": {"../secret": "x"},
		"backslash":      {`assets\secret`: "x"},
		"oversized":      {"classes.dex": strings.Repeat("x", 17)},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeAPKFixture(t, fixture)
			_, err := ReadAPK(path, Limits{MaxEntryBytes: 16, MaxTotalBytes: 64})
			if err == nil {
				t.Fatal("unsafe APK was accepted")
			}
		})
	}
}

func TestParseManifestReturnsCanonicalSecuritySurface(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.kurdistanvpn.app">
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
  <application android:allowBackup="false" android:usesCleartextTraffic="false">
    <service android:name="org.kurdistanvpn.runtime.android.KurdVpnService"
      android:permission="android.permission.BIND_VPN_SERVICE"
      android:exported="false"
      android:process=":vpn"
      android:foregroundServiceType="specialUse" />
  </application>
</manifest>`)

	manifest, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantPermissions := []string{
		"android.permission.ACCESS_NETWORK_STATE",
		"android.permission.INTERNET",
	}
	if !reflect.DeepEqual(manifest.Permissions, wantPermissions) {
		t.Fatalf("permissions = %v, want %v", manifest.Permissions, wantPermissions)
	}
	if manifest.UsesCleartextTraffic == nil || *manifest.UsesCleartextTraffic {
		t.Fatalf("usesCleartextTraffic = %v", manifest.UsesCleartextTraffic)
	}
	if manifest.AllowBackup == nil || *manifest.AllowBackup {
		t.Fatalf("allowBackup = %v", manifest.AllowBackup)
	}
	if len(manifest.Services) != 1 {
		t.Fatalf("services = %v", manifest.Services)
	}
	service := manifest.Services[0]
	if service.Name != "org.kurdistanvpn.runtime.android.KurdVpnService" ||
		service.Permission != "android.permission.BIND_VPN_SERVICE" || service.Exported ||
		service.Process != ":vpn" || service.ForegroundServiceType != "specialUse" {
		t.Fatalf("unexpected service: %+v", service)
	}
}

func TestParseManifestRejectsDuplicatePermissionsAndInvalidBooleans(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate permission": `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.INTERNET"/><application/></manifest>`,
		"invalid cleartext":    `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="sometimes"/></manifest>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(raw)); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func writeAPKFixture(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, value := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
