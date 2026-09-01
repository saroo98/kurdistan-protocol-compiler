// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidartifact

import (
	"archive/zip"
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestReadAPKIndexesBoundedContents(t *testing.T) {
	raw := writeAPKFixture(t, map[string]string{
		"classes.dex":                          "release-marker",
		"lib/arm64-v8a/libkurdistan_bridge.so": "native-marker",
		"assets/config.txt":                    "asset-marker",
	})

	artifact, err := ParseAPK(raw, Limits{MaxEntryBytes: 1024, MaxTotalBytes: 4096})
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
	raw := writeAPKFixture(t, map[string]string{
		"classes.dex": "dex-marker",
		"assets/a":    "asset-marker",
	})
	artifact, err := ParseAPK(raw, Limits{MaxEntryBytes: 1024, MaxTotalBytes: 4096})
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
			raw := writeAPKFixture(t, fixture)
			_, err := ParseAPK(raw, Limits{MaxEntryBytes: 16, MaxTotalBytes: 64})
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
      android:foregroundServiceType="specialUse">
      <meta-data
        android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON"
        android:value="true" />
    </service>
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
		service.Process != ":vpn" || service.ForegroundServiceType != "specialUse" ||
		service.SupportsAlwaysOn == nil || !*service.SupportsAlwaysOn {
		t.Fatalf("unexpected service: %+v", service)
	}
}

func TestParseManifestRejectsDuplicatePermissionsAndInvalidBooleans(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate permission": `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.INTERNET"/><application/></manifest>`,
		"invalid cleartext":    `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="sometimes"/></manifest>`,
		"invalid always-on":    `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application><service android:name="Vpn" android:exported="false"><meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="sometimes"/></service></application></manifest>`,
		"duplicate always-on":  `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application><service android:name="Vpn" android:exported="false"><meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="true"/><meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="true"/></service></application></manifest>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(raw)); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestParseManifestPreservesAuthorityServiceAndForegroundPropertyBoundaries(t *testing.T) {
	raw := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.synthetic">
<application android:process="example.synthetic" android:permission="example.synthetic.LOCAL" android:directBootAware="false" android:enabled="true">
<service android:name="example.synthetic.Restore" android:exported="false" android:directBootAware="false" android:enabled="true" android:isolatedProcess="false" android:externalService="false"/>
<service android:name="example.synthetic.Vpn" android:exported="false" android:directBootAware="false" android:permission="android.permission.BIND_VPN_SERVICE" android:process=":vpn" android:foregroundServiceType="specialUse" android:stopWithTask="false">
<intent-filter><action android:name="android.net.VpnService"/></intent-filter>
<meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="true"/>
<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="synthetic protected VPN transport"/>
</service></application></manifest>`)
	manifest, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.PackageName != "example.synthetic" || manifest.ApplicationProcess != "example.synthetic" || manifest.ApplicationPermission != "example.synthetic.LOCAL" || manifest.ApplicationDirectBootAware == nil || *manifest.ApplicationDirectBootAware || manifest.ApplicationEnabled == nil || !*manifest.ApplicationEnabled {
		t.Fatalf("application defaults were lost: %+v", manifest)
	}
	restore, vpn := manifest.Services[0], manifest.Services[1]
	if restore.DirectBootAware == nil || *restore.DirectBootAware || restore.Enabled == nil || !*restore.Enabled || restore.IsolatedProcess == nil || *restore.IsolatedProcess || restore.ExternalService == nil || *restore.ExternalService || restore.IntentFilterCount != 0 {
		t.Fatalf("restore boundary was lost: %+v", restore)
	}
	if vpn.SpecialUseSubtype != "synthetic protected VPN transport" || vpn.IntentFilterCount != 1 || !reflect.DeepEqual(vpn.IntentActions, []string{"android.net.VpnService"}) || vpn.StopWithTask == nil || *vpn.StopWithTask {
		t.Fatalf("foreground VPN boundary was lost: %+v", vpn)
	}
}

func TestParseManifestRejectsAmbiguousBoundaryDeclarations(t *testing.T) {
	const start = `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application>`
	const end = `</application></manifest>`
	for name, raw := range map[string]string{
		"unnamespaced exported":       start + `<service android:name="Example" exported="false"/>` + end,
		"foreign namespace":           `<manifest xmlns:android="urn:not-android"><application><service android:name="Example" android:exported="false"/></application></manifest>`,
		"shadowed namespace":          start + `<service xmlns:other="urn:other" android:name="Example" android:exported="true" other:exported="false"/>` + end,
		"duplicate attribute":         start + `<service android:name="Example" android:exported="true" android:exported="false"/>` + end,
		"noncanonical boolean":        start + `<service android:name="Example" android:exported="0"/>` + end,
		"invalid direct boot":         start + `<service android:name="Example" android:exported="false" android:directBootAware="maybe"/>` + end,
		"duplicate service":           start + `<service android:name="Example" android:exported="false"/><service android:name="Example" android:exported="false"/>` + end,
		"blank service":               start + `<service android:name=" " android:exported="false"/>` + end,
		"duplicate application":       `<manifest><application/><application/></manifest>`,
		"trailing root":               `<manifest><application/></manifest><manifest><application/></manifest>`,
		"wrong root":                  `<not-manifest><application/></not-manifest>`,
		"nested root":                 `<manifest><application/><manifest/></manifest>`,
		"service outside application": `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application/><service android:name="Example" android:exported="false"/></manifest>`,
		"empty special use":           start + `<service android:name="Example" android:exported="false"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value=" "/></service>` + end,
		"duplicate special use":       start + `<service android:name="Example" android:exported="false"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="one"/><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="two"/></service>` + end,
		"resource special use":        start + `<service android:name="Example" android:exported="false"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:resource="@string/unresolved"/></service>` + end,
		"wrong special use element":   start + `<service android:name="Example" android:exported="false"><meta-data android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="wrong element"/></service>` + end,
		"duplicate action":            start + `<service android:name="Example" android:exported="false"><intent-filter><action android:name="android.net.VpnService"/><action android:name="android.net.VpnService"/></intent-filter></service>` + end,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(raw)); err == nil {
				t.Fatal("ambiguous declaration accepted")
			}
		})
	}
}

func TestParseManifestEnforcesBoundsAndRejectsDirectives(t *testing.T) {
	var services strings.Builder
	for index := 0; index < 257; index++ {
		fmt.Fprintf(&services, `<service android:name="Synthetic%d" android:exported="false"/>`, index)
	}
	for name, raw := range map[string][]byte{
		"empty":      nil,
		"oversized":  bytes.Repeat([]byte(" "), maxManifestBytes+1),
		"directive":  []byte(`<!DOCTYPE manifest><manifest><application/></manifest>`),
		"deep nodes": []byte(`<manifest><application>` + strings.Repeat(`<node>`, 32) + strings.Repeat(`</node>`, 32) + `</application></manifest>`),
		"services":   []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application>` + services.String() + `</application></manifest>`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest(raw); err == nil {
				t.Fatal("unbounded or directive-bearing manifest accepted")
			}
		})
	}
}

func TestReadAPKSharedInspectorRejectsDuplicateEntriesAndOverflowLimits(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for range 2 {
		entry, err := writer.Create("classes.dex")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("synthetic")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAPK(buffer.Bytes(), Limits{MaxEntryBytes: 64, MaxTotalBytes: 128}); err == nil {
		t.Fatal("duplicate archive entry accepted")
	}
	maxInt64 := int64(^uint64(0) >> 1)
	validArchive := writeAPKFixture(t, map[string]string{"classes.dex": "synthetic"})
	for _, limits := range []Limits{
		{MaxEntryBytes: maxInt64, MaxTotalBytes: maxInt64},
		{MaxEntryBytes: -1, MaxTotalBytes: 128},
		{MaxEntryBytes: 128, MaxTotalBytes: 64},
	} {
		if _, err := ParseAPK(validArchive, limits); err == nil {
			t.Fatalf("unsafe limits accepted: %+v", limits)
		}
	}
	if _, err := ParseAPK(writeAPKFixture(t, map[string]string{"classes.dex": "first", "assets/a": "second"}), Limits{MaxEntryBytes: 6, MaxTotalBytes: 10}); err == nil {
		t.Fatal("combined decompression bound exceeded without rejection")
	}
}

func writeAPKFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
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
	return buffer.Bytes()
}
