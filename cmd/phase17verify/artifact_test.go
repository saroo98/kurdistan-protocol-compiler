// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/androidartifact"
)

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
			if err := verifyPhase17Manifest(mutate(valid)); err == nil {
				t.Fatal("invalid live VPN manifest was accepted")
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
	return androidartifact.Manifest{
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
		}},
	}
}

func TestPhase17SourceManifestRejectsAlwaysOnOptOut(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, filepath.FromSlash(phase17RuntimeAndroidManifestPath))
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeManifest := func(value string) {
		t.Helper()
		raw := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <service android:name="org.kurdistanvpn.runtime.android.KurdVpnService"
      android:permission="android.permission.BIND_VPN_SERVICE"
      android:exported="false"
      android:process=":vpn"
      android:foregroundServiceType="specialUse">
      <meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="` + value + `" />
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

func phase17APKFixture(t *testing.T, markers []string) androidartifact.APK {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
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
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	artifact, err := androidartifact.ReadAPK(path, androidartifact.Limits{MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 20})
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
