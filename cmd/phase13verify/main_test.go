// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResourceNamesRejectsDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strings.xml")
	if err := os.WriteFile(path, []byte(`<resources><string name="a">A</string><string name="a">B</string></resources>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resourceNames(path); err == nil {
		t.Fatal("resourceNames accepted duplicate keys")
	}
}

func TestManifestRejectsBroadPackageVisibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AndroidManifest.xml")
	if err := os.WriteFile(path, []byte(`<manifest><uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/></manifest>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(path); err == nil {
		t.Fatal("verifyManifest accepted broad package visibility")
	}
}

func TestProductClaimScanRejectsGuaranteedClaims(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Claim.kt")
	if err := os.WriteFile(path, []byte(`val claim = "guaranteed bypass"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyProductClaims(root); err == nil {
		t.Fatal("verifyProductClaims accepted an unsupported claim")
	}
}
