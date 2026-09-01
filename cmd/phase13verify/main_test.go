// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRepositoryKeepsSanitizedHistoricalEvidenceUnavailable(t *testing.T) {
	err := verify(filepath.Clean(filepath.Join("..", "..")))
	if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatalf("sanitized historical evidence classification = %v", err)
	}
}

func TestRunReportsHistoricalEvidenceUnavailableWithoutOpeningQualification(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithVerifier([]string{"-root", "."}, &stdout, &stderr, func(string) error {
		return errHistoricalEvidenceNotAvailable
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("NOT_AVAILABLE run = code %d stderr %q", code, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "NOT_AVAILABLE") || !strings.Contains(output, "BLOCKED") || strings.Contains(output, "PASSED") {
		t.Fatalf("NOT_AVAILABLE output opened or obscured the gate: %q", output)
	}
}

func TestRunKeepsOrdinaryVerificationFailureRed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithVerifier([]string{"-root", "."}, &stdout, &stderr, func(string) error {
		return errors.New("synthetic verifier failure")
	})
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "VERIFICATION FAILED") {
		t.Fatalf("ordinary failure = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

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
