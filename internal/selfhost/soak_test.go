// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestHundredIssueAndroidVerifyAndRevokeCyclesDoNotDrift(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Now().UTC().Add(-time.Hour)
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "soak-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(dataDir, recovery, passphrase, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for cycle := 1; cycle <= 100; cycle++ {
		at := now.Add(time.Duration(cycle*3) * time.Second)
		issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: fmt.Sprintf("phone-%03d", cycle), ValidFor: 24 * time.Hour, Now: at})
		if err != nil {
			t.Fatalf("cycle %d issue: %v", cycle, err)
		}
		verified, err := VerifyAndroidArtifact(issued.Artifact, at.Add(time.Second), issued.Generation)
		if err != nil || verified.Profile.Generation != uint64(cycle) {
			t.Fatalf("cycle %d Android verify: generation=%d err=%v", cycle, verified.Profile.Generation, err)
		}
		if err := RevokeProfile(dataDir, RevokeProfileOptions{ProfileID: issued.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: at.Add(2 * time.Second)}); err != nil {
			t.Fatalf("cycle %d revoke: %v", cycle, err)
		}
		if _, err := VerifyBundleAgainstCurrentState(dataDir, issued.Artifact, at.Add(2*time.Second)); err == nil {
			t.Fatalf("cycle %d revoked profile remained admissible", cycle)
		}
	}
	status, err := LoadStatus(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Generation != 100 || status.ProfileCount != 100 || status.RevokedProfileCount != 100 || status.RevocationEpoch != 101 {
		t.Fatalf("soak state drifted: %+v", status)
	}
	if report, err := Doctor(dataDir, now.Add(10*time.Minute)); err != nil || report.Overall != "PASS" {
		t.Fatalf("doctor after soak: report=%+v err=%v", report, err)
	}
}
