// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzQualificationCanonicalDecoders(f *testing.F) {
	policyRaw, err := MarshalCanonical(validPolicyForTest())
	if err != nil {
		f.Fatal(err)
	}
	candidateRaw := qualificationCandidateSeed(f)
	environmentRaw, err := MarshalEnvironmentContext(EnvironmentContext{
		Schema: EnvironmentSchema, HostOS: "windows", HostArch: "amd64", HostBootClass: "BOUND_CURRENT_BOOT",
		AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64", VPSOS: "linux", VPSArch: "amd64",
		ProviderClass: "PRIMARY", TimeSource: "OWNER_VPS_INTERVAL_REQUIRED", PowerPolicy: "RUNNER_SYSTEM_REQUIRED",
		PythonSHA256: strings.Repeat("1", 64), ADBSHA256: strings.Repeat("2", 64),
		SSHSHA256: strings.Repeat("3", 64), SCPSHA256: strings.Repeat("4", 64),
		PowerShellSHA256: strings.Repeat("5", 64), PrivateCommitment: strings.Repeat("6", 64),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), policyRaw)
	f.Add(uint8(1), candidateRaw)
	f.Add(uint8(2), environmentRaw)
	f.Add(uint8(0), []byte(`{"schema":null}`))
	f.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		switch kind % 3 {
		case 0:
			value, err := DecodePolicy(bytes.NewReader(raw))
			if err != nil {
				return
			}
			canonical, err := MarshalCanonical(value)
			if err != nil || !bytes.Equal(raw, canonical) {
				t.Fatalf("successful policy decode was not canonical: %v", err)
			}
		case 1:
			value, err := DecodeCandidateManifest(bytes.NewReader(raw))
			if err != nil {
				return
			}
			canonical, err := MarshalCandidateManifest(value)
			if err != nil || !bytes.Equal(raw, canonical) {
				t.Fatalf("successful candidate decode was not canonical: %v", err)
			}
		case 2:
			value, err := DecodeEnvironmentContext(bytes.NewReader(raw))
			if err != nil {
				return
			}
			canonical, err := MarshalEnvironmentContext(value)
			if err != nil || !bytes.Equal(raw, canonical) {
				t.Fatalf("successful environment decode was not canonical: %v", err)
			}
		}
	})
}

func FuzzQualificationReceiptVerification(f *testing.F) {
	privateKey, publicKey := receiptKeyPair(14)
	candidateRaw := qualificationCandidateSeed(f)
	manifest, err := DecodeCandidateManifest(bytes.NewReader(candidateRaw))
	if err != nil {
		f.Fatal(err)
	}
	candidate, err := CandidateIdentityFromManifest(manifest)
	if err != nil {
		f.Fatal(err)
	}
	validRaw, err := SignStatement(privateKey, StatementRCLocked, RCLockedPayload{
		Schema: RCLockedSchema, Candidate: candidate, AuthorizationID: strings.Repeat("a", 32), IssuedAt: "2026-08-14T12:00:00Z",
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validRaw)
	f.Add([]byte(`{"schema":"kurdistan-phase17-qualification-envelope-v1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		verified, err := VerifyStatement(raw, publicKey)
		if err != nil {
			return
		}
		digest := sha256.Sum256(raw)
		if verified.DigestSHA256 != hex.EncodeToString(digest[:]) || verified.KeyID == "" || verified.Payload == nil {
			t.Fatalf("verified receipt identity incomplete: %+v", verified)
		}
	})
}

func FuzzQualificationLedgerVerification(f *testing.F) {
	privateKey, publicKey := receiptKeyPair(15)
	attempt := validAttemptPayload(1, "")
	attempt.Mode = "Stress"
	attempt.AuthorizationSHA256 = attempt.RCLockedSHA256
	validRaw, err := SignStatement(privateKey, StatementAttempt, attempt)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validRaw)
	f.Add([]byte("truncated"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maximumLedgerEntryBytes {
			return
		}
		directory := t.TempDir()
		digest := sha256.Sum256(raw)
		name := fmt.Sprintf("%020d-%s.json", 1, hex.EncodeToString(digest[:]))
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		state, err := VerifyLedger(directory, attempt.CandidateID, publicKey)
		if err != nil {
			return
		}
		if state.Entries != 1 || state.HeadSHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("verified ledger state=%+v", state)
		}
	})
}

func qualificationCandidateSeed(f *testing.F) []byte {
	root := f.TempDir()
	subjects := make([]SubjectManifest, 0, len(exactArtifactSubjectOrder))
	for index, name := range exactArtifactSubjectOrder {
		relative := fmt.Sprintf("subject-%d.bin", index)
		if err := os.WriteFile(filepath.Join(root, relative), []byte(name), 0o600); err != nil {
			f.Fatal(err)
		}
		manifest, err := BuildSubjectManifest(name, root, []string{relative})
		if err != nil {
			f.Fatal(err)
		}
		subjects = append(subjects, manifest)
	}
	source, err := NewSourceProvenance(
		"owner/project", strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40),
		[]string{"cmd/phase17field/main.go"},
		[]ManifestEntry{{Path: "go.mod", Size: 1, SHA256: strings.Repeat("d", 64)}},
		[]ManifestEntry{{Path: "go.sum", Size: 1, SHA256: strings.Repeat("e", 64)}},
	)
	if err != nil {
		f.Fatal(err)
	}
	manifest, err := NewCandidateManifest(source, strings.Repeat("f", 64), subjects)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := MarshalCandidateManifest(manifest)
	if err != nil {
		f.Fatal(err)
	}
	return raw
}
