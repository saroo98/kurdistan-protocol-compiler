// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildSoakReadyRequiresExactCompleteCandidateBoundEvidenceFiles(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(7)
	rcPayload := validRCLockedPayload(t)
	rcRaw, err := SignStatement(privateKey, StatementRCLocked, rcPayload)
	if err != nil {
		t.Fatal(err)
	}
	rcVerified, err := VerifyStatement(rcRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRoot := t.TempDir()
	index := validReadinessIndex(t, evidenceRoot, rcPayload.Candidate.Roots, rcVerified.DigestSHA256)
	indexRaw, err := MarshalReadinessEvidenceIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	verifiedKinds := make([]string, 0, len(exactReadinessEvidenceKinds))
	verifier := func(kind string, raw []byte, candidate CandidateIdentity) error {
		if candidate != rcPayload.Candidate || !bytes.Equal(raw, readinessEvidenceBytes(kind)) {
			return errors.New("test readiness evidence rejected")
		}
		verifiedKinds = append(verifiedKinds, kind)
		return nil
	}
	ready, err := BuildSoakReadyPayload(
		rcPayload.Candidate, rcRaw, indexRaw, evidenceRoot,
		LedgerState{CandidateID: rcPayload.Candidate.Roots.CandidateID, Entries: 13, HeadSHA256: index.LedgerHeadSHA256},
		publicKey, verifier, strings.Repeat("f", 32), "2026-08-14T13:00:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if ready.CandidateID != rcPayload.Candidate.Roots.CandidateID || ready.RCLockedSHA256 != rcVerified.DigestSHA256 ||
		ready.EvidenceIndexSHA256 == "" || ready.LedgerHeadSHA256 != index.LedgerHeadSHA256 ||
		ready.PriorStressResultSHA256 != index.Entries[4].EvidenceSHA256 ||
		len(verifiedKinds) != len(exactReadinessEvidenceKinds) {
		t.Fatalf("soak readiness payload=%+v verified=%v", ready, verifiedKinds)
	}
}

func TestBuildSoakReadyRejectsChangedUnverifiedOrStaleLedgerEvidence(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(8)
	rcPayload := validRCLockedPayload(t)
	rcRaw, err := SignStatement(privateKey, StatementRCLocked, rcPayload)
	if err != nil {
		t.Fatal(err)
	}
	rcVerified, err := VerifyStatement(rcRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRoot := t.TempDir()
	index := validReadinessIndex(t, evidenceRoot, rcPayload.Candidate.Roots, rcVerified.DigestSHA256)
	indexRaw, err := MarshalReadinessEvidenceIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	state := LedgerState{CandidateID: rcPayload.Candidate.Roots.CandidateID, Entries: 13, HeadSHA256: index.LedgerHeadSHA256}
	accept := func(string, []byte, CandidateIdentity) error { return nil }

	changedPath := filepath.Join(evidenceRoot, filepath.FromSlash(index.Entries[0].Path))
	if err := os.WriteFile(changedPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSoakReadyPayload(rcPayload.Candidate, rcRaw, indexRaw, evidenceRoot, state, publicKey, accept, strings.Repeat("f", 32), "2026-08-14T13:00:00Z"); err == nil {
		t.Fatal("changed readiness evidence accepted")
	}
	if err := os.WriteFile(changedPath, readinessEvidenceBytes(index.Entries[0].Kind), 0o600); err != nil {
		t.Fatal(err)
	}
	reject := func(string, []byte, CandidateIdentity) error { return errors.New("content rejected") }
	if _, err := BuildSoakReadyPayload(rcPayload.Candidate, rcRaw, indexRaw, evidenceRoot, state, publicKey, reject, strings.Repeat("f", 32), "2026-08-14T13:00:00Z"); err == nil {
		t.Fatal("unverified readiness evidence accepted")
	}
	stale := state
	stale.HeadSHA256 = strings.Repeat("0", 64)
	if _, err := BuildSoakReadyPayload(rcPayload.Candidate, rcRaw, indexRaw, evidenceRoot, stale, publicKey, accept, strings.Repeat("f", 32), "2026-08-14T13:00:00Z"); err == nil {
		t.Fatal("stale readiness ledger head accepted")
	}
}

func TestReadinessIndexRejectsMissingFailingRetainedOrAmbiguousEvidence(t *testing.T) {
	roots, err := NewSubjectRoots(
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	valid := validReadinessIndex(t, t.TempDir(), roots, strings.Repeat("a", 64))
	mutations := map[string]func(*ReadinessEvidenceIndex){
		"missing entry": func(value *ReadinessEvidenceIndex) { value.Entries = value.Entries[:len(value.Entries)-1] },
		"reordered entry": func(value *ReadinessEvidenceIndex) {
			value.Entries[0], value.Entries[1] = value.Entries[1], value.Entries[0]
		},
		"failing entry":      func(value *ReadinessEvidenceIndex) { value.Entries[4].Result = "FAIL_PRODUCT" },
		"raw retained":       func(value *ReadinessEvidenceIndex) { value.Entries[7].RawLogRetained = true },
		"candidate mismatch": func(value *ReadinessEvidenceIndex) { value.CandidateID = strings.Repeat("b", 64) },
		"root mismatch":      func(value *ReadinessEvidenceIndex) { value.Roots.ProductSHA256 = strings.Repeat("c", 64) },
		"duplicate evidence": func(value *ReadinessEvidenceIndex) { value.Entries[1].EvidenceSHA256 = value.Entries[0].EvidenceSHA256 },
		"duplicate path":     func(value *ReadinessEvidenceIndex) { value.Entries[1].Path = value.Entries[0].Path },
		"path traversal":     func(value *ReadinessEvidenceIndex) { value.Entries[0].Path = "../outside.json" },
		"windows absolute":   func(value *ReadinessEvidenceIndex) { value.Entries[0].Path = "C:/outside.json" },
		"posix absolute":     func(value *ReadinessEvidenceIndex) { value.Entries[0].Path = "/outside.json" },
		"zero size":          func(value *ReadinessEvidenceIndex) { value.Entries[0].Size = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := cloneReadinessIndex(valid)
			mutate(&value)
			if err := ValidateReadinessEvidenceIndex(value); err == nil {
				t.Fatal("invalid readiness evidence index accepted")
			}
		})
	}
}

func TestDecodeReadinessIndexRejectsNonCanonicalUnknownAndDuplicateJSON(t *testing.T) {
	roots, err := NewSubjectRoots(
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReadinessEvidenceIndex(validReadinessIndex(t, t.TempDir(), roots, strings.Repeat("a", 64)))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"newline":   append(append([]byte(nil), raw...), '\n'),
		"unknown":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"duplicate": bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReadinessEvidenceIndex(bytes.NewReader(candidate)); err == nil {
				t.Fatal("non-strict readiness evidence accepted")
			}
		})
	}
}

func TestReadinessProofIsCanonicalAndCandidateBound(t *testing.T) {
	candidate := validRCLockedPayload(t).Candidate
	value := ReadinessProof{
		Schema: ReadinessProofSchema, Kind: "SOURCE_GATES", CandidateID: candidate.Roots.CandidateID,
		Roots: candidate.Roots, Result: "PASS", RawLogRetained: false,
	}
	raw, err := MarshalReadinessProof(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReadinessProof(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != value {
		t.Fatalf("decoded=%+v", decoded)
	}
	if _, err := DecodeReadinessProof(bytes.NewReader(append(raw, '\n'))); err == nil {
		t.Fatal("noncanonical readiness proof accepted")
	}
	value.CandidateID = strings.Repeat("0", 64)
	if _, err := MarshalReadinessProof(value); err == nil {
		t.Fatal("cross-candidate readiness proof accepted")
	}
}

func TestReadinessEvidenceKindsRequireOneCurrentPhysicalDevice(t *testing.T) {
	want := []string{
		"SOURCE_GATES",
		"REPRODUCIBILITY",
		"FUNCTIONAL",
		"DETERMINISTIC_GAUNTLET",
		"STRESS",
		"SOAK_60M",
		"SOAK_90M",
		"SOAK_120M",
		"PHYSICAL_CURRENT",
		"SECOND_PROVIDER",
		"PRIVACY_SCANNERS",
		"BOUNDARY_MONITOR",
	}
	if got := ReadinessEvidenceKinds(); !reflect.DeepEqual(got, want) {
		t.Fatalf("readiness evidence kinds=%v, want %v", got, want)
	}
}

func validReadinessIndex(t *testing.T, root string, roots SubjectRoots, rcDigest string) ReadinessEvidenceIndex {
	t.Helper()
	entries := make([]ReadinessEvidenceEntry, len(exactReadinessEvidenceKinds))
	for index, kind := range exactReadinessEvidenceKinds {
		raw := readinessEvidenceBytes(kind)
		digest := sha256.Sum256(raw)
		path := filepath.ToSlash(filepath.Join("evidence", strings.ToLower(kind)+".json"))
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		entries[index] = ReadinessEvidenceEntry{
			Kind: kind, Path: path, Size: uint64(len(raw)), EvidenceSHA256: hex.EncodeToString(digest[:]),
			Result: "PASS", RawLogRetained: false,
		}
	}
	return ReadinessEvidenceIndex{
		Schema: ReadinessEvidenceIndexSchema, CandidateID: roots.CandidateID, Roots: roots,
		RCLockedSHA256: rcDigest, LedgerHeadSHA256: strings.Repeat("e", 64), Entries: entries,
	}
}

func readinessEvidenceBytes(kind string) []byte {
	return []byte(`{"schema":"test-readiness-proof-v1","kind":"` + kind + `","result":"PASS"}`)
}

func cloneReadinessIndex(value ReadinessEvidenceIndex) ReadinessEvidenceIndex {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result ReadinessEvidenceIndex
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return result
}
