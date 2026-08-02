// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEmitsGOForExactDigestBoundEvidence(t *testing.T) {
	root, policyDigest := writeReleasePolicyFixture(t, fixtureOptions{})
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"-root", root,
		"-policy", "release-policy.json",
		"-policy-sha256", policyDigest,
		"-now", "2026-08-02T10:05:00Z",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run releasepolicy: %v (stderr %q)", err, stderr.String())
	}
	var result evaluation
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Decision != "GO" || result.PolicySHA256 != policyDigest || len(result.Evidence) != 1 || result.Evidence[0].ID != "independent-review" {
		t.Fatalf("unexpected evaluation: %+v", result)
	}
}

func TestRunEmitsNOGoForEvidenceSubjectMismatch(t *testing.T) {
	root, policyDigest := writeReleasePolicyFixture(t, fixtureOptions{EvidenceSubjectMismatch: true})
	var stdout bytes.Buffer
	if err := run([]string{"-root", root, "-policy", "release-policy.json", "-policy-sha256", policyDigest, "-now", "2026-08-02T10:05:00Z"}, &stdout, &bytes.Buffer{}); !errors.Is(err, errNoGo) {
		t.Fatalf("error = %v, want NO_GO", err)
	}
	var result evaluation
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Decision != "NO_GO" || len(result.Reasons) == 0 {
		t.Fatalf("unexpected evaluation: %+v", result)
	}
}

func TestRunRejectsDuplicateJSONKeys(t *testing.T) {
	root, _ := writeReleasePolicyFixture(t, fixtureOptions{})
	path := filepath.Join(root, "release-policy.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"policyId":"public-v1"`), []byte(`"policyId":"public-v1","policyId":"public-v1"`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if err := run([]string{"-root", root, "-policy", "release-policy.json", "-policy-sha256", digest, "-now", "2026-08-02T10:05:00Z"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected duplicate JSON key rejection")
	}
}

func TestRunFailsClosedForDigestAndFreshnessFailures(t *testing.T) {
	tests := []struct {
		name            string
		options         fixtureOptions
		badPolicyDigest bool
	}{
		{name: "evidence digest mismatch", options: fixtureOptions{EvidenceDigestMismatch: true}},
		{name: "expired evidence", options: fixtureOptions{EvidenceExpired: true}},
		{name: "policy digest mismatch", badPolicyDigest: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, policyDigest := writeReleasePolicyFixture(t, test.options)
			if test.badPolicyDigest {
				policyDigest = strings.Repeat("0", 64)
			}
			var stdout bytes.Buffer
			err := run([]string{"-root", root, "-policy", "release-policy.json", "-policy-sha256", policyDigest, "-now", "2026-08-02T10:05:00Z"}, &stdout, &bytes.Buffer{})
			if !errors.Is(err, errNoGo) {
				t.Fatalf("error = %v, want NO_GO", err)
			}
			var result evaluation
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Decision != "NO_GO" || len(result.Reasons) == 0 {
				t.Fatalf("unexpected evaluation: %+v", result)
			}
		})
	}
}

func TestRunRejectsUnknownTruncatedAndTraversalPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown", mutate: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"policyId":`), []byte(`"unknown":true,"policyId":`), 1)
		}},
		{name: "truncated", mutate: func(raw []byte) []byte { return raw[:len(raw)-1] }},
		{name: "traversal", mutate: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"path":"evidence/independent-review.json"`), []byte(`"path":"../independent-review.json"`), 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, _ := writeReleasePolicyFixture(t, fixtureOptions{})
			path := filepath.Join(root, "release-policy.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = test.mutate(raw)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(raw))
			if err := run([]string{"-root", root, "-policy", "release-policy.json", "-policy-sha256", digest, "-now", "2026-08-02T10:05:00Z"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("expected strict policy rejection")
			}
		})
	}
}

type fixtureOptions struct {
	EvidenceSubjectMismatch bool
	EvidenceExpired         bool
	EvidenceDigestMismatch  bool
}

func writeReleasePolicyFixture(t *testing.T, options fixtureOptions) (string, string) {
	t.Helper()
	root := t.TempDir()
	subject := releaseSubject{
		Repository: "saroo98/kurdistan-protocol-compiler",
		Commit:     strings.Repeat("1", 40), Tree: strings.Repeat("2", 40), Ref: "refs/heads/main",
		ArtifactSHA256: strings.Repeat("3", 64), MetadataSHA256: strings.Repeat("4", 64), RollbackSHA256: strings.Repeat("5", 64),
	}
	evidenceSubject := subject
	if options.EvidenceSubjectMismatch {
		evidenceSubject.ArtifactSHA256 = strings.Repeat("6", 64)
	}
	evidence := evidenceRecord{
		Schema: "kurdistan-release-evidence-v1", EvidenceID: "independent-review",
		Subject: evidenceSubject, ObservedAt: "2026-08-02T10:00:00Z", Status: "PASS", Terminal: true,
		Limitations: []string{},
	}
	if options.EvidenceExpired {
		evidence.ExpiresAt = "2026-08-02T10:04:00Z"
	}
	evidenceRaw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "evidence", "independent-review.json"), evidenceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceDigest := fmt.Sprintf("%x", sha256.Sum256(evidenceRaw))
	if options.EvidenceDigestMismatch {
		evidenceDigest = strings.Repeat("f", 64)
	}
	maxAge := int64(0)
	if options.EvidenceExpired {
		maxAge = 240
	}
	policy := releasePolicy{
		Schema: "kurdistan-release-policy-v1", PolicyID: "public-v1",
		Subject:          subject,
		RequiredEvidence: []evidenceRequirement{{ID: "independent-review", Path: "evidence/independent-review.json", SHA256: evidenceDigest, MaxAgeSeconds: maxAge}},
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-policy.json"), policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, fmt.Sprintf("%x", sha256.Sum256(policyRaw))
}
