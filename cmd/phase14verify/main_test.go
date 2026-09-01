// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
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

func validNoGoDecision() acceptance {
	local := map[string]string{}
	for _, key := range requiredLocalEvidence {
		local[key] = "PENDING"
	}
	external := map[string]string{}
	for _, key := range requiredExternalEvidence {
		external[key] = "UNVERIFIED"
	}
	return acceptance{
		Schema:             "kurdistan-phase14-acceptance-v1",
		Phase:              14,
		Complete:           false,
		ReadinessStatus:    "IN_PROGRESS",
		ReleaseDecision:    "NO_GO",
		PriorPhaseBaseline: map[string]string{"phase13": "PASS"},
		Local:              local,
		External:           external,
		Blockers: []blocker{{
			ID: "P14-EXT-001", Severity: "CRITICAL", Category: "field",
			ConditionToClear: "observe authorized field evidence",
		}},
		Limitations: []string{"local evidence is not field evidence"},
	}
}

func TestNoGoRequiresBlocker(t *testing.T) {
	value := validNoGoDecision()
	value.Blockers = nil
	if err := validateDecision(value); err == nil {
		t.Fatal("NO_GO decision without clearing condition passed")
	}
}

func TestGoRejectsUnverifiedEvidence(t *testing.T) {
	value := validNoGoDecision()
	value.Complete = true
	value.ReadinessStatus = "READY"
	value.ReleaseDecision = "GO"
	value.Blockers = nil
	if err := validateDecision(value); err == nil {
		t.Fatal("GO decision accepted unverified evidence")
	}
}

func TestGoRequiresEveryEvidencePass(t *testing.T) {
	value := validNoGoDecision()
	value.Complete = true
	value.ReadinessStatus = "READY"
	value.ReleaseDecision = "GO"
	value.Blockers = nil
	for key := range value.Local {
		value.Local[key] = "PASS"
	}
	for key := range value.External {
		value.External[key] = "PASS"
	}
	if err := validateDecision(value); err != nil {
		t.Fatalf("fully evidenced GO decision rejected: %v", err)
	}
}

func TestDuplicateBlockerRejected(t *testing.T) {
	value := validNoGoDecision()
	value.Blockers = append(value.Blockers, value.Blockers[0])
	if err := validateDecision(value); err == nil {
		t.Fatal("duplicate blocker IDs passed")
	}
}

func TestUnknownEvidenceStatusRejected(t *testing.T) {
	value := validNoGoDecision()
	value.Local[requiredLocalEvidence[0]] = "TRUST_ME"
	if err := validateDecision(value); err == nil {
		t.Fatal("unknown evidence status passed")
	}
}

func TestLocalEvidenceReportMustMatchAcceptanceStatus(t *testing.T) {
	decision := validNoGoDecision()
	report := localEvidenceReport{
		Schema:      "kurdistan-phase14-local-evidence-v1",
		EvidenceKey: "releaseArtifactReproducibility",
		Status:      "PASS",
		Scope:       "same-host unsigned release comparison",
		Commands:    []string{"gradlew clean assembleRelease"},
		Evidence:    []string{"matching SHA-256"},
		Limitations: []string{"not cross-host evidence"},
	}
	if err := validateLocalEvidenceReport(decision, report.EvidenceKey, report); err == nil {
		t.Fatal("mismatched evidence report passed")
	}
}
