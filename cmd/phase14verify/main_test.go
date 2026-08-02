// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "testing"

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
