// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase12EvidenceRejectsUnknownAndTrailingJSONV1(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "evidence", "phase12", "acceptance-status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	top["production_ready"] = json.RawMessage(`true`)
	unknownTop, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePhase12AcceptanceStatusV1(unknownTop); err == nil {
		t.Fatal("unknown top-level acceptance claim was accepted")
	}

	var nested map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&nested); err != nil {
		t.Fatal(err)
	}
	reviews := nested["security_reviews"].(map[string]any)
	review := reviews["second_adversarial_review"].(map[string]any)
	review["verdict"] = "production-ready"
	unknownNested, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePhase12AcceptanceStatusV1(unknownNested); err == nil {
		t.Fatal("unknown nested acceptance claim was accepted")
	}

	if _, err := decodePhase12AcceptanceStatusV1(append(append([]byte(nil), raw...), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestPhase12EvidenceCannotOverstateExternalOrProductClaims(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "evidence", "phase12", "acceptance-status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status phase12AcceptanceStatusV1
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	if err := validatePhase12AcceptanceStatusV1(status); err != nil {
		t.Fatal(err)
	}
	for _, name := range phase12SecondReviewFindingNamesV1 {
		if status.Local[name] != "verified-by-local-test" {
			t.Fatalf("second-review finding %q is not bound to local evidence", name)
		}
	}
}

func TestPhase12EvidenceVocabularyMutationsV1(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "evidence", "phase12", "acceptance-status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var baseline phase12AcceptanceStatusV1
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	if err := validatePhase12AcceptanceStatusV1(baseline); err != nil {
		t.Fatal(err)
	}
	clone := func() phase12AcceptanceStatusV1 {
		t.Helper()
		encoded, err := json.Marshal(baseline)
		if err != nil {
			t.Fatal(err)
		}
		var status phase12AcceptanceStatusV1
		if err := json.Unmarshal(encoded, &status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	mutations := map[string]func(*phase12AcceptanceStatusV1){
		"local-deletion": func(status *phase12AcceptanceStatusV1) {
			delete(status.Local, phase12LocalEvidenceNamesV1[0])
		},
		"local-addition": func(status *phase12AcceptanceStatusV1) {
			status.Local["self_asserted_local_check"] = "verified-by-local-test"
		},
		"local-substitution": func(status *phase12AcceptanceStatusV1) {
			delete(status.Local, phase12LocalEvidenceNamesV1[0])
			status.Local["self_asserted_local_check"] = "verified-by-local-test"
		},
		"external-deletion": func(status *phase12AcceptanceStatusV1) {
			delete(status.External, phase12ExternalEvidenceNamesV1[0])
		},
		"external-addition": func(status *phase12AcceptanceStatusV1) {
			status.External["self_asserted_external_boundary"] = "[UNVERIFIED]"
		},
		"external-substitution": func(status *phase12AcceptanceStatusV1) {
			delete(status.External, phase12ExternalEvidenceNamesV1[0])
			status.External["self_asserted_external_boundary"] = "[UNVERIFIED]"
		},
		"claim-deletion": func(status *phase12AcceptanceStatusV1) {
			delete(status.Claims, phase12ClaimNamesV1[0])
		},
		"claim-addition": func(status *phase12AcceptanceStatusV1) {
			status.Claims["self_asserted_claim"] = false
		},
		"claim-substitution": func(status *phase12AcceptanceStatusV1) {
			delete(status.Claims, phase12ClaimNamesV1[0])
			status.Claims["self_asserted_claim"] = false
		},
		"review-deletion": func(status *phase12AcceptanceStatusV1) {
			delete(status.SecurityReviews, "second_adversarial_review")
		},
		"review-addition": func(status *phase12AcceptanceStatusV1) {
			status.SecurityReviews["self_asserted_review"] = status.SecurityReviews["second_adversarial_review"]
		},
		"review-substitution": func(status *phase12AcceptanceStatusV1) {
			review := status.SecurityReviews["second_adversarial_review"]
			delete(status.SecurityReviews, "second_adversarial_review")
			status.SecurityReviews["self_asserted_review"] = review
		},
		"review-finding-deletion": func(status *phase12AcceptanceStatusV1) {
			review := status.SecurityReviews["second_adversarial_review"]
			delete(review.Findings, phase12SecondReviewFindingNamesV1[0])
			status.SecurityReviews["second_adversarial_review"] = review
		},
		"review-finding-addition": func(status *phase12AcceptanceStatusV1) {
			review := status.SecurityReviews["second_adversarial_review"]
			review.Findings["self_asserted_review_finding"] = "verified-by-local-test"
			status.SecurityReviews["second_adversarial_review"] = review
		},
		"review-finding-substitution": func(status *phase12AcceptanceStatusV1) {
			review := status.SecurityReviews["second_adversarial_review"]
			delete(review.Findings, phase12SecondReviewFindingNamesV1[0])
			review.Findings["self_asserted_review_finding"] = "verified-by-local-test"
			status.SecurityReviews["second_adversarial_review"] = review
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			status := clone()
			mutate(&status)
			if err := validatePhase12AcceptanceStatusV1(status); err == nil {
				t.Fatal("Phase 12 acceptance evidence vocabulary mutation accepted")
			}
		})
	}
}

func TestPhase12DocumentsRecordSecondReviewWithoutClosingExternalBoundaries(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(relative string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	kip := read(filepath.Join("docs", "KIP-0087-phase12-operator-provisioning-relay-fleet.md"))
	index := read(filepath.Join("docs", "PHASE12_EVIDENCE_INDEX.md"))
	for name, document := range map[string]string{
		"KIP-0087":       kip,
		"evidence index": index,
	} {
		if !strings.Contains(document, "**[UNVERIFIED]**") {
			t.Fatalf("%s lost its external evidence boundary", name)
		}
	}
	for _, required := range []string{
		"## Second adversarial review closure",
		"Recoverer identity shape and `recover` duty",
		"root-set member's canonical signed delegation",
		"bind authoritative creation time",
		"exact current artifact digest",
		"redacted value DTO and exact event ID",
		"safety-priority lane preserves per-target ordering",
		"Expired operations, including safety operations",
		"bounded failure path rather than bypassing expiry",
		"`ValidUntil <= PublishedAt`",
		"exact revision continuity",
	} {
		if !strings.Contains(index, required) {
			t.Fatalf("Phase 12 evidence index missing second-review claim %q", required)
		}
	}
	for _, required := range []string{
		"validates the recoverer actor",
		"root-signed delegation",
		"exact digest of the current admitted artifact",
		"Complete journal copying",
		"production trusted-time source",
	} {
		if !strings.Contains(kip, required) {
			t.Fatalf("KIP-0087 missing corrected boundary %q", required)
		}
	}
}
