// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"testing"
)

func TestHistoricalSupersessionRejectsWideningAndNonGreenPredecessor(t *testing.T) {
	valid := validSupersessionForTest()
	if err := validateSupersession(valid); err != nil {
		t.Fatal(err)
	}

	thirdRule := valid
	thirdRule.SupersededRules = append(append([]string(nil), valid.SupersededRules...), "release-may-export-admin-interface")
	if err := validateSupersession(thirdRule); err == nil {
		t.Fatal("third superseded rule was accepted")
	}

	nonGreen := valid
	nonGreen.Predecessor.CIConclusion = "failure"
	if err := validateSupersession(nonGreen); err == nil {
		t.Fatal("non-green predecessor CI was accepted")
	}

	wrongArtifact := valid
	wrongArtifact.Artifacts.ReleaseAPKSHA256 = digest64("f")
	if err := validateSupersession(wrongArtifact); err == nil {
		t.Fatal("wrong predecessor artifact digest was accepted")
	}
}

func TestPhase17AcceptanceCannotHideExternalEvidence(t *testing.T) {
	value := validAcceptanceForTest()
	if err := validateAcceptance(value); err != nil {
		t.Fatal(err)
	}
	value.Complete = true
	value.Status = "COMPLETE"
	if err := validateAcceptance(value); err == nil {
		t.Fatal("complete Phase 17 accepted unverified external evidence")
	}
}

func TestStrictJSONRejectsUnknownAndDuplicateFields(t *testing.T) {
	valid := []byte(`{"schema":"phase17-historical-gate-supersession-v1"}`)
	var target struct {
		Schema string `json:"schema"`
	}
	if err := decodeStrict(valid, &target); err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict([]byte(`{"schema":"x","unknown":true}`), &target); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if err := decodeStrict([]byte(`{"schema":"x","schema":"y"}`), &target); err == nil {
		t.Fatal("duplicate field was accepted")
	}
	if err := decodeStrict(bytes.Join([][]byte{valid, valid}, nil), &target); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func validSupersessionForTest() supersession {
	return supersession{
		Schema: "phase17-historical-gate-supersession-v1",
		Predecessor: predecessor{
			CommitSHA:    "07c7fcfcfea22c417c83ea7e9ffec6a6dcbd8467",
			TreeSHA:      "ae120ee345af105b5ccb9004dc2375a7541a9736",
			CIURL:        "https://github.com/saroo98/kurdistan-protocol-compiler/actions/runs/31140567216",
			CIConclusion: "success",
		},
		Artifacts: predecessorArtifacts{
			ReleaseAPKSHA256:     "2bd10c95aee3b61cf40b817cc4131cbdcdaf0bce7f7e13539e01d99925236cf6",
			InternalAPKSHA256:    "87a5cac5876038b58723625dc7deeac68160f11c96bd9009a738c2af226ecfc2",
			MergedManifestSHA256: "c8918a762d9e8ed3458b758ce19ca1634317cc58d041ca60edea72d9dbc84117",
		},
		HistoricalVerifierSHA256:      "a7b3303c3c4bdd9866c023ad42c2de1b872096c2f68a6baeb0ce4c7c0bd2348b",
		HistoricalTestInventorySHA256: "5aebb2b87cf65011c6ac631f583dc65b0b8e82070260a383fc649f0469d4c82b",
		SupersededRules: []string{
			"release-manifest-forbids-internet-and-access-network-state",
			"current-runtime-is-loopback-only",
		},
		SuccessorPolicySHA256: digest64("c"),
		SuccessorGate:         "phase17Gate",
	}
}

func validAcceptanceForTest() acceptance {
	return acceptance{
		Schema:   "kurdistan-phase17-acceptance-v1",
		Phase:    17,
		Complete: false,
		Status:   "IN_PROGRESS",
		Local: map[string]string{
			"currentArtifactPolicy":       "PASS",
			"historicalSupersession":      "PASS",
			"api26Emulator":               "PENDING",
			"api34Emulator":               "PENDING",
			"api36Emulator":               "PENDING",
			"linuxNamespace":              "PENDING",
			"ownedVps":                    "PENDING",
			"loadRecoveryPrivacyCampaign": "PENDING",
		},
		External: map[string]string{
			"physicalApi26Device": "UNVERIFIED",
			"physicalApi34Device": "UNVERIFIED",
			"secondVpsProvider":   "UNVERIFIED",
		},
		Limitations: []string{"physical devices and a second unrelated VPS remain external evidence"},
	}
}

func digest64(value string) string {
	return string(bytes.Repeat([]byte(value), 64))
}
