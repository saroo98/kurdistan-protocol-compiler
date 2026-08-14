// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	phase17 "kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
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

func TestConvertSanitizedEvidenceUpdatesAcceptanceAtomically(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "owned-vps.json")
	output := filepath.Join(directory, "acceptance-status.json")
	current, err := phase17.MarshalCanonical(validAcceptanceForTest())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, validOwnedVPSEvidenceForCommandTest(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := convertOwnedVPSFiles(input, output); err != nil {
		t.Fatal(err)
	}
	var updated acceptance
	raw, err := os.ReadFile(output)
	if err != nil || decodeStrict(raw, &updated) != nil {
		t.Fatalf("decode converted evidence: %v", err)
	}
	if updated.Local["ownedVps"] != "PASS" || updated.Local["api36Emulator"] != "PASS" {
		t.Fatalf("converted status=%+v", updated.Local)
	}
}

func TestSanitizeOwnedVPSV3FilesUsesOneExplicitCanonicalPassAndExclusiveOutput(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "exact-attempt-result.json")
	output := filepath.Join(directory, "sanitized.json")
	value := validOwnedVPSV3ForCommandTest(t)
	raw, err := phase17.MarshalOwnedVPSRawV3(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sanitizeOwnedVPSV3Files(input, output); err != nil {
		t.Fatal(err)
	}
	sanitizedRaw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, err := phase17.DecodeOwnedVPSSanitizedV3(sanitizedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if sanitized.Schema != phase17.OwnedVPSSchemaV3 || sanitized.Attempt.AttemptID != value.Attempt.AttemptID {
		t.Fatalf("sanitized=%+v", sanitized)
	}
	if err := sanitizeOwnedVPSV3Files(input, output); err == nil {
		t.Fatal("sanitizer overwrote an existing final output")
	}

	failure := value
	failure.Outcome = "INCONCLUSIVE"
	failure.Metrics = phase17.FieldMetricsV3{}
	for index := range failure.Checks {
		failure.Checks[index].Result = "NOT_RUN"
	}
	failure.Scanners = []phase17.FieldScannerV3{{Name: "GO_A", Result: "NOT_RUN"}, {Name: "PYTHON_B", Result: "NOT_RUN"}}
	failure.Boundary = phase17.FieldBoundaryV3{Result: "NOT_RUN"}
	failureRaw, err := phase17.MarshalOwnedVPSRawV3(failure)
	if err != nil {
		t.Fatal(err)
	}
	failurePath := filepath.Join(directory, "failure.json")
	if err := os.WriteFile(failurePath, failureRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sanitizeOwnedVPSV3Files(failurePath, filepath.Join(directory, "failure-sanitized.json")); err == nil {
		t.Fatal("non-PASS v3 evidence was sanitized")
	}
}

func TestWriteExclusiveSyncedPublishesExactlyOneSanitizedArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sanitized.json")
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, raw := range [][]byte{[]byte("first"), []byte("second")} {
		raw := append([]byte(nil), raw...)
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- writeExclusiveSyncedWith(path, raw, syncEvidenceDirectory)
		}()
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful sanitized publications=%d, want exactly one", succeeded)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "first" && string(raw) != "second" {
		t.Fatalf("sanitized output=%q error=%v", raw, err)
	}
}

func TestWriteExclusiveSyncedFailsClosedWhenDirectorySyncFails(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "sanitized.json")
	want := errors.New("synthetic directory sync failure")
	called := 0
	err := writeExclusiveSyncedWith(path, []byte("complete"), func(got string) error {
		called++
		if got != directory {
			t.Fatalf("synced directory=%q, want %q", got, directory)
		}
		return want
	})
	if !errors.Is(err, want) || called != 1 {
		t.Fatalf("error=%v sync calls=%d", err, called)
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

func validOwnedVPSEvidenceForCommandTest() []byte {
	checks := ""
	for index, name := range phase17.RequiredOwnedVPSChecks() {
		if index > 0 {
			checks += ","
		}
		checks += `"` + name + `":"PASS"`
	}
	return []byte(`{"schema":"kurdistan-phase17-owned-vps-evidence-v2","result":"PASS","subject":{"commitSha":"0123456789abcdef0123456789abcdef01234567","treeSha":"89abcdef0123456789abcdef0123456789abcdef","packageSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","appApkSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","testApkSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"environment":{"hostClass":"OWNER_CONTROLLED_VPS","os":"linux","arch":"amd64","androidClass":"EMULATOR","androidApi":36,"androidAbi":"x86_64","ipv4":true,"ipv6":true},"checks":{` + checks + `},"metrics":{"durationMs":1200,"peakRssBytes":1048576,"peakFileDescriptors":12,"reconnects":2},"privacy":{"payloadRetained":false,"destinationRetained":false,"dnsNameRetained":false,"credentialRetained":false,"keyRetained":false,"profileRetained":false,"rawLogRetained":false},"limitations":["first owner-controlled provider and emulator evidence only"],"campaign":{"mode":"Functional","restartReconnectCycles":0,"profileRotationCycles":0,"impairments":[],"soakDurationMs":0,"soakCycles":0}}`)
}

func validOwnedVPSV3ForCommandTest(t *testing.T) phase17.OwnedVPSEvidenceV3 {
	t.Helper()
	roots, err := phase17qualification.NewSubjectRoots(
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	checks := make([]phase17.FieldCheckV3, 0, len(phase17.RequiredOwnedVPSChecks()))
	for _, name := range phase17.RequiredOwnedVPSChecks() {
		checks = append(checks, phase17.FieldCheckV3{Name: name, Result: "PASS"})
	}
	return phase17.OwnedVPSEvidenceV3{
		Schema: phase17.OwnedVPSRawSchemaV3, Outcome: "PASS",
		Subject: phase17.FieldSubjectV3{
			Repository: "saroo98/kurdistan-protocol-compiler", CommitSHA: strings.Repeat("6", 40), TreeSHA: strings.Repeat("7", 40),
			CandidateID: roots.CandidateID, SourceSHA256: roots.SourceSHA256, ProductSHA256: roots.ProductSHA256,
			HarnessSHA256: roots.HarnessSHA256, WorkloadSHA256: roots.WorkloadSHA256, VerifierSHA256: roots.VerifierSHA256,
			ComparisonSHA256: strings.Repeat("8", 64), PolicySHA256: strings.Repeat("9", 64),
			PackageSHA256: strings.Repeat("a", 64), AppAPKSHA256: strings.Repeat("b", 64), TestAPKSHA256: strings.Repeat("c", 64),
		},
		Attempt: phase17.FieldAttemptV3{
			AttemptID: strings.Repeat("d", 32), RCLockedSHA256: strings.Repeat("e", 64),
			AuthorizationSHA256: strings.Repeat("e", 64), EnvironmentSHA256: strings.Repeat("f", 64),
			PreflightSHA256: strings.Repeat("0", 64),
		},
		Environment: phase17.FieldEnvironmentV3{
			HostOS: "windows", HostArch: "amd64", AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64",
			VPSOS: "linux", VPSArch: "amd64", ProviderClass: "PRIMARY", IPv4: true, IPv6: true,
		},
		Checks: checks,
		Metrics: phase17.FieldMetricsV3{
			DurationMS: 1200, PeakRSSBytes: 1 << 20, PeakFileDescriptors: 12,
		},
		Scanners: []phase17.FieldScannerV3{
			{Name: "GO_A", IdentitySHA256: strings.Repeat("1", 64), InputSHA256: strings.Repeat("2", 64), BytesConsumed: 100, RecordsConsumed: 2, Result: "PASS"},
			{Name: "PYTHON_B", IdentitySHA256: strings.Repeat("3", 64), InputSHA256: strings.Repeat("2", 64), BytesConsumed: 100, RecordsConsumed: 2, Result: "PASS"},
		},
		Boundary: phase17.FieldBoundaryV3{Result: "PASS", MonitorSHA256: strings.Repeat("4", 64)},
		Campaign: phase17.FieldCampaignV3{Mode: "Functional", Impairments: []string{}},
	}
}
