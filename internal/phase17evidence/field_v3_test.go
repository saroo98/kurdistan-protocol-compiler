// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17evidence

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/phase17qualification"
)

func TestOwnedVPSV3PreservesV2AndSeparatesStressFromSoak(t *testing.T) {
	if _, err := DecodeOwnedVPS(validOwnedVPSEvidence(t)); err != nil {
		t.Fatalf("frozen v2 evidence regressed: %v", err)
	}
	stress := validOwnedVPSV3(t, "Stress")
	stressRaw, err := MarshalOwnedVPSRawV3(stress)
	if err != nil {
		t.Fatal(err)
	}
	decodedStress, err := DecodeOwnedVPSRawV3(stressRaw)
	if err != nil {
		t.Fatal(err)
	}
	if decodedStress.Campaign.RestartReconnectCycles != 100 || decodedStress.Campaign.ProfileRotationCycles != 100 ||
		decodedStress.Campaign.SoakDurationMS != 0 || decodedStress.Campaign.SoakCycles != 0 {
		t.Fatalf("stress campaign=%+v", decodedStress.Campaign)
	}

	soak := validOwnedVPSV3(t, "Soak12h")
	soakRaw, err := MarshalOwnedVPSRawV3(soak)
	if err != nil {
		t.Fatal(err)
	}
	decodedSoak, err := DecodeOwnedVPSRawV3(soakRaw)
	if err != nil {
		t.Fatal(err)
	}
	if decodedSoak.Campaign.RestartReconnectCycles != 0 || decodedSoak.Campaign.ProfileRotationCycles != 0 ||
		len(decodedSoak.Campaign.Impairments) != 0 || decodedSoak.Campaign.SoakDurationMS < 43_200_000 || decodedSoak.Campaign.SoakCycles < 144 {
		t.Fatalf("soak campaign=%+v", decodedSoak.Campaign)
	}

	overstated := soak
	overstated.Campaign.RestartReconnectCycles = 100
	if _, err := MarshalOwnedVPSRawV3(overstated); err == nil {
		t.Fatal("Soak12h repeated or overstated Stress inventory")
	}
	stressWithSoak := stress
	stressWithSoak.Campaign.SoakDurationMS = 43_200_000
	stressWithSoak.Campaign.SoakCycles = 144
	stressWithSoak.Campaign.CadenceMS = 300_000
	if _, err := MarshalOwnedVPSRawV3(stressWithSoak); err == nil {
		t.Fatal("Stress overstated soak evidence")
	}
}

func TestOwnedVPSV3AcceptsCurrentPhysicalAPIWithoutWideningEmulatorMatrix(t *testing.T) {
	physical := validOwnedVPSV3(t, "Functional")
	physical.Environment.AndroidClass = "PHYSICAL"
	physical.Environment.AndroidAPI = 37
	physical.Environment.AndroidABI = "arm64-v8a"
	if _, err := MarshalOwnedVPSRawV3(physical); err != nil {
		t.Fatalf("current physical API rejected: %v", err)
	}

	emulator := physical
	emulator.Environment.AndroidClass = "EMULATOR"
	emulator.Environment.AndroidABI = "x86_64"
	if _, err := MarshalOwnedVPSRawV3(emulator); err == nil {
		t.Fatal("unqualified emulator API accepted")
	}
}

func TestOwnedVPSV3BindsCandidateAttemptAuthorizationScannersAndBoundary(t *testing.T) {
	valid := validOwnedVPSV3(t, "Functional")
	mutations := map[string]func(*OwnedVPSEvidenceV3){
		"candidate":          func(value *OwnedVPSEvidenceV3) { value.Subject.CandidateID = strings.Repeat("0", 64) },
		"root":               func(value *OwnedVPSEvidenceV3) { value.Subject.ProductSHA256 = strings.Repeat("0", 64) },
		"policy":             func(value *OwnedVPSEvidenceV3) { value.Subject.PolicySHA256 = "invalid" },
		"attempt":            func(value *OwnedVPSEvidenceV3) { value.Attempt.AttemptID = "invalid" },
		"authorization":      func(value *OwnedVPSEvidenceV3) { value.Attempt.AuthorizationSHA256 = "invalid" },
		"environment":        func(value *OwnedVPSEvidenceV3) { value.Attempt.EnvironmentSHA256 = "invalid" },
		"preflight":          func(value *OwnedVPSEvidenceV3) { value.Attempt.PreflightSHA256 = "invalid" },
		"unsupported VPS":    func(value *OwnedVPSEvidenceV3) { value.Environment.VPSArch = "arm64" },
		"scanner identity":   func(value *OwnedVPSEvidenceV3) { value.Scanners[1].IdentitySHA256 = value.Scanners[0].IdentitySHA256 },
		"scanner byte count": func(value *OwnedVPSEvidenceV3) { value.Scanners[1].BytesConsumed++ },
		"scanner truncation": func(value *OwnedVPSEvidenceV3) { value.Scanners[0].Truncated = true },
		"boundary":           func(value *OwnedVPSEvidenceV3) { value.Boundary.DNSLeak = true },
		"privacy":            func(value *OwnedVPSEvidenceV3) { value.Privacy.RawLogRetained = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Checks = append([]FieldCheckV3(nil), valid.Checks...)
			candidate.Scanners = append([]FieldScannerV3(nil), valid.Scanners...)
			mutate(&candidate)
			if _, err := MarshalOwnedVPSRawV3(candidate); err == nil {
				t.Fatal("invalid v3 evidence accepted")
			}
		})
	}
}

func TestOwnedVPSV3RequiresCanonicalSchemaAndExactCandidate(t *testing.T) {
	value := validOwnedVPSV3(t, "Soak60m")
	raw, err := MarshalOwnedVPSRawV3(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOwnedVPSRawV3(append(raw, '\n')); err == nil {
		t.Fatal("noncanonical v3 evidence accepted")
	}
	if _, err := DecodeOwnedVPSSanitizedV3(raw); err == nil {
		t.Fatal("raw v3 evidence accepted as sanitized evidence")
	}
	sanitized := value
	sanitized.Schema = OwnedVPSSchemaV3
	sanitizedRaw, err := MarshalOwnedVPSSanitizedV3(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOwnedVPSSanitizedV3(sanitizedRaw); err != nil {
		t.Fatal(err)
	}
	candidate := phase17qualification.CandidateIdentity{
		Repository: value.Subject.Repository, CommitSHA: value.Subject.CommitSHA, TreeSHA: value.Subject.TreeSHA,
		Roots: phase17qualification.SubjectRoots{
			SourceSHA256: value.Subject.SourceSHA256, ProductSHA256: value.Subject.ProductSHA256,
			HarnessSHA256: value.Subject.HarnessSHA256, WorkloadSHA256: value.Subject.WorkloadSHA256,
			VerifierSHA256: value.Subject.VerifierSHA256, CandidateID: value.Subject.CandidateID,
		},
		ComparisonSHA256: value.Subject.ComparisonSHA256,
	}
	if err := ValidateOwnedVPSV3Candidate(sanitized, candidate, value.Subject.PolicySHA256); err != nil {
		t.Fatal(err)
	}
	candidate.TreeSHA = strings.Repeat("f", 40)
	if err := ValidateOwnedVPSV3Candidate(sanitized, candidate, value.Subject.PolicySHA256); err == nil {
		t.Fatal("cross-candidate v3 evidence accepted")
	}
}

func TestOwnedVPSV3RecordsCategoricalTerminalFailuresWithoutClaimingPass(t *testing.T) {
	value := validOwnedVPSV3(t, "Functional")
	value.Outcome = "FAIL_HARNESS"
	value.Checks[8].Result = "NOT_RUN"
	value.Scanners[0].Result = "NOT_RUN"
	value.Scanners[0].IdentitySHA256 = ""
	value.Scanners[0].InputSHA256 = ""
	value.Scanners[0].BytesConsumed = 0
	value.Scanners[0].RecordsConsumed = 0
	value.Scanners[1].Result = "NOT_RUN"
	value.Scanners[1].IdentitySHA256 = ""
	value.Scanners[1].InputSHA256 = ""
	value.Scanners[1].BytesConsumed = 0
	value.Scanners[1].RecordsConsumed = 0
	value.Boundary.Result = "NOT_RUN"
	value.Boundary.MonitorSHA256 = ""
	raw, err := MarshalOwnedVPSRawV3(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOwnedVPSRawV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Outcome != "FAIL_HARNESS" {
		t.Fatalf("outcome=%q", decoded.Outcome)
	}
	value.Outcome = "PASS"
	if _, err := MarshalOwnedVPSRawV3(value); err == nil {
		t.Fatal("PASS evidence with incomplete checks was accepted")
	}
}

func TestOwnedVPSV3FailureRecordsOnlyCompletedCampaignWork(t *testing.T) {
	stress := validOwnedVPSV3(t, "Stress")
	stress.Outcome = "FAIL_PRODUCT"
	stress.Checks[8].Result = "FAIL"
	stress.Campaign.RestartReconnectCycles = 17
	stress.Campaign.ProfileRotationCycles = 0
	stress.Campaign.Impairments = []string{}
	stress.Scanners = notRunScannersV3()
	stress.Boundary = FieldBoundaryV3{Result: "NOT_RUN"}
	if _, err := MarshalOwnedVPSRawV3(stress); err != nil {
		t.Fatalf("partial Stress failure rejected: %v", err)
	}
	stress.Campaign.RestartReconnectCycles = 101
	if _, err := MarshalOwnedVPSRawV3(stress); err == nil {
		t.Fatal("failure overstated completed Stress work")
	}

	soak := validOwnedVPSV3(t, "Soak60m")
	soak.Outcome = "ABORT_ENVIRONMENT"
	soak.Checks[8].Result = "NOT_RUN"
	soak.Campaign.SoakDurationMS = 900_000
	soak.Campaign.SoakCycles = 3
	soak.Scanners = notRunScannersV3()
	soak.Boundary = FieldBoundaryV3{Result: "NOT_RUN"}
	soak.Metrics.DurationMS = 900_000
	if _, err := MarshalOwnedVPSRawV3(soak); err != nil {
		t.Fatalf("partial soak abort rejected: %v", err)
	}
	soak.Campaign.SoakCycles = 13
	if _, err := MarshalOwnedVPSRawV3(soak); err == nil {
		t.Fatal("failure overstated completed soak cycles")
	}
}

func notRunScannersV3() []FieldScannerV3 {
	return []FieldScannerV3{{Name: "GO_A", Result: "NOT_RUN"}, {Name: "PYTHON_B", Result: "NOT_RUN"}}
}

func validOwnedVPSV3(t testing.TB, mode string) OwnedVPSEvidenceV3 {
	t.Helper()
	roots, err := phase17qualification.NewSubjectRoots(
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	checks := make([]FieldCheckV3, 0, len(requiredOwnedVPSChecks))
	for _, name := range requiredOwnedVPSChecks {
		checks = append(checks, FieldCheckV3{Name: name, Result: "PASS"})
	}
	campaign, found := phase17qualification.CampaignPolicyForMode(mode)
	if !found {
		t.Fatalf("unknown test mode %q", mode)
	}
	fieldCampaign := FieldCampaignV3{
		Mode: campaign.Mode, RestartReconnectCycles: campaign.RestartReconnectCycles,
		ProfileRotationCycles: campaign.ProfileRotationCycles, Impairments: append([]string{}, campaign.Impairments...),
		SoakDurationMS: campaign.MinimumDurationMS, CadenceMS: campaign.CadenceMS, SoakCycles: campaign.MinimumCycles,
	}
	priorStress := ""
	soakReady := ""
	if mode == "Soak12h" {
		priorStress = strings.Repeat("d", 64)
		soakReady = strings.Repeat("e", 64)
	}
	return OwnedVPSEvidenceV3{
		Schema: OwnedVPSRawSchemaV3, Outcome: "PASS",
		Subject: FieldSubjectV3{
			Repository: "saroo98/kurdistan-protocol-compiler", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
			CandidateID: roots.CandidateID, SourceSHA256: roots.SourceSHA256, ProductSHA256: roots.ProductSHA256,
			HarnessSHA256: roots.HarnessSHA256, WorkloadSHA256: roots.WorkloadSHA256, VerifierSHA256: roots.VerifierSHA256,
			ComparisonSHA256: strings.Repeat("6", 64), PolicySHA256: strings.Repeat("7", 64),
			PackageSHA256: strings.Repeat("8", 64), AppAPKSHA256: strings.Repeat("9", 64), TestAPKSHA256: strings.Repeat("a", 64),
		},
		Attempt: FieldAttemptV3{
			AttemptID: strings.Repeat("b", 32), RCLockedSHA256: strings.Repeat("c", 64),
			AuthorizationSHA256: func() string {
				if soakReady != "" {
					return soakReady
				}
				return strings.Repeat("c", 64)
			}(),
			EnvironmentSHA256: strings.Repeat("f", 64), PreflightSHA256: strings.Repeat("0", 64),
			PriorStressResultSHA256: priorStress, SoakReadySHA256: soakReady,
		},
		Environment: FieldEnvironmentV3{
			HostOS: "windows", HostArch: "amd64", AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64",
			VPSOS: "linux", VPSArch: "amd64", ProviderClass: "PRIMARY", IPv4: true, IPv6: true,
		},
		Checks: checks,
		Metrics: FieldMetricsV3{
			DurationMS: maxUint64(1_200, campaign.MinimumDurationMS), PeakRSSBytes: 1 << 20,
			PeakFileDescriptors: 12, PeakSwapBytes: 0, OOMKills: 0, Reconnects: 2, TerminalGaps: 0,
		},
		Privacy: FieldPrivacyV3{},
		Scanners: []FieldScannerV3{
			{Name: "GO_A", IdentitySHA256: strings.Repeat("1", 64), InputSHA256: strings.Repeat("2", 64), BytesConsumed: 4096, RecordsConsumed: 32, Result: "PASS", Privacy: FieldPrivacyV3{}},
			{Name: "PYTHON_B", IdentitySHA256: strings.Repeat("3", 64), InputSHA256: strings.Repeat("2", 64), BytesConsumed: 4096, RecordsConsumed: 32, Result: "PASS", Privacy: FieldPrivacyV3{}},
		},
		Boundary: FieldBoundaryV3{Result: "PASS", MonitorSHA256: strings.Repeat("4", 64), RouteLeak: false, DNSLeak: false},
		Campaign: fieldCampaign,
	}
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func TestOwnedVPSV3CanonicalEncodingHasNoTrailingWhitespace(t *testing.T) {
	raw, err := MarshalOwnedVPSRawV3(validOwnedVPSV3(t, "Functional"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("v3 canonical encoding=%q", raw)
	}
}

func TestSanitizeOwnedVPSV3PromotesOnlyTheExactCanonicalPass(t *testing.T) {
	value := validOwnedVPSV3(t, "Soak12h")
	raw, err := MarshalOwnedVPSRawV3(value)
	if err != nil {
		t.Fatal(err)
	}
	sanitizedRaw, err := SanitizeOwnedVPSV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, err := DecodeOwnedVPSSanitizedV3(sanitizedRaw)
	if err != nil {
		t.Fatal(err)
	}
	value.Schema = OwnedVPSSchemaV3
	if !reflect.DeepEqual(sanitized, value) {
		t.Fatalf("sanitized=%+v want=%+v", sanitized, value)
	}

	failure := validOwnedVPSV3(t, "Functional")
	failure.Outcome = "INCONCLUSIVE"
	for index := range failure.Checks {
		failure.Checks[index].Result = "NOT_RUN"
	}
	failure.Scanners = []FieldScannerV3{{Name: "GO_A", Result: "NOT_RUN"}, {Name: "PYTHON_B", Result: "NOT_RUN"}}
	failure.Boundary = FieldBoundaryV3{Result: "NOT_RUN"}
	failure.Metrics = FieldMetricsV3{}
	failureRaw, err := MarshalOwnedVPSRawV3(failure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SanitizeOwnedVPSV3(failureRaw); err == nil {
		t.Fatal("non-PASS field evidence was promoted")
	}
	if _, err := SanitizeOwnedVPSV3(append(raw, '\n')); err == nil {
		t.Fatal("noncanonical raw field evidence was promoted")
	}
}
