// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17evidence

import (
	"bytes"
	"errors"
	"regexp"

	"kurdistan/internal/phase17qualification"
)

const (
	OwnedVPSRawSchemaV3 = "kurdistan-phase17-owned-vps-raw-v3"
	OwnedVPSSchemaV3    = "kurdistan-phase17-owned-vps-evidence-v3"
)

var repositoryV3Pattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

type FieldSubjectV3 struct {
	Repository       string `json:"repository"`
	CommitSHA        string `json:"commitSha"`
	TreeSHA          string `json:"treeSha"`
	CandidateID      string `json:"candidateId"`
	SourceSHA256     string `json:"sourceSha256"`
	ProductSHA256    string `json:"productSha256"`
	HarnessSHA256    string `json:"harnessSha256"`
	WorkloadSHA256   string `json:"workloadSha256"`
	VerifierSHA256   string `json:"verifierSha256"`
	ComparisonSHA256 string `json:"comparisonSha256"`
	PolicySHA256     string `json:"policySha256"`
	PackageSHA256    string `json:"packageSha256"`
	AppAPKSHA256     string `json:"appApkSha256"`
	TestAPKSHA256    string `json:"testApkSha256"`
}

type FieldAttemptV3 struct {
	AttemptID               string `json:"attemptId"`
	RCLockedSHA256          string `json:"rcLockedSha256"`
	AuthorizationSHA256     string `json:"authorizationSha256"`
	EnvironmentSHA256       string `json:"environmentSha256"`
	PreflightSHA256         string `json:"preflightSha256"`
	PriorStressResultSHA256 string `json:"priorStressResultSha256"`
	SoakReadySHA256         string `json:"soakReadySha256"`
}

type FieldEnvironmentV3 struct {
	HostOS        string `json:"hostOs"`
	HostArch      string `json:"hostArch"`
	AndroidClass  string `json:"androidClass"`
	AndroidAPI    int    `json:"androidApi"`
	AndroidABI    string `json:"androidAbi"`
	VPSOS         string `json:"vpsOs"`
	VPSArch       string `json:"vpsArch"`
	ProviderClass string `json:"providerClass"`
	IPv4          bool   `json:"ipv4"`
	IPv6          bool   `json:"ipv6"`
}

type FieldCheckV3 struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

type FieldMetricsV3 struct {
	DurationMS          uint64 `json:"durationMs"`
	PeakRSSBytes        uint64 `json:"peakRssBytes"`
	PeakFileDescriptors uint64 `json:"peakFileDescriptors"`
	PeakSwapBytes       uint64 `json:"peakSwapBytes"`
	OOMKills            uint64 `json:"oomKills"`
	Reconnects          uint64 `json:"reconnects"`
	TerminalGaps        uint64 `json:"terminalGaps"`
}

type FieldPrivacyV3 struct {
	PayloadRetained     bool `json:"payloadRetained"`
	DestinationRetained bool `json:"destinationRetained"`
	DNSNameRetained     bool `json:"dnsNameRetained"`
	CredentialRetained  bool `json:"credentialRetained"`
	KeyRetained         bool `json:"keyRetained"`
	ProfileRetained     bool `json:"profileRetained"`
	RawLogRetained      bool `json:"rawLogRetained"`
}

type FieldScannerV3 struct {
	Name                string         `json:"name"`
	IdentitySHA256      string         `json:"identitySha256"`
	InputSHA256         string         `json:"inputSha256"`
	BytesConsumed       uint64         `json:"bytesConsumed"`
	RecordsConsumed     uint64         `json:"recordsConsumed"`
	Result              string         `json:"result"`
	Truncated           bool           `json:"truncated"`
	ParseFailure        bool           `json:"parseFailure"`
	BackpressureFailure bool           `json:"backpressureFailure"`
	CoverageGap         bool           `json:"coverageGap"`
	Privacy             FieldPrivacyV3 `json:"privacy"`
}

type FieldBoundaryV3 struct {
	Result        string `json:"result"`
	MonitorSHA256 string `json:"monitorSha256"`
	RouteLeak     bool   `json:"routeLeak"`
	DNSLeak       bool   `json:"dnsLeak"`
}

type FieldCampaignV3 struct {
	Mode                   string   `json:"mode"`
	RestartReconnectCycles uint64   `json:"restartReconnectCycles"`
	ProfileRotationCycles  uint64   `json:"profileRotationCycles"`
	Impairments            []string `json:"impairments"`
	SoakDurationMS         uint64   `json:"soakDurationMs"`
	CadenceMS              uint64   `json:"cadenceMs"`
	SoakCycles             uint64   `json:"soakCycles"`
}

type OwnedVPSEvidenceV3 struct {
	Schema      string             `json:"schema"`
	Outcome     string             `json:"outcome"`
	Subject     FieldSubjectV3     `json:"subject"`
	Attempt     FieldAttemptV3     `json:"attempt"`
	Environment FieldEnvironmentV3 `json:"environment"`
	Checks      []FieldCheckV3     `json:"checks"`
	Metrics     FieldMetricsV3     `json:"metrics"`
	Privacy     FieldPrivacyV3     `json:"privacy"`
	Scanners    []FieldScannerV3   `json:"scanners"`
	Boundary    FieldBoundaryV3    `json:"boundary"`
	Campaign    FieldCampaignV3    `json:"campaign"`
}

func MarshalOwnedVPSRawV3(value OwnedVPSEvidenceV3) ([]byte, error) {
	if value.Schema != OwnedVPSRawSchemaV3 {
		return nil, errors.New("owned-VPS raw v3 schema rejected")
	}
	return marshalOwnedVPSV3(value)
}

func MarshalOwnedVPSSanitizedV3(value OwnedVPSEvidenceV3) ([]byte, error) {
	if value.Schema != OwnedVPSSchemaV3 {
		return nil, errors.New("owned-VPS sanitized v3 schema rejected")
	}
	return marshalOwnedVPSV3(value)
}

func DecodeOwnedVPSRawV3(raw []byte) (OwnedVPSEvidenceV3, error) {
	return decodeOwnedVPSV3(raw, OwnedVPSRawSchemaV3)
}

func DecodeOwnedVPSSanitizedV3(raw []byte) (OwnedVPSEvidenceV3, error) {
	return decodeOwnedVPSV3(raw, OwnedVPSSchemaV3)
}

func SanitizeOwnedVPSV3(raw []byte) ([]byte, error) {
	value, err := DecodeOwnedVPSRawV3(raw)
	if err != nil {
		return nil, err
	}
	if value.Outcome != "PASS" {
		return nil, errors.New("owned-VPS v3 non-PASS evidence cannot be promoted")
	}
	value.Schema = OwnedVPSSchemaV3
	return MarshalOwnedVPSSanitizedV3(value)
}

func ValidateOwnedVPSV3Candidate(value OwnedVPSEvidenceV3, candidate phase17qualification.CandidateIdentity, policySHA256 string) error {
	if err := validateOwnedVPSV3(value); err != nil {
		return err
	}
	if value.Subject.Repository != candidate.Repository || value.Subject.CommitSHA != candidate.CommitSHA ||
		value.Subject.TreeSHA != candidate.TreeSHA || value.Subject.CandidateID != candidate.Roots.CandidateID ||
		value.Subject.SourceSHA256 != candidate.Roots.SourceSHA256 || value.Subject.ProductSHA256 != candidate.Roots.ProductSHA256 ||
		value.Subject.HarnessSHA256 != candidate.Roots.HarnessSHA256 || value.Subject.WorkloadSHA256 != candidate.Roots.WorkloadSHA256 ||
		value.Subject.VerifierSHA256 != candidate.Roots.VerifierSHA256 || value.Subject.ComparisonSHA256 != candidate.ComparisonSHA256 ||
		value.Subject.PolicySHA256 != policySHA256 {
		return errors.New("owned-VPS v3 candidate identity rejected")
	}
	return nil
}

func marshalOwnedVPSV3(value OwnedVPSEvidenceV3) ([]byte, error) {
	if err := validateOwnedVPSV3(value); err != nil {
		return nil, err
	}
	return phase17qualification.MarshalCanonical(value)
}

func decodeOwnedVPSV3(raw []byte, schema string) (OwnedVPSEvidenceV3, error) {
	if len(raw) == 0 || len(raw) > 4<<20 || containsSensitiveFieldEvidence(raw) {
		return OwnedVPSEvidenceV3{}, errors.New("owned-VPS v3 input rejected")
	}
	var value OwnedVPSEvidenceV3
	if err := DecodeStrict(raw, &value); err != nil {
		return OwnedVPSEvidenceV3{}, err
	}
	if value.Schema != schema {
		return OwnedVPSEvidenceV3{}, errors.New("owned-VPS v3 schema boundary rejected")
	}
	if err := validateOwnedVPSV3(value); err != nil {
		return OwnedVPSEvidenceV3{}, err
	}
	canonical, err := phase17qualification.MarshalCanonical(value)
	if err != nil {
		return OwnedVPSEvidenceV3{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return OwnedVPSEvidenceV3{}, errors.New("owned-VPS v3 evidence is not canonical")
	}
	return value, nil
}

func validateOwnedVPSV3(value OwnedVPSEvidenceV3) error {
	if value.Schema != OwnedVPSRawSchemaV3 && value.Schema != OwnedVPSSchemaV3 {
		return errors.New("owned-VPS v3 schema rejected")
	}
	if !containsString(phase17qualification.Outcomes(), value.Outcome) {
		return errors.New("owned-VPS v3 outcome rejected")
	}
	if err := validateFieldSubjectV3(value.Subject); err != nil {
		return err
	}
	if err := validateFieldAttemptV3(value.Attempt, value.Campaign.Mode); err != nil {
		return err
	}
	if err := validateFieldEnvironmentV3(value.Environment); err != nil {
		return err
	}
	allChecksPass, err := validateFieldChecksV3(value.Checks)
	if err != nil {
		return err
	}
	if err := validateFieldCampaignV3(value.Campaign, value.Outcome); err != nil {
		return err
	}
	if err := validateFieldMetricsV3(value.Metrics, value.Campaign, value.Outcome); err != nil {
		return err
	}
	scannersPass, err := validateFieldScannersV3(value.Scanners)
	if err != nil {
		return err
	}
	boundaryPass, err := validateFieldBoundaryV3(value.Boundary)
	if err != nil {
		return err
	}
	privacyPass := value.Privacy == (FieldPrivacyV3{})
	if value.Outcome == "PASS" {
		if !allChecksPass || !scannersPass || !boundaryPass || !privacyPass || value.Metrics.OOMKills != 0 || value.Metrics.TerminalGaps != 0 {
			return errors.New("owned-VPS v3 PASS lacks complete proof")
		}
	} else if allChecksPass && scannersPass && boundaryPass && privacyPass {
		return errors.New("owned-VPS v3 terminal failure has no categorical failing evidence")
	}
	return nil
}

func validateFieldSubjectV3(value FieldSubjectV3) error {
	if !repositoryV3Pattern.MatchString(value.Repository) || !validLowerHex(value.CommitSHA, 40) || !validLowerHex(value.TreeSHA, 40) {
		return errors.New("owned-VPS v3 source subject rejected")
	}
	for _, digest := range []string{
		value.CandidateID, value.SourceSHA256, value.ProductSHA256, value.HarnessSHA256, value.WorkloadSHA256,
		value.VerifierSHA256, value.ComparisonSHA256, value.PolicySHA256, value.PackageSHA256, value.AppAPKSHA256, value.TestAPKSHA256,
	} {
		if !validDigest(digest) {
			return errors.New("owned-VPS v3 subject digest rejected")
		}
	}
	roots, err := phase17qualification.NewSubjectRoots(
		value.SourceSHA256, value.ProductSHA256, value.HarnessSHA256, value.WorkloadSHA256, value.VerifierSHA256,
	)
	if err != nil || roots.CandidateID != value.CandidateID {
		return errors.New("owned-VPS v3 subject roots rejected")
	}
	return nil
}

func validateFieldAttemptV3(value FieldAttemptV3, mode string) error {
	if !validLowerHex(value.AttemptID, 32) || !validDigest(value.RCLockedSHA256) ||
		!validDigest(value.AuthorizationSHA256) || !validDigest(value.EnvironmentSHA256) || !validDigest(value.PreflightSHA256) {
		return errors.New("owned-VPS v3 attempt identity rejected")
	}
	if mode == "Soak12h" {
		if !validDigest(value.PriorStressResultSHA256) || !validDigest(value.SoakReadySHA256) || value.AuthorizationSHA256 != value.SoakReadySHA256 {
			return errors.New("owned-VPS v3 final soak authorization chain rejected")
		}
	} else if value.PriorStressResultSHA256 != "" || value.SoakReadySHA256 != "" || value.AuthorizationSHA256 != value.RCLockedSHA256 {
		return errors.New("owned-VPS v3 non-final campaign authorization chain rejected")
	}
	return nil
}

func validateFieldEnvironmentV3(value FieldEnvironmentV3) error {
	if !containsString([]string{"windows", "linux", "darwin"}, value.HostOS) || !containsString([]string{"amd64", "arm64"}, value.HostArch) ||
		!containsString([]string{"EMULATOR", "PHYSICAL"}, value.AndroidClass) ||
		!phase17qualification.ValidAndroidAPIForClass(value.AndroidClass, value.AndroidAPI) ||
		!containsString([]string{"x86_64", "arm64-v8a"}, value.AndroidABI) || value.VPSOS != "linux" || value.VPSArch != "amd64" ||
		!containsString([]string{"PRIMARY", "UNRELATED_SECONDARY"}, value.ProviderClass) || !value.IPv4 {
		return errors.New("owned-VPS v3 environment rejected")
	}
	return nil
}

func validateFieldChecksV3(values []FieldCheckV3) (bool, error) {
	if len(values) != len(requiredOwnedVPSChecks) {
		return false, errors.New("owned-VPS v3 check inventory rejected")
	}
	allPass := true
	for index, value := range values {
		if value.Name != requiredOwnedVPSChecks[index] || !containsString([]string{"PASS", "FAIL", "NOT_RUN"}, value.Result) {
			return false, errors.New("owned-VPS v3 check entry rejected")
		}
		allPass = allPass && value.Result == "PASS"
	}
	return allPass, nil
}

func validateFieldCampaignV3(value FieldCampaignV3, outcome string) error {
	policy, found := phase17qualification.CampaignPolicyForMode(value.Mode)
	if !found {
		return errors.New("owned-VPS v3 campaign policy rejected")
	}
	if outcome == "PASS" && (!equalStrings(value.Impairments, policy.Impairments) ||
		value.RestartReconnectCycles != policy.RestartReconnectCycles || value.ProfileRotationCycles != policy.ProfileRotationCycles) {
		return errors.New("owned-VPS v3 campaign cycle inventory rejected")
	}
	if outcome != "PASS" && (value.RestartReconnectCycles > policy.RestartReconnectCycles ||
		value.ProfileRotationCycles > policy.ProfileRotationCycles || !stringPrefix(value.Impairments, policy.Impairments)) {
		return errors.New("owned-VPS v3 failed campaign overstated completed work")
	}
	if policy.MinimumDurationMS == 0 {
		if value.SoakDurationMS != 0 || value.CadenceMS != 0 || value.SoakCycles != 0 {
			return errors.New("owned-VPS v3 non-soak campaign overstated endurance")
		}
		return nil
	}
	maximumDuration := policy.MinimumDurationMS + 2*policy.CadenceMS
	if outcome == "PASS" && (value.SoakDurationMS < policy.MinimumDurationMS || value.SoakDurationMS > maximumDuration ||
		value.CadenceMS != policy.CadenceMS || value.SoakCycles < policy.MinimumCycles || value.SoakCycles > policy.MinimumCycles+2) {
		return errors.New("owned-VPS v3 soak duration or cadence rejected")
	}
	if outcome != "PASS" && (value.SoakDurationMS > maximumDuration || value.SoakCycles > policy.MinimumCycles ||
		(value.CadenceMS != 0 && value.CadenceMS != policy.CadenceMS) ||
		(value.SoakCycles > 0 && value.CadenceMS != policy.CadenceMS)) {
		return errors.New("owned-VPS v3 failed soak overstated completed work")
	}
	return nil
}

func validateFieldMetricsV3(value FieldMetricsV3, campaign FieldCampaignV3, outcome string) error {
	if value.DurationMS > 7*24*60*60*1000 || value.PeakRSSBytes > 384<<20 || value.PeakFileDescriptors > 1024 ||
		value.PeakSwapBytes > 64<<20 || value.Reconnects > 2000 || value.TerminalGaps > 1 {
		return errors.New("owned-VPS v3 metrics rejected")
	}
	if outcome == "PASS" && (value.DurationMS == 0 || value.PeakRSSBytes == 0 || value.PeakFileDescriptors == 0 ||
		value.DurationMS < campaign.SoakDurationMS) {
		return errors.New("owned-VPS v3 passing metrics incomplete")
	}
	return nil
}

func validateFieldScannersV3(values []FieldScannerV3) (bool, error) {
	if len(values) != 2 || values[0].Name != "GO_A" || values[1].Name != "PYTHON_B" {
		return false, errors.New("owned-VPS v3 scanner inventory rejected")
	}
	for _, value := range values {
		if !containsString([]string{"PASS", "FAIL", "NOT_RUN"}, value.Result) {
			return false, errors.New("owned-VPS v3 scanner receipt rejected")
		}
		if value.Result == "NOT_RUN" {
			if value.IdentitySHA256 != "" || value.InputSHA256 != "" || value.BytesConsumed != 0 || value.RecordsConsumed != 0 ||
				value.Truncated || value.ParseFailure || value.BackpressureFailure || value.CoverageGap || value.Privacy != (FieldPrivacyV3{}) {
				return false, errors.New("owned-VPS v3 scanner NOT_RUN contradicts its evidence")
			}
			continue
		}
		if !validDigest(value.IdentitySHA256) || !validDigest(value.InputSHA256) || value.BytesConsumed == 0 || value.RecordsConsumed == 0 {
			return false, errors.New("owned-VPS v3 scanner receipt rejected")
		}
		if value.Result == "PASS" && (value.Truncated || value.ParseFailure || value.BackpressureFailure || value.CoverageGap || value.Privacy != (FieldPrivacyV3{})) {
			return false, errors.New("owned-VPS v3 scanner PASS contradicts its evidence")
		}
	}
	if values[0].Result == "NOT_RUN" || values[1].Result == "NOT_RUN" {
		return false, nil
	}
	if values[0].IdentitySHA256 == values[1].IdentitySHA256 || values[0].InputSHA256 != values[1].InputSHA256 ||
		values[0].BytesConsumed != values[1].BytesConsumed || values[0].RecordsConsumed != values[1].RecordsConsumed {
		return false, errors.New("owned-VPS v3 scanner independence or stream parity rejected")
	}
	return values[0].Result == "PASS" && values[1].Result == "PASS", nil
}

func validateFieldBoundaryV3(value FieldBoundaryV3) (bool, error) {
	if !containsString([]string{"PASS", "FAIL", "NOT_RUN"}, value.Result) {
		return false, errors.New("owned-VPS v3 boundary receipt rejected")
	}
	if value.Result == "NOT_RUN" {
		if value.MonitorSHA256 != "" || value.RouteLeak || value.DNSLeak {
			return false, errors.New("owned-VPS v3 boundary NOT_RUN contradicts its evidence")
		}
		return false, nil
	}
	if !validDigest(value.MonitorSHA256) {
		return false, errors.New("owned-VPS v3 boundary identity rejected")
	}
	if value.Result == "PASS" && (value.RouteLeak || value.DNSLeak) {
		return false, errors.New("owned-VPS v3 boundary PASS contradicts a leak")
	}
	return value.Result == "PASS", nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func stringPrefix(prefix, complete []string) bool {
	if len(prefix) > len(complete) {
		return false
	}
	for index := range prefix {
		if prefix[index] != complete[index] {
			return false
		}
	}
	return true
}
