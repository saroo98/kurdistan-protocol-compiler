// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

func ValidateFamilyDescriptor(desc CandidateFamilyDescriptor) error {
	if desc.Family == "" || desc.Role == "" || desc.CarrierClass == "" || desc.MetadataRiskBucket == "" || desc.DefaultTTLClass == "" {
		return ErrInvalidFamily
	}
	if !validTTL(desc.DefaultTTLClass) {
		return ErrInvalidFreshness
	}
	if desc.HighRisk && desc.DefaultEligible {
		return ErrInvalidFamily
	}
	if (desc.HighRisk || desc.Experimental || desc.Family == CandidateDNSSurvival) && !desc.Gated {
		return ErrInvalidFamily
	}
	if desc.DescriptorHash != "" && desc.DescriptorHash != HashValue(familyHashInput(desc)) {
		return ErrInvalidFamily
	}
	return ScanForLeak(desc)
}

func ValidateCandidate(candidate PathCandidate) error {
	if candidate.CandidateID == "" || candidate.Family == "" || candidate.ProfileID == "" || candidate.ProfileSeed == 0 || candidate.WirePolicyHash == "" || candidate.RelayID == "" || candidate.SyntheticHostID == "" || candidate.CarrierClass == "" || candidate.RouteClass == "" || candidate.RelayRiskBucket == "" || candidate.MetadataRiskBucket == "" {
		return ErrInvalidCandidate
	}
	if _, ok := FamilyDescriptor(candidate.Family); !ok {
		return ErrInvalidFamily
	}
	if candidate.PayloadLogged || candidate.SecretLogged {
		return ErrUnsafeAdaptivePath
	}
	if candidate.CandidateHash != "" && candidate.CandidateHash != HashValue(candidateHashInput(candidate)) {
		return ErrInvalidCandidate
	}
	return ScanForLeak(candidate)
}

func ValidateCondition(condition SyntheticPathCondition) error {
	if condition.ConditionID == "" || condition.ConditionClass == "" || condition.ExpectedState == "" || condition.VolatilityBucket == "" || condition.ConfidenceTTLClass == "" || len(condition.AffectedFamilies) == 0 || len(condition.ObservationKinds) == 0 {
		return ErrInvalidCondition
	}
	for _, fam := range condition.AffectedFamilies {
		if _, ok := FamilyDescriptor(fam); !ok {
			return ErrInvalidFamily
		}
	}
	if !validState(condition.ExpectedState) || !validTTL(condition.ConfidenceTTLClass) {
		return ErrInvalidCondition
	}
	if condition.ConditionHash != "" && condition.ConditionHash != HashValue(conditionHashInput(condition)) {
		return ErrInvalidCondition
	}
	return ScanForLeak(condition)
}

func ValidateObservation(obs PathObservation) error {
	if obs.ObservationID == "" || obs.CandidateID == "" || obs.Kind == "" || obs.ConfidenceTTLClass == "" || obs.FreshnessClass == "" || obs.LatencyBucket == "" || obs.TimeToUsefulByteBucket == "" {
		return ErrInvalidObservation
	}
	if !validObservationKind(obs.Kind) || !validTTL(obs.ConfidenceTTLClass) || !validFreshness(obs.FreshnessClass) {
		return ErrInvalidObservation
	}
	if obs.PayloadLogged || obs.SecretLogged {
		return ErrUnsafeAdaptivePath
	}
	if obs.ObservationHash != "" && obs.ObservationHash != HashValue(observationHashInput(obs)) {
		return ErrInvalidObservation
	}
	return ScanForLeak(obs)
}

func ValidateViabilityReport(report CandidateViabilityReport) error {
	if report.CandidateID == "" || report.Family == "" || report.CurrentState == "" || report.ViabilityBucket == "" || report.FreshnessClass == "" || report.UncertaintyBucket == "" || report.DecisionInputLike() == "" {
		return ErrInvalidViability
	}
	if report.PayloadLogged || report.SecretLogged || report.Conclusion != "passed" {
		return ErrInvalidViability
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(viabilityHashInput(report)) {
		return ErrInvalidViability
	}
	return ScanForLeak(report)
}

func (r CandidateViabilityReport) DecisionInputLike() string {
	return r.RecentSuccessBucket + r.RecentFailureBucket + r.LastFailureBucket
}

func ValidateDecisionSet(set CandidateDecisionSet) error {
	if set.Version != string(Version) || set.CandidateCount == 0 || len(set.Inputs) == 0 || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidDecisionInput
	}
	for _, input := range set.Inputs {
		if input.CandidateID == "" || input.Family == "" || input.CurrentState == "" || input.DecisionHash == "" || input.DecisionHash != HashValue(decisionHashInput(input)) {
			return ErrInvalidDecisionInput
		}
	}
	if set.DecisionSetHash != "" && set.DecisionSetHash != HashValue(decisionSetHashInput(set)) {
		return ErrInvalidDecisionInput
	}
	return ScanForLeak(set)
}

func ValidateFixtureSet(set AdaptivePathFixtureSet) error {
	if set.Version != string(Version) || len(set.Families) == 0 || len(set.Conditions) == 0 || len(set.Candidates) == 0 || len(set.Observations) == 0 || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidFixture
	}
	for _, desc := range set.Families {
		if err := ValidateFamilyDescriptor(desc); err != nil {
			return err
		}
	}
	for _, condition := range set.Conditions {
		if err := ValidateCondition(condition); err != nil {
			return err
		}
	}
	for _, candidate := range set.Candidates {
		if err := ValidateCandidate(candidate); err != nil {
			return err
		}
	}
	for _, obs := range set.Observations {
		if err := ValidateObservation(obs); err != nil {
			return err
		}
	}
	for _, report := range set.ViabilityReports {
		if err := ValidateViabilityReport(report); err != nil {
			return err
		}
	}
	if err := ValidateDecisionSet(set.DecisionInputs); err != nil {
		return err
	}
	if set.MisuseReport.Conclusion != "passed" || set.CollapsedControl.Conclusion != "failed" || set.Parity.Conclusion != "passed" {
		return ErrInvalidFixture
	}
	if set.FixtureSetHash != "" && set.FixtureSetHash != HashValue(fixtureSetHashInput(set)) {
		return ErrInvalidFixture
	}
	return ScanForLeak(set)
}

func LoadFixtureSet(path string) (AdaptivePathFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AdaptivePathFixtureSet{}, err
	}
	var set AdaptivePathFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return AdaptivePathFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes",
	"destination_address", "endpoint", "real_host", "proxy_ip", "server_ip", "domain", "sni", "host_header", "url", "uri", "ip_address",
	"dns_query", "resolver", "resolver_ip", "nameserver", "cloud_provider", "aws", "gcp", "azure", "region", "instance_id", "credential",
	"secret", "derived_key", "client_write_key", "server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
}

func ForbiddenMarkers() []string {
	return append([]string(nil), forbiddenMarkers...)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	findings := []string{}
	scanLeakValue(decoded, "", &findings)
	if len(findings) > 0 {
		sort.Strings(findings)
		return fmt.Errorf("%w: %s", ErrUnsafeAdaptivePath, strings.Join(uniqueStrings(findings), ","))
	}
	return nil
}

func scanLeakValue(value any, key string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for childKey, child := range v {
			lower := strings.ToLower(childKey)
			if forbiddenAdaptiveKey(lower) {
				*findings = append(*findings, childKey)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			scanLeakValue(child, childKey, findings)
		}
	case []any:
		for _, child := range v {
			scanLeakValue(child, key, findings)
		}
	case string:
		if !utf8.ValidString(v) {
			*findings = append(*findings, "invalid_utf8")
			return
		}
		lower := strings.ToLower(v)
		for _, marker := range forbiddenMarkers {
			if marker == "payload" || marker == "secret" || marker == "domain" || marker == "nonce" || marker == "url" || marker == "uri" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func forbiddenAdaptiveKey(key string) bool {
	for _, marker := range forbiddenMarkers {
		if key == marker || strings.Contains(key, marker) {
			switch key {
			case "payload_logged", "secret_logged", "payload_hygiene", "secret_hygiene", "metadata_risk_bucket", "default_eligible", "default_ttl_class", "decision_input_matches", "decision_inputs":
				return false
			}
			return true
		}
	}
	return false
}

func validState(state CandidateState) bool {
	switch state {
	case CandidateUnknown, CandidateLikelyUsable, CandidateDegraded, CandidateUnstable, CandidateBlocked, CandidateBurned, CandidateQuarantined, CandidateRejected:
		return true
	default:
		return false
	}
}

func validObservationKind(kind PathObservationKind) bool {
	for _, valid := range []PathObservationKind{ObservationHandshakeOK, ObservationHandshakeFailed, ObservationFirstUsefulByteOK, ObservationStallAfterHandshake, ObservationStallAfterData, ObservationResetLikeFailure, ObservationBlackholeLikeFailure, ObservationPoisoningLikeSignal, ObservationTruncationLikeSignal, ObservationRelayBurnRisk, ObservationShortSuccess, ObservationShortFailure} {
		if kind == valid {
			return true
		}
	}
	return false
}

func validTTL(ttl string) bool {
	switch ttl {
	case TTLSeconds, TTLOneMinute, TTLFiveMinutes, TTLShortSession, TTLExpired:
		return true
	default:
		return false
	}
}

func validFreshness(value string) bool {
	switch value {
	case FreshSeconds, FreshShort, StaleShort, StaleMedium, Expired, FreshUnknown:
		return true
	default:
		return false
	}
}

func countBucket(v int) string {
	switch {
	case v == 0:
		return "zero"
	case v == 1:
		return "one"
	case v < 4:
		return "few"
	default:
		return "many"
	}
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
