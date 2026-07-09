// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreview

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_capture", "pcap", "ciphertext", "plaintext",
	"endpoint", "real_endpoint", "bridge_endpoint", "domain", "url", "sni", "host_header", "dns_query", "resolver", "resolver_ip",
	"tls_mimicry", "real_tls", "real_http", "real_quic", "real_udp", "cdn", "cloud_provider", "service_name", "provider_name",
	"account_metadata", "sim", "device_id", "phone", "location", "secret", "derived_key", "nonce_base", "auth_tag", "proof_material",
	"guaranteed_bypass", "undetectable", "field_ready", "production_vpn",
}

func ForbiddenMarkers() []string {
	return append([]string(nil), forbiddenMarkers...)
}

func ValidateDescriptor(desc CarrierFamilyDescriptor) error {
	if desc.Family == "" || desc.ReviewClass == "" || desc.RiskClass == "" || desc.Readiness == "" {
		return ErrInvalidCarrierReview
	}
	if !knownFamily(desc.Family) || !knownReadiness(desc.Readiness) {
		return ErrInvalidCarrierReview
	}
	if desc.Family == FamilyDomesticMediaRisk && (!desc.ManualReviewRequired || desc.DefaultEligible) {
		return fmt.Errorf("%w: domestic risk family must stay manual-review-only", ErrInvalidCarrierReview)
	}
	if desc.Family == FamilyExperimentalUDPQUIC && desc.DefaultEligible {
		return fmt.Errorf("%w: experimental UDP/QUIC family cannot be default eligible", ErrInvalidCarrierReview)
	}
	if desc.Family == FamilyDNSSurvival && desc.Readiness == ReadinessReadySynthetic {
		return fmt.Errorf("%w: dns survival cannot be ungated", ErrInvalidCarrierReview)
	}
	return ScanForLeak(desc)
}

func ValidateReview(review CarrierFamilyReview) error {
	if review.Version != Version || review.ReviewID == "" || len(review.Descriptors) == 0 || review.PayloadLogged || review.SecretLogged {
		return ErrInvalidCarrierReview
	}
	seen := map[string]bool{}
	for _, desc := range review.Descriptors {
		if seen[desc.Family] {
			return fmt.Errorf("%w: duplicate family", ErrInvalidCarrierReview)
		}
		seen[desc.Family] = true
		if err := ValidateDescriptor(desc); err != nil {
			return err
		}
	}
	if review.Readiness.Conclusion != "passed" || review.Parity.Conclusion != "passed" || review.Misuse.Conclusion != "passed" {
		return ErrInvalidCarrierReview
	}
	if review.ReviewHash != "" && review.ReviewHash != HashValue(reviewHashInput(review)) {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidCarrierReview)
	}
	return ScanForLeak(review)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	findings := []string{}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err == nil {
		scanReviewValue(decoded, "", &findings)
	}
	findings = uniqueStrings(findings)
	if len(findings) > 0 {
		return fmt.Errorf("%w: %s", ErrUnsafeMetadata, strings.Join(findings, ","))
	}
	return nil
}

func scanReviewValue(value any, parentKey string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			if lower == "payload_logged" || lower == "secret_logged" {
				scanReviewValue(child, lower, findings)
				continue
			}
			for _, marker := range forbiddenMarkers {
				if lower == marker || strings.Contains(lower, marker) {
					*findings = append(*findings, marker)
				}
			}
			scanReviewValue(child, lower, findings)
		}
	case []any:
		for _, child := range v {
			scanReviewValue(child, parentKey, findings)
		}
	case string:
		if strings.Contains(parentKey, "forbidden") || strings.Contains(parentKey, "notes") {
			return
		}
		lower := strings.ReplaceAll(strings.ToLower(v), " ", "_")
		for _, marker := range forbiddenMarkers {
			if marker == "payload" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func LoadReview(path string) (CarrierFamilyReview, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CarrierFamilyReview{}, err
	}
	var review CarrierFamilyReview
	if err := json.Unmarshal(raw, &review); err != nil {
		return CarrierFamilyReview{}, err
	}
	return review, ValidateReview(review)
}

func CompareReviews(oldReview, newReview CarrierFamilyReview) CarrierReviewComparisonReport {
	report := CarrierReviewComparisonReport{Version: Version, OldHash: oldReview.ReviewHash, NewHash: newReview.ReviewHash, Conclusion: "passed"}
	if err := ValidateReview(oldReview); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if err := ValidateReview(newReview); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if oldReview.ReviewHash != newReview.ReviewHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "review_hash_changed")
	}
	if oldReview.PayloadLogged || newReview.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldReview.SecretLogged || newReview.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func knownFamily(value string) bool {
	for _, candidate := range []string{FamilyHTTPSLikeTCP, FamilyDNSSurvival, FamilyExperimentalUDPQUIC, FamilyDomesticMediaRisk, FamilyRelayBridgeRotation, FamilyUnsafeControl} {
		if value == candidate {
			return true
		}
	}
	return false
}

func knownReadiness(value string) bool {
	for _, candidate := range []string{ReadinessReadySynthetic, ReadinessGatedSurvival, ReadinessExperimentalGated, ReadinessManualReviewOnly, ReadinessBlockedByRisk} {
		if value == candidate {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
