// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_packet", "packet_capture", "pcap", "raw_bytes", "encoded_bytes", "decoded_bytes",
	"ciphertext", "plaintext", "exact_destination", "domain", "url", "sni", "host_header", "dns_query", "resolver_ip",
	"client_ip", "server_ip", "precise_timestamp", "location", "phone", "sim", "imsi", "imei", "device", "advertising",
	"account", "contacts", "browser_history", "installed_apps", "key", "nonce", "auth_tag", "proof_material",
	"session_secret", "private_key", "telemetry_upload", "background_collection", "field_ready", "guaranteed_bypass", "undetectable",
}

func ForbiddenMarkers() []string {
	return append([]string(nil), forbiddenMarkers...)
}

func ValidateObservationField(field ObservationField) error {
	if field.Name == "" || field.Class == "" || field.RedactionClass == "" || field.RetentionClass == "" {
		return ErrInvalidMeasurementReview
	}
	if !knownRedaction(field.RedactionClass) || !knownRetention(field.RetentionClass) {
		return ErrInvalidMeasurementReview
	}
	return ScanForLeak(field)
}

func ValidateReview(review MeasurementReview) error {
	if review.Version != Version || review.ReviewID == "" || len(review.Fields) == 0 || review.PayloadLogged || review.SecretLogged {
		return ErrInvalidMeasurementReview
	}
	seen := map[string]bool{}
	for _, field := range review.Fields {
		if seen[field.Name] {
			return fmt.Errorf("%w: duplicate observation field", ErrInvalidMeasurementReview)
		}
		seen[field.Name] = true
		if err := ValidateObservationField(field); err != nil {
			return err
		}
	}
	if review.Policy.ConsentMode == "" || !knownConsent(review.Policy.ConsentMode) || !knownRetention(review.Policy.RetentionClass) {
		return ErrInvalidMeasurementReview
	}
	if review.Policy.BackgroundCollection || !review.Policy.LocalDiagnosticsOnly {
		return ErrInvalidMeasurementReview
	}
	if review.Diagnostics.Conclusion != "passed" || review.Misuse.Conclusion != "passed" || review.Parity.Conclusion != "passed" || review.Readiness.Conclusion != "passed" {
		return ErrInvalidMeasurementReview
	}
	if review.ReviewHash != "" && review.ReviewHash != HashValue(reviewHashInput(review)) {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidMeasurementReview)
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
			lower := normalize(key)
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			if lower == "payload_logged" || lower == "secret_logged" {
				scanReviewValue(child, lower, findings)
				continue
			}
			if lower == "background_collection" {
				if child == true {
					*findings = append(*findings, "background_collection_true")
				}
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
		if strings.Contains(parentKey, "rejected") || strings.Contains(parentKey, "forbidden") || strings.Contains(parentKey, "notes") {
			return
		}
		lower := normalize(v)
		for _, marker := range forbiddenMarkers {
			if marker == "payload" || marker == "key" || marker == "nonce" || marker == "sim" || marker == "device" || marker == "account" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func normalize(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_")
	return replacer.Replace(value)
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

func LoadReview(path string) (MeasurementReview, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return MeasurementReview{}, err
	}
	var review MeasurementReview
	if err := json.Unmarshal(raw, &review); err != nil {
		return MeasurementReview{}, err
	}
	return review, ValidateReview(review)
}

func CompareReviews(oldReview, newReview MeasurementReview) MeasurementReviewComparisonReport {
	report := MeasurementReviewComparisonReport{Version: Version, OldHash: oldReview.ReviewHash, NewHash: newReview.ReviewHash, Conclusion: "passed"}
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

func knownRedaction(value string) bool {
	for _, candidate := range AllowedRedactionClasses() {
		if value == candidate {
			return true
		}
	}
	return false
}

func knownConsent(value string) bool {
	for _, candidate := range AllowedConsentModes() {
		if value == candidate {
			return true
		}
	}
	return false
}

func knownRetention(value string) bool {
	for _, candidate := range AllowedRetentionClasses() {
		if value == candidate {
			return true
		}
	}
	return false
}
