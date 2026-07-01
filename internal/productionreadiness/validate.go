// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package productionreadiness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrInvalidReview   = errors.New("invalid production readiness review")
	ErrUnsafeMetadata  = errors.New("unsafe production readiness metadata")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing production readiness fixture")
)

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_capture", "pcap",
	"endpoint", "resolver", "dns_query", "domain", "url", "sni", "host_header", "client_ip", "server_ip",
	"secret", "key", "nonce", "auth_tag", "proof_material", "ciphertext", "plaintext", "private_key",
	"deployment_token", "cloud_credential", "field_ready", "guaranteed_bypass", "undetectable",
}

func ValidateReview(review ProductionReadinessReview) error {
	if review.Version != Version || review.ReviewID == "" || len(review.Items) == 0 || review.PayloadLogged || review.SecretLogged {
		return ErrInvalidReview
	}
	if len(review.Dependencies) < 10 || len(review.Boundaries) < 5 || len(review.Contracts) < 4 {
		return ErrInvalidReview
	}
	seen := map[string]bool{}
	for _, item := range review.Items {
		if item.Name == "" || item.Layer == "" || item.Status == "" || seen[item.Name] {
			return ErrInvalidReview
		}
		seen[item.Name] = true
	}
	for _, boundary := range review.Boundaries {
		if boundary.Name == "" || boundary.Policy == "" || boundary.Allowed || boundary.Conclusion != "passed" || boundary.PayloadLogged || boundary.SecretLogged {
			return ErrInvalidReview
		}
	}
	for _, contract := range review.Contracts {
		if contract.Milestone == "" || contract.Name == "" || contract.AllowedScope == "" || len(contract.RequiredGates) == 0 || len(contract.ForbiddenScopes) == 0 {
			return ErrInvalidReview
		}
	}
	if review.Misuse.Conclusion != "passed" || review.Parity.Conclusion != "passed" {
		return ErrInvalidReview
	}
	if review.ReviewHash != "" && review.ReviewHash != HashValue(reviewHashInput(review)) {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidReview)
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
		scanValue(decoded, "", &findings)
	}
	findings = uniqueStrings(findings)
	if len(findings) > 0 {
		return fmt.Errorf("%w: %s", ErrUnsafeMetadata, strings.Join(findings, ","))
	}
	return nil
}

func scanValue(value any, parentKey string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := normalize(key)
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			if lower == "payload_logged" || lower == "secret_logged" || lower == "forbidden" || lower == "forbidden_scopes" || lower == "remaining_risk" || lower == "summary" {
				scanValue(child, lower, findings)
				continue
			}
			for _, marker := range forbiddenMarkers {
				if lower == marker || strings.Contains(lower, marker) {
					*findings = append(*findings, marker)
				}
			}
			scanValue(child, lower, findings)
		}
	case []any:
		for _, child := range v {
			scanValue(child, parentKey, findings)
		}
	case string:
		if parentKey == "forbidden" || parentKey == "forbidden_scopes" || parentKey == "remaining_risk" || parentKey == "summary" || strings.Contains(parentKey, "evidence") {
			return
		}
		lower := normalize(v)
		for _, marker := range forbiddenMarkers {
			if marker == "payload" || marker == "key" || marker == "secret" || marker == "endpoint" || marker == "resolver" {
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

func LoadReview(path string) (ProductionReadinessReview, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProductionReadinessReview{}, err
	}
	var review ProductionReadinessReview
	if err := json.Unmarshal(raw, &review); err != nil {
		return ProductionReadinessReview{}, err
	}
	return review, ValidateReview(review)
}

func CompareReviews(oldReview, newReview ProductionReadinessReview) ReadinessComparisonReport {
	report := ReadinessComparisonReport{Version: Version, OldHash: oldReview.ReviewHash, NewHash: newReview.ReviewHash, Conclusion: "passed"}
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
