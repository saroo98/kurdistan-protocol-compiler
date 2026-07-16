// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package strategy defines the pure, offline permitted-fallback contract.
// It selects metadata only and performs no probing, networking, or other I/O.
package strategy

import (
	"errors"
	"fmt"
	"strings"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
)

const Version = "permitted-fallback-v1"

const (
	OutcomeSelected = "selected"
	OutcomeBlocked  = "blocked"
	ReasonSelected  = "eligible"
	ReasonNoSafe    = "no_safe_candidate"
)

const (
	maxItems           = 64
	maxIdentifierBytes = 64
	maxBindingBytes    = 256
)

type Candidate struct {
	Family               string
	RequiredCapabilities []string
	MinimumSafetyFloor   uint32
	MinimumPrivacyFloor  uint32
}

type Policy struct {
	Version             string
	ProfileID           string
	Scope               string
	EvidenceReference   string
	Generation          uint64
	Permitted           []Candidate
	MinimumSafetyFloor  uint32
	MinimumPrivacyFloor uint32
}

type Client struct {
	SupportedVersion  string
	SupportedFamilies []string
	Capabilities      []string
	SafetyFloor       uint32
	PrivacyFloor      uint32
}

type Request struct {
	Lifecycle        lifecycle.State
	Policy           Policy
	Client           Client
	ManualPreference string
}

// Result is deliberately bounded metadata. SelectedFamily is empty unless
// Outcome is OutcomeSelected.
type Result struct {
	Outcome        string
	SelectedFamily string
	Reason         string
}

// Select returns the first eligible profile-ordered family, or an explicit
// blocked result. Malformed or incompatible input returns an error and a zero
// Result. A manual preference may promote only an already-eligible family.
func Select(req Request) (Result, error) {
	if err := validateRequest(req); err != nil {
		return Result{}, err
	}
	supported := stringSet(req.Client.SupportedFamilies)
	capabilities := stringSet(req.Client.Capabilities)
	eligible := make([]string, 0, len(req.Policy.Permitted))
	for _, candidate := range req.Policy.Permitted {
		if !supported[candidate.Family] {
			continue
		}
		if req.Client.SafetyFloor < req.Policy.MinimumSafetyFloor || req.Client.SafetyFloor < candidate.MinimumSafetyFloor ||
			req.Client.PrivacyFloor < req.Policy.MinimumPrivacyFloor || req.Client.PrivacyFloor < candidate.MinimumPrivacyFloor {
			continue
		}
		if containsAll(capabilities, candidate.RequiredCapabilities) {
			eligible = append(eligible, candidate.Family)
		}
	}
	if req.ManualPreference != "" {
		for _, family := range eligible {
			if family == req.ManualPreference {
				return Result{Outcome: OutcomeSelected, SelectedFamily: family, Reason: ReasonSelected}, nil
			}
		}
		return Result{}, errors.New("strategy: manual preference is not an eligible permitted family")
	}
	if len(eligible) == 0 {
		return Result{Outcome: OutcomeBlocked, Reason: ReasonNoSafe}, nil
	}
	return Result{Outcome: OutcomeSelected, SelectedFamily: eligible[0], Reason: ReasonSelected}, nil
}

func validateRequest(req Request) error {
	if err := validateInputStrings(req); err != nil {
		return err
	}
	s := req.Lifecycle
	if s.Status != lifecycle.Admitted || s.Generation == 0 {
		return errors.New("strategy: complete admitted lifecycle state is required")
	}
	if req.Policy.Version != Version || req.Client.SupportedVersion != Version {
		return errors.New("strategy: incompatible contract version")
	}
	if req.Policy.ProfileID != s.ProfileID || req.Policy.Scope != s.Scope ||
		req.Policy.EvidenceReference != s.EvidenceReference ||
		req.Policy.Generation == 0 || req.Policy.Generation != s.Generation {
		return errors.New("strategy: policy is not bound to the admitted lifecycle state")
	}
	if req.Policy.MinimumSafetyFloor == 0 || req.Policy.MinimumPrivacyFloor == 0 || req.Client.SafetyFloor == 0 || req.Client.PrivacyFloor == 0 {
		return errors.New("strategy: safety and privacy floors must be explicit")
	}
	if len(req.Policy.Permitted) == 0 || len(req.Policy.Permitted) > maxItems {
		return errors.New("strategy: permitted family list is empty or too large")
	}
	if err := validateUniqueStrings("supported family", req.Client.SupportedFamilies, false); err != nil {
		return err
	}
	if err := validateUniqueStrings("client capability", req.Client.Capabilities, true); err != nil {
		return err
	}
	ceiling, err := carrierSafetyCeiling()
	if err != nil {
		return err
	}
	for _, family := range req.Client.SupportedFamilies {
		if !ceiling[family] {
			return errors.New("strategy: client-supported family is outside the carrier safety ceiling")
		}
	}
	seen := map[string]bool{}
	for _, c := range req.Policy.Permitted {
		if err := validateBoundedString("permitted family", c.Family, maxIdentifierBytes, false); err != nil {
			return err
		}
		if !ceiling[c.Family] {
			return errors.New("strategy: permitted family is outside the carrier safety ceiling")
		}
		if seen[c.Family] {
			return errors.New("strategy: duplicate permitted family")
		}
		seen[c.Family] = true
		if c.MinimumSafetyFloor == 0 || c.MinimumPrivacyFloor == 0 {
			return errors.New("strategy: candidate floors must be explicit")
		}
		if err := validateUniqueStrings("required capability", c.RequiredCapabilities, true); err != nil {
			return err
		}
	}
	return nil
}

func validateInputStrings(req Request) error {
	checks := []struct {
		kind     string
		value    string
		maxBytes int
		optional bool
	}{
		{"lifecycle status", string(req.Lifecycle.Status), maxIdentifierBytes, false},
		{"lifecycle profile ID", req.Lifecycle.ProfileID, maxBindingBytes, false},
		{"lifecycle scope", req.Lifecycle.Scope, maxIdentifierBytes, false},
		{"lifecycle evidence reference", req.Lifecycle.EvidenceReference, maxBindingBytes, false},
		{"policy version", req.Policy.Version, maxIdentifierBytes, false},
		{"policy profile ID", req.Policy.ProfileID, maxBindingBytes, false},
		{"policy scope", req.Policy.Scope, maxIdentifierBytes, false},
		{"policy evidence reference", req.Policy.EvidenceReference, maxBindingBytes, false},
		{"client version", req.Client.SupportedVersion, maxIdentifierBytes, false},
		{"manual preference", req.ManualPreference, maxIdentifierBytes, true},
	}
	for _, check := range checks {
		if err := validateBoundedString(check.kind, check.value, check.maxBytes, check.optional); err != nil {
			return err
		}
	}
	return nil
}

func validateBoundedString(kind, value string, maxBytes int, optional bool) error {
	if optional && value == "" {
		return nil
	}
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return fmt.Errorf("strategy: invalid %s", kind)
	}
	return nil
}

func validateUniqueStrings(kind string, values []string, allowEmptyList bool) error {
	if (!allowEmptyList && len(values) == 0) || len(values) > maxItems {
		return fmt.Errorf("strategy: %s list is empty or too large", kind)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if err := validateBoundedString(kind, value, maxIdentifierBytes, false); err != nil {
			return err
		}
		if seen[value] {
			return fmt.Errorf("strategy: invalid or duplicate %s", kind)
		}
		seen[value] = true
	}
	return nil
}

func carrierSafetyCeiling() (map[string]bool, error) {
	result := map[string]bool{}
	for _, d := range carrierreview.DefaultDescriptors() {
		if err := carrierreview.ValidateDescriptor(d); err != nil {
			return nil, fmt.Errorf("strategy: invalid carrier safety descriptor: %w", err)
		}
		if d.DefaultEligible && d.SyntheticOnly && !d.ManualReviewRequired && d.Readiness != carrierreview.ReadinessBlockedByRisk {
			result[d.Family] = true
		}
	}
	return result, nil
}

func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}
func containsAll(have map[string]bool, required []string) bool {
	for _, value := range required {
		if !have[value] {
			return false
		}
	}
	return true
}
