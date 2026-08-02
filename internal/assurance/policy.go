// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package assurance defines the fail-closed policy and evidence types used by
// CI. It contains no network or release mutation authority.
package assurance

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	ProofPolicySchema  = "kurdistan-proof-policy-v1"
	ImpactPolicySchema = "kurdistan-impact-policy-v1"
	CacheIndependent   = "CACHE_INDEPENDENT"
	CacheAllowed       = "CACHE_ALLOWED_FEEDBACK"
)

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

type ProofPolicy struct {
	Schema string  `json:"schema"`
	Proofs []Proof `json:"proofs"`
}

type Proof struct {
	ID                        string                `json:"id"`
	Commands                  [][]string            `json:"commands,omitempty"`
	CommandsByOperatingSystem map[string][][]string `json:"commandsByOperatingSystem,omitempty"`
	OperatingSystems          []string              `json:"operatingSystems"`
	CachePolicy               string                `json:"cachePolicy"`
	Deterministic             bool                  `json:"deterministic"`
	FreshnessSeconds          int64                 `json:"freshnessSeconds,omitempty"`
	InvalidatedBy             []string              `json:"invalidatedBy"`
	AuthorizedPhase           int                   `json:"authorizedPhase"`
}

func DecodeProofPolicy(reader io.Reader) (ProofPolicy, error) {
	var value ProofPolicy
	if err := decodeStrict(reader, &value); err != nil {
		return ProofPolicy{}, fmt.Errorf("decode proof policy: %w", err)
	}
	if err := value.Validate(); err != nil {
		return ProofPolicy{}, err
	}
	return value, nil
}

func (value ProofPolicy) Validate() error {
	if value.Schema != ProofPolicySchema || len(value.Proofs) == 0 || len(value.Proofs) > 64 {
		return errors.New("invalid proof policy identity or cardinality")
	}
	seen := map[string]bool{}
	for index, proof := range value.Proofs {
		if !identifierPattern.MatchString(proof.ID) || seen[proof.ID] {
			return fmt.Errorf("invalid or duplicate proof id at %d", index)
		}
		seen[proof.ID] = true
		if err := exactStrings("operating system", proof.OperatingSystems, map[string]bool{"linux": true, "windows": true, "android-emulator": true}); err != nil {
			return fmt.Errorf("proof %s: %w", proof.ID, err)
		}
		if err := validateProofCommands(proof); err != nil {
			return fmt.Errorf("proof %s: %w", proof.ID, err)
		}
		if proof.CachePolicy != CacheIndependent && proof.CachePolicy != CacheAllowed {
			return fmt.Errorf("proof %s has invalid cache policy", proof.ID)
		}
		if proof.Deterministic && proof.FreshnessSeconds != 0 {
			return fmt.Errorf("deterministic proof %s cannot expire by time", proof.ID)
		}
		if !proof.Deterministic && proof.FreshnessSeconds < 1 {
			return fmt.Errorf("freshness-limited proof %s needs a positive TTL", proof.ID)
		}
		if proof.AuthorizedPhase < 16 || proof.AuthorizedPhase > 22 {
			return fmt.Errorf("proof %s has invalid authorizing phase", proof.ID)
		}
		if err := validatePaths(proof.InvalidatedBy); err != nil {
			return fmt.Errorf("proof %s invalidation policy: %w", proof.ID, err)
		}
	}
	return nil
}

func (proof Proof) CommandsForOperatingSystem(operatingSystem string) ([][]string, error) {
	if len(proof.CommandsByOperatingSystem) == 0 {
		if len(proof.Commands) == 0 {
			return nil, errors.New("proof has no command inventory")
		}
		return proof.Commands, nil
	}
	commands, ok := proof.CommandsByOperatingSystem[operatingSystem]
	if !ok {
		return nil, fmt.Errorf("proof has no command inventory for %s", operatingSystem)
	}
	return commands, nil
}

func validateProofCommands(proof Proof) error {
	if len(proof.Commands) > 0 && len(proof.CommandsByOperatingSystem) > 0 {
		return errors.New("commands and commandsByOperatingSystem are mutually exclusive")
	}
	if len(proof.CommandsByOperatingSystem) > 0 {
		if len(proof.CommandsByOperatingSystem) != len(proof.OperatingSystems) {
			return errors.New("platform command inventory must cover every operating system exactly")
		}
		for operatingSystem := range proof.CommandsByOperatingSystem {
			if !containsString(proof.OperatingSystems, operatingSystem) {
				return fmt.Errorf("platform command inventory contains unknown operating system %q", operatingSystem)
			}
		}
		for _, operatingSystem := range proof.OperatingSystems {
			if err := validateCommandSet(proof.CommandsByOperatingSystem[operatingSystem]); err != nil {
				return fmt.Errorf("%s commands: %w", operatingSystem, err)
			}
		}
		return nil
	}
	return validateCommandSet(proof.Commands)
}

func validateCommandSet(commands [][]string) error {
	if len(commands) == 0 || len(commands) > 16 {
		return errors.New("invalid command count")
	}
	for commandIndex, command := range commands {
		if len(command) == 0 || len(command) > 32 {
			return fmt.Errorf("command %d has invalid argument count", commandIndex)
		}
		for _, argument := range command {
			if argument == "" || len(argument) > 2048 || strings.ContainsRune(argument, '\x00') {
				return errors.New("command contains an invalid argument")
			}
		}
	}
	return nil
}

type ImpactPolicy struct {
	Schema        string       `json:"schema"`
	DefaultProofs []string     `json:"defaultProofs"`
	Rules         []ImpactRule `json:"rules"`
}

type ImpactRule struct {
	Pattern string   `json:"pattern"`
	Proofs  []string `json:"proofs"`
}

func DecodeImpactPolicy(reader io.Reader) (ImpactPolicy, error) {
	var value ImpactPolicy
	if err := decodeStrict(reader, &value); err != nil {
		return ImpactPolicy{}, fmt.Errorf("decode impact policy: %w", err)
	}
	if err := value.Validate(); err != nil {
		return ImpactPolicy{}, err
	}
	return value, nil
}

func (value ImpactPolicy) Validate() error {
	if value.Schema != ImpactPolicySchema || len(value.Rules) == 0 || len(value.Rules) > 256 {
		return errors.New("invalid impact policy identity or cardinality")
	}
	if err := exactStrings("default proof", value.DefaultProofs, nil); err != nil {
		return err
	}
	seen := map[string]bool{}
	for index, rule := range value.Rules {
		if !validPattern(rule.Pattern) || seen[rule.Pattern] {
			return fmt.Errorf("invalid or duplicate impact pattern at %d", index)
		}
		seen[rule.Pattern] = true
		if err := exactStrings("impact proof", rule.Proofs, nil); err != nil {
			return fmt.Errorf("impact pattern %s: %w", rule.Pattern, err)
		}
	}
	return nil
}

func (value ImpactPolicy) ProofsForPaths(paths []string) ([]string, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return append([]string(nil), value.DefaultProofs...), nil
	}
	proofs := map[string]bool{}
	for _, raw := range paths {
		path := filepath.ToSlash(filepath.Clean(filepath.FromSlash(raw)))
		if path != raw || filepath.IsAbs(raw) || strings.HasPrefix(path, "../") {
			return nil, fmt.Errorf("invalid changed path %q", raw)
		}
		matched := false
		for _, rule := range value.Rules {
			if patternMatches(rule.Pattern, path) {
				matched = true
				for _, proof := range rule.Proofs {
					proofs[proof] = true
				}
			}
		}
		if !matched {
			for _, proof := range value.DefaultProofs {
				proofs[proof] = true
			}
		}
	}
	result := make([]string, 0, len(proofs))
	for proof := range proofs {
		result = append(result, proof)
	}
	sort.Strings(result)
	return result, nil
}

// ValidateImpactProofReferences ensures path selection can emit only leaf
// proofs defined by the authoritative proof policy. Aggregate aliases are not
// accepted because they could hide missing proof lanes.
func ValidateImpactProofReferences(impact ImpactPolicy, proofs ProofPolicy) error {
	if err := impact.Validate(); err != nil {
		return err
	}
	if err := proofs.Validate(); err != nil {
		return err
	}
	known := make(map[string]bool, len(proofs.Proofs))
	for _, proof := range proofs.Proofs {
		known[proof.ID] = true
	}
	check := func(values []string) error {
		for _, value := range values {
			if !known[value] {
				return fmt.Errorf("impact policy references unknown proof %q", value)
			}
		}
		return nil
	}
	if err := check(impact.DefaultProofs); err != nil {
		return err
	}
	for _, rule := range impact.Rules {
		if err := check(rule.Proofs); err != nil {
			return fmt.Errorf("impact pattern %s: %w", rule.Pattern, err)
		}
	}
	return nil
}

func exactStrings(name string, values []string, allowed map[string]bool) error {
	if len(values) == 0 || len(values) > 64 {
		return fmt.Errorf("%s set has invalid cardinality", name)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !identifierPattern.MatchString(value) || seen[value] || (allowed != nil && !allowed[value]) {
			return fmt.Errorf("%s set contains invalid or duplicate value %q", name, value)
		}
		seen[value] = true
	}
	return nil
}

func validatePaths(paths []string) error {
	if len(paths) == 0 || len(paths) > 256 {
		return errors.New("path set has invalid cardinality")
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !validPattern(path) || seen[path] {
			return fmt.Errorf("invalid or duplicate path %q", path)
		}
		seen[path] = true
	}
	return nil
}

func validPattern(pattern string) bool {
	if pattern == "" || len(pattern) > 256 || filepath.IsAbs(pattern) || strings.Contains(pattern, "\\") || strings.Contains(pattern, "..") {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.Contains(pattern, "*") && (!strings.HasSuffix(pattern, "/**") || strings.Count(pattern, "*") != 2) {
		return false
	}
	base := strings.TrimSuffix(pattern, "/**")
	return base != "" && filepath.ToSlash(filepath.Clean(filepath.FromSlash(base))) == base
}

func patternMatches(pattern, path string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "**")
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}
