// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

const PolicyInventorySchema = "kurdistan-proof-inventory-v1"

type PolicyInventory struct {
	Schema       string      `json:"schema"`
	PolicySHA256 string      `json:"policySha256"`
	Lanes        []ProofLane `json:"lanes"`
}

type ProofLane struct {
	ProofID          string `json:"proofId"`
	OperatingSystem  string `json:"operatingSystem"`
	CommandsSHA256   string `json:"commandsSha256"`
	CachePolicy      string `json:"cachePolicy"`
	Deterministic    bool   `json:"deterministic"`
	FreshnessSeconds int64  `json:"freshnessSeconds,omitempty"`
	AuthorizedPhase  int    `json:"authorizedPhase"`
}

func DecodePolicyInventory(reader io.Reader) (PolicyInventory, error) {
	var value PolicyInventory
	if err := decodeStrict(reader, &value); err != nil {
		return PolicyInventory{}, fmt.Errorf("decode proof inventory: %w", err)
	}
	if err := value.Validate(); err != nil {
		return PolicyInventory{}, err
	}
	return value, nil
}

func BuildPolicyInventory(policy ProofPolicy, policySHA256 string) (PolicyInventory, error) {
	if err := policy.Validate(); err != nil {
		return PolicyInventory{}, err
	}
	if !sha256Pattern.MatchString(policySHA256) {
		return PolicyInventory{}, errors.New("invalid proof policy digest")
	}
	value := PolicyInventory{Schema: PolicyInventorySchema, PolicySHA256: policySHA256}
	for _, proof := range policy.Proofs {
		for _, operatingSystem := range proof.OperatingSystems {
			commands, err := proof.CommandsForOperatingSystem(operatingSystem)
			if err != nil {
				return PolicyInventory{}, err
			}
			encoded, err := json.Marshal(commands)
			if err != nil {
				return PolicyInventory{}, err
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
			value.Lanes = append(value.Lanes, ProofLane{
				ProofID:          proof.ID,
				OperatingSystem:  operatingSystem,
				CommandsSHA256:   digest,
				CachePolicy:      proof.CachePolicy,
				Deterministic:    proof.Deterministic,
				FreshnessSeconds: proof.FreshnessSeconds,
				AuthorizedPhase:  proof.AuthorizedPhase,
			})
		}
	}
	sort.Slice(value.Lanes, func(left, right int) bool {
		if value.Lanes[left].ProofID != value.Lanes[right].ProofID {
			return value.Lanes[left].ProofID < value.Lanes[right].ProofID
		}
		return value.Lanes[left].OperatingSystem < value.Lanes[right].OperatingSystem
	})
	if err := value.Validate(); err != nil {
		return PolicyInventory{}, err
	}
	return value, nil
}

func (value PolicyInventory) Validate() error {
	if value.Schema != PolicyInventorySchema || !sha256Pattern.MatchString(value.PolicySHA256) || len(value.Lanes) == 0 || len(value.Lanes) > 256 {
		return errors.New("invalid proof inventory identity or cardinality")
	}
	last := ""
	for _, lane := range value.Lanes {
		key := lane.ProofID + "\x00" + lane.OperatingSystem
		if !identifierPattern.MatchString(lane.ProofID) || lane.OperatingSystem == "" || key <= last || !sha256Pattern.MatchString(lane.CommandsSHA256) || (lane.CachePolicy != CacheIndependent && lane.CachePolicy != CacheAllowed) || lane.AuthorizedPhase < 16 || lane.AuthorizedPhase > 22 {
			return fmt.Errorf("invalid, duplicate, or unordered proof lane %q", key)
		}
		if lane.Deterministic && lane.FreshnessSeconds != 0 {
			return fmt.Errorf("deterministic proof lane %q cannot expire", key)
		}
		if !lane.Deterministic && lane.FreshnessSeconds < 1 {
			return fmt.Errorf("freshness-limited proof lane %q needs a TTL", key)
		}
		last = key
	}
	return nil
}
