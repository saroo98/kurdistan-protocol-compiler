// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir

import (
	"encoding/hex"
	"fmt"
)

// BuildEffectiveSecurityPolicyFromProjectionV1 recreates the existing
// transcript-bound effective policy from the product-safe projection.  The
// program ID and generation hash replace the model profile identity and hash.
func BuildEffectiveSecurityPolicyFromProjectionV1(
	programID [16]byte,
	sourceGenerationHash [32]byte,
	compilerSecurityVersion string,
	minimumRuntimeVersion string,
	security SecurityPolicy,
	clientMandatory, relayMandatory, selected []string,
) (EffectiveSecurityPolicy, error) {
	if allZeroProjectionV1(programID[:]) || allZeroProjectionV1(sourceGenerationHash[:]) || compilerSecurityVersion == "" || minimumRuntimeVersion == "" {
		return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
	}
	if err := validateSecurityPolicy(security); err != nil {
		return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
	}
	client, err := canonicalEffectiveCapabilities(clientMandatory)
	if err != nil || len(client) == 0 {
		return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
	}
	relay, err := canonicalEffectiveCapabilities(relayMandatory)
	if err != nil || len(relay) == 0 {
		return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
	}
	selection, err := canonicalEffectiveCapabilities(selected)
	if err != nil || len(selection) == 0 {
		return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
	}
	selectedSet := make(map[string]struct{}, len(selection))
	for _, capability := range selection {
		selectedSet[capability] = struct{}{}
	}
	for _, floor := range [][]string{client, relay} {
		for _, capability := range floor {
			if _, ok := selectedSet[capability]; !ok {
				return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
			}
		}
	}
	policy := EffectiveSecurityPolicy{
		ProfileID: hex.EncodeToString(programID[:]), ProfileHash: hex.EncodeToString(sourceGenerationHash[:]),
		SchemaVersion: SupportedVersion, CompilerSecurityVersion: compilerSecurityVersion, MinimumRuntimeVersion: minimumRuntimeVersion,
		SecurityVersion: security.SecurityVersion, TranscriptMode: security.TranscriptMode, KDFSuite: security.KDFSuite, AEADSuite: security.AEADSuite, MACSuite: security.MACSuite,
		NonceMode: security.NonceMode, ReplayPolicy: security.ReplayPolicy, ReplayWindowSize: security.ReplayWindowSize, DowngradePolicy: security.DowngradePolicy,
		CapabilityNegotiationPolicy: security.CapabilityNegotiationPolicy, ProfileCompatibilityPolicy: security.ProfileCompatibilityPolicy, KeyRotationPolicy: security.KeyRotationPolicy,
		ConfigValidationPolicy: security.ConfigValidationPolicy, SecureEnvelopeMode: security.SecureEnvelopeMode, MaxSessionMessages: security.MaxSessionMessages,
		MaxKeyLifetimeMessages: security.MaxKeyLifetimeMessages, ClientMandatoryCapabilities: client, ServerMandatoryCapabilities: relay, SelectedCapabilities: selection,
	}
	var errHash error
	policy.validationHash, errHash = effectivePolicyHash(policy)
	if errHash != nil || ValidateEffectiveSecurityPolicy(policy) != nil {
		return EffectiveSecurityPolicy{}, fmt.Errorf("effective security projection is invalid")
	}
	return policy.Clone(), nil
}

func allZeroProjectionV1(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
