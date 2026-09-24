// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"encoding/binary"
	"errors"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/selfhost"
	"reflect"
	"time"
	"unsafe"
)

// DecodeLegacyBootstrapPolicyV1 reuses the historical canonical KRS1 decoder.
// The two one-byte sentinel rows are syntax, not authority material.
func DecodeLegacyBootstrapPolicyV1(encoded []byte) (RuntimePolicyRequest, error) {
	if len(encoded) < 28 || len(encoded) > 16777 || binary.BigEndian.Uint32(encoded[18:22]) != 1 || binary.BigEndian.Uint32(encoded[22:26]) != 1 || encoded[len(encoded)-2] != 1 || encoded[len(encoded)-1] != 1 {
		return RuntimePolicyRequest{}, errors.New("androidbridge: invalid bootstrap policy")
	}
	request, err := DecodeRuntimeOpenRequest(encoded)
	defer clear(request.VerifyRequest)
	defer clear(request.ActivationRecord)
	if err != nil {
		return RuntimePolicyRequest{}, err
	}
	return request.Policy, nil
}

type RuntimeBootstrapBindingV1 struct {
	Generation         uint64
	PlanDigest         [32]byte
	SignedRetryMaximum uint8
}

// ReadLegacyRuntimeBootstrapBindingV1 computes the historical KRS1 binding.
// It never creates a runtime context, registry entry, factory or network owner.
func ReadLegacyRuntimeBootstrapBindingV1(input MaintenanceCurrentInputV1, policy RuntimePolicyRequest,
	environment RecipientVerificationEnvironmentAt, now time.Time, limits selfhost.LiveMaintenanceLimits) (RuntimeBootstrapBindingV1, ErrorCode) {
	if environment == nil || now.IsZero() {
		return RuntimeBootstrapBindingV1{}, CodeTrustUnavailable
	}
	if _, code := maintenanceBridgeReservation(input); code != MaintenanceSuccess {
		if code == MaintenanceSizeLimit {
			return RuntimeBootstrapBindingV1{}, CodeSizeLimit
		}
		return RuntimeBootstrapBindingV1{}, CodeInvalidArgument
	}
	if limits.OwnedBudgetBytes == 0 || limits.OwnedBudgetBytes > productionBudgetMaximumOwnedV1 {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	bridge, ok := maintenanceBridgeReservationLedger()
	if !ok {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	inputBytes := uint64(16777)
	for _, p := range productionInputPartsV1(input) {
		inputBytes += uint64(len(p))
	}
	fixed := 2*inputBytes + 2*41 + bootstrapBoundaryHoldersV1() + 16777 + 64*16 +
		uint64(unsafe.Sizeof(RuntimePolicyRequest{})) + 2*uint64(unsafe.Sizeof(RuntimeBootstrapBindingV1{})) +
		uint64(unsafe.Sizeof(legacyBootstrapCalculationV1{})) + 2*uint64(unsafe.Sizeof(RecipientCredentials{}))
	decodeBytes := maintenanceMaxV1(bridge.VerifyDecode, bridge.IngressFile, bridge.IngressURI, bridge.IngressQR, bridge.CredentialsRequest, bridge.CredentialsPrivate, bridge.CredentialsCheck, bridge.CredentialsClone, bridge.ActivationRecord)
	budget := bootstrapLocalBudgetV1{capacity: limits.OwnedBudgetBytes}
	if !budget.set(fixed + decodeBytes) {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	artifact, credentials, m := decodeMaintenanceCurrentIngressV1(input, limits)
	defer clear(artifact)
	defer credentials.Destroy()
	if m != MaintenanceSuccess {
		return RuntimeBootstrapBindingV1{}, legacyBootstrapMaintenanceStatusV1(m)
	}
	retained := uint64(cap(artifact)) + productionAdmissionBackingV1(reflect.ValueOf(credentials))
	for _, leaf := range [][]byte{credentials.Request.RecipientPublic, credentials.Request.ClientAuthPublic, credentials.Request.Nonce, credentials.Request.Signature, credentials.Private.RecipientPrivate, credentials.Private.ClientAuthSeed} {
		if len(leaf) > 0 {
			retained += 2*uint64(len(leaf)) + 8
		}
	}
	if !budget.set(fixed + retained) {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	residual := budget.capacity - budget.owned
	if residual == 0 {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	limits.OwnedBudgetBytes = residual
	verified, bounds, err := environment.VerifyWithRecipientAt(artifact, envelope.ArtifactDeviceRecipient, credentials.Clone(), now, limits)
	defer destroyMaintenanceVerifiedV1(&verified)
	if err != nil {
		return RuntimeBootstrapBindingV1{}, legacyBootstrapMaintenanceStatusV1(maintenanceResultFromError(err))
	}
	if bootstrapObservedCapacityV1(bounds.PeakReservedBytes, residual) != 0 {
		return RuntimeBootstrapBindingV1{}, ErrorCode(BootstrapCapacityInvariantFailureV1)
	}
	if bounds.BudgetBytes != residual || bounds.RetainedBytes == 0 || bounds.RetainedBytes > bounds.PeakReservedBytes || bounds.PeakReservedBytes > residual {
		return RuntimeBootstrapBindingV1{}, CodeInternalFailure
	}
	calculation, ok := sessionplan.AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes)
	if !ok {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	// Strict policy returned by DecodeV2At remains an outer Build request owner.
	// ActivationRecord's bounded decoder/returned owner remains charged through
	// record equality and the suffix; only one decoder stage executes at a time.
	suffixBytes := calculation.PolicyBytes + calculation.SuffixBytes
	if !budget.set(fixed + retained + bounds.RetainedBytes + decodeBytes + suffixBytes) {
		return RuntimeBootstrapBindingV1{}, CodeResourceLimit
	}
	preview := VerifyPreview{Verified: verified, recipient: &credentials}
	verified = profile.OfflineVerifiedArtifact{}
	calculated, code := calculateLegacyBootstrapSuffixV1(RuntimeOpenRequestV2{input.VerifyRequest, input.ActivationRecord, input.RecipientRequest, input.RecipientPrivate, policy}, preview, now)
	if code != CodeOK {
		return RuntimeBootstrapBindingV1{}, code
	}
	defer calculated.destroy()
	if status := bootstrapObservedPlanCapacityV1(&calculated.plan, calculation.PlanBytes); status != 0 {
		return RuntimeBootstrapBindingV1{}, ErrorCode(status)
	}
	return RuntimeBootstrapBindingV1{calculated.plan.ProfileGeneration, calculated.plan.Digest, calculated.plan.MaxReconnectAttempts}, CodeOK
}

type legacyBootstrapCalculationV1 struct {
	preview  VerifyPreview
	plan     sessionplan.PlanV2
	fallback uint8
}

func (c *legacyBootstrapCalculationV1) destroy() {
	c.preview.Destroy()
	c.plan.Destroy()
	*c = legacyBootstrapCalculationV1{}
}

// Shared prefix ends before any context/session/registry allocation. Only the
// existing live opener moves the plan and credentials out of this owning value.
func calculateLegacyBootstrapV1(request RuntimeOpenRequestV2, environment RecipientVerificationEnvironment, now time.Time) (legacyBootstrapCalculationV1, ErrorCode) {
	preview, code := VerifyAndPreviewWithRecipient(request.VerifyRequest, request.RecipientRequest, request.RecipientPrivate, environment)
	if code != CodeOK {
		return legacyBootstrapCalculationV1{}, code
	}
	return calculateLegacyBootstrapSuffixV1(request, preview, now)
}

func calculateLegacyBootstrapSuffixV1(request RuntimeOpenRequestV2, preview VerifyPreview, now time.Time) (legacyBootstrapCalculationV1, ErrorCode) {
	transferred := false
	defer func() {
		if !transferred {
			preview.Destroy()
		}
	}()
	record, err := DecodeActivationRecord(request.ActivationRecord)
	defer destroyMaintenanceActivationRecordV1(&record)
	if err != nil || !runtimeRecordMatches(preview, record) || preview.recipient == nil {
		return legacyBootstrapCalculationV1{}, CodePolicyRejected
	}
	policy, err := runtimepolicy.DecodeV2At(record.Profile.Policy, now)
	defer destroyLegacyBootstrapPolicyV1(&policy)
	if err != nil || !runtimeRecipientMatchesPolicy(*preview.recipient, policy) {
		return legacyBootstrapCalculationV1{}, CodePolicyRejected
	}
	narrowing, err := runtimeNarrowingV2(request.Policy)
	defer func() {
		for _, dns := range narrowing.DNSServers {
			clear(dns)
		}
	}()
	if err != nil {
		return legacyBootstrapCalculationV1{}, CodePolicyRejected
	}
	plan, err := sessionplan.BuildV2At(sessionplan.RequestV2{Profile: record.Profile, ActivationReceipt: record.State.Receipt, RuntimePolicy: policy, Requested: narrowing}, now)
	if err != nil {
		plan.Destroy()
		return legacyBootstrapCalculationV1{}, CodePolicyRejected
	}
	transferred = true
	return legacyBootstrapCalculationV1{preview, plan, runtimeFallbackAttemptsV2(plan, policy)}, CodeOK
}

func legacyBootstrapMaintenanceStatusV1(status MaintenanceResultV1) ErrorCode {
	switch status {
	case MaintenanceSuccess:
		return CodeOK
	case MaintenanceInvalidRequest:
		return CodeInvalidArgument
	case MaintenanceSizeLimit:
		return CodeSizeLimit
	case MaintenanceResourceLimit:
		return CodeResourceLimit
	case MaintenanceInvalidState, MaintenanceNotAdmitted, MaintenanceRateLimited, MaintenanceCancelled, MaintenanceTimeout, MaintenanceNetworkUnavailable, MaintenanceDestinationDenied, MaintenanceTLSTrustUnavailable, MaintenanceTLSRejected, MaintenanceSignatureInvalid, MaintenanceProfileMismatch, MaintenanceRootRotationRejected, MaintenanceWrongRecipient, MaintenanceRollback, MaintenanceExpired, MaintenanceRevoked, MaintenanceIncompatible:
		return CodeVerificationRejected
	default:
		return CodeInternalFailure
	}
}

func destroyLegacyBootstrapPolicyV1(p *runtimepolicy.PolicyV2) {
	p.Destroy()
}
