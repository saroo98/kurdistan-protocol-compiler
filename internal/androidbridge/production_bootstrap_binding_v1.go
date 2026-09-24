// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"errors"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/selfhost"
	"reflect"
	"slices"
	"time"
	"unsafe"
)

type ProductionBootstrapFactsV1 struct {
	Generation                         uint64
	PlanDigest                         [32]byte
	EffectiveMTU                       uint16
	SignedRetryMaximum                 uint8
	EffectiveAutomaticReconnectMaximum uint8
}

// BootstrapCapacityInvariantFailureV1 is private bootstrap control signaling,
// not a canonical ErrorCode/P1 enum member. C/JNI must preserve it; the Java
// boundary reports canonical INTERNAL_FAILURE and permanently retains its guard.
const BootstrapCapacityInvariantFailureV1 int32 = -6401

func bootstrapObservedCapacityV1(actual, reserved uint64) int32 {
	if actual > reserved {
		return BootstrapCapacityInvariantFailureV1
	}
	return 0
}

func bootstrapObservedPlanCapacityV1(plan *sessionplan.PlanV2, reserved uint64) int32 {
	return bootstrapObservedCapacityV1(productionAdmissionBackingV1(reflect.ValueOf(*plan)), reserved)
}

// ReadProductionRuntimeBootstrapBindingV1 returns paired role availability, not
// a session capability. All proof/projected owners are retired before publication.
func ReadProductionRuntimeBootstrapBindingV1(input MaintenanceCurrentInputV1, settingsWire []byte,
	environment productionCurrentEnvironmentV1, now time.Time, limits selfhost.LiveMaintenanceLimits,
	activeSelectorsOutput, disconnectedSelectorsOutput []byte) (facts ProductionBootstrapFactsV1, activeWritten, disconnectedWritten int, status int32) {
	if environment == nil {
		return facts, 0, 0, 2
	}
	if _, m := maintenanceBridgeReservation(input); m != MaintenanceSuccess {
		return facts, 0, 0, productionMaintenanceStatusV1(m)
	}
	if len(settingsWire) == 0 {
		return facts, 0, 0, 2
	}
	if len(settingsWire) > productionSettingsMaxBytesV1 || len(activeSelectorsOutput) < 512 || len(disconnectedSelectorsOutput) < 512 {
		return facts, 0, 0, 4
	}
	outputs := [][]byte{activeSelectorsOutput[:512], disconnectedSelectorsOutput[:512]}
	inputs := productionInputPartsV1(input)
	for i, o := range outputs {
		if bootstrapSpansOverlapV1(o, settingsWire) {
			return facts, 0, 0, 2
		}
		for _, p := range inputs {
			if bootstrapSpansOverlapV1(o, p) {
				return facts, 0, 0, 2
			}
		}
		for j := 0; j < i; j++ {
			if bootstrapSpansOverlapV1(o, outputs[j]) {
				return facts, 0, 0, 2
			}
		}
	}
	if limits.OwnedBudgetBytes == 0 || limits.OwnedBudgetBytes > productionBudgetMaximumOwnedV1 {
		return facts, 0, 0, 5
	}
	bridge, ok := maintenanceBridgeReservationLedger()
	if !ok {
		return facts, 0, 0, 5
	}
	// Call-scoped caller and Go-copy overlap plus fixed C/JNI facts/metadata,
	// Three paired selector stages (Java/cmd/helper). Settings
	// scanner aliases its input, with bounded fixed holders (no settings clone).
	inputBytes := uint64(len(settingsWire))
	for _, p := range inputs {
		inputBytes += uint64(len(p))
	}
	fixed := 2*inputBytes + 2*44 + 8 + 8 + 6*512 + bootstrapBoundaryHoldersV1() +
		2*uint64(unsafe.Sizeof(productionSettingsV1{})) + uint64(unsafe.Sizeof(productionSettingsScannerV1{})) +
		uint64(unsafe.Sizeof(productionOpeningInputsV1{})) + uint64(unsafe.Sizeof(ProductionBootstrapFactsV1{})) +
		2*uint64(unsafe.Sizeof(productionVerifiedArgumentsV1{}))
	budget := bootstrapLocalBudgetV1{capacity: limits.OwnedBudgetBytes}
	if !budget.set(fixed) {
		return facts, 0, 0, 5
	}
	settings, s := decodeProductionSettingsV1(settingsWire)
	if s != 0 {
		return facts, 0, 0, int32(s)
	}
	decodeBytes := maintenanceMaxV1(bridge.VerifyDecode, bridge.IngressFile, bridge.IngressURI, bridge.IngressQR, bridge.CredentialsRequest, bridge.CredentialsPrivate, bridge.CredentialsCheck, bridge.CredentialsClone, bridge.ActivationRecord)
	if !budget.set(fixed + decodeBytes) {
		return facts, 0, 0, 5
	}
	var decoded productionOpeningInputsV1
	defer decoded.destroyV1()
	var m MaintenanceResultV1
	decoded.artifact, decoded.credentials, m = decodeMaintenanceCurrentIngressV1(input, limits)
	if m != MaintenanceSuccess {
		return facts, 0, 0, productionMaintenanceStatusV1(m)
	}
	var err error
	decoded.record, err = DecodeActivationRecord(input.ActivationRecord)
	if err != nil {
		return facts, 0, 0, 3
	}
	retained := productionAdmissionBackingV1(reflect.ValueOf(decoded)) + uint64(unsafe.Sizeof(RecipientCredentials{}))
	for _, leaf := range [][]byte{decoded.credentials.Request.RecipientPublic, decoded.credentials.Request.ClientAuthPublic, decoded.credentials.Request.Nonce, decoded.credentials.Request.Signature, decoded.credentials.Private.RecipientPrivate, decoded.credentials.Private.ClientAuthSeed} {
		if len(leaf) > 0 {
			retained += 2*uint64(len(leaf)) + 8
		}
	}
	if !budget.set(fixed + retained) {
		return facts, 0, 0, 5
	}
	if now.IsZero() || now.Unix() <= 0 {
		return facts, 0, 0, 21
	}
	residual := budget.capacity - budget.owned
	if residual == 0 {
		return facts, 0, 0, 5
	}
	limits.OwnedBudgetBytes = residual
	current, err := environment.VerifyProductionCurrentAt(decoded.artifact, envelope.ArtifactDeviceRecipient, decoded.record.State, decoded.credentials.Clone(), now, limits)
	if current != nil {
		defer current.Destroy()
	}
	if err != nil {
		return facts, 0, 0, productionMaintenanceStatusV1(maintenanceResultFromError(err))
	}
	if current == nil {
		return facts, 0, 0, 18
	}
	bounds, err := current.BoundsV1()
	if err == nil && bootstrapObservedCapacityV1(bounds.PeakReservedBytes, residual) != 0 {
		return facts, 0, 0, BootstrapCapacityInvariantFailureV1
	}
	if err != nil || bounds.BudgetBytes != residual || bounds.RetainedBytes == 0 || bounds.RetainedBytes > bounds.PeakReservedBytes || bounds.PeakReservedBytes > residual {
		return facts, 0, 0, 18
	}
	// Same admitted projection/Validate construction envelope used by the live
	// admission prefix, without charging its nonexistent parent/resources.
	// Catalogue encoders execute sequentially. One <=512 encoder and one
	// <=17-ID set are live; reserving both role sets is a conservative bound.
	selectorScratch := uint64(512+2*17*(2*65+8)) + 2*uint64(unsafe.Sizeof(productionSelectorSetV1{}))
	calculation, ok := sessionplan.AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes)
	if !ok {
		return facts, 0, 0, 5
	}
	projectionBytes := calculation.SuffixBytes + 2*uint64(unsafe.Sizeof(productionProjectionV1{}))
	if !budget.set(fixed + retained + bounds.RetainedBytes + projectionBytes + selectorScratch) {
		return facts, 0, 0, 5
	}
	var projection productionProjectionV1
	defer projection.Destroy()
	var active, disconnected [512]byte
	defer clear(active[:])
	defer clear(disconnected[:])
	var result ProductionBootstrapFactsV1
	var semantic int32
	err = current.WithVerifiedV1(func(v profile.OfflineVerifiedArtifact, state lifecycle.VerifiedState, policy runtimepolicy.PolicyV2, deadline time.Time) error {
		if semantic = validateProductionCurrentBindingV1(&decoded, v, state, policy); semantic != 0 {
			return errors.New("bootstrap binding rejected")
		}
		projection, s = projectProductionSettingsV1(settings, sessionplan.RequestV2{Profile: v.Profile, ActivationReceipt: state.Receipt, RuntimePolicy: policy}, now)
		if s != 0 {
			semantic = int32(s)
			return errors.New("bootstrap projection rejected")
		}
		if semantic = bootstrapObservedPlanCapacityV1(&projection.plan, calculation.PlanBytes); semantic != 0 {
			return errors.New("bootstrap plan reservation exceeded")
		}
		if err := sessionplan.ValidateV2At(projection.plan, now); err != nil {
			return err
		}
		activeWritten, s = bootstrapSelectorsV1(projection, v.Profile.StrategyIDs, policy, 2, active[:])
		if s != 0 {
			semantic = int32(s)
			return errors.New("active availability rejected")
		}
		disconnectedWritten, s = bootstrapSelectorsV1(projection, v.Profile.StrategyIDs, policy, 1, disconnected[:])
		if s != 0 {
			semantic = int32(s)
			return errors.New("disconnected availability rejected")
		}
		result = ProductionBootstrapFactsV1{projection.plan.ProfileGeneration, projection.plan.Digest, projection.effectiveMTU, projection.signedReconnectMax, projection.effectiveAutomaticReconnectMax}
		return nil
	})
	if err != nil {
		if semantic == 0 {
			semantic = 18
		}
		return facts, 0, 0, semantic
	}
	projection.Destroy()
	current.Destroy()
	decoded.destroyV1()
	copy(activeSelectorsOutput, active[:activeWritten])
	copy(disconnectedSelectorsOutput, disconnected[:disconnectedWritten])
	return result, activeWritten, disconnectedWritten, 0
}

type bootstrapLocalBudgetV1 struct{ capacity, owned uint64 }

func (b *bootstrapLocalBudgetV1) set(bytes uint64) bool {
	if bytes > b.capacity {
		return false
	}
	b.owned = bytes
	return true
}

func bootstrapBoundaryHoldersV1() uint64 {
	// Maximum production C/JNI local arrays:9 jobjects,9 pointer/u32 spans;
	// Go private bridge:5 inputs,2 metadata,5 outputs,10 combined spans,5 byte slices.
	// Go helper:2 output slices and4 input slices. All targets are qualified64-bit.
	return 9*8 + 9*16 + (5+2+5+10)*16 + 5*24 + (2+4)*24
}

func bootstrapSpansOverlapV1(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	if x <= y {
		return y-x < uintptr(len(a))
	}
	return x-y < uintptr(len(b))
}

func validateProductionCurrentBindingV1(decoded *productionOpeningInputsV1, v profile.OfflineVerifiedArtifact, state lifecycle.VerifiedState, policy runtimepolicy.PolicyV2) int32 {
	if state != decoded.record.State || !runtimeRecordMatches(VerifyPreview{Verified: v}, decoded.record) {
		return 3
	}
	if !runtimeRecipientMatchesPolicy(decoded.credentials, policy) {
		return 23
	}
	return 0
}

func bootstrapSelectorsV1(p productionProjectionV1, signed []string, policy runtimepolicy.PolicyV2, mode uint8, output []byte) (int, productionStatusV1) {
	set := productionSelectorSetV1{profileGeneration: p.plan.ProfileGeneration, planDigest: p.plan.Digest, strategyCount: 1}
	defer func() {
		for _, id := range set.strategyIDs {
			clear(id)
		}
		for _, id := range set.probeIDs {
			clear(id)
		}
	}()
	strategy, ok := productionStrategyCatalogV1(p.plan.StrategyID, signed)
	if !ok {
		return 0, productionInternalFailureV1
	}
	set.strategyIDs[0] = strategy
	capability := productionCapabilityProbeActiveV1
	if mode == 1 {
		capability = productionCapabilityProbeDisconnectedV1
	}
	if p.effectiveCapabilityMask&capability != 0 && policy.Services != nil && policy.Services.Probes != nil {
		for _, target := range policy.Services.Probes.Targets {
			id, ok := productionProbeCatalogV1(target.ID, policy.Services.Probes.Targets, mode)
			if !ok {
				continue
			}
			if set.probeCount >= 16 {
				clear(id)
				return 0, productionSizeLimitV1
			}
			set.probeIDs[set.probeCount] = id
			set.probeCount++
		}
	}
	ids := set.probeIDs[:set.probeCount]
	slices.SortFunc(ids, func(a, b []byte) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return bytes.Compare(a, b)
	})
	return encodeProductionSelectorsV1(set, output)
}
