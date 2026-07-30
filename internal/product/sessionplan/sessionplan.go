// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package sessionplan creates the immutable authority boundary for live
// transport execution. It performs no I/O and never interprets relay endpoint
// references. Callers must present the complete inputs needed to recompute both
// strategy selection and relay admission.
package sessionplan

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"

	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

const Version = "session-plan-v1"

const (
	minFrameBytes    = 1024
	maxFrameBytes    = 1 << 20
	maxDialMillis    = 30_000
	maxReferenceSize = 256
)

var (
	ErrInvalid      = errors.New("sessionplan: invalid request")
	ErrStrategy     = errors.New("sessionplan: strategy proof rejected")
	ErrRelay        = errors.New("sessionplan: relay admission proof rejected")
	ErrDescriptor   = errors.New("sessionplan: descriptor not admitted")
	ErrInconsistent = errors.New("sessionplan: inconsistent authority")
)

type Request struct {
	StrategyRequest  strategy.Request
	ClaimedStrategy  strategy.Result
	RelayRequest     relaydescriptor.Request
	ClaimedAdmission relaydescriptor.Admission
	DescriptorID     string
	DialTimeoutMs    uint32
	MaxFrameBytes    uint32
}

// Plan contains only immutable, bounded execution authority. EndpointReference
// remains opaque until a separately reviewed carrier resolver consumes it.
type Plan struct {
	Version           string
	ProfileID         string
	Scope             string
	EvidenceReference string
	Generation        uint64
	ClientID          string
	StrategyFamily    string
	CarrierFamily     string
	LoopbackOnly      bool
	DescriptorID      string
	EndpointReference string
	DialTimeoutMs     uint32
	MaxFrameBytes     uint32
	Digest            [32]byte
}

func Build(req Request) (Plan, error) {
	if req.DialTimeoutMs == 0 || req.DialTimeoutMs > maxDialMillis ||
		req.MaxFrameBytes < minFrameBytes || req.MaxFrameBytes > maxFrameBytes ||
		!bounded(req.DescriptorID, maxReferenceSize) {
		return Plan{}, ErrInvalid
	}

	selected, err := strategy.Select(req.StrategyRequest)
	if err != nil || !reflect.DeepEqual(selected, req.ClaimedStrategy) ||
		selected.Outcome != strategy.OutcomeSelected {
		return Plan{}, ErrStrategy
	}
	if !reflect.DeepEqual(req.RelayRequest.StrategyRequest, req.StrategyRequest) ||
		!reflect.DeepEqual(req.RelayRequest.ClaimedResult, selected) {
		return Plan{}, ErrInconsistent
	}

	admitted, err := relaydescriptor.Admit(req.RelayRequest)
	if err != nil || !reflect.DeepEqual(admitted, req.ClaimedAdmission) {
		return Plan{}, ErrRelay
	}
	if admitted.SelectedFamily != selected.SelectedFamily ||
		admitted.ProfileID != req.StrategyRequest.Lifecycle.ProfileID ||
		admitted.Scope != req.StrategyRequest.Lifecycle.Scope ||
		admitted.EvidenceReference != req.StrategyRequest.Lifecycle.EvidenceReference ||
		admitted.Generation != req.StrategyRequest.Lifecycle.Generation {
		return Plan{}, ErrInconsistent
	}
	carrierAuthority, err := livecarrier.Resolve(selected.SelectedFamily)
	if err != nil || carrierAuthority.Version != livecarrier.Version ||
		carrierAuthority.StrategyFamily != selected.SelectedFamily {
		return Plan{}, ErrStrategy
	}

	var chosen relaydescriptor.AdmittedDescriptor
	found := false
	for _, descriptor := range admitted.Descriptors {
		if descriptor.DescriptorID == req.DescriptorID {
			if found {
				return Plan{}, ErrDescriptor
			}
			chosen = descriptor
			found = true
		}
	}
	if !found || !bounded(chosen.EndpointReference, maxReferenceSize) {
		return Plan{}, ErrDescriptor
	}

	plan := Plan{
		Version:           Version,
		ProfileID:         admitted.ProfileID,
		Scope:             admitted.Scope,
		EvidenceReference: admitted.EvidenceReference,
		Generation:        admitted.Generation,
		ClientID:          admitted.ClientID,
		StrategyFamily:    admitted.SelectedFamily,
		CarrierFamily:     carrierAuthority.ImplementationFamily,
		LoopbackOnly:      carrierAuthority.LoopbackConformanceOnly,
		DescriptorID:      chosen.DescriptorID,
		EndpointReference: chosen.EndpointReference,
		DialTimeoutMs:     req.DialTimeoutMs,
		MaxFrameBytes:     req.MaxFrameBytes,
	}
	plan.Digest = digest(plan)
	return plan, nil
}

// Validate rejects any plan that was modified after Build or whose carrier
// authority no longer matches the closed live-carrier registry.
func Validate(plan Plan) error {
	if plan.Version != Version ||
		!bounded(plan.ProfileID, maxReferenceSize) ||
		!bounded(plan.Scope, maxReferenceSize) ||
		!bounded(plan.EvidenceReference, maxReferenceSize) ||
		plan.Generation == 0 ||
		!bounded(plan.ClientID, maxReferenceSize) ||
		!bounded(plan.StrategyFamily, maxReferenceSize) ||
		!bounded(plan.CarrierFamily, maxReferenceSize) ||
		!bounded(plan.DescriptorID, maxReferenceSize) ||
		!bounded(plan.EndpointReference, maxReferenceSize) ||
		plan.DialTimeoutMs == 0 || plan.DialTimeoutMs > maxDialMillis ||
		plan.MaxFrameBytes < minFrameBytes || plan.MaxFrameBytes > maxFrameBytes ||
		plan.Digest == ([32]byte{}) || plan.Digest != digest(plan) {
		return ErrInvalid
	}
	authority, err := livecarrier.Resolve(plan.StrategyFamily)
	if err != nil ||
		authority.Version != livecarrier.Version ||
		authority.ImplementationFamily != plan.CarrierFamily ||
		authority.LoopbackConformanceOnly != plan.LoopbackOnly {
		return ErrStrategy
	}
	return nil
}

func bounded(value string, limit int) bool {
	return value != "" && len(value) <= limit
}

func digest(plan Plan) [32]byte {
	hash := sha256.New()
	for _, value := range []string{
		plan.Version,
		plan.ProfileID,
		plan.Scope,
		plan.EvidenceReference,
		plan.ClientID,
		plan.StrategyFamily,
		plan.CarrierFamily,
		plan.DescriptorID,
		plan.EndpointReference,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	var numbers [16]byte
	binary.BigEndian.PutUint64(numbers[0:8], plan.Generation)
	binary.BigEndian.PutUint32(numbers[8:12], plan.DialTimeoutMs)
	binary.BigEndian.PutUint32(numbers[12:16], plan.MaxFrameBytes)
	_, _ = hash.Write(numbers[:])
	if plan.LoopbackOnly {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
