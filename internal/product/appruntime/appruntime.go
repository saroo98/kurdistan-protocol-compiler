// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package appruntime defines a pure, offline application-runtime eligibility
// contract. It performs no platform, service, storage, routing, DNS, network,
// telemetry, or cryptographic action.
package appruntime

import (
	"errors"
	"reflect"
	"strings"

	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

const Version = "offline-app-runtime-v1"

type Intent string

const (
	IntentEvaluate Intent = "evaluate"
	IntentConnect  Intent = "connect"
	IntentRecover  Intent = "recover"
)

type StateKind string

const (
	StateInactive          StateKind = "inactive"
	StateEligible          StateKind = "eligible"
	StateBlocked           StateKind = "blocked"
	StateDisconnectPending StateKind = "disconnect_pending"
)

type Disposition string

const (
	DispositionReadyToStart     Disposition = "ready_to_start"
	DispositionRemainInactive   Disposition = "remain_inactive"
	DispositionBlocked          Disposition = "blocked"
	DispositionShutdownRequired Disposition = "shutdown_required"
)

type Reason string

const (
	ReasonEligible                    Reason = "eligible"
	ReasonPermissionRequired          Reason = "permission_required"
	ReasonProtectedStorageUnavailable Reason = "protected_storage_unavailable"
	ReasonRoutingUnsafe               Reason = "routing_unsafe"
	ReasonDNSUnsafe                   Reason = "dns_unsafe"
	ReasonKillSwitchUnavailable       Reason = "kill_switch_unavailable"
	ReasonProfileNotAdmitted          Reason = "profile_not_admitted"
	ReasonFallbackNotSelected         Reason = "fallback_not_selected"
	ReasonRelayNotAdmitted            Reason = "relay_not_admitted"
	ReasonIncompatibleContract        Reason = "incompatible_contract"
	ReasonShutdownRequested           Reason = "shutdown_required"
)

var (
	ErrInvalidRequest = errors.New("appruntime: invalid request")
	ErrInvalidState   = errors.New("appruntime: invalid current state")
	ErrGeneration     = errors.New("appruntime: invalid transition generation")
)

type State struct {
	Version    string
	Kind       StateKind
	Generation uint64
}

type PlatformSnapshot struct {
	Version                   string
	PermissionStateKnown      bool
	VPNConsentGranted         bool
	ProtectedStorageAvailable bool
	RoutingPolicySafe         bool
	DNSPolicySafe             bool
	KillSwitchAvailable       bool
}

type Request struct {
	Version               string
	Intent                Intent
	Current               State
	RequestedGeneration   uint64
	Platform              PlatformSnapshot
	Lifecycle             lifecycle.State
	StrategyRequest       strategy.Request
	ClaimedStrategyResult strategy.Result
	RelayRequest          relaydescriptor.Request
	ClaimedRelayAdmission relaydescriptor.Admission
}

type Decision struct {
	Version     string
	Next        State
	Disposition Disposition
	Reason      Reason
}

type DisconnectRequest struct {
	CurrentGeneration   uint64
	RequestedGeneration uint64
}

// Evaluate returns offline eligibility metadata only. In particular,
// ready_to_start does not mean that a VPN, service, tunnel, relay, route, DNS
// policy, or kill switch exists or has started.
func Evaluate(req Request) (Decision, error) {
	// A pending shutdown is terminal in this contract. This check deliberately
	// precedes every version, generation, and nested predecessor inspection so
	// malformed or unavailable evidence cannot prevent a shutdown request.
	if req.Current.Kind == StateDisconnectPending {
		generation := max(req.Current.Generation, req.RequestedGeneration)
		return shutdownDecision(generation), nil
	}

	if req.Version != Version || req.Current.Version != Version {
		return Decision{}, ErrInvalidRequest
	}
	if !knownIntent(req.Intent) {
		return Decision{}, ErrInvalidRequest
	}
	if !validCurrent(req.Current) {
		return Decision{}, ErrInvalidState
	}
	if req.RequestedGeneration == 0 || req.RequestedGeneration <= req.Current.Generation {
		return Decision{}, ErrGeneration
	}

	if req.Platform.Version != Version || predecessorVersionMismatch(req) {
		return blocked(req.RequestedGeneration, ReasonIncompatibleContract), nil
	}
	if !req.Platform.PermissionStateKnown || !req.Platform.VPNConsentGranted {
		return blocked(req.RequestedGeneration, ReasonPermissionRequired), nil
	}
	if !req.Platform.ProtectedStorageAvailable {
		return blocked(req.RequestedGeneration, ReasonProtectedStorageUnavailable), nil
	}
	if !req.Platform.RoutingPolicySafe {
		return blocked(req.RequestedGeneration, ReasonRoutingUnsafe), nil
	}
	if !req.Platform.DNSPolicySafe {
		return blocked(req.RequestedGeneration, ReasonDNSUnsafe), nil
	}
	if !req.Platform.KillSwitchAvailable {
		return blocked(req.RequestedGeneration, ReasonKillSwitchUnavailable), nil
	}

	if !validAdmittedLifecycle(req.Lifecycle) ||
		!reflect.DeepEqual(req.Lifecycle, req.StrategyRequest.Lifecycle) {
		return blocked(req.RequestedGeneration, ReasonProfileNotAdmitted), nil
	}

	selected, err := strategy.Select(req.StrategyRequest)
	if err != nil || !reflect.DeepEqual(selected, req.ClaimedStrategyResult) || selected.Outcome != strategy.OutcomeSelected {
		return blocked(req.RequestedGeneration, ReasonFallbackNotSelected), nil
	}
	admission, err := relaydescriptor.Admit(req.RelayRequest)
	if err != nil || len(req.ClaimedRelayAdmission.Descriptors) > 32 ||
		!reflect.DeepEqual(req.RelayRequest.StrategyRequest, req.StrategyRequest) ||
		!reflect.DeepEqual(req.RelayRequest.ClaimedResult, req.ClaimedStrategyResult) ||
		!reflect.DeepEqual(admission, req.ClaimedRelayAdmission) ||
		admission.ProfileID != req.Lifecycle.ProfileID || admission.Scope != req.Lifecycle.Scope ||
		admission.EvidenceReference != req.Lifecycle.EvidenceReference || admission.Generation != req.Lifecycle.Generation ||
		admission.SelectedFamily != selected.SelectedFamily {
		return blocked(req.RequestedGeneration, ReasonRelayNotAdmitted), nil
	}

	disposition := DispositionReadyToStart
	if req.Intent == IntentEvaluate {
		disposition = DispositionRemainInactive
	}
	return Decision{
		Version:     Version,
		Next:        State{Version: Version, Kind: StateEligible, Generation: req.RequestedGeneration},
		Disposition: disposition,
		Reason:      ReasonEligible,
	}, nil
}

func validAdmittedLifecycle(state lifecycle.State) bool {
	return state.Status == lifecycle.Admitted && state.Generation != 0 &&
		validBinding(state.ProfileID, 256) && validBinding(state.Scope, 64) &&
		validBinding(state.EvidenceReference, 256)
}

func validBinding(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && strings.TrimSpace(value) == value
}

// RequestDisconnect always returns an offline shutdown request. It has no
// prerequisite fields and does not claim that shutdown has completed.
func RequestDisconnect(req DisconnectRequest) Decision {
	generation := max(req.CurrentGeneration, req.RequestedGeneration)
	if generation == 0 {
		generation = 1
	}
	return shutdownDecision(generation)
}

func predecessorVersionMismatch(req Request) bool {
	return req.StrategyRequest.Policy.Version != strategy.Version ||
		req.StrategyRequest.Client.SupportedVersion != strategy.Version ||
		req.RelayRequest.Version != relaydescriptor.Version ||
		req.RelayRequest.StrategyRequest.Policy.Version != strategy.Version ||
		req.RelayRequest.StrategyRequest.Client.SupportedVersion != strategy.Version ||
		req.RelayRequest.Policy.Version != relaydescriptor.Version ||
		req.RelayRequest.Policy.FallbackPolicy.Version != strategy.Version ||
		req.RelayRequest.Revocation.Version != relaydescriptor.Version ||
		req.ClaimedRelayAdmission.Version != relaydescriptor.Version ||
		hasWrongDescriptorVersion(req.RelayRequest.Descriptors) ||
		hasWrongDescriptorVersion(req.RelayRequest.Policy.AuthorizedDescriptors)
}

func hasWrongDescriptorVersion(descriptors []relaydescriptor.Descriptor) bool {
	// Match the predecessor's public maximum before scanning caller-controlled
	// entries. Oversized input is left for Admit to reject categorically.
	if len(descriptors) > 32 {
		return false
	}
	for _, descriptor := range descriptors {
		if descriptor.Version != relaydescriptor.Version {
			return true
		}
	}
	return false
}

func knownIntent(intent Intent) bool {
	switch intent {
	case IntentEvaluate, IntentConnect, IntentRecover:
		return true
	default:
		return false
	}
}

func validCurrent(state State) bool {
	switch state.Kind {
	case StateInactive:
		return state.Generation == 0
	case StateEligible, StateBlocked:
		return state.Generation != 0
	default:
		return false
	}
}

func blocked(generation uint64, reason Reason) Decision {
	return Decision{
		Version:     Version,
		Next:        State{Version: Version, Kind: StateBlocked, Generation: generation},
		Disposition: DispositionBlocked,
		Reason:      reason,
	}
}

func shutdownDecision(generation uint64) Decision {
	return Decision{
		Version:     Version,
		Next:        State{Version: Version, Kind: StateDisconnectPending, Generation: generation},
		Disposition: DispositionShutdownRequired,
		Reason:      ReasonShutdownRequested,
	}
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
