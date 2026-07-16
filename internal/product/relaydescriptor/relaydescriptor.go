// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package relaydescriptor defines pure, offline relay-descriptor admission.
// It validates bounded metadata only. It never resolves or uses relay references.
package relaydescriptor

import (
	"errors"
	"reflect"
	"strings"

	"kurdistan/internal/product/strategy"
)

const Version = "offline-relay-descriptor-admission-v1"

const (
	maxDescriptors     = 32
	maxListItems       = 64
	maxMetadataItems   = 16
	maxIdentifierBytes = 128
	maxStrategyIDBytes = 64
	maxReferenceBytes  = 256
	maxMetadataBytes   = 256
)

var (
	ErrInvalidRequest = errors.New("relaydescriptor: invalid request")
	ErrVersion        = errors.New("relaydescriptor: incompatible version")
	ErrStrategyProof  = errors.New("relaydescriptor: invalid strategy proof")
	ErrBinding        = errors.New("relaydescriptor: binding mismatch")
	ErrTime           = errors.New("relaydescriptor: invalid validity state")
	ErrRevocation     = errors.New("relaydescriptor: invalid revocation state")
	ErrUnauthorized   = errors.New("relaydescriptor: unauthorized descriptor")
	ErrDescriptor     = errors.New("relaydescriptor: invalid descriptor")
)

// Metadata is bounded, printable structural metadata. It conveys no authority.
type Metadata struct {
	Name  string
	Value string
}

// Descriptor is an exact profile-authorized descriptor. EndpointReference is
// grammar-validated as an opaque relay reference, but is never parsed or
// interpreted as a network destination, resolved, connected to, logged, or
// echoed.
type Descriptor struct {
	Version            string
	DescriptorID       string
	ProfileID          string
	Scope              string
	EvidenceReference  string
	Generation         uint64
	Family             string
	ClientID           string
	ClientCapabilities []string
	EndpointReference  string
	NotBefore          int64
	ExpiresAt          int64
	Metadata           []Metadata
}

// Policy binds exact authorized descriptors and client identities to the
// complete Phase 4 policy and selected family.
type Policy struct {
	Version               string
	ProfileID             string
	Scope                 string
	EvidenceReference     string
	Generation            uint64
	FallbackPolicy        strategy.Policy
	SelectedFamily        string
	ClientCapabilities    []string
	AuthorizedClientIDs   []string
	AuthorizedDescriptors []Descriptor
}

// RevocationState is a complete caller-supplied snapshot for EvaluationTime.
// This package does not fetch or infer revocation state.
type RevocationState struct {
	Version              string
	Complete             bool
	ProfileID            string
	Scope                string
	EvidenceReference    string
	Generation           uint64
	EvaluatedAt          int64
	RevokedDescriptorIDs []string
}

type ClientBinding struct {
	ID string
}

type Request struct {
	Version         string
	StrategyRequest strategy.Request
	ClaimedResult   strategy.Result
	EvaluationTime  int64
	Client          ClientBinding
	Policy          Policy
	Revocation      RevocationState
	Descriptors     []Descriptor
}

// AdmittedDescriptor is the minimal structural output. EndpointReference
// remains opaque and receives no reachability or authenticity claim.
type AdmittedDescriptor struct {
	DescriptorID      string
	EndpointReference string
}

type Admission struct {
	Version           string
	ProfileID         string
	Scope             string
	EvidenceReference string
	Generation        uint64
	ClientID          string
	SelectedFamily    string
	Descriptors       []AdmittedDescriptor
}

// Admit recomputes the exact Phase 4 result and admits all descriptors or none.
// Every rejection returns a zero Admission and a stable categorical error.
func Admit(req Request) (Admission, error) {
	if req.Version != Version || req.Policy.Version != Version || req.Revocation.Version != Version {
		return Admission{}, ErrVersion
	}
	if req.EvaluationTime <= 0 || !validID(req.Client.ID, maxIdentifierBytes) {
		return Admission{}, ErrInvalidRequest
	}
	if !boundedRequestShape(req) {
		return Admission{}, ErrInvalidRequest
	}

	recomputed, err := strategy.Select(req.StrategyRequest)
	if err != nil || !reflect.DeepEqual(recomputed, req.ClaimedResult) || recomputed.Outcome != strategy.OutcomeSelected {
		return Admission{}, ErrStrategyProof
	}

	s := req.StrategyRequest.Lifecycle
	if req.Policy.ProfileID != s.ProfileID || req.Policy.Scope != s.Scope ||
		req.Policy.EvidenceReference != s.EvidenceReference || req.Policy.Generation != s.Generation ||
		!reflect.DeepEqual(req.Policy.FallbackPolicy, req.StrategyRequest.Policy) ||
		req.Policy.SelectedFamily != recomputed.SelectedFamily ||
		!reflect.DeepEqual(req.Policy.ClientCapabilities, req.StrategyRequest.Client.Capabilities) {
		return Admission{}, ErrBinding
	}
	if !validID(req.Policy.ProfileID, maxReferenceBytes) || !validID(req.Policy.Scope, maxStrategyIDBytes) ||
		!validID(req.Policy.EvidenceReference, maxReferenceBytes) || req.Policy.Generation == 0 ||
		!validID(req.Policy.SelectedFamily, maxStrategyIDBytes) ||
		validateUniqueIDs(req.Policy.ClientCapabilities, true) != nil ||
		validateUniqueIDs(req.Policy.AuthorizedClientIDs, false) != nil ||
		!contains(req.Policy.AuthorizedClientIDs, req.Client.ID) {
		return Admission{}, ErrBinding
	}

	if !req.Revocation.Complete || req.Revocation.ProfileID != s.ProfileID || req.Revocation.Scope != s.Scope ||
		req.Revocation.EvidenceReference != s.EvidenceReference || req.Revocation.Generation != s.Generation ||
		req.Revocation.EvaluatedAt != req.EvaluationTime ||
		validateUniqueIDs(req.Revocation.RevokedDescriptorIDs, true) != nil {
		return Admission{}, ErrRevocation
	}

	if err := validateAuthorizedDescriptors(req.Policy.AuthorizedDescriptors, req); err != nil {
		return Admission{}, err
	}
	revoked := stringSet(req.Revocation.RevokedDescriptorIDs)
	seen := make(map[string]bool, len(req.Descriptors))
	output := make([]AdmittedDescriptor, 0, len(req.Descriptors))
	for _, descriptor := range req.Descriptors {
		if err := validateDescriptor(descriptor, req); err != nil {
			return Admission{}, err
		}
		if seen[descriptor.DescriptorID] {
			return Admission{}, ErrDescriptor
		}
		seen[descriptor.DescriptorID] = true
		if revoked[descriptor.DescriptorID] {
			return Admission{}, ErrRevocation
		}
		if !containsExactDescriptor(req.Policy.AuthorizedDescriptors, descriptor) {
			return Admission{}, ErrUnauthorized
		}
		output = append(output, AdmittedDescriptor{DescriptorID: descriptor.DescriptorID, EndpointReference: descriptor.EndpointReference})
	}

	return Admission{
		Version:           Version,
		ProfileID:         s.ProfileID,
		Scope:             s.Scope,
		EvidenceReference: s.EvidenceReference,
		Generation:        s.Generation,
		ClientID:          req.Client.ID,
		SelectedFamily:    recomputed.SelectedFamily,
		Descriptors:       output,
	}, nil
}

func validateAuthorizedDescriptors(descriptors []Descriptor, req Request) error {
	seen := make(map[string]bool, len(descriptors))
	for _, descriptor := range descriptors {
		if err := validateDescriptor(descriptor, req); err != nil {
			return err
		}
		if seen[descriptor.DescriptorID] {
			return ErrDescriptor
		}
		seen[descriptor.DescriptorID] = true
	}
	return nil
}

// boundedRequestShape runs before exact comparisons and output allocation so
// caller-controlled slices cannot turn validation into unbounded work.
func boundedRequestShape(req Request) bool {
	if len(req.Descriptors) == 0 || len(req.Descriptors) > maxDescriptors ||
		len(req.Policy.AuthorizedDescriptors) == 0 || len(req.Policy.AuthorizedDescriptors) > maxDescriptors ||
		len(req.Policy.ClientCapabilities) > maxListItems || len(req.Policy.AuthorizedClientIDs) > maxListItems ||
		len(req.Revocation.RevokedDescriptorIDs) > maxListItems ||
		len(req.Policy.FallbackPolicy.Permitted) > maxListItems {
		return false
	}
	if !boundedString(req.Policy.ProfileID, maxReferenceBytes) || !boundedString(req.Policy.Scope, maxStrategyIDBytes) ||
		!boundedString(req.Policy.EvidenceReference, maxReferenceBytes) ||
		!boundedString(req.Policy.SelectedFamily, maxStrategyIDBytes) ||
		!boundedString(req.Revocation.ProfileID, maxReferenceBytes) ||
		!boundedString(req.Revocation.Scope, maxStrategyIDBytes) ||
		!boundedString(req.Revocation.EvidenceReference, maxReferenceBytes) ||
		!boundedString(req.ClaimedResult.Outcome, maxIdentifierBytes) ||
		!boundedString(req.ClaimedResult.SelectedFamily, maxIdentifierBytes) ||
		!boundedString(req.ClaimedResult.Reason, maxIdentifierBytes) ||
		!boundedString(req.Policy.FallbackPolicy.Version, maxIdentifierBytes) ||
		!boundedString(req.Policy.FallbackPolicy.ProfileID, maxReferenceBytes) ||
		!boundedString(req.Policy.FallbackPolicy.Scope, maxStrategyIDBytes) ||
		!boundedString(req.Policy.FallbackPolicy.EvidenceReference, maxReferenceBytes) {
		return false
	}
	for _, candidate := range req.Policy.FallbackPolicy.Permitted {
		if len(candidate.RequiredCapabilities) > maxListItems || !boundedString(candidate.Family, maxStrategyIDBytes) {
			return false
		}
	}
	for _, descriptor := range req.Policy.AuthorizedDescriptors {
		if !boundedDescriptorShape(descriptor) {
			return false
		}
	}
	for _, descriptor := range req.Descriptors {
		if !boundedDescriptorShape(descriptor) {
			return false
		}
	}
	return true
}

func boundedDescriptorShape(d Descriptor) bool {
	return len(d.ClientCapabilities) <= maxListItems && len(d.Metadata) <= maxMetadataItems &&
		boundedString(d.DescriptorID, maxIdentifierBytes) && boundedString(d.ProfileID, maxReferenceBytes) &&
		boundedString(d.Scope, maxStrategyIDBytes) && boundedString(d.EvidenceReference, maxReferenceBytes) &&
		boundedString(d.Family, maxStrategyIDBytes) && boundedString(d.ClientID, maxIdentifierBytes) &&
		boundedString(d.EndpointReference, maxReferenceBytes)
}

func boundedString(value string, maxBytes int) bool {
	return len(value) <= maxBytes
}

func validateDescriptor(d Descriptor, req Request) error {
	if d.Version != Version {
		return ErrVersion
	}
	s := req.StrategyRequest.Lifecycle
	if d.ProfileID != s.ProfileID || d.Scope != s.Scope || d.EvidenceReference != s.EvidenceReference ||
		d.Generation != s.Generation || d.Family != req.ClaimedResult.SelectedFamily || d.ClientID != req.Client.ID ||
		!reflect.DeepEqual(d.ClientCapabilities, req.StrategyRequest.Client.Capabilities) {
		return ErrBinding
	}
	if !validID(d.DescriptorID, maxIdentifierBytes) || !validID(d.ProfileID, maxReferenceBytes) ||
		!validID(d.Scope, maxStrategyIDBytes) || !validID(d.EvidenceReference, maxReferenceBytes) ||
		!validID(d.Family, maxStrategyIDBytes) || !validID(d.ClientID, maxIdentifierBytes) ||
		!validEndpointReference(d.EndpointReference) ||
		validateUniqueIDs(d.ClientCapabilities, true) != nil || len(d.Metadata) > maxMetadataItems {
		return ErrDescriptor
	}
	if d.NotBefore <= 0 || d.ExpiresAt <= d.NotBefore || req.EvaluationTime < d.NotBefore || req.EvaluationTime >= d.ExpiresAt {
		return ErrTime
	}
	seenMetadata := map[string]bool{}
	for _, item := range d.Metadata {
		if !validID(item.Name, maxIdentifierBytes) || !validPrintable(item.Value, maxMetadataBytes) || seenMetadata[item.Name] {
			return ErrDescriptor
		}
		seenMetadata[item.Name] = true
	}
	return nil
}

func containsExactDescriptor(values []Descriptor, wanted Descriptor) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, wanted) {
			return true
		}
	}
	return false
}

func validateUniqueIDs(values []string, allowEmpty bool) error {
	if (!allowEmpty && len(values) == 0) || len(values) > maxListItems {
		return ErrInvalidRequest
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !validID(value, maxIdentifierBytes) || seen[value] {
			return ErrInvalidRequest
		}
		seen[value] = true
	}
	return nil
}

func validID(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validPrintable(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func validEndpointReference(value string) bool {
	const prefix = "relayref:"
	if !strings.HasPrefix(value, prefix) || len(value) > maxReferenceBytes {
		return false
	}
	token := strings.TrimPrefix(value, prefix)
	if token == "" || len(token) > maxIdentifierBytes {
		return false
	}
	lower := strings.ToLower(token)
	for _, marker := range []string{"secret", "key", "token", "password", "payload"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, r := range token {
		if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
