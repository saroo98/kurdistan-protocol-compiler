// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/runtimepolicy"
)

const (
	VersionV2                 = "session-plan-v2"
	supportedStrategyTLS13TCP = "strategy.kurd-tls13-tcp"
	planDigestDomainV2        = "kurd-session-plan-v2\x00"
	receiptDigestDomainV2     = "kurd-activation-receipt-v1\x00"
)

var (
	ErrInvalidV2     = errors.New("sessionplan: invalid v2 authority")
	ErrReceiptV2     = errors.New("sessionplan: activation receipt rejected")
	ErrWideningV2    = errors.New("sessionplan: requested authority widening")
	ErrUnsupportedV2 = errors.New("sessionplan: unsupported v2 authority")
)

type RequestV2 struct {
	Profile           envelope.CanonicalProfileV1
	ActivationReceipt lifecycle.VerifiedReceipt
	RuntimePolicy     runtimepolicy.PolicyV2
	Requested         NarrowingRequestV2
}

type NarrowingRequestV2 struct {
	StrategyID           string
	EndpointIndexes      []uint8
	IPMode               runtimepolicy.IPModeV2
	Routes               []runtimepolicy.PrefixV2
	DNSServers           [][]byte
	MTU                  uint16
	PayloadProtocols     []runtimepolicy.PayloadProtocolV2
	MaxQueuePackets      uint16
	MaxIncompleteOps     uint16
	MaxReconnectAttempts uint8
	AllowLAN             bool
}

type PlanV2 struct {
	Version                 string
	ProfileContentID        string
	ProfileGeneration       uint64
	ActivationReceiptDigest [32]byte
	RuntimePolicyDigest     [32]byte
	LiveProgramDigest       [32]byte
	StrategyID              string
	RelayKeyID              string
	CarrierFamily           string
	ALPN                    string
	Endpoints               []runtimepolicy.EndpointV2
	ClientIPv4              [4]byte
	DNSIPv4                 [4]byte
	ClientIPv6              [16]byte
	DNSIPv6                 [16]byte
	Routes                  []runtimepolicy.PrefixV2
	IPMode                  runtimepolicy.IPModeV2
	MTU                     uint16
	PayloadProtocols        []runtimepolicy.PayloadProtocolV2
	MaxQueuePackets         uint16
	MaxIncompleteOps        uint16
	MaxReconnectAttempts    uint8
	DialTimeout             time.Duration
	IdleTimeout             time.Duration
	Digest                  [32]byte

	runtimePolicyBytes []byte
}

func (p PlanV2) Clone() PlanV2 {
	p.Endpoints = cloneEndpointsV2(p.Endpoints)
	p.Routes = clonePrefixesV2(p.Routes)
	p.PayloadProtocols = slices.Clone(p.PayloadProtocols)
	p.runtimePolicyBytes = bytes.Clone(p.runtimePolicyBytes)
	return p
}

func BuildV2(request RequestV2) (PlanV2, error) {
	return BuildV2At(request, time.Now())
}

// BuildV2At constructs client authority using the caller's trusted time.
func BuildV2At(request RequestV2, now time.Time) (PlanV2, error) {
	if _, err := envelope.EncodeCanonicalProfileV1(request.Profile); err != nil ||
		now.IsZero() || request.Profile.Generation == 0 || now.Unix() < request.Profile.ValidFrom || now.Unix() >= request.Profile.ValidUntil {
		return PlanV2{}, ErrInvalidV2
	}
	if !receiptMatchesProfileV2(request.ActivationReceipt, request.Profile) {
		return PlanV2{}, ErrReceiptV2
	}
	if request.RuntimePolicy.ValidateAgainstEnvelopeAt(request.Profile, now) != nil {
		return PlanV2{}, ErrInvalidV2
	}
	return buildAuthorityV2(authorityV2{
		profileContentID:        request.Profile.ContentID,
		profileGeneration:       request.Profile.Generation,
		activationReceiptDigest: digestReceiptV2(request.ActivationReceipt),
		policy:                  request.RuntimePolicy,
		strategyIDs:             request.Profile.StrategyIDs,
		relayIDs:                request.Profile.RelayIDs,
	}, request.Requested, now)
}

type authorityV2 struct {
	profileContentID        string
	profileGeneration       uint64
	activationReceiptDigest [32]byte
	policy                  runtimepolicy.PolicyV2
	strategyIDs             []string
	relayIDs                []string
}

func buildAuthorityV2(authority authorityV2, requested NarrowingRequestV2, now time.Time) (PlanV2, error) {
	if now.IsZero() || !boundedV2(authority.profileContentID, 128) || authority.profileGeneration == 0 ||
		authority.activationReceiptDigest == ([32]byte{}) || len(authority.strategyIDs) == 0 || len(authority.relayIDs) == 0 {
		return PlanV2{}, ErrInvalidV2
	}
	policy := authority.policy.Clone()
	if err := runtimepolicy.ValidateV2At(policy, now); err != nil ||
		len(policy.LiveProgram) == 0 {
		return PlanV2{}, ErrInvalidV2
	}
	policyBytes, err := runtimepolicy.EncodeV2At(policy, now)
	if err != nil {
		return PlanV2{}, ErrInvalidV2
	}
	carrierAuthority, err := livecarrier.ResolveV2At(policy, now)
	if err != nil || !carrierAuthority.Networked || carrierAuthority.EndpointCount != len(policy.Endpoints) {
		return PlanV2{}, ErrUnsupportedV2
	}

	strategyID, err := selectStrategyV2(authority.strategyIDs, requested.StrategyID)
	if err != nil {
		return PlanV2{}, err
	}
	if !slices.Contains(authority.relayIDs, policy.RelayAuthKeyID) {
		return PlanV2{}, ErrWideningV2
	}
	endpointIndexes, err := selectEndpointIndexesV2(policy.Fallback.EndpointIndexes, requested.EndpointIndexes)
	if err != nil {
		return PlanV2{}, err
	}
	mode, err := selectIPModeV2(policy.AllowedIPModes, requested.IPMode)
	if err != nil {
		return PlanV2{}, err
	}
	routes, _, client4, dns4, client6, dns6, err := selectNetworkV2(policy, mode, requested.Routes, requested.DNSServers)
	if err != nil {
		return PlanV2{}, err
	}
	protocols, err := selectProtocolsV2(policy.AllowedProtocols, requested.PayloadProtocols)
	if err != nil {
		return PlanV2{}, err
	}
	queue, incomplete, reconnects, err := selectLimitsV2(policy, requested)
	if err != nil {
		return PlanV2{}, err
	}
	if requested.AllowLAN || requested.MTU != 0 && requested.MTU != policy.MTU || policy.MTU != 1280 {
		return PlanV2{}, ErrWideningV2
	}

	plan := PlanV2{
		Version: VersionV2, ProfileContentID: authority.profileContentID, ProfileGeneration: authority.profileGeneration,
		ActivationReceiptDigest: authority.activationReceiptDigest, RuntimePolicyDigest: sha256.Sum256(policyBytes),
		LiveProgramDigest: policy.LiveProgramSHA256, StrategyID: strategyID, RelayKeyID: policy.RelayAuthKeyID,
		CarrierFamily: carrierAuthority.CarrierFamily, ALPN: carrierAuthority.ALPN, Endpoints: selectEndpointsV2(policy.Endpoints, endpointIndexes),
		ClientIPv4: client4, DNSIPv4: dns4, ClientIPv6: client6, DNSIPv6: dns6, Routes: routes, IPMode: mode, MTU: policy.MTU,
		PayloadProtocols: protocols, MaxQueuePackets: queue, MaxIncompleteOps: incomplete, MaxReconnectAttempts: reconnects,
		DialTimeout:        time.Duration(policy.Fallback.AttemptTimeoutSeconds) * time.Second,
		IdleTimeout:        time.Duration(policy.Limits.MaxIdleSeconds) * time.Second,
		runtimePolicyBytes: bytes.Clone(policyBytes),
	}
	plan.Digest = digestPlanV2(plan)
	if err := ValidateV2At(plan, now); err != nil {
		return PlanV2{}, err
	}
	return plan.Clone(), nil
}

func ValidateV2(plan PlanV2) error {
	return ValidateV2At(plan, time.Now())
}

// ValidateV2At validates a plan using the caller's trusted time.
func ValidateV2At(plan PlanV2, now time.Time) error {
	if plan.Version != VersionV2 || !boundedV2(plan.ProfileContentID, 128) || plan.ProfileGeneration == 0 ||
		plan.ActivationReceiptDigest == ([32]byte{}) || plan.RuntimePolicyDigest == ([32]byte{}) ||
		plan.LiveProgramDigest == ([32]byte{}) || plan.StrategyID != supportedStrategyTLS13TCP ||
		!boundedV2(plan.RelayKeyID, 64) || plan.CarrierFamily != runtimepolicy.CarrierFamilyTLS13TCP ||
		plan.ALPN != "kurd/1" || len(plan.Endpoints) == 0 || len(plan.Endpoints) > 4 ||
		plan.MTU != 1280 || plan.MaxQueuePackets == 0 || plan.MaxIncompleteOps == 0 ||
		plan.MaxReconnectAttempts == 0 || plan.DialTimeout <= 0 || plan.DialTimeout > 10*time.Second ||
		plan.IdleTimeout <= 0 || plan.Digest == ([32]byte{}) || len(plan.runtimePolicyBytes) == 0 ||
		sha256.Sum256(plan.runtimePolicyBytes) != plan.RuntimePolicyDigest {
		return ErrInvalidV2
	}
	policy, err := runtimepolicy.DecodeV2At(plan.runtimePolicyBytes, now)
	if err != nil || policy.LiveProgramSHA256 != plan.LiveProgramDigest || policy.RelayAuthKeyID != plan.RelayKeyID ||
		plan.MaxQueuePackets > uint16(policy.Limits.MaxQueuedPackets) || plan.MaxIncompleteOps > uint16(policy.Limits.MaxQueuedPackets) ||
		uint32(plan.MaxReconnectAttempts) > policy.Limits.MaxReconnectAttempts ||
		plan.DialTimeout != time.Duration(policy.Fallback.AttemptTimeoutSeconds)*time.Second ||
		plan.IdleTimeout != time.Duration(policy.Limits.MaxIdleSeconds)*time.Second ||
		!endpointsSubsetV2(policy, plan.Endpoints) || !modePermittedV2(policy.AllowedIPModes, plan.IPMode) ||
		!protocolSubsetV2(policy.AllowedProtocols, plan.PayloadProtocols) ||
		!networkMatchesModeV2(policy, plan) {
		return ErrInvalidV2
	}
	if digestPlanV2(plan) != plan.Digest {
		return ErrInvalidV2
	}
	return nil
}

func receiptMatchesProfileV2(receipt lifecycle.VerifiedReceipt, profile envelope.CanonicalProfileV1) bool {
	if receipt.ContentID != profile.ContentID || receipt.ProviderID != profile.ProviderID || receipt.LineageID != profile.LineageID ||
		receipt.RootEpoch != profile.RootEpoch || receipt.RevocationEpoch != profile.RevocationEpoch ||
		len(receipt.AuthenticatedArtifactSHA256) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(receipt.AuthenticatedArtifactSHA256)
	return err == nil && len(decoded) == 32 && receipt.AuthenticatedArtifactSHA256 == hex.EncodeToString(decoded)
}

func selectStrategyV2(signed []string, requested string) (string, error) {
	if requested != "" {
		if requested != supportedStrategyTLS13TCP || !slices.Contains(signed, requested) {
			return "", ErrWideningV2
		}
		return requested, nil
	}
	if slices.Contains(signed, supportedStrategyTLS13TCP) {
		return supportedStrategyTLS13TCP, nil
	}
	return "", ErrUnsupportedV2
}

func selectEndpointIndexesV2(signed, requested []uint8) ([]uint8, error) {
	if len(requested) == 0 {
		return slices.Clone(signed), nil
	}
	if !orderedUint8SubsetV2(signed, requested) {
		return nil, ErrWideningV2
	}
	return slices.Clone(requested), nil
}

func orderedUint8SubsetV2(signed, requested []uint8) bool {
	position := 0
	for i, value := range requested {
		if i > 0 && requested[i-1] >= value {
			return false
		}
		for position < len(signed) && signed[position] != value {
			position++
		}
		if position == len(signed) {
			return false
		}
		position++
	}
	return len(requested) > 0
}

func selectIPModeV2(signed []runtimepolicy.IPModeV2, requested runtimepolicy.IPModeV2) (runtimepolicy.IPModeV2, error) {
	if requested == "" {
		if len(signed) == 0 {
			return "", ErrUnsupportedV2
		}
		return signed[0], nil
	}
	if !modePermittedV2(signed, requested) {
		return "", ErrWideningV2
	}
	return requested, nil
}

func modePermittedV2(signed []runtimepolicy.IPModeV2, requested runtimepolicy.IPModeV2) bool {
	return slices.Contains(signed, requested)
}

func selectNetworkV2(policy runtimepolicy.PolicyV2, mode runtimepolicy.IPModeV2, requestedRoutes []runtimepolicy.PrefixV2, requestedDNS [][]byte) ([]runtimepolicy.PrefixV2, [][]byte, [4]byte, [4]byte, [16]byte, [16]byte, error) {
	wantRoutes := make([]runtimepolicy.PrefixV2, 0, 2)
	wantDNS := make([][]byte, 0, 2)
	var client4, dns4 [4]byte
	var client6, dns6 [16]byte
	if mode == runtimepolicy.IPModeIPv4Only || mode == runtimepolicy.IPModeDualStack {
		if len(policy.ClientIPv4) != 4 || len(policy.DNSIPv4) != 4 {
			return nil, nil, client4, dns4, client6, dns6, ErrUnsupportedV2
		}
		copy(client4[:], policy.ClientIPv4)
		copy(dns4[:], policy.DNSIPv4)
		wantRoutes = append(wantRoutes, runtimepolicy.PrefixV2{Address: []byte{0, 0, 0, 0}, PrefixLen: 0})
		wantDNS = append(wantDNS, bytes.Clone(policy.DNSIPv4))
	}
	if mode == runtimepolicy.IPModeIPv6Only || mode == runtimepolicy.IPModeDualStack {
		if len(policy.ClientIPv6) != 16 || len(policy.DNSIPv6) != 16 {
			return nil, nil, client4, dns4, client6, dns6, ErrUnsupportedV2
		}
		copy(client6[:], policy.ClientIPv6)
		copy(dns6[:], policy.DNSIPv6)
		wantRoutes = append(wantRoutes, runtimepolicy.PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
		wantDNS = append(wantDNS, bytes.Clone(policy.DNSIPv6))
	}
	if len(requestedRoutes) != 0 && !reflectPrefixesV2(requestedRoutes, wantRoutes) ||
		len(requestedDNS) != 0 && !reflectBytes2DV2(requestedDNS, wantDNS) {
		return nil, nil, client4, dns4, client6, dns6, ErrWideningV2
	}
	return clonePrefixesV2(wantRoutes), cloneBytes2DV2(wantDNS), client4, dns4, client6, dns6, nil
}

func selectProtocolsV2(signed, requested []runtimepolicy.PayloadProtocolV2) ([]runtimepolicy.PayloadProtocolV2, error) {
	if len(requested) == 0 {
		return slices.Clone(signed), nil
	}
	if !protocolSubsetV2(signed, requested) {
		return nil, ErrWideningV2
	}
	return slices.Clone(requested), nil
}

func protocolSubsetV2(signed, requested []runtimepolicy.PayloadProtocolV2) bool {
	position := 0
	for i, value := range requested {
		if i > 0 && requested[i-1] >= value {
			return false
		}
		for position < len(signed) && signed[position] != value {
			position++
		}
		if position == len(signed) {
			return false
		}
		position++
	}
	return len(requested) > 0
}

func selectLimitsV2(policy runtimepolicy.PolicyV2, requested NarrowingRequestV2) (uint16, uint16, uint8, error) {
	if policy.Limits.MaxQueuedPackets > 1<<16-1 || policy.Limits.MaxReconnectAttempts > 1<<8-1 {
		return 0, 0, 0, ErrUnsupportedV2
	}
	queue := uint16(policy.Limits.MaxQueuedPackets)
	if requested.MaxQueuePackets != 0 {
		queue = requested.MaxQueuePackets
	}
	incomplete := uint16(policy.Limits.MaxQueuedPackets)
	if requested.MaxIncompleteOps != 0 {
		incomplete = requested.MaxIncompleteOps
	}
	reconnects := uint8(policy.Limits.MaxReconnectAttempts)
	if requested.MaxReconnectAttempts != 0 {
		reconnects = requested.MaxReconnectAttempts
	}
	if queue == 0 || incomplete == 0 || reconnects == 0 ||
		uint32(queue) > policy.Limits.MaxQueuedPackets || uint32(incomplete) > policy.Limits.MaxQueuedPackets ||
		uint32(reconnects) > policy.Limits.MaxReconnectAttempts {
		return 0, 0, 0, ErrWideningV2
	}
	return queue, incomplete, reconnects, nil
}

func selectEndpointsV2(signed []runtimepolicy.EndpointV2, indexes []uint8) []runtimepolicy.EndpointV2 {
	result := make([]runtimepolicy.EndpointV2, len(indexes))
	for i, index := range indexes {
		result[i] = signed[index]
		result[i].Address = bytes.Clone(signed[index].Address)
	}
	return result
}

func endpointsSubsetV2(policy runtimepolicy.PolicyV2, endpoints []runtimepolicy.EndpointV2) bool {
	position := 0
	for _, endpoint := range endpoints {
		found := false
		for position < len(policy.Fallback.EndpointIndexes) {
			candidate := policy.Endpoints[policy.Fallback.EndpointIndexes[position]]
			position++
			if endpoint.Priority == candidate.Priority && endpoint.Family == candidate.Family && endpoint.Port == candidate.Port && bytes.Equal(endpoint.Address, candidate.Address) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(endpoints) > 0
}

func networkMatchesModeV2(policy runtimepolicy.PolicyV2, plan PlanV2) bool {
	routes, _, client4, dns4, client6, dns6, err := selectNetworkV2(policy, plan.IPMode, plan.Routes, nil)
	return err == nil && reflectPrefixesV2(routes, plan.Routes) && client4 == plan.ClientIPv4 && dns4 == plan.DNSIPv4 && client6 == plan.ClientIPv6 && dns6 == plan.DNSIPv6
}

func digestReceiptV2(receipt lifecycle.VerifiedReceipt) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(receiptDigestDomainV2))
	writeStringV2(h, receipt.ContentID)
	writeStringV2(h, receipt.ProviderID)
	writeStringV2(h, receipt.LineageID)
	writeStringV2(h, receipt.AuthenticatedArtifactSHA256)
	writeUint64V2(h, receipt.RootEpoch)
	writeUint64V2(h, receipt.RevocationEpoch)
	writeUint64V2(h, receipt.RecipientEpoch)
	return sumV2(h)
}

func digestPlanV2(plan PlanV2) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(planDigestDomainV2))
	writeStringV2(h, plan.ProfileContentID)
	_, _ = h.Write(plan.ActivationReceiptDigest[:])
	writeBytesV2(h, plan.runtimePolicyBytes)
	writeBytesV2(h, effectiveNarrowingV2(plan))
	writeStringV2(h, plan.StrategyID)
	writeStringV2(h, plan.RelayKeyID)
	writeEndpointsV2(h, plan.Endpoints)
	return sumV2(h)
}

func effectiveNarrowingV2(plan PlanV2) []byte {
	h := sha256.New()
	writeUint64V2(h, plan.ProfileGeneration)
	_, _ = h.Write(plan.RuntimePolicyDigest[:])
	_, _ = h.Write(plan.LiveProgramDigest[:])
	writeStringV2(h, plan.CarrierFamily)
	writeStringV2(h, plan.ALPN)
	writeStringV2(h, string(plan.IPMode))
	writeUint64V2(h, uint64(plan.MTU))
	writeUint64V2(h, uint64(plan.MaxQueuePackets))
	writeUint64V2(h, uint64(plan.MaxIncompleteOps))
	writeUint64V2(h, uint64(plan.MaxReconnectAttempts))
	writeUint64V2(h, uint64(plan.DialTimeout))
	writeUint64V2(h, uint64(plan.IdleTimeout))
	_, _ = h.Write(plan.ClientIPv4[:])
	_, _ = h.Write(plan.DNSIPv4[:])
	_, _ = h.Write(plan.ClientIPv6[:])
	_, _ = h.Write(plan.DNSIPv6[:])
	writePrefixesV2(h, plan.Routes)
	writeProtocolsV2(h, plan.PayloadProtocols)
	return h.Sum(nil)
}

type hashWriterV2 interface{ Write([]byte) (int, error) }

func writeStringV2(h hashWriterV2, value string) { writeBytesV2(h, []byte(value)) }

func writeBytesV2(h hashWriterV2, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

func writeUint64V2(h hashWriterV2, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func writeEndpointsV2(h hashWriterV2, endpoints []runtimepolicy.EndpointV2) {
	writeUint64V2(h, uint64(len(endpoints)))
	for _, endpoint := range endpoints {
		_, _ = h.Write([]byte{endpoint.Priority, endpoint.Family})
		writeUint64V2(h, uint64(endpoint.Port))
		writeBytesV2(h, endpoint.Address)
	}
}

func writePrefixesV2(h hashWriterV2, prefixes []runtimepolicy.PrefixV2) {
	writeUint64V2(h, uint64(len(prefixes)))
	for _, prefix := range prefixes {
		_, _ = h.Write([]byte{prefix.PrefixLen})
		writeBytesV2(h, prefix.Address)
	}
}

func writeProtocolsV2(h hashWriterV2, protocols []runtimepolicy.PayloadProtocolV2) {
	writeUint64V2(h, uint64(len(protocols)))
	for _, protocol := range protocols {
		writeStringV2(h, string(protocol))
	}
}

func sumV2(h interface{ Sum([]byte) []byte }) [32]byte {
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func cloneEndpointsV2(values []runtimepolicy.EndpointV2) []runtimepolicy.EndpointV2 {
	result := slices.Clone(values)
	for i := range result {
		result[i].Address = bytes.Clone(result[i].Address)
	}
	return result
}

func clonePrefixesV2(values []runtimepolicy.PrefixV2) []runtimepolicy.PrefixV2 {
	result := slices.Clone(values)
	for i := range result {
		result[i].Address = bytes.Clone(result[i].Address)
	}
	return result
}

func cloneBytes2DV2(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = bytes.Clone(values[i])
	}
	return result
}

func reflectPrefixesV2(a, b []runtimepolicy.PrefixV2) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].PrefixLen != b[i].PrefixLen || !bytes.Equal(a[i].Address, b[i].Address) {
			return false
		}
	}
	return true
}

func reflectBytes2DV2(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func boundedV2(value string, max int) bool { return value != "" && len(value) <= max }
