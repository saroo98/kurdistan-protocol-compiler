// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"slices"
	"time"
	"unsafe"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
)

const (
	RelayAdmissionPrefaceVersionV1  = "kurd-relay-admission-preface-v1"
	MaxRelayAdmissionPrefaceBytesV1 = 8 << 10
)

var ErrRelayAdmissionV1 = errors.New("sessionplan: relay admission rejected")

// RelayAuthorityV2 is the relay-owned, nonsecret projection needed to rebuild
// a client plan. It contains no recipient key, profile artifact, or endpoint
// authority outside the already authenticated runtime policy.
type RelayAuthorityV2 struct {
	ProfileContentID      string
	ProfileGeneration     uint64
	ValidFrom, ValidUntil int64
	RuntimePolicy         runtimepolicy.PolicyV2
	StrategyIDs           []string
	RelayIDs              []string
}

func (authority RelayAuthorityV2) Clone() RelayAuthorityV2 {
	authority.RuntimePolicy = authority.RuntimePolicy.Clone()
	authority.StrategyIDs = slices.Clone(authority.StrategyIDs)
	authority.RelayIDs = slices.Clone(authority.RelayIDs)
	return authority
}

// RelayAdmissionPrefaceV1 is a bounded, nonsecret client claim. The relay
// independently intersects Requested with RelayAuthorityV2 before accepting
// PlanDigest. ActivationReceiptDigest is an opaque client-local trust binding.
// The relay commits it into the exact plan digest but never treats it as a
// source of network authority.
type RelayAdmissionPrefaceV1 struct {
	Version                 string
	ProfileContentID        string
	ProfileGeneration       uint64
	ActivationReceiptDigest [32]byte
	PlanDigest              [32]byte
	Requested               NarrowingRequestV2
}

func (preface RelayAdmissionPrefaceV1) Clone() RelayAdmissionPrefaceV1 {
	preface.Requested.EndpointIndexes = slices.Clone(preface.Requested.EndpointIndexes)
	preface.Requested.Routes = clonePrefixesV2(preface.Requested.Routes)
	preface.Requested.DNSServers = cloneBytes2DV2(preface.Requested.DNSServers)
	preface.Requested.PayloadProtocols = slices.Clone(preface.Requested.PayloadProtocols)
	return preface
}

// NewRelayAdmissionPrefaceV1 derives the only admissible wire claim from an
// already validated client plan.
func NewRelayAdmissionPrefaceV1(plan PlanV2) (RelayAdmissionPrefaceV1, error) {
	return NewRelayAdmissionPrefaceV1At(plan, time.Now())
}

// NewRelayAdmissionPrefaceV1At validates and constructs the ordinary preface at
// the caller's captured trusted time. It grants no authority independently of
// the validated plan.
func NewRelayAdmissionPrefaceV1At(plan PlanV2, now time.Time) (RelayAdmissionPrefaceV1, error) {
	if now.IsZero() || ValidateV2At(plan, now) != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	policy, err := runtimepolicy.DecodeRuntimeAt(plan.runtimePolicyBytes, now)
	if err != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	indexes, err := effectiveEndpointIndexesV1(policy, plan.Endpoints)
	if err != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	preface := RelayAdmissionPrefaceV1{
		Version: RelayAdmissionPrefaceVersionV1, ProfileContentID: plan.ProfileContentID,
		ProfileGeneration: plan.ProfileGeneration, ActivationReceiptDigest: plan.ActivationReceiptDigest,
		PlanDigest: plan.Digest,
		Requested: NarrowingRequestV2{
			StrategyID: plan.StrategyID, EndpointIndexes: indexes, IPMode: plan.IPMode,
			Routes: clonePrefixesV2(plan.Routes), DNSServers: effectiveDNSServersV1(plan), MTU: plan.MTU,
			PayloadProtocols: slices.Clone(plan.PayloadProtocols), MaxQueuePackets: plan.MaxQueuePackets,
			MaxIncompleteOps: plan.MaxIncompleteOps, MaxReconnectAttempts: plan.MaxReconnectAttempts,
		},
	}
	if validateRelayAdmissionPrefaceV1(preface) != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	return preface.Clone(), nil
}

// BuildRelayV2At independently rebuilds the client's exact effective plan at
// relay trusted time. A client-supplied digest never creates authority.
func BuildRelayV2At(authority RelayAuthorityV2, preface RelayAdmissionPrefaceV1, now time.Time) (PlanV2, error) {
	if now.IsZero() || now.Unix() < authority.ValidFrom || now.Unix() >= authority.ValidUntil ||
		validateRelayAdmissionPrefaceV1(preface) != nil ||
		authority.ProfileContentID != preface.ProfileContentID || authority.ProfileGeneration != preface.ProfileGeneration {
		return PlanV2{}, ErrRelayAdmissionV1
	}
	plan, err := buildAuthorityV2(authorityV2{
		// Relay authority has no canonical profile span. Use its admitted upper bound.
		admittedProfileBytes:    envelope.MaxPayloadBytes,
		profileContentID:        authority.ProfileContentID,
		profileGeneration:       authority.ProfileGeneration,
		activationReceiptDigest: preface.ActivationReceiptDigest,
		policy:                  authority.RuntimePolicy,
		strategyIDs:             authority.StrategyIDs,
		relayIDs:                authority.RelayIDs,
	}, preface.Requested, now)
	if err != nil || plan.Digest != preface.PlanDigest {
		return PlanV2{}, ErrRelayAdmissionV1
	}
	return plan.Clone(), nil
}

type relayAdmissionPrefixWireV1 struct {
	_         struct{} `cbor:",toarray"`
	Address   []byte
	PrefixLen uint8
}

type relayAdmissionPrefaceWireV1 struct {
	_                       struct{} `cbor:",toarray"`
	Version                 string
	ProfileContentID        string
	ProfileGeneration       uint64
	ActivationReceiptDigest []byte
	PlanDigest              []byte
	StrategyID              string
	EndpointIndexes         []uint8
	IPMode                  string
	Routes                  []relayAdmissionPrefixWireV1
	DNSServers              [][]byte
	MTU                     uint16
	PayloadProtocols        []string
	MaxQueuePackets         uint16
	MaxIncompleteOps        uint16
	MaxReconnectAttempts    uint8
	AllowLAN                bool
}

type relayPrefaceArithmeticV1 struct{ overflow bool }

func (c *relayPrefaceArithmeticV1) add(values ...uint64) uint64 {
	var n uint64
	for _, v := range values {
		if v > math.MaxUint64-n {
			c.overflow = true
			return 0
		}
		n += v
	}
	return n
}

func (c *relayPrefaceArithmeticV1) mul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		c.overflow = true
		return 0
	}
	return a * b
}

func (c *relayPrefaceArithmeticV1) clone(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return c.add(c.mul(2, n), 8)
}

func cborHeadBytesV1(n uint64) uint64 {
	switch {
	case n < 24:
		return 1
	case n <= math.MaxUint8:
		return 2
	case n <= math.MaxUint16:
		return 3
	case n <= math.MaxUint32:
		return 5
	default:
		return 9
	}
}

// RelayAdmissionPrefaceWorkspaceV1 calculates the constructor's two preface
// graphs and the encoder's preface/wire/CBOR graphs. It does not validate a plan,
// decode policy, allocate, or authorize I/O. The caller separately accounts for
// ValidateV2At/DecodeRuntimeAt and its retained plan/policy. CBOR's 11*n+8192
// envelope and clone's 2*n+8 recurrence are pinned to Go1.26.6/cbor v2.9.2.
func RelayAdmissionPrefaceWorkspaceV1(plan PlanV2) (uint64, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 || len(plan.ProfileContentID) == 0 || len(plan.ProfileContentID) > 128 ||
		len(plan.StrategyID) > 128 || len(plan.Endpoints) == 0 || len(plan.Endpoints) > 4 ||
		len(plan.Routes) == 0 || len(plan.Routes) > 2 || len(plan.PayloadProtocols) == 0 || len(plan.PayloadProtocols) > 4 {
		return 0, ErrRelayAdmissionV1
	}
	c := relayPrefaceArithmeticV1{}
	item := func(n uint64) uint64 { return c.add(cborHeadBytesV1(n), n) }
	text := func(s string) uint64 { return item(uint64(len(s))) }
	var dnsN, dnsBytes, dnsBacking uint64
	switch plan.IPMode {
	case runtimepolicy.IPModeIPv4Only:
		dnsN, dnsBytes, dnsBacking = 1, item(4), c.clone(4)
	case runtimepolicy.IPModeIPv6Only:
		dnsN, dnsBytes, dnsBacking = 1, item(16), c.clone(16)
	case runtimepolicy.IPModeDualStack:
		dnsN, dnsBytes, dnsBacking = 2, c.add(item(4), item(16)), c.add(c.clone(4), c.clone(16))
	default:
		return 0, ErrRelayAdmissionV1
	}
	routesN := uint64(len(plan.Routes))
	routeBytes, routeBacking := cborHeadBytesV1(routesN), uint64(0)
	for _, r := range plan.Routes {
		if len(r.Address) != 4 && len(r.Address) != 16 {
			return 0, ErrRelayAdmissionV1
		}
		routeBytes = c.add(routeBytes, 1, item(uint64(len(r.Address))), cborHeadBytesV1(uint64(r.PrefixLen)))
		routeBacking = c.add(routeBacking, c.clone(uint64(len(r.Address))))
	}
	protocolsN := uint64(len(plan.PayloadProtocols))
	protocolBytes := cborHeadBytesV1(protocolsN)
	for _, p := range plan.PayloadProtocols {
		if len(p) > 6 {
			return 0, ErrRelayAdmissionV1
		}
		protocolBytes = c.add(protocolBytes, text(string(p)))
	}
	n := c.add(1, text(RelayAdmissionPrefaceVersionV1), text(plan.ProfileContentID), cborHeadBytesV1(plan.ProfileGeneration),
		item(32), item(32), text(plan.StrategyID), item(uint64(len(plan.Endpoints))), text(string(plan.IPMode)),
		routeBytes, cborHeadBytesV1(dnsN), dnsBytes, cborHeadBytesV1(uint64(plan.MTU)), protocolBytes,
		cborHeadBytesV1(uint64(plan.MaxQueuePackets)), cborHeadBytesV1(uint64(plan.MaxIncompleteOps)),
		cborHeadBytesV1(uint64(plan.MaxReconnectAttempts)), 1)
	if n > MaxRelayAdmissionPrefaceBytesV1 {
		return 0, ErrRelayAdmissionV1
	}
	common := c.add(c.clone(uint64(len(plan.Endpoints))), c.clone(c.mul(routesN, uint64(unsafe.Sizeof(runtimepolicy.PrefixV2{})))),
		routeBacking, dnsBacking, c.clone(c.mul(protocolsN, uint64(unsafe.Sizeof(runtimepolicy.PayloadProtocolV2(""))))))
	// effectiveDNSServers reserves two descriptors; Clone makes exact len.
	constructor := c.add(c.mul(3, uint64(unsafe.Sizeof(RelayAdmissionPrefaceV1{}))), c.mul(2, common), c.mul(c.add(2, dnsN), uint64(unsafe.Sizeof([]byte{}))))
	preface := c.add(common, c.mul(dnsN, uint64(unsafe.Sizeof([]byte{}))))
	wire := c.add(c.mul(routesN, uint64(unsafe.Sizeof(relayAdmissionPrefixWireV1{}))), routeBacking,
		c.mul(dnsN, uint64(unsafe.Sizeof([]byte{}))), dnsBacking, c.mul(protocolsN, uint64(unsafe.Sizeof(""))),
		c.clone(uint64(len(plan.Endpoints))), c.mul(2, c.clone(32)))
	encoder := c.add(c.mul(3, uint64(unsafe.Sizeof(RelayAdmissionPrefaceV1{}))), c.mul(2, uint64(unsafe.Sizeof(relayAdmissionPrefaceWireV1{}))), preface, wire, c.mul(11, n), 8192, 4)
	if c.overflow {
		return 0, ErrRelayAdmissionV1
	}
	return max(constructor, encoder), nil
}

func EncodeRelayAdmissionPrefaceV1(preface RelayAdmissionPrefaceV1) ([]byte, error) {
	if validateRelayAdmissionPrefaceV1(preface) != nil {
		return nil, ErrRelayAdmissionV1
	}
	wire := relayAdmissionPrefaceToWireV1(preface)
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, ErrRelayAdmissionV1
	}
	encoded, err := mode.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxRelayAdmissionPrefaceBytesV1 {
		return nil, ErrRelayAdmissionV1
	}
	return encoded, nil
}

func DecodeRelayAdmissionPrefaceV1(encoded []byte) (RelayAdmissionPrefaceV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxRelayAdmissionPrefaceBytesV1 {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	mode, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 8, MaxArrayElements: 32, MaxMapPairs: 16,
		IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, IntDec: cbor.IntDecConvertNone,
		UTF8: cbor.UTF8RejectInvalid, BignumTag: cbor.BignumTagForbidden,
	}.DecMode()
	if err != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	var wire relayAdmissionPrefaceWireV1
	if mode.Unmarshal(encoded, &wire) != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	preface, err := relayAdmissionPrefaceFromWireV1(wire)
	if err != nil {
		return RelayAdmissionPrefaceV1{}, err
	}
	reencoded, err := EncodeRelayAdmissionPrefaceV1(preface)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	return preface.Clone(), nil
}

func WriteRelayAdmissionPrefaceV1(writer io.Writer, preface RelayAdmissionPrefaceV1) error {
	if writer == nil {
		return ErrRelayAdmissionV1
	}
	encoded, err := EncodeRelayAdmissionPrefaceV1(preface)
	if err != nil {
		return ErrRelayAdmissionV1
	}
	defer clear(encoded)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if writeRelayAdmissionBytesV1(writer, length[:]) != nil || writeRelayAdmissionBytesV1(writer, encoded) != nil {
		return ErrRelayAdmissionV1
	}
	return nil
}

func ReadRelayAdmissionPrefaceV1(reader io.Reader) (RelayAdmissionPrefaceV1, error) {
	if reader == nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > MaxRelayAdmissionPrefaceBytesV1 {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	encoded := make([]byte, size)
	defer clear(encoded)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	return DecodeRelayAdmissionPrefaceV1(encoded)
}

func writeRelayAdmissionBytesV1(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil || count <= 0 || count > len(value) {
			return ErrRelayAdmissionV1
		}
		value = value[count:]
	}
	return nil
}

func validateRelayAdmissionPrefaceV1(preface RelayAdmissionPrefaceV1) error {
	request := preface.Requested
	if preface.Version != RelayAdmissionPrefaceVersionV1 || !boundedV2(preface.ProfileContentID, 128) ||
		preface.ProfileGeneration == 0 || preface.ActivationReceiptDigest == ([32]byte{}) || preface.PlanDigest == ([32]byte{}) ||
		request.StrategyID != supportedStrategyTLS13TCP || len(request.EndpointIndexes) == 0 || len(request.EndpointIndexes) > 4 ||
		!strictUint8V1(request.EndpointIndexes) || !knownIPModeV1(request.IPMode) || len(request.Routes) == 0 || len(request.Routes) > 2 ||
		len(request.DNSServers) == 0 || len(request.DNSServers) > 2 || request.MTU != 1280 ||
		len(request.PayloadProtocols) == 0 || len(request.PayloadProtocols) > 4 || request.MaxQueuePackets == 0 ||
		request.MaxIncompleteOps == 0 || request.MaxReconnectAttempts == 0 || request.AllowLAN {
		return ErrRelayAdmissionV1
	}
	for _, prefix := range request.Routes {
		if len(prefix.Address) != 4 && len(prefix.Address) != 16 {
			return ErrRelayAdmissionV1
		}
	}
	for _, server := range request.DNSServers {
		if len(server) != 4 && len(server) != 16 {
			return ErrRelayAdmissionV1
		}
	}
	for i, protocol := range request.PayloadProtocols {
		if !knownPayloadProtocolV1(protocol) || i > 0 && request.PayloadProtocols[i-1] >= protocol {
			return ErrRelayAdmissionV1
		}
	}
	return nil
}

func effectiveEndpointIndexesV1(policy runtimepolicy.PolicyV2, endpoints []runtimepolicy.EndpointV2) ([]uint8, error) {
	indexes := make([]uint8, 0, len(endpoints))
	position := 0
	for _, endpoint := range endpoints {
		found := false
		for position < len(policy.Fallback.EndpointIndexes) {
			index := policy.Fallback.EndpointIndexes[position]
			position++
			candidate := policy.Endpoints[index]
			if endpoint.Priority == candidate.Priority && endpoint.Family == candidate.Family && endpoint.Port == candidate.Port && bytes.Equal(endpoint.Address, candidate.Address) {
				indexes = append(indexes, index)
				found = true
				break
			}
		}
		if !found {
			return nil, ErrRelayAdmissionV1
		}
	}
	return indexes, nil
}

func effectiveDNSServersV1(plan PlanV2) [][]byte {
	servers := make([][]byte, 0, 2)
	if plan.IPMode == runtimepolicy.IPModeIPv4Only || plan.IPMode == runtimepolicy.IPModeDualStack {
		servers = append(servers, bytes.Clone(plan.DNSIPv4[:]))
	}
	if plan.IPMode == runtimepolicy.IPModeIPv6Only || plan.IPMode == runtimepolicy.IPModeDualStack {
		servers = append(servers, bytes.Clone(plan.DNSIPv6[:]))
	}
	return servers
}

func relayAdmissionPrefaceToWireV1(preface RelayAdmissionPrefaceV1) relayAdmissionPrefaceWireV1 {
	routes := make([]relayAdmissionPrefixWireV1, len(preface.Requested.Routes))
	for i, prefix := range preface.Requested.Routes {
		routes[i] = relayAdmissionPrefixWireV1{Address: bytes.Clone(prefix.Address), PrefixLen: prefix.PrefixLen}
	}
	protocols := make([]string, len(preface.Requested.PayloadProtocols))
	for i, protocol := range preface.Requested.PayloadProtocols {
		protocols[i] = string(protocol)
	}
	return relayAdmissionPrefaceWireV1{
		Version: preface.Version, ProfileContentID: preface.ProfileContentID, ProfileGeneration: preface.ProfileGeneration,
		ActivationReceiptDigest: bytes.Clone(preface.ActivationReceiptDigest[:]), PlanDigest: bytes.Clone(preface.PlanDigest[:]),
		StrategyID: preface.Requested.StrategyID, EndpointIndexes: slices.Clone(preface.Requested.EndpointIndexes), IPMode: string(preface.Requested.IPMode),
		Routes: routes, DNSServers: cloneBytes2DV2(preface.Requested.DNSServers), MTU: preface.Requested.MTU,
		PayloadProtocols: protocols, MaxQueuePackets: preface.Requested.MaxQueuePackets, MaxIncompleteOps: preface.Requested.MaxIncompleteOps,
		MaxReconnectAttempts: preface.Requested.MaxReconnectAttempts, AllowLAN: preface.Requested.AllowLAN,
	}
}

func relayAdmissionPrefaceFromWireV1(wire relayAdmissionPrefaceWireV1) (RelayAdmissionPrefaceV1, error) {
	if len(wire.ActivationReceiptDigest) != 32 || len(wire.PlanDigest) != 32 {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	preface := RelayAdmissionPrefaceV1{
		Version: wire.Version, ProfileContentID: wire.ProfileContentID, ProfileGeneration: wire.ProfileGeneration,
		Requested: NarrowingRequestV2{
			StrategyID: wire.StrategyID, EndpointIndexes: slices.Clone(wire.EndpointIndexes), IPMode: runtimepolicy.IPModeV2(wire.IPMode),
			DNSServers: cloneBytes2DV2(wire.DNSServers), MTU: wire.MTU, MaxQueuePackets: wire.MaxQueuePackets,
			MaxIncompleteOps: wire.MaxIncompleteOps, MaxReconnectAttempts: wire.MaxReconnectAttempts, AllowLAN: wire.AllowLAN,
		},
	}
	copy(preface.ActivationReceiptDigest[:], wire.ActivationReceiptDigest)
	copy(preface.PlanDigest[:], wire.PlanDigest)
	preface.Requested.Routes = make([]runtimepolicy.PrefixV2, len(wire.Routes))
	for i, prefix := range wire.Routes {
		preface.Requested.Routes[i] = runtimepolicy.PrefixV2{Address: bytes.Clone(prefix.Address), PrefixLen: prefix.PrefixLen}
	}
	preface.Requested.PayloadProtocols = make([]runtimepolicy.PayloadProtocolV2, len(wire.PayloadProtocols))
	for i, protocol := range wire.PayloadProtocols {
		preface.Requested.PayloadProtocols[i] = runtimepolicy.PayloadProtocolV2(protocol)
	}
	if validateRelayAdmissionPrefaceV1(preface) != nil {
		return RelayAdmissionPrefaceV1{}, ErrRelayAdmissionV1
	}
	return preface, nil
}

func strictUint8V1(values []uint8) bool {
	for i := range values {
		if i > 0 && values[i-1] >= values[i] {
			return false
		}
	}
	return true
}

func knownIPModeV1(mode runtimepolicy.IPModeV2) bool {
	return mode == runtimepolicy.IPModeIPv4Only || mode == runtimepolicy.IPModeIPv6Only || mode == runtimepolicy.IPModeDualStack
}

func knownPayloadProtocolV1(protocol runtimepolicy.PayloadProtocolV2) bool {
	switch protocol {
	case runtimepolicy.PayloadProtocolICMP, runtimepolicy.PayloadProtocolICMPv6, runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP:
		return true
	default:
		return false
	}
}
