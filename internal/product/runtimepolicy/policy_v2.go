// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package runtimepolicy implements the signed, product-facing runtime policy.
// It deliberately admits only transport authority required by release clients
// and relays.  It neither reads files nor performs network I/O.
package runtimepolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/protocol/liveprogram"
)

const (
	SchemaVersionV2       uint64 = 2
	WireProtocolV1               = "kurd-wire-v1"
	CarrierFamilyTLS13TCP        = "tls13-tcp"
	MaxEncodedBytes              = 64 << 10
	MaxLiveProgramBytes          = 48 << 10
	policyFieldCount             = 25
)

type ErrorCategory string

const (
	ErrorInvalid      ErrorCategory = "invalid"
	ErrorSize         ErrorCategory = "size"
	ErrorSchema       ErrorCategory = "schema"
	ErrorNonCanonical ErrorCategory = "non-canonical"
	ErrorBinding      ErrorCategory = "binding"
)

// Error is intentionally categorical.  Its text contains no policy material.
type Error struct{ Category ErrorCategory }

func (e *Error) Error() string { return "runtime policy: " + string(e.Category) }

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}

func fail(category ErrorCategory) error { return &Error{Category: category} }

type EndpointV2 struct {
	Priority uint8
	Address  []byte
	Family   uint8
	Port     uint16
}

type PrefixV2 struct {
	Address   []byte
	PrefixLen uint8
}

type IPModeV2 string

const (
	IPModeDualStack IPModeV2 = "dual-stack"
	IPModeIPv4Only  IPModeV2 = "ipv4-only"
	IPModeIPv6Only  IPModeV2 = "ipv6-only"
)

type PayloadProtocolV2 string

const (
	PayloadProtocolICMP   PayloadProtocolV2 = "icmp"
	PayloadProtocolICMPv6 PayloadProtocolV2 = "icmpv6"
	PayloadProtocolTCP    PayloadProtocolV2 = "tcp"
	PayloadProtocolUDP    PayloadProtocolV2 = "udp"
)

type LimitsV2 struct {
	MaxPackets           uint32
	MaxQueuedPackets     uint32
	MaxFrames            uint32
	MaxMessages          uint32
	MaxIdleSeconds       uint32
	MaxReconnectAttempts uint32
}

type FallbackV2 struct {
	EndpointIndexes       []uint8
	TotalAttempts         uint32
	AttemptTimeoutSeconds uint32
	MaxBackoffSeconds     uint32
}

// PolicyV2 is the deterministic inner policy carried as CanonicalProfileV1.Policy.
// The admission digest binds precisely labels 1 through 24.
type PolicyV2 struct {
	SchemaVersion        uint64
	WireProtocol         string
	CarrierFamily        string
	LiveProgram          []byte
	LiveProgramSHA256    [32]byte
	ClientAuthKeyID      string
	ClientAuthPublic     [32]byte
	RelayAuthKeyID       string
	RelayAuthPublic      [32]byte
	TLSServerName        string
	TLSLeafDER           []byte
	TLSLeafSHA256        [32]byte
	Endpoints            []EndpointV2
	ClientIPv4           []byte
	DNSIPv4              []byte
	ClientIPv6           []byte
	DNSIPv6              []byte
	Routes               []PrefixV2
	DNSServers           [][]byte
	MTU                  uint16
	AllowedIPModes       []IPModeV2
	AllowedProtocols     []PayloadProtocolV2
	Limits               LimitsV2
	Fallback             FallbackV2
	RelayAdmissionDigest [32]byte
}

func (p PolicyV2) Clone() PolicyV2 {
	p.LiveProgram = bytes.Clone(p.LiveProgram)
	p.TLSLeafDER = bytes.Clone(p.TLSLeafDER)
	p.Endpoints = append([]EndpointV2(nil), p.Endpoints...)
	for i := range p.Endpoints {
		p.Endpoints[i].Address = bytes.Clone(p.Endpoints[i].Address)
	}
	p.ClientIPv4 = bytes.Clone(p.ClientIPv4)
	p.DNSIPv4 = bytes.Clone(p.DNSIPv4)
	p.ClientIPv6 = bytes.Clone(p.ClientIPv6)
	p.DNSIPv6 = bytes.Clone(p.DNSIPv6)
	p.Routes = append([]PrefixV2(nil), p.Routes...)
	for i := range p.Routes {
		p.Routes[i].Address = bytes.Clone(p.Routes[i].Address)
	}
	p.DNSServers = cloneBytes2D(p.DNSServers)
	p.AllowedIPModes = append([]IPModeV2(nil), p.AllowedIPModes...)
	p.AllowedProtocols = append([]PayloadProtocolV2(nil), p.AllowedProtocols...)
	p.Fallback.EndpointIndexes = append([]uint8(nil), p.Fallback.EndpointIndexes...)
	return p
}

func EncodeV2(policy PolicyV2) ([]byte, error) {
	if err := validatePolicy(policy, true); err != nil {
		return nil, err
	}
	encoded, err := marshal(policyMap(policy, true))
	if err != nil || len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return nil, fail(ErrorSize)
	}
	return encoded, nil
}

func DecodeV2(encoded []byte) (PolicyV2, error) {
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return PolicyV2{}, fail(ErrorSize)
	}
	if err := validateCore(encoded); err != nil {
		return PolicyV2{}, fail(ErrorNonCanonical)
	}
	fields, err := rawMap(encoded, policyFieldCount)
	if err != nil {
		return PolicyV2{}, err
	}
	var policy PolicyV2
	if err := decodePolicy(fields, &policy); err != nil {
		return PolicyV2{}, err
	}
	if err := validatePolicy(policy, true); err != nil {
		return PolicyV2{}, err
	}
	reencoded, err := EncodeV2(policy)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return PolicyV2{}, fail(ErrorNonCanonical)
	}
	return policy.Clone(), nil
}

// RelayAdmissionDigestV2 recomputes the digest for labels 1 through 24.
// Callers use it during issuance before assigning RelayAdmissionDigest.
func RelayAdmissionDigestV2(policy PolicyV2) ([32]byte, error) {
	if err := validatePolicy(policy, false); err != nil {
		return [32]byte{}, err
	}
	encoded, err := marshal(policyMap(policy, false))
	if err != nil {
		return [32]byte{}, fail(ErrorNonCanonical)
	}
	return sha256.Sum256(encoded), nil
}

// ValidateAgainstEnvelope confirms the exact deterministic policy bytes are
// the bytes authenticated by the enclosing canonical profile.
func (p PolicyV2) ValidateAgainstEnvelope(profile envelope.CanonicalProfileV1) error {
	encoded, err := EncodeV2(p)
	if err != nil || !bytes.Equal(encoded, profile.Policy) {
		return fail(ErrorBinding)
	}
	return nil
}

func validatePolicy(p PolicyV2, requireDigest bool) error {
	if p.SchemaVersion != SchemaVersionV2 || p.WireProtocol != WireProtocolV1 || p.CarrierFamily != CarrierFamilyTLS13TCP {
		return fail(ErrorInvalid)
	}
	program, err := validateLiveProgram(p.LiveProgram, p.LiveProgramSHA256)
	if err != nil {
		return err
	}
	if !keyIDMatches(p.ClientAuthKeyID, p.ClientAuthPublic) || !boundedRelayKeyID(p.RelayAuthKeyID) {
		return fail(ErrorBinding)
	}
	if err := validateTLS(p.TLSServerName, p.TLSLeafDER, p.TLSLeafSHA256); err != nil {
		return err
	}
	if err := validateAddresses(p); err != nil {
		return err
	}
	if int(p.MTU) > program.Limits.MaxFrameBytes {
		return fail(ErrorInvalid)
	}
	if err := validateModesAndProtocols(p.AllowedIPModes, p.AllowedProtocols, p.ClientIPv4, p.ClientIPv6); err != nil {
		return err
	}
	if err := validateLimits(p.Limits, program); err != nil {
		return err
	}
	if err := validateFallback(p.Fallback, len(p.Endpoints)); err != nil {
		return err
	}
	if requireDigest {
		digest, err := RelayAdmissionDigestV2(p)
		if err != nil || digest != p.RelayAdmissionDigest {
			return fail(ErrorBinding)
		}
	}
	return nil
}

func validateLiveProgram(encoded []byte, expected [32]byte) (liveprogram.ProgramV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxLiveProgramBytes || sha256.Sum256(encoded) != expected {
		return liveprogram.ProgramV1{}, fail(ErrorBinding)
	}
	program, err := liveprogram.DecodeV1(encoded)
	if err != nil {
		return liveprogram.ProgramV1{}, fail(ErrorBinding)
	}
	reencoded, err := liveprogram.EncodeV1(program)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return liveprogram.ProgramV1{}, fail(ErrorNonCanonical)
	}
	return program, nil
}

func keyIDMatches(id string, public [32]byte) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return false
	}
	digest := sha256.Sum256(public[:])
	return id == hex.EncodeToString(digest[:16])
}

func boundedRelayKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validateTLS(serverName string, der []byte, expected [32]byte) error {
	if !validServerName(serverName) || len(der) == 0 || len(der) > 4096 || sha256.Sum256(der) != expected {
		return fail(ErrorInvalid)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) || leaf.CheckSignatureFrom(leaf) != nil || leaf.VerifyHostname(serverName) != nil {
		return fail(ErrorBinding)
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return nil
		}
	}
	return fail(ErrorBinding)
}

func validServerName(value string) bool {
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String() == value
	}
	if strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

func validateAddresses(p PolicyV2) error {
	if len(p.Endpoints) == 0 || len(p.Endpoints) > 4 || p.MTU != 1280 {
		return fail(ErrorInvalid)
	}
	for i, endpoint := range p.Endpoints {
		if endpoint.Port == 0 || !validAddress(endpoint.Address, endpoint.Family) || (i > 0 && p.Endpoints[i-1].Priority >= endpoint.Priority) {
			return fail(ErrorInvalid)
		}
	}
	if !validOptionalAddress(p.ClientIPv4, 4) || !validOptionalAddress(p.DNSIPv4, 4) || !validOptionalAddress(p.ClientIPv6, 6) || !validOptionalAddress(p.DNSIPv6, 6) ||
		(len(p.ClientIPv4) == 0) != (len(p.DNSIPv4) == 0) || (len(p.ClientIPv6) == 0) != (len(p.DNSIPv6) == 0) {
		return fail(ErrorInvalid)
	}
	if err := validateRoutes(p.Routes, p.ClientIPv4, p.ClientIPv6); err != nil {
		return err
	}
	return validateDNS(p.DNSServers, p.DNSIPv4, p.DNSIPv6)
}

func validOptionalAddress(value []byte, family uint8) bool {
	return len(value) == 0 || validAddress(value, family)
}

func validAddress(value []byte, family uint8) bool {
	want := 0
	if family == 4 {
		want = 4
	} else if family == 6 {
		want = 16
	}
	if len(value) != want {
		return false
	}
	address, ok := netip.AddrFromSlice(value)
	return ok && address.IsValid() && !address.IsUnspecified() && !address.IsMulticast()
}

func validateRoutes(routes []PrefixV2, ipv4, ipv6 []byte) error {
	want := 0
	if len(ipv4) != 0 {
		want++
	}
	if len(ipv6) != 0 {
		want++
	}
	if len(routes) != want {
		return fail(ErrorInvalid)
	}
	position := 0
	if len(ipv4) != 0 {
		if len(routes[position].Address) != 4 || routes[position].PrefixLen != 0 || !allZero(routes[position].Address) {
			return fail(ErrorInvalid)
		}
		position++
	}
	if len(ipv6) != 0 && (len(routes[position].Address) != 16 || routes[position].PrefixLen != 0 || !allZero(routes[position].Address)) {
		return fail(ErrorInvalid)
	}
	return nil
}

func validateDNS(values [][]byte, ipv4, ipv6 []byte) error {
	want := make([][]byte, 0, 2)
	if len(ipv4) != 0 {
		want = append(want, ipv4)
	}
	if len(ipv6) != 0 {
		want = append(want, ipv6)
	}
	if len(values) != len(want) {
		return fail(ErrorInvalid)
	}
	for i := range want {
		if !bytes.Equal(values[i], want[i]) {
			return fail(ErrorBinding)
		}
	}
	return nil
}

func validateModesAndProtocols(modes []IPModeV2, protocols []PayloadProtocolV2, ipv4, ipv6 []byte) error {
	if len(modes) == 0 || !sortedUniqueModes(modes) || len(protocols) < 2 || !sortedUniqueProtocols(protocols) {
		return fail(ErrorInvalid)
	}
	for _, mode := range modes {
		if mode == IPModeIPv4Only && len(ipv4) == 0 || mode == IPModeIPv6Only && len(ipv6) == 0 || mode == IPModeDualStack && (len(ipv4) == 0 || len(ipv6) == 0) {
			return fail(ErrorInvalid)
		}
	}
	haveTCP, haveUDP := false, false
	for _, protocol := range protocols {
		haveTCP = haveTCP || protocol == PayloadProtocolTCP
		haveUDP = haveUDP || protocol == PayloadProtocolUDP
	}
	if !haveTCP || !haveUDP {
		return fail(ErrorInvalid)
	}
	return nil
}

func sortedUniqueModes(values []IPModeV2) bool {
	for i, value := range values {
		if value != IPModeIPv4Only && value != IPModeIPv6Only && value != IPModeDualStack || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func sortedUniqueProtocols(values []PayloadProtocolV2) bool {
	for i, value := range values {
		if value != PayloadProtocolTCP && value != PayloadProtocolUDP && value != PayloadProtocolICMP && value != PayloadProtocolICMPv6 || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func validateLimits(l LimitsV2, program liveprogram.ProgramV1) error {
	if l.MaxPackets == 0 || l.MaxQueuedPackets == 0 || l.MaxFrames == 0 || l.MaxMessages == 0 || l.MaxIdleSeconds == 0 || l.MaxReconnectAttempts == 0 ||
		l.MaxPackets > 1<<24 || l.MaxQueuedPackets > 1<<16 || l.MaxFrames > 1<<24 || l.MaxMessages > uint32(program.Limits.MaxSessionMessages) || l.MaxFrames > uint32(program.Limits.MaxSessionMessages) ||
		uint64(l.MaxIdleSeconds)*1000 > uint64(program.Limits.MaxSessionMillis) || l.MaxReconnectAttempts > 64 {
		return fail(ErrorInvalid)
	}
	return nil
}

func validateFallback(f FallbackV2, endpointCount int) error {
	if len(f.EndpointIndexes) == 0 || len(f.EndpointIndexes) > endpointCount || f.TotalAttempts == 0 || f.TotalAttempts > 16 || f.AttemptTimeoutSeconds == 0 || f.AttemptTimeoutSeconds > 60 || f.MaxBackoffSeconds < f.AttemptTimeoutSeconds || f.MaxBackoffSeconds > 600 {
		return fail(ErrorInvalid)
	}
	for i, index := range f.EndpointIndexes {
		if int(index) >= endpointCount || i > 0 && f.EndpointIndexes[i-1] >= index {
			return fail(ErrorInvalid)
		}
	}
	return nil
}

func policyMap(p PolicyV2, includeDigest bool) map[uint64]any {
	values := map[uint64]any{
		1: p.SchemaVersion, 2: p.WireProtocol, 3: p.CarrierFamily, 4: bytes.Clone(p.LiveProgram), 5: p.LiveProgramSHA256[:],
		6: p.ClientAuthKeyID, 7: p.ClientAuthPublic[:], 8: p.RelayAuthKeyID, 9: p.RelayAuthPublic[:], 10: p.TLSServerName,
		11: bytes.Clone(p.TLSLeafDER), 12: p.TLSLeafSHA256[:], 13: endpointMaps(p.Endpoints), 14: bytes.Clone(p.ClientIPv4),
		15: bytes.Clone(p.DNSIPv4), 16: bytes.Clone(p.ClientIPv6), 17: bytes.Clone(p.DNSIPv6), 18: prefixMaps(p.Routes),
		19: cloneBytes2D(p.DNSServers), 20: p.MTU, 21: modeValues(p.AllowedIPModes), 22: protocolValues(p.AllowedProtocols),
		23: map[uint64]any{1: p.Limits.MaxPackets, 2: p.Limits.MaxQueuedPackets, 3: p.Limits.MaxFrames, 4: p.Limits.MaxMessages, 5: p.Limits.MaxIdleSeconds, 6: p.Limits.MaxReconnectAttempts},
		24: map[uint64]any{1: append([]uint8(nil), p.Fallback.EndpointIndexes...), 2: p.Fallback.TotalAttempts, 3: p.Fallback.AttemptTimeoutSeconds, 4: p.Fallback.MaxBackoffSeconds},
	}
	if includeDigest {
		values[25] = p.RelayAdmissionDigest[:]
	}
	return values
}

func endpointMaps(values []EndpointV2) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = map[uint64]any{1: value.Priority, 2: bytes.Clone(value.Address), 3: value.Family, 4: value.Port}
	}
	return result
}

func prefixMaps(values []PrefixV2) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = map[uint64]any{1: bytes.Clone(value.Address), 2: value.PrefixLen}
	}
	return result
}

func modeValues(values []IPModeV2) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = string(values[i])
	}
	return result
}

func protocolValues(values []PayloadProtocolV2) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = string(values[i])
	}
	return result
}

func decodePolicy(fields map[uint64]cbor.RawMessage, p *PolicyV2) error {
	values := []any{&p.SchemaVersion, &p.WireProtocol, &p.CarrierFamily, &p.LiveProgram, nil, &p.ClientAuthKeyID, nil, &p.RelayAuthKeyID, nil, &p.TLSServerName, &p.TLSLeafDER, nil, nil, &p.ClientIPv4, &p.DNSIPv4, &p.ClientIPv6, &p.DNSIPv6, nil, &p.DNSServers, &p.MTU, nil, nil, nil, nil}
	for i, destination := range values {
		label := uint64(i + 1)
		if destination != nil && decode(fields[label], destination) != nil {
			return fail(ErrorSchema)
		}
	}
	if fixedBytes(fields[5], p.LiveProgramSHA256[:]) != nil || fixedBytes(fields[7], p.ClientAuthPublic[:]) != nil || fixedBytes(fields[9], p.RelayAuthPublic[:]) != nil || fixedBytes(fields[12], p.TLSLeafSHA256[:]) != nil || fixedBytes(fields[25], p.RelayAdmissionDigest[:]) != nil {
		return fail(ErrorSchema)
	}
	var err error
	if p.Endpoints, err = decodeEndpoints(fields[13]); err != nil {
		return err
	}
	if p.Routes, err = decodePrefixes(fields[18]); err != nil {
		return err
	}
	if p.AllowedIPModes, err = decodeModes(fields[21]); err != nil {
		return err
	}
	if p.AllowedProtocols, err = decodeProtocols(fields[22]); err != nil {
		return err
	}
	if p.Limits, err = decodeLimits(fields[23]); err != nil {
		return err
	}
	p.Fallback, err = decodeFallback(fields[24])
	return err
}

func decodeEndpoints(raw []byte) ([]EndpointV2, error) {
	var values []cbor.RawMessage
	if decode(raw, &values) != nil || len(values) == 0 || len(values) > 4 {
		return nil, fail(ErrorSchema)
	}
	result := make([]EndpointV2, len(values))
	for i, value := range values {
		fields, err := rawMap(value, 4)
		if err != nil {
			return nil, err
		}
		if decode(fields[1], &result[i].Priority) != nil || decode(fields[2], &result[i].Address) != nil || decode(fields[3], &result[i].Family) != nil || decode(fields[4], &result[i].Port) != nil {
			return nil, fail(ErrorSchema)
		}
	}
	return result, nil
}

func decodePrefixes(raw []byte) ([]PrefixV2, error) {
	var values []cbor.RawMessage
	if decode(raw, &values) != nil || len(values) == 0 || len(values) > 2 {
		return nil, fail(ErrorSchema)
	}
	result := make([]PrefixV2, len(values))
	for i, value := range values {
		fields, err := rawMap(value, 2)
		if err != nil {
			return nil, err
		}
		if decode(fields[1], &result[i].Address) != nil || decode(fields[2], &result[i].PrefixLen) != nil {
			return nil, fail(ErrorSchema)
		}
	}
	return result, nil
}

func decodeModes(raw []byte) ([]IPModeV2, error) {
	var values []string
	if decode(raw, &values) != nil {
		return nil, fail(ErrorSchema)
	}
	result := make([]IPModeV2, len(values))
	for i := range values {
		result[i] = IPModeV2(values[i])
	}
	return result, nil
}

func decodeProtocols(raw []byte) ([]PayloadProtocolV2, error) {
	var values []string
	if decode(raw, &values) != nil {
		return nil, fail(ErrorSchema)
	}
	result := make([]PayloadProtocolV2, len(values))
	for i := range values {
		result[i] = PayloadProtocolV2(values[i])
	}
	return result, nil
}

func decodeLimits(raw []byte) (LimitsV2, error) {
	fields, err := rawMap(raw, 6)
	if err != nil {
		return LimitsV2{}, err
	}
	var result LimitsV2
	values := []any{&result.MaxPackets, &result.MaxQueuedPackets, &result.MaxFrames, &result.MaxMessages, &result.MaxIdleSeconds, &result.MaxReconnectAttempts}
	for i, destination := range values {
		if decode(fields[uint64(i+1)], destination) != nil {
			return LimitsV2{}, fail(ErrorSchema)
		}
	}
	return result, nil
}

func decodeFallback(raw []byte) (FallbackV2, error) {
	fields, err := rawMap(raw, 4)
	if err != nil {
		return FallbackV2{}, err
	}
	var result FallbackV2
	if decode(fields[1], &result.EndpointIndexes) != nil || decode(fields[2], &result.TotalAttempts) != nil || decode(fields[3], &result.AttemptTimeoutSeconds) != nil || decode(fields[4], &result.MaxBackoffSeconds) != nil {
		return FallbackV2{}, fail(ErrorSchema)
	}
	return result, nil
}

func rawMap(raw []byte, count int) (map[uint64]cbor.RawMessage, error) {
	var fields map[uint64]cbor.RawMessage
	if decode(raw, &fields) != nil || len(fields) != count {
		return nil, fail(ErrorSchema)
	}
	for label := uint64(1); label <= uint64(count); label++ {
		if _, ok := fields[label]; !ok {
			return nil, fail(ErrorSchema)
		}
	}
	return fields, nil
}

func decode(raw []byte, destination any) error {
	mode, err := strictMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(raw, destination)
}

func fixedBytes(raw []byte, destination []byte) error {
	var value []byte
	if decode(raw, &value) != nil || len(value) != len(destination) {
		return errors.New("fixed")
	}
	copy(destination, value)
	return nil
}

func marshal(value any) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

func validateCore(encoded []byte) error {
	mode, err := strictMode()
	if err != nil {
		return err
	}
	var value any
	if err = mode.Unmarshal(encoded, &value); err != nil {
		return err
	}
	canonical, err := marshal(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return errors.New("noncanonical")
	}
	return nil
}

func strictMode() (cbor.DecMode, error) {
	return cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 32, MaxArrayElements: 64, MaxMapPairs: 32, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, IntDec: cbor.IntDecConvertNone, UTF8: cbor.UTF8RejectInvalid, BignumTag: cbor.BignumTagForbidden}.DecMode()
}

func cloneBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = bytes.Clone(values[i])
	}
	return result
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
