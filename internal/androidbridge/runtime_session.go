// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
)

const (
	runtimeOpenMagic        = "KRS1"
	runtimeSnapshotMagic    = "KSS1"
	runtimeWireVersion      = byte(1)
	runtimeOpenHeaderBytes  = 26
	runtimeSnapshotFixed    = 102
	MaxRuntimeOpenBytes     = MaxVerifyRequestBytes + MaxBridgeResultBytes + 32*1024
	MaxRuntimeSnapshotBytes = 32 * 1024
	MaxRuntimePayloadBytes  = 32 * 1024
	maxRuntimePackages      = 64
	maxRuntimePackageBytes  = 255
	maxRuntimeIDBytes       = 256
)

type RuntimeSelectionMode uint8

const (
	RuntimeSelectionAutomatic RuntimeSelectionMode = iota + 1
	RuntimeSelectionKurdOnly
	RuntimeSelectionManual
)

type RuntimePerAppMode uint8

const (
	RuntimePerAppAllApps RuntimePerAppMode = iota + 1
	RuntimePerAppIncludeOnly
	RuntimePerAppExcludeSelected
)

type RuntimeIPMode uint8

const (
	RuntimeIPAuto RuntimeIPMode = iota + 1
	RuntimeIPV4Only
	RuntimeIPV6Only
	RuntimeIPDualStack
)

type RuntimeDNSMode uint8

const (
	RuntimeDNSInternal RuntimeDNSMode = iota + 1
	RuntimeDNSCustom
)

type RuntimePolicyRequest struct {
	SelectionMode    RuntimeSelectionMode
	ManualStrategyID string
	PerAppMode       RuntimePerAppMode
	Packages         []string
	IPMode           RuntimeIPMode
	DNSMode          RuntimeDNSMode
	CustomDNS        string
	MTU              uint16
	Metered          bool
	AllowLAN         bool
}

type RuntimeOpenRequest struct {
	VerifyRequest    []byte
	ActivationRecord []byte
	Policy           RuntimePolicyRequest
}

type RuntimeSessionSnapshot struct {
	Generation          uint64
	PlanDigest          [32]byte
	ContentFingerprint  [16]byte
	StrategyFingerprint [16]byte
	RelayFingerprint    [16]byte
	SelectionMode       RuntimeSelectionMode
	PerAppMode          RuntimePerAppMode
	Packages            []string
	IPMode              RuntimeIPMode
	DNSMode             RuntimeDNSMode
	MTU                 uint16
	Metered             bool
	LoopbackOnly        bool
}

type runtimeSessionHandle struct {
	snapshot RuntimeSessionSnapshot
}

func (state *runtimeSessionHandle) Destroy() {
	if state == nil {
		return
	}
	state.snapshot = RuntimeSessionSnapshot{}
}

func EncodeRuntimeOpenRequest(request RuntimeOpenRequest) ([]byte, error) {
	policy, err := normalizeRuntimePolicy(request.Policy)
	if err != nil || len(request.VerifyRequest) == 0 || len(request.VerifyRequest) > MaxVerifyRequestBytes ||
		len(request.ActivationRecord) == 0 || len(request.ActivationRecord) > MaxBridgeResultBytes {
		return nil, errors.New("androidbridge: invalid runtime open request")
	}
	manual := []byte(policy.ManualStrategyID)
	customDNS := []byte(policy.CustomDNS)
	size := runtimeOpenHeaderBytes + len(manual) + len(customDNS) +
		len(request.VerifyRequest) + len(request.ActivationRecord)
	for _, value := range policy.Packages {
		size += 2 + len(value)
	}
	if size > MaxRuntimeOpenBytes {
		return nil, errors.New("androidbridge: runtime open request too large")
	}
	out := make([]byte, size)
	copy(out[:4], runtimeOpenMagic)
	out[4] = runtimeWireVersion
	out[5] = byte(policy.SelectionMode)
	out[6] = byte(policy.PerAppMode)
	out[7] = byte(policy.IPMode)
	out[8] = byte(policy.DNSMode)
	if policy.Metered {
		out[9] |= 1
	}
	if policy.AllowLAN {
		out[9] |= 2
	}
	binary.BigEndian.PutUint16(out[10:12], policy.MTU)
	binary.BigEndian.PutUint16(out[12:14], uint16(len(policy.Packages)))
	binary.BigEndian.PutUint16(out[14:16], uint16(len(manual)))
	binary.BigEndian.PutUint16(out[16:18], uint16(len(customDNS)))
	binary.BigEndian.PutUint32(out[18:22], uint32(len(request.VerifyRequest)))
	binary.BigEndian.PutUint32(out[22:26], uint32(len(request.ActivationRecord)))
	offset := runtimeOpenHeaderBytes
	for _, value := range policy.Packages {
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(value)))
		offset += 2
		copy(out[offset:], value)
		offset += len(value)
	}
	copy(out[offset:], manual)
	offset += len(manual)
	copy(out[offset:], customDNS)
	offset += len(customDNS)
	copy(out[offset:], request.VerifyRequest)
	offset += len(request.VerifyRequest)
	copy(out[offset:], request.ActivationRecord)
	return out, nil
}

func DecodeRuntimeOpenRequest(encoded []byte) (RuntimeOpenRequest, error) {
	if len(encoded) < runtimeOpenHeaderBytes || len(encoded) > MaxRuntimeOpenBytes ||
		string(encoded[:4]) != runtimeOpenMagic || encoded[4] != runtimeWireVersion || encoded[9]&^byte(3) != 0 {
		return RuntimeOpenRequest{}, errors.New("androidbridge: invalid runtime open header")
	}
	packageCount := int(binary.BigEndian.Uint16(encoded[12:14]))
	manualLength := int(binary.BigEndian.Uint16(encoded[14:16]))
	dnsLength := int(binary.BigEndian.Uint16(encoded[16:18]))
	verifyLength := int(binary.BigEndian.Uint32(encoded[18:22]))
	activationLength := int(binary.BigEndian.Uint32(encoded[22:26]))
	if packageCount > maxRuntimePackages || manualLength > maxRuntimeIDBytes || dnsLength > 45 ||
		verifyLength <= 0 || verifyLength > MaxVerifyRequestBytes ||
		activationLength <= 0 || activationLength > MaxBridgeResultBytes {
		return RuntimeOpenRequest{}, errors.New("androidbridge: invalid runtime open lengths")
	}
	offset := runtimeOpenHeaderBytes
	packages := make([]string, packageCount)
	for index := range packages {
		if offset+2 > len(encoded) {
			return RuntimeOpenRequest{}, errors.New("androidbridge: truncated runtime package")
		}
		length := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
		offset += 2
		if length == 0 || length > maxRuntimePackageBytes || offset+length > len(encoded) {
			return RuntimeOpenRequest{}, errors.New("androidbridge: invalid runtime package")
		}
		packages[index] = string(encoded[offset : offset+length])
		offset += length
	}
	tail := manualLength + dnsLength + verifyLength + activationLength
	if offset+tail != len(encoded) {
		return RuntimeOpenRequest{}, errors.New("androidbridge: invalid runtime open tail")
	}
	manual := string(encoded[offset : offset+manualLength])
	offset += manualLength
	customDNS := string(encoded[offset : offset+dnsLength])
	offset += dnsLength
	verifyRequest := bytes.Clone(encoded[offset : offset+verifyLength])
	offset += verifyLength
	activation := bytes.Clone(encoded[offset : offset+activationLength])
	request := RuntimeOpenRequest{
		VerifyRequest:    verifyRequest,
		ActivationRecord: activation,
		Policy: RuntimePolicyRequest{
			SelectionMode:    RuntimeSelectionMode(encoded[5]),
			ManualStrategyID: manual,
			PerAppMode:       RuntimePerAppMode(encoded[6]),
			Packages:         packages,
			IPMode:           RuntimeIPMode(encoded[7]),
			DNSMode:          RuntimeDNSMode(encoded[8]),
			CustomDNS:        customDNS,
			MTU:              binary.BigEndian.Uint16(encoded[10:12]),
			Metered:          encoded[9]&1 != 0,
			AllowLAN:         encoded[9]&2 != 0,
		},
	}
	reencoded, err := EncodeRuntimeOpenRequest(request)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return RuntimeOpenRequest{}, errors.New("androidbridge: non-canonical runtime open request")
	}
	return request, nil
}

func OpenRuntimeSession(
	registry *HandleRegistry,
	encoded []byte,
	environment VerificationEnvironment,
) (Handle, RuntimeSessionSnapshot, ErrorCode) {
	if registry == nil || environment == nil {
		return 0, RuntimeSessionSnapshot{}, CodeTrustUnavailable
	}
	request, err := DecodeRuntimeOpenRequest(encoded)
	if err != nil {
		return 0, RuntimeSessionSnapshot{}, CodeInvalidArgument
	}
	preview, code := VerifyAndPreview(request.VerifyRequest, environment)
	if code != CodeOK {
		return 0, RuntimeSessionSnapshot{}, code
	}
	defer preview.Destroy()
	record, err := DecodeActivationRecord(request.ActivationRecord)
	if err != nil || !runtimeRecordMatches(preview, record) {
		return 0, RuntimeSessionSnapshot{}, CodePolicyRejected
	}
	policy, selectedStrategy, selectedRelay, err := authorizeRuntimePolicy(request.Policy, record.Profile)
	if err != nil {
		return 0, RuntimeSessionSnapshot{}, CodePolicyRejected
	}
	policyBytes, err := encodeRuntimePolicyOnly(policy)
	if err != nil {
		return 0, RuntimeSessionSnapshot{}, CodeInternalFailure
	}
	planInput := make([]byte, 0, len(request.ActivationRecord)+len(policyBytes)+len(selectedStrategy)+len(selectedRelay)+32)
	planInput = append(planInput, []byte("kurd-android-runtime-plan-v1\x00")...)
	planInput = append(planInput, request.ActivationRecord...)
	planInput = append(planInput, policyBytes...)
	planInput = append(planInput, selectedStrategy...)
	planInput = append(planInput, 0)
	planInput = append(planInput, selectedRelay...)
	planDigest := sha256.Sum256(planInput)
	clear(planInput)
	contentDigest := sha256.Sum256([]byte(preview.Inspection.ContentSHA256))
	strategyDigest := sha256.Sum256([]byte(selectedStrategy))
	relayDigest := sha256.Sum256([]byte(selectedRelay))
	snapshot := RuntimeSessionSnapshot{
		Generation:    record.Profile.Generation,
		PlanDigest:    planDigest,
		SelectionMode: policy.SelectionMode,
		PerAppMode:    policy.PerAppMode,
		Packages:      append([]string(nil), policy.Packages...),
		IPMode:        policy.IPMode,
		DNSMode:       policy.DNSMode,
		MTU:           policy.MTU,
		Metered:       policy.Metered,
		LoopbackOnly:  true,
	}
	copy(snapshot.ContentFingerprint[:], contentDigest[:16])
	copy(snapshot.StrategyFingerprint[:], strategyDigest[:16])
	copy(snapshot.RelayFingerprint[:], relayDigest[:16])
	handle, code := registry.Open(HandleRuntimeSession, &runtimeSessionHandle{snapshot: snapshot})
	if code != CodeOK {
		return 0, RuntimeSessionSnapshot{}, code
	}
	return handle, snapshot, CodeOK
}

func RuntimeSessionRoundTrip(
	registry *HandleRegistry,
	handle Handle,
	payload []byte,
	roundTrip func([]byte) ([]byte, ErrorCode),
) ([]byte, ErrorCode) {
	if len(payload) == 0 || len(payload) > MaxRuntimePayloadBytes || roundTrip == nil {
		return nil, CodeInvalidArgument
	}
	value, code := registry.Get(handle, HandleRuntimeSession)
	if code != CodeOK {
		return nil, code
	}
	state, ok := value.(*runtimeSessionHandle)
	if !ok || state.snapshot.PlanDigest == ([32]byte{}) || !state.snapshot.LoopbackOnly {
		return nil, CodeInternalFailure
	}
	return roundTrip(payload)
}

func EncodeRuntimeSessionSnapshot(snapshot RuntimeSessionSnapshot) ([]byte, error) {
	if snapshot.Generation == 0 || snapshot.PlanDigest == ([32]byte{}) || snapshot.MTU < 1280 || snapshot.MTU > 1500 ||
		len(snapshot.Packages) > maxRuntimePackages {
		return nil, errors.New("androidbridge: invalid runtime snapshot")
	}
	size := runtimeSnapshotFixed
	for _, value := range snapshot.Packages {
		if !validRuntimePackage(value) {
			return nil, errors.New("androidbridge: invalid runtime snapshot package")
		}
		size += 2 + len(value)
	}
	if size > MaxRuntimeSnapshotBytes {
		return nil, errors.New("androidbridge: runtime snapshot too large")
	}
	out := make([]byte, size)
	copy(out[:4], runtimeSnapshotMagic)
	out[4] = runtimeWireVersion
	if snapshot.LoopbackOnly {
		out[5] |= 1
	}
	if snapshot.Metered {
		out[5] |= 2
	}
	out[6] = byte(snapshot.SelectionMode)
	out[7] = byte(snapshot.PerAppMode)
	out[8] = byte(snapshot.IPMode)
	out[9] = byte(snapshot.DNSMode)
	binary.BigEndian.PutUint16(out[10:12], snapshot.MTU)
	binary.BigEndian.PutUint64(out[12:20], snapshot.Generation)
	copy(out[20:52], snapshot.PlanDigest[:])
	copy(out[52:68], snapshot.ContentFingerprint[:])
	copy(out[68:84], snapshot.StrategyFingerprint[:])
	copy(out[84:100], snapshot.RelayFingerprint[:])
	binary.BigEndian.PutUint16(out[100:102], uint16(len(snapshot.Packages)))
	offset := runtimeSnapshotFixed
	for _, value := range snapshot.Packages {
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(value)))
		offset += 2
		copy(out[offset:], value)
		offset += len(value)
	}
	return out, nil
}

func runtimeRecordMatches(preview VerifyPreview, record profile.ActivationRecord) bool {
	expectedReceipt := expectedRuntimeReceipt(preview)
	return bytes.Equal(record.Artifact, preview.Verified.ExactArtifact) &&
		bytes.Equal(record.SignedObject, preview.Verified.ExactSignedObject) &&
		reflect.DeepEqual(record.Profile, preview.Verified.Profile) &&
		record.State.Status == lifecycle.Admitted &&
		record.State.ProfileID == record.Profile.ProfileID &&
		record.State.Scope == record.Profile.RevocationScope &&
		record.State.EvidenceReference == expectedReceipt.AuthenticatedArtifactSHA256 &&
		record.State.Generation == record.Profile.Generation &&
		record.State.Receipt == expectedReceipt
}

func authorizeRuntimePolicy(
	requested RuntimePolicyRequest,
	profileValue envelope.CanonicalProfileV1,
) (RuntimePolicyRequest, string, string, error) {
	policy, err := normalizeRuntimePolicy(requested)
	if err != nil || len(profileValue.StrategyIDs) == 0 || len(profileValue.RelayIDs) == 0 {
		return RuntimePolicyRequest{}, "", "", errors.New("androidbridge: invalid runtime policy")
	}
	if policy.IPMode == RuntimeIPV6Only || policy.IPMode == RuntimeIPDualStack ||
		policy.DNSMode != RuntimeDNSInternal || policy.CustomDNS != "" || policy.AllowLAN {
		return RuntimePolicyRequest{}, "", "", errors.New("androidbridge: unsupported runtime widening")
	}
	selectedStrategy := profileValue.StrategyIDs[0]
	if policy.SelectionMode == RuntimeSelectionManual {
		index := sort.SearchStrings(profileValue.StrategyIDs, policy.ManualStrategyID)
		if index >= len(profileValue.StrategyIDs) || profileValue.StrategyIDs[index] != policy.ManualStrategyID {
			return RuntimePolicyRequest{}, "", "", errors.New("androidbridge: strategy not permitted")
		}
		selectedStrategy = policy.ManualStrategyID
	}
	return policy, selectedStrategy, profileValue.RelayIDs[0], nil
}

func normalizeRuntimePolicy(policy RuntimePolicyRequest) (RuntimePolicyRequest, error) {
	if policy.SelectionMode < RuntimeSelectionAutomatic || policy.SelectionMode > RuntimeSelectionManual ||
		policy.PerAppMode < RuntimePerAppAllApps || policy.PerAppMode > RuntimePerAppExcludeSelected ||
		policy.IPMode < RuntimeIPAuto || policy.IPMode > RuntimeIPDualStack ||
		policy.DNSMode < RuntimeDNSInternal || policy.DNSMode > RuntimeDNSCustom ||
		policy.MTU < 1280 || policy.MTU > 1500 || len(policy.Packages) > maxRuntimePackages ||
		len(policy.ManualStrategyID) > maxRuntimeIDBytes || len(policy.CustomDNS) > 45 {
		return RuntimePolicyRequest{}, errors.New("androidbridge: invalid runtime policy")
	}
	if policy.SelectionMode == RuntimeSelectionManual {
		if !boundedRuntimeID(policy.ManualStrategyID) {
			return RuntimePolicyRequest{}, errors.New("androidbridge: invalid manual strategy")
		}
	} else if policy.ManualStrategyID != "" {
		return RuntimePolicyRequest{}, errors.New("androidbridge: unexpected manual strategy")
	}
	if policy.PerAppMode == RuntimePerAppAllApps && len(policy.Packages) != 0 ||
		policy.PerAppMode == RuntimePerAppIncludeOnly && len(policy.Packages) == 0 {
		return RuntimePolicyRequest{}, errors.New("androidbridge: invalid per-app policy")
	}
	packages := append([]string(nil), policy.Packages...)
	for _, value := range packages {
		if !validRuntimePackage(value) {
			return RuntimePolicyRequest{}, errors.New("androidbridge: invalid package")
		}
	}
	sort.Strings(packages)
	for index := 1; index < len(packages); index++ {
		if packages[index-1] == packages[index] {
			return RuntimePolicyRequest{}, errors.New("androidbridge: duplicate package")
		}
	}
	policy.Packages = packages
	policy.CustomDNS = strings.TrimSpace(policy.CustomDNS)
	return policy, nil
}

func encodeRuntimePolicyOnly(policy RuntimePolicyRequest) ([]byte, error) {
	return EncodeRuntimeOpenRequest(RuntimeOpenRequest{
		VerifyRequest:    []byte{1},
		ActivationRecord: []byte{1},
		Policy:           policy,
	})
}

func validRuntimePackage(value string) bool {
	if len(value) < 3 || len(value) > maxRuntimePackageBytes {
		return false
	}
	segments := strings.Split(value, ".")
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments {
		if segment == "" || !(segment[0] == '_' || segment[0] >= 'A' && segment[0] <= 'Z' || segment[0] >= 'a' && segment[0] <= 'z') {
			return false
		}
		for _, character := range segment {
			if character != '_' && (character < '0' || character > '9') &&
				(character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
		}
	}
	return true
}

func boundedRuntimeID(value string) bool {
	if value == "" || len(value) > maxRuntimeIDBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func expectedRuntimeReceipt(preview VerifyPreview) lifecycle.VerifiedReceipt {
	digest := sha256.Sum256(preview.Verified.ExactSignedObject)
	return lifecycle.VerifiedReceipt{
		ContentID:                   preview.Verified.Profile.ContentID,
		ProviderID:                  preview.Verified.Profile.ProviderID,
		LineageID:                   preview.Verified.Profile.LineageID,
		AuthenticatedArtifactSHA256: hex.EncodeToString(digest[:]),
		RootEpoch:                   preview.Verified.Profile.RootEpoch,
		RevocationEpoch:             preview.Verified.Profile.RevocationEpoch,
		RecipientEpoch:              preview.Verified.Metadata.RecipientEpoch,
	}
}
