// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/liveprogram"
)

func validateLiveProgramBytesV1(encoded []byte) ([]byte, [32]byte, error) {
	if len(encoded) == 0 || len(encoded) > liveprogram.MaxEncodedBytes {
		return nil, [32]byte{}, ErrInvalidInput
	}
	decoded, err := liveprogram.DecodeV1(encoded)
	if err != nil || liveprogram.ValidateV1(decoded) != nil {
		return nil, [32]byte{}, ErrInvalidInput
	}
	reencoded, err := liveprogram.EncodeV1(decoded)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return nil, [32]byte{}, ErrInvalidInput
	}
	for _, forbidden := range [][]byte{[]byte("lab_tcp"), []byte("hmac-sha256-transcript-test-only"), []byte("test-only-")} {
		if bytes.Contains(encoded, forbidden) {
			return nil, [32]byte{}, ErrInvalidInput
		}
	}
	return bytes.Clone(encoded), sha256.Sum256(encoded), nil
}

func buildRuntimePolicyV2(state *persistedState, request enrollment.PublicRequestV1, ipv4, ipv6, program []byte, programDigest [32]byte, now time.Time) (runtimepolicy.PolicyV2, []byte, error) {
	host, portText, err := net.SplitHostPort(state.Endpoint)
	if err != nil {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	address, err := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || address.Is4In6() || address.String() != strings.ToLower(host) || port < 1 || port > 65535 {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	decodedProgram, err := liveprogram.DecodeV1(program)
	if err != nil {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	var clientPublic, relayPublic [32]byte
	copy(clientPublic[:], request.ClientAuthPublic)
	copy(relayPublic[:], state.RelayPublic)
	policy := runtimepolicy.PolicyV2{
		SchemaVersion: runtimepolicy.SchemaVersionV2, WireProtocol: runtimepolicy.WireProtocolV1, CarrierFamily: runtimepolicy.CarrierFamilyTLS13TCP,
		LiveProgram: bytes.Clone(program), LiveProgramSHA256: programDigest, ClientAuthKeyID: request.ClientAuthKeyID, ClientAuthPublic: clientPublic,
		RelayAuthKeyID: state.RelayKeyID, RelayAuthPublic: relayPublic, TLSServerName: state.TLS.SAN, TLSLeafDER: bytes.Clone(state.TLS.LeafDER),
		MTU: 1280, Limits: runtimepolicy.LimitsV2{MaxReconnectAttempts: 5}, Fallback: runtimepolicy.FallbackV2{EndpointIndexes: []uint8{0}, TotalAttempts: 5, AttemptTimeoutSeconds: 10, MaxBackoffSeconds: 30},
	}
	copy(policy.TLSLeafSHA256[:], state.TLS.LeafDigest)
	family := addressFamilyIPv6
	if address.Is4() {
		family = addressFamilyIPv4
	}
	policy.Endpoints = []runtimepolicy.EndpointV2{{Priority: 0, Address: address.AsSlice(), Family: family, Port: uint16(port)}}
	policy.ClientIPv4, policy.ClientIPv6 = bytes.Clone(ipv4), bytes.Clone(ipv6)
	if len(ipv4) != 0 {
		policy.DNSIPv4 = bytes.Clone(state.IPv4Pool.ServerDNS)
		policy.Routes = append(policy.Routes, runtimepolicy.PrefixV2{Address: make([]byte, 4), PrefixLen: 0})
		policy.DNSServers = append(policy.DNSServers, bytes.Clone(policy.DNSIPv4))
	}
	if len(ipv6) != 0 {
		policy.DNSIPv6 = bytes.Clone(state.IPv6Pool.ServerDNS)
		policy.Routes = append(policy.Routes, runtimepolicy.PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
		policy.DNSServers = append(policy.DNSServers, bytes.Clone(policy.DNSIPv6))
	}
	switch {
	case len(ipv4) != 0 && len(ipv6) != 0:
		policy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeDualStack, runtimepolicy.IPModeIPv4Only, runtimepolicy.IPModeIPv6Only}
	case len(ipv4) != 0:
		policy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeIPv4Only}
	case len(ipv6) != 0:
		policy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeIPv6Only}
	default:
		return runtimepolicy.PolicyV2{}, nil, ErrAddressExhausted
	}
	policy.AllowedProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP}
	if len(ipv4) != 0 {
		policy.AllowedProtocols = append(policy.AllowedProtocols, runtimepolicy.PayloadProtocolICMP)
	}
	if len(ipv6) != 0 {
		policy.AllowedProtocols = append(policy.AllowedProtocols, runtimepolicy.PayloadProtocolICMPv6)
	}
	sort.Slice(policy.AllowedProtocols, func(i, j int) bool { return policy.AllowedProtocols[i] < policy.AllowedProtocols[j] })
	maxMessages := uint32(decodedProgram.Limits.MaxSessionMessages)
	maxQueued := maxMessages
	if maxQueued > 256 {
		maxQueued = 256
	}
	maxIdle := uint32(decodedProgram.Limits.MaxSessionMillis / 1000)
	if maxIdle > 300 {
		maxIdle = 300
	}
	policy.Limits.MaxPackets, policy.Limits.MaxFrames, policy.Limits.MaxMessages = maxMessages, maxMessages, maxMessages
	policy.Limits.MaxQueuedPackets, policy.Limits.MaxIdleSeconds = maxQueued, maxIdle
	digest, err := runtimepolicy.RelayAdmissionDigestV2At(policy, now)
	if err != nil {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	policy.RelayAdmissionDigest = digest
	encoded, err := runtimepolicy.EncodeV2At(policy, now)
	if err != nil {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	decoded, err := runtimepolicy.DecodeV2At(encoded, now)
	if err != nil {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	reencoded, err := runtimepolicy.EncodeV2At(decoded, now)
	if err != nil || !bytes.Equal(encoded, reencoded) || decoded.RelayAdmissionDigest != digest {
		return runtimepolicy.PolicyV2{}, nil, ErrInvalidInput
	}
	return decoded, encoded, nil
}

func issueLiveProfile(
	state *persistedState,
	master []byte,
	name, profileID, previousContentID, updateKind string,
	validFor time.Duration,
	liveProgramBytes []byte,
	now time.Time,
	request enrollment.PublicRequestV1,
	recipientEpoch uint64,
	reservation *recipientUseReservationV1,
) (IssuedProfile, profileRecord, error) {
	if state == nil || len(master) == 0 || validateProfileTLSLifetime(state.TLS, now.Unix(), now.Add(validFor).Unix()) != nil {
		return IssuedProfile{}, profileRecord{}, ErrTLSUnavailable
	}
	bindingRecord, recipientPublic, clientKeyID, clientPublic, err := recipientCapabilityFromRequest(*state, request, recipientEpoch)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	if reservation != nil {
		if reservation.Record != recipientUseRecord(request, profileID, now.Unix()) || !validID(reservation.RegistryID) {
			return IssuedProfile{}, profileRecord{}, ErrRecipientRegistry
		}
	}
	ipv4, err := allocateAddress(&state.IPv4Pool, state.Assignments, now.Unix())
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	var ipv6 []byte
	if state.IPv6Pool.Enabled {
		ipv6, err = allocateAddress(&state.IPv6Pool, state.Assignments, now.Unix())
		if err != nil {
			return IssuedProfile{}, profileRecord{}, err
		}
	}
	program, programDigest, err := validateLiveProgramBytesV1(liveProgramBytes)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	policyValue, policyBytes, err := buildRuntimePolicyV2(state, request, ipv4, ipv6, program, programDigest, now)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	contentID, err := randomID("content")
	if err != nil || state.Generation == ^uint64(0) {
		return IssuedProfile{}, profileRecord{}, ErrInvalidInput
	}
	generation := state.Generation + 1
	validUntil := now.Add(validFor).Unix()
	profileValue := envelope.CanonicalProfileV1{
		ContentID: contentID, ProfileID: profileID,
		LineageID: state.Delegation.Scope.LineageID, ProviderID: state.Delegation.Scope.ProviderID,
		ContractVersion: "product-profile-admission-v1", RevocationScope: state.Revocations.Scope,
		SnapshotMode: "full-snapshot", UpdateKind: updateKind, Generation: generation,
		RequiredSafetyFloor: 1, ValidFrom: now.Unix(), ValidUntil: validUntil,
		RootEpoch: state.Root.Epoch, RevocationEpoch: state.Revocations.Epoch,
		PreviousContentID: previousContentID,
		RelayIDs:          []string{state.RelayKeyID}, StrategyIDs: []string{"strategy.kurd-tls13-tcp"}, Policy: policyBytes,
	}
	binding := bindingRecord.binding()
	spec := profile.OfflineIssuanceSpec{
		Profile: profileValue, Class: envelope.ArtifactDeviceRecipient, Audience: envelope.AudienceProvisionedDevice,
		Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer,
		IssuerScope: state.Delegation.Scope, IssuerKey: state.IssuerKey, Recipient: &binding,
		MinimumGeneration: generation, Now: now.Unix(),
	}
	intent, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	issuerDER, err := openWithKey(master, state.IssuerSecret, []byte(state.DeploymentID+"|"+state.IssuerKey.KeyID))
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	defer zero(issuerDER)
	issuerPrivate, err := parseP256Private(issuerDER)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, ErrStateCorrupt
	}
	issuerPublic, err := parseP256Public(state.IssuerPublicDER)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, ErrStateCorrupt
	}
	sealer, err := profilehpke.NewSealer(binding, recipientPublic)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, ErrInvalidInput
	}
	receipt, err := profile.IssueOfflineChecked(
		intent,
		p256Signer{keyID: state.IssuerKey.KeyID, key: issuerPrivate},
		p256Verifier{keys: map[string]*ecdsa.PublicKey{state.IssuerKey.KeyID: issuerPublic}},
		sealer,
	)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	bundle := liveProfileBundleV2{
		Version: liveBundleVersion, DeploymentID: state.DeploymentID,
		Root: state.Root, RootPublicDER: bytes.Clone(state.RootPublicDER), RootFingerprint: state.RootFingerprint,
		IssuerKey: state.IssuerKey, IssuerPublicDER: bytes.Clone(state.IssuerPublicDER),
		Delegation: state.Delegation, DelegationPayload: bytes.Clone(state.DelegationPayload), DelegationSignature: bytes.Clone(state.DelegationSig),
		Revocations: state.Revocations, RevocationPayload: bytes.Clone(state.RevocationPayload), RevocationSignature: bytes.Clone(state.RevocationSig),
		SealedProfile: receipt.ExactArtifact(),
	}
	artifact, err := encodeLiveBundle(bundle)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	if _, metadata, err := verifyLiveBundleAuthority(artifact, now, generation); err != nil || metadata.RecipientHint != request.RequestID || metadata.RecipientEpoch != binding.Epoch {
		return IssuedProfile{}, profileRecord{}, ErrInvalidInput
	}
	uri, err := envelope.EncodeArtifactURI(artifact)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	chunks, err := envelope.EncodeQRChunks(artifact, 768)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	record := profileRecord{
		Name: name, ProfileID: profileID, ContentID: contentID, Generation: generation,
		Artifact: bytes.Clone(artifact), CreatedAt: now.Unix(), ValidUntil: validUntil, Mode: profileModeLive,
		Recipient: bindingRecord, RecipientPublic: bytes.Clone(recipientPublic),
		ClientAuthKeyID: clientKeyID, ClientAuthPublic: bytes.Clone(clientPublic),
		RuntimePolicy: bytes.Clone(policyBytes), RelayAdmissionDigest: bytes.Clone(policyValue.RelayAdmissionDigest[:]),
		AssignedIPv4: bytes.Clone(ipv4), AssignedIPv6: bytes.Clone(ipv6),
	}
	assignments := append([]addressAssignmentV1(nil), state.Assignments...)
	if len(ipv4) != 0 {
		assignments = append(assignments, addressAssignmentV1{Family: addressFamilyIPv4, Address: bytes.Clone(ipv4), ProfileID: profileID, ContentID: contentID, Generation: generation, State: addressStateActive, AssignedAt: now.Unix(), ProfileValidUntil: validUntil})
	}
	if len(ipv6) != 0 {
		assignments = append(assignments, addressAssignmentV1{Family: addressFamilyIPv6, Address: bytes.Clone(ipv6), ProfileID: profileID, ContentID: contentID, Generation: generation, State: addressStateActive, AssignedAt: now.Unix(), ProfileValidUntil: validUntil})
	}
	sort.Slice(assignments, func(i, j int) bool {
		if assignments[i].Family != assignments[j].Family {
			return assignments[i].Family < assignments[j].Family
		}
		return bytes.Compare(assignments[i].Address, assignments[j].Address) < 0
	})
	ledger := state.RecipientUses
	if reservation != nil {
		ledger, err = appendRecipientUse(state.RecipientUses, reservation.RegistryID, reservation.Record)
		if err != nil {
			return IssuedProfile{}, profileRecord{}, err
		}
	}
	state.Generation = generation
	state.Assignments = assignments
	state.RecipientUses = ledger
	return IssuedProfile{
		ProfileID: profileID, ContentID: contentID, Generation: generation, ValidUntil: validUntil,
		Mode: profileModeLive, Sealed: true, Connectable: true,
		Artifact: bytes.Clone(artifact), URI: uri, QRChunks: append([]string(nil), chunks...),
	}, record, nil
}

func recipientCapabilityFromRequest(state persistedState, request enrollment.PublicRequestV1, epoch uint64) (recipientBindingRecord, []byte, string, []byte, error) {
	if epoch == 0 || request.RequestID == "" || request.RecipientKeyID != recipientPublicKeyID(request.RecipientPublic) ||
		request.ClientAuthKeyID != clientPublicKeyID(request.ClientAuthPublic) || len(request.RecipientPublic) != 65 || len(request.ClientAuthPublic) != 32 {
		return recipientBindingRecord{}, nil, "", nil, ErrInvalidInput
	}
	binding := profile.RecipientBinding{
		Class: envelope.ArtifactDeviceRecipient, ProviderID: state.Delegation.Scope.ProviderID, LineageID: state.Delegation.Scope.LineageID,
		ProfileNamespace: state.Delegation.Scope.ProfileNamespace, Hint: request.RequestID, KeyID: request.RecipientKeyID, Epoch: epoch,
	}
	if _, err := profile.ResolveRecipientBinding([]profile.RecipientBinding{binding}, binding.Class, binding.Hint); err != nil {
		return recipientBindingRecord{}, nil, "", nil, ErrInvalidInput
	}
	return recipientRecord(binding), append([]byte(nil), request.RecipientPublic...), request.ClientAuthKeyID, append([]byte(nil), request.ClientAuthPublic...), nil
}

func (record recipientBindingRecord) binding() profile.RecipientBinding {
	return profile.RecipientBinding{
		Class: envelope.ArtifactClass(record.Class), ProviderID: record.ProviderID, LineageID: record.LineageID,
		ProfileNamespace: record.Namespace, Hint: record.Hint, KeyID: record.KeyID, Epoch: record.Epoch, Revoked: record.Revoked,
	}
}

func recipientRecord(binding profile.RecipientBinding) recipientBindingRecord {
	return recipientBindingRecord{
		Class: string(binding.Class), ProviderID: binding.ProviderID, LineageID: binding.LineageID,
		Namespace: binding.ProfileNamespace, Hint: binding.Hint, KeyID: binding.KeyID, Epoch: binding.Epoch, Revoked: binding.Revoked,
	}
}

func validateProfileRecordV2(state persistedState, record profileRecord) error {
	switch record.Mode {
	case profileModeAuthorityOnly:
		if !recipientRecordEmpty(record.Recipient) || len(record.RecipientPublic) != 0 || record.ClientAuthKeyID != "" || len(record.ClientAuthPublic) != 0 ||
			len(record.RuntimePolicy) != 0 || len(record.RelayAdmissionDigest) != 0 || len(record.AssignedIPv4) != 0 || len(record.AssignedIPv6) != 0 {
			return ErrStateCorrupt
		}
		return nil
	case profileModeLive:
		return validateLiveProfileRecord(state, record)
	default:
		return ErrStateCorrupt
	}
}

func validateLiveProfileRecord(state persistedState, record profileRecord) error {
	binding := record.Recipient.binding()
	if _, err := profile.ResolveRecipientBinding([]profile.RecipientBinding{binding}, binding.Class, binding.Hint); err != nil ||
		binding.Class != envelope.ArtifactDeviceRecipient || binding.ProviderID != state.Delegation.Scope.ProviderID ||
		binding.LineageID != state.Delegation.Scope.LineageID || binding.ProfileNamespace != state.Delegation.Scope.ProfileNamespace || binding.Revoked {
		return ErrStateCorrupt
	}
	if len(record.RecipientPublic) != 65 || binding.KeyID != recipientPublicKeyID(record.RecipientPublic) ||
		len(record.ClientAuthPublic) != 32 || record.ClientAuthKeyID != clientPublicKeyID(record.ClientAuthPublic) ||
		len(record.RelayAdmissionDigest) != sha256.Size || len(record.RuntimePolicy) == 0 {
		return ErrStateCorrupt
	}
	now := time.Unix(record.CreatedAt, 0).UTC()
	policy, err := runtimepolicy.DecodeV2At(record.RuntimePolicy, now)
	if err != nil {
		return ErrStateCorrupt
	}
	canonical, err := runtimepolicy.EncodeV2At(policy, now)
	if err != nil || !bytes.Equal(canonical, record.RuntimePolicy) {
		return ErrStateCorrupt
	}
	digest, err := runtimepolicy.RelayAdmissionDigestV2At(policy, now)
	if err != nil || digest != policy.RelayAdmissionDigest || !bytes.Equal(digest[:], record.RelayAdmissionDigest) ||
		policy.ClientAuthKeyID != record.ClientAuthKeyID || !bytes.Equal(policy.ClientAuthPublic[:], record.ClientAuthPublic) ||
		!bytes.Equal(policy.ClientIPv4, record.AssignedIPv4) || !bytes.Equal(policy.ClientIPv6, record.AssignedIPv6) ||
		len(record.AssignedIPv4) != 0 && !bytes.Equal(policy.DNSIPv4, state.IPv4Pool.ServerDNS) ||
		len(record.AssignedIPv6) != 0 && !bytes.Equal(policy.DNSIPv6, state.IPv6Pool.ServerDNS) {
		return ErrStateCorrupt
	}
	if record.Revoked {
		if !profileHasNoActiveAssignments(state.Assignments, record.ProfileID) {
			return ErrStateCorrupt
		}
		return nil
	}
	if policy.RelayAuthKeyID != state.RelayKeyID || !bytes.Equal(policy.RelayAuthPublic[:], state.RelayPublic) ||
		policy.TLSServerName != state.TLS.SAN || !bytes.Equal(policy.TLSLeafDER, state.TLS.LeafDER) || !bytes.Equal(policy.TLSLeafSHA256[:], state.TLS.LeafDigest) ||
		validateProfileTLSLifetime(state.TLS, record.CreatedAt, record.ValidUntil) != nil {
		return ErrStateCorrupt
	}
	if !policyHasConfiguredEndpoint(policy, state.Endpoint) || !profileAssignmentsMatch(state.Assignments, record) {
		return ErrStateCorrupt
	}
	return nil
}

func profileHasNoActiveAssignments(assignments []addressAssignmentV1, profileID string) bool {
	for _, assignment := range assignments {
		if assignment.ProfileID == profileID && assignment.State == addressStateActive {
			return false
		}
	}
	return true
}

func recipientRecordEmpty(record recipientBindingRecord) bool {
	return record == (recipientBindingRecord{})
}

func recipientPublicKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return "recipient." + hex.EncodeToString(digest[:8])
}

func clientPublicKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

func policyHasConfiguredEndpoint(policy runtimepolicy.PolicyV2, endpoint string) bool {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Is4In6() {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	for _, candidate := range policy.Endpoints {
		if int(candidate.Port) == port && bytes.Equal(candidate.Address, address.AsSlice()) {
			return true
		}
	}
	return false
}

func profileAssignmentsMatch(assignments []addressAssignmentV1, record profileRecord) bool {
	want := map[uint8][]byte{}
	if len(record.AssignedIPv4) != 0 {
		want[addressFamilyIPv4] = record.AssignedIPv4
	}
	if len(record.AssignedIPv6) != 0 {
		want[addressFamilyIPv6] = record.AssignedIPv6
	}
	seen := map[uint8]bool{}
	for _, assignment := range assignments {
		if assignment.ProfileID != record.ProfileID || assignment.State != addressStateActive {
			continue
		}
		if !bytes.Equal(want[assignment.Family], assignment.Address) || assignment.ContentID != record.ContentID || assignment.Generation != record.Generation || assignment.ProfileValidUntil != record.ValidUntil {
			return false
		}
		seen[assignment.Family] = true
	}
	return len(seen) == len(want)
}
