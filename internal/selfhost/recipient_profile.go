// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"time"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

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
