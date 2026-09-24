// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/selfhost"
)

const (
	verifyRequestMagic    = "KVI1"
	verifyPreviewMagic    = "KVP2"
	verifyRequestHeader   = 8
	MaxVerifySegments     = envelope.MaxIngressQRChunks
	MaxVerifyRequestBytes = envelope.MaxIngressEncodedChars +
		MaxVerifySegments*(4+32) + verifyRequestHeader
)

type VerificationEnvironment interface {
	Verify(artifact []byte, class envelope.ArtifactClass) (profile.OfflineVerifiedArtifact, error)
}

// RecipientVerificationEnvironment verifies a device-recipient artifact with
// the exact enrollment capability retained by the Android secure store.
type RecipientVerificationEnvironment interface {
	VerifyWithRecipient(artifact []byte, class envelope.ArtifactClass, credentials RecipientCredentials) (profile.OfflineVerifiedArtifact, error)
}

func verifyMaintenanceCurrentV1(current MaintenanceCurrentInputV1, environment RecipientVerificationEnvironmentAt, now time.Time, limits selfhost.LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, maintenanceCheckedCurrentV1, RecipientCredentials, MaintenanceResultV1) {
	if environment == nil || now.IsZero() || now.Unix() <= 0 {
		return profile.OfflineVerifiedArtifact{}, selfhost.LiveMaintenanceBounds{}, maintenanceCheckedCurrentV1{}, RecipientCredentials{}, MaintenanceInvalidRequest
	}
	artifact, credentials, result := decodeMaintenanceCurrentIngressV1(current, limits)
	if result != MaintenanceSuccess {
		return profile.OfflineVerifiedArtifact{}, selfhost.LiveMaintenanceBounds{}, maintenanceCheckedCurrentV1{}, RecipientCredentials{}, result
	}
	// decodeMaintenanceCurrentIngressV1 has rejected empty and original-cap
	// oversized input. This call verifies only those exact owned current bytes;
	// the original limits remain with the parent for future candidates.
	currentLimits := limits
	currentLimits.MaxArtifactBytes = uint32(len(artifact))
	verified, bounds, err := environment.VerifyWithRecipientAt(artifact, envelope.ArtifactDeviceRecipient, credentials.Clone(), now, currentLimits)
	if err != nil {
		clear(artifact)
		destroyMaintenanceVerifiedV1(&verified)
		credentials.Destroy()
		return profile.OfflineVerifiedArtifact{}, selfhost.LiveMaintenanceBounds{}, maintenanceCheckedCurrentV1{}, RecipientCredentials{}, maintenanceResultFromError(err)
	}
	record, err := DecodeActivationRecord(current.ActivationRecord)
	if err != nil || !runtimeRecordMatches(VerifyPreview{Verified: verified}, record) {
		clear(artifact)
		destroyMaintenanceActivationRecordV1(&record)
		destroyMaintenanceVerifiedV1(&verified)
		credentials.Destroy()
		return profile.OfflineVerifiedArtifact{}, selfhost.LiveMaintenanceBounds{}, maintenanceCheckedCurrentV1{}, RecipientCredentials{}, MaintenanceInvalidState
	}
	checked := maintenanceCheckedCurrentV1{state: record.State, scope: maintenanceScopeIdentityV1(verified), artifact: artifact}
	destroyMaintenanceActivationRecordV1(&record)
	return verified, bounds, checked, credentials, MaintenanceSuccess
}

// Shared bounded ingress only. Maintenance still verifies before decoding the
// activation record, preserving its existing error precedence.
func decodeMaintenanceCurrentIngressV1(current MaintenanceCurrentInputV1, limits selfhost.LiveMaintenanceLimits) ([]byte, RecipientCredentials, MaintenanceResultV1) {
	request, artifact, code := decodeVerifyArtifact(current.VerifyRequest)
	if code != CodeOK {
		result := MaintenanceInvalidRequest
		if code == CodeSizeLimit {
			result = MaintenanceSizeLimit
		}
		return nil, RecipientCredentials{}, result
	}
	class := request.Class
	for index := range request.Parts {
		clear(request.Parts[index])
	}
	request = VerifyRequest{}
	if class != envelope.ArtifactDeviceRecipient || len(artifact) == 0 {
		clear(artifact)
		return nil, RecipientCredentials{}, MaintenanceInvalidRequest
	}
	if uint64(len(artifact)) > uint64(limits.MaxArtifactBytes) {
		clear(artifact)
		return nil, RecipientCredentials{}, MaintenanceSizeLimit
	}
	credentials, code := DecodeRecipientCredentials(current.RecipientRequest, current.RecipientPrivate)
	if code != CodeOK {
		clear(artifact)
		return nil, RecipientCredentials{}, MaintenanceInvalidRequest
	}
	return artifact, credentials, MaintenanceSuccess
}

func destroyMaintenanceVerifiedV1(verified *profile.OfflineVerifiedArtifact) {
	if verified == nil {
		return
	}
	clear(verified.ExactArtifact)
	clear(verified.ExactSignedObject)
	clear(verified.Profile.Policy)
	*verified = profile.OfflineVerifiedArtifact{}
}

func destroyMaintenanceActivationRecordV1(record *profile.ActivationRecord) {
	if record == nil {
		return
	}
	clear(record.Artifact)
	clear(record.SignedObject)
	clear(record.Profile.Policy)
	*record = profile.ActivationRecord{}
}

// TrustPreviewEnvironment optionally supplies redacted, independently
// verified deployment information for an explicit first-trust decision. It
// must derive every field from the exact artifact already admitted by Verify
// and must not perform a network request.
type TrustPreviewEnvironment interface {
	TrustPreview(artifact []byte, class envelope.ArtifactClass) (TrustPreview, error)
}

type RecipientTrustPreviewEnvironment interface {
	TrustPreviewWithRecipient(artifact []byte, class envelope.ArtifactClass, credentials RecipientCredentials) (TrustPreview, error)
}

type TrustPreview struct {
	DeploymentFingerprint string
	RelayEndpoint         string
	AuthorityScope        string
	UpdateLocation        string
	OwnerControlled       bool
	UpdatesEnabled        bool
}

type VerifyRequest struct {
	Ingress envelope.IngressKind
	Class   envelope.ArtifactClass
	Parts   [][]byte
}

type VerifyPreview struct {
	Inspection profile.RedactedInspection
	Verified   profile.OfflineVerifiedArtifact
	Trust      TrustPreview
	recipient  *RecipientCredentials
}

func (preview *VerifyPreview) Destroy() {
	if preview == nil {
		return
	}
	clear(preview.Verified.ExactArtifact)
	clear(preview.Verified.ExactSignedObject)
	clear(preview.Verified.Profile.Policy)
	if preview.recipient != nil {
		preview.recipient.Destroy()
	}
	*preview = VerifyPreview{}
}

func EncodeVerifyRequest(request VerifyRequest) ([]byte, error) {
	kind, ok := encodeIngressKind(request.Ingress)
	if !ok || len(request.Parts) == 0 || len(request.Parts) > MaxVerifySegments {
		return nil, errors.New("androidbridge: invalid verify request")
	}
	class, ok := encodeArtifactClass(request.Class)
	if !ok {
		return nil, errors.New("androidbridge: invalid artifact class")
	}
	size := verifyRequestHeader
	for _, part := range request.Parts {
		if len(part) == 0 || len(part) > envelope.MaxIngressEncodedChars {
			return nil, errors.New("androidbridge: invalid verify part")
		}
		size += 4 + len(part)
	}
	if size > MaxVerifyRequestBytes {
		return nil, errors.New("androidbridge: verify request too large")
	}
	out := make([]byte, size)
	copy(out[:4], verifyRequestMagic)
	out[4], out[5] = kind, class
	binary.BigEndian.PutUint16(out[6:8], uint16(len(request.Parts)))
	offset := verifyRequestHeader
	for _, part := range request.Parts {
		binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(part)))
		offset += 4
		copy(out[offset:], part)
		offset += len(part)
	}
	return out, nil
}

func DecodeVerifyRequest(encoded []byte) (VerifyRequest, error) {
	if len(encoded) < verifyRequestHeader ||
		len(encoded) > MaxVerifyRequestBytes ||
		string(encoded[:4]) != verifyRequestMagic {
		return VerifyRequest{}, errors.New("androidbridge: invalid verify header")
	}
	ingress, ok := decodeIngressKind(encoded[4])
	if !ok {
		return VerifyRequest{}, errors.New("androidbridge: invalid ingress kind")
	}
	class, ok := decodeArtifactClass(encoded[5])
	if !ok {
		return VerifyRequest{}, errors.New("androidbridge: invalid artifact class")
	}
	count := int(binary.BigEndian.Uint16(encoded[6:8]))
	if count == 0 || count > MaxVerifySegments {
		return VerifyRequest{}, errors.New("androidbridge: invalid verify segment count")
	}
	parts := make([][]byte, count)
	transferred := false
	defer func() {
		if !transferred {
			for _, part := range parts {
				clear(part)
			}
		}
	}()
	offset := verifyRequestHeader
	for index := range parts {
		if offset+4 > len(encoded) {
			return VerifyRequest{}, errors.New("androidbridge: truncated verify segment")
		}
		length := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
		offset += 4
		if length == 0 || length > envelope.MaxIngressEncodedChars || offset+length > len(encoded) {
			return VerifyRequest{}, errors.New("androidbridge: invalid verify segment")
		}
		parts[index] = append([]byte(nil), encoded[offset:offset+length]...)
		offset += length
	}
	if offset != len(encoded) {
		return VerifyRequest{}, errors.New("androidbridge: trailing verify data")
	}
	request := VerifyRequest{Ingress: ingress, Class: class, Parts: parts}
	canonical, err := EncodeVerifyRequest(request)
	defer clear(canonical)
	if err != nil || len(canonical) != len(encoded) {
		return VerifyRequest{}, errors.New("androidbridge: non-canonical verify request")
	}
	for index := range encoded {
		if encoded[index] != canonical[index] {
			return VerifyRequest{}, errors.New("androidbridge: non-canonical verify request")
		}
	}
	transferred = true
	return request, nil
}

func VerifyAndPreview(encoded []byte, environment VerificationEnvironment) (VerifyPreview, ErrorCode) {
	if environment == nil {
		return VerifyPreview{}, CodeTrustUnavailable
	}
	request, artifact, code := decodeVerifyArtifact(encoded)
	if code != CodeOK {
		return VerifyPreview{}, code
	}
	verified, err := environment.Verify(artifact, request.Class)
	if err != nil {
		return VerifyPreview{}, CodeVerificationRejected
	}
	var trust TrustPreview
	if provider, ok := environment.(TrustPreviewEnvironment); ok {
		trust, err = provider.TrustPreview(artifact, request.Class)
		if err != nil {
			return VerifyPreview{}, CodeVerificationRejected
		}
	}
	return VerifyPreview{
		Inspection: profile.InspectRedacted(verified),
		Verified:   verified,
		Trust:      trust,
	}, CodeOK
}

func VerifyAndPreviewWithRecipient(encoded, requestBytes, privateBytes []byte, environment RecipientVerificationEnvironment) (VerifyPreview, ErrorCode) {
	if environment == nil {
		return VerifyPreview{}, CodeTrustUnavailable
	}
	request, artifact, code := decodeVerifyArtifact(encoded)
	defer func() {
		for _, part := range request.Parts {
			clear(part)
		}
		clear(artifact)
	}()
	if code != CodeOK {
		return VerifyPreview{}, code
	}
	if request.Class != envelope.ArtifactDeviceRecipient {
		return VerifyPreview{}, CodePolicyRejected
	}
	credentials, code := DecodeRecipientCredentials(requestBytes, privateBytes)
	if code != CodeOK {
		return VerifyPreview{}, code
	}
	verified, err := environment.VerifyWithRecipient(artifact, request.Class, credentials.Clone())
	transferred := false
	defer func() {
		if !transferred {
			destroyMaintenanceVerifiedV1(&verified)
		}
	}()
	if err != nil {
		credentials.Destroy()
		return VerifyPreview{}, CodeVerificationRejected
	}
	var trust TrustPreview
	if provider, ok := environment.(RecipientTrustPreviewEnvironment); ok {
		trust, err = provider.TrustPreviewWithRecipient(artifact, request.Class, credentials.Clone())
		if err != nil {
			credentials.Destroy()
			return VerifyPreview{}, CodeVerificationRejected
		}
	}
	transferred = true
	return VerifyPreview{
		Inspection: profile.InspectRedacted(verified),
		Verified:   verified,
		Trust:      trust,
		recipient:  &credentials,
	}, CodeOK
}

func decodeVerifyArtifact(encoded []byte) (VerifyRequest, []byte, ErrorCode) {
	request, err := DecodeVerifyRequest(encoded)
	transferred := false
	defer func() {
		if !transferred {
			for _, part := range request.Parts {
				clear(part)
			}
		}
	}()
	if err != nil {
		return VerifyRequest{}, nil, CodeInvalidArgument
	}
	ingress := envelope.ProfileIngress{Kind: request.Ingress}
	switch request.Ingress {
	case envelope.IngressFile, envelope.IngressSubscription:
		if len(request.Parts) != 1 {
			return VerifyRequest{}, nil, CodeInvalidArgument
		}
		ingress.Bytes = request.Parts[0]
	case envelope.IngressURI, envelope.IngressClipboard:
		if len(request.Parts) != 1 {
			return VerifyRequest{}, nil, CodeInvalidArgument
		}
		ingress.Text = string(request.Parts[0])
	case envelope.IngressQRChunks:
		ingress.Chunks = make([]string, len(request.Parts))
		for index, part := range request.Parts {
			ingress.Chunks[index] = string(part)
		}
	default:
		return VerifyRequest{}, nil, CodeInvalidArgument
	}
	artifact, err := envelope.NormalizeProfileIngress(ingress)
	if err != nil {
		if envelope.IngressErrorIs(err, envelope.IngressSizeLimit) {
			return VerifyRequest{}, nil, CodeSizeLimit
		}
		return VerifyRequest{}, nil, CodeVerificationRejected
	}
	transferred = true
	return request, artifact, CodeOK
}

func OpenVerifyPreview(registry *HandleRegistry, encoded []byte, environment VerificationEnvironment) (Handle, []byte, ErrorCode) {
	if registry == nil {
		return 0, nil, CodeInvalidArgument
	}
	preview, code := VerifyAndPreview(encoded, environment)
	if code != CodeOK {
		return 0, nil, code
	}
	result, err := EncodeVerifyPreview(preview)
	if err != nil {
		return 0, nil, CodeInternalFailure
	}
	handle, code := registry.Open(HandleVerifyPreview, &preview)
	if code != CodeOK {
		return 0, nil, code
	}
	return handle, result, CodeOK
}

func OpenVerifyPreviewWithRecipient(registry *HandleRegistry, encoded, requestBytes, privateBytes []byte, environment RecipientVerificationEnvironment) (Handle, []byte, ErrorCode) {
	if registry == nil {
		return 0, nil, CodeInvalidArgument
	}
	preview, code := VerifyAndPreviewWithRecipient(encoded, requestBytes, privateBytes, environment)
	if code != CodeOK {
		return 0, nil, code
	}
	result, err := EncodeVerifyPreview(preview)
	if err != nil {
		preview.Destroy()
		return 0, nil, CodeInternalFailure
	}
	handle, code := registry.Open(HandleVerifyPreview, &preview)
	if code != CodeOK {
		preview.Destroy()
		return 0, nil, code
	}
	return handle, result, CodeOK
}

func EncodeVerifyPreview(preview VerifyPreview) ([]byte, error) {
	fields := []string{
		preview.Inspection.Class,
		preview.Inspection.Audience,
		preview.Inspection.ContentSHA256,
		lineageFingerprint(preview.Verified.Profile.ProviderID, preview.Verified.Profile.LineageID),
	}
	optionalFields := []string{
		preview.Trust.DeploymentFingerprint,
		preview.Trust.RelayEndpoint,
		preview.Trust.AuthorityScope,
		preview.Trust.UpdateLocation,
	}
	size := 4 + 1 + 8 + 8
	for _, field := range fields {
		if len(field) == 0 || len(field) > 255 {
			return nil, errors.New("androidbridge: invalid preview field")
		}
		size += 1 + len(field)
	}
	for _, field := range optionalFields {
		if len(field) > 255 {
			return nil, errors.New("androidbridge: invalid optional preview field")
		}
		size += 1 + len(field)
	}
	if size > MaxBridgeResultBytes {
		return nil, errors.New("androidbridge: preview too large")
	}
	out := make([]byte, size)
	copy(out[:4], verifyPreviewMagic)
	offset := 4
	for _, field := range fields {
		out[offset] = byte(len(field))
		offset++
		copy(out[offset:], field)
		offset += len(field)
	}
	for _, field := range optionalFields {
		out[offset] = byte(len(field))
		offset++
		copy(out[offset:], field)
		offset += len(field)
	}
	var flags byte
	if preview.Inspection.Sealed {
		flags |= 1
	}
	if preview.Trust.OwnerControlled {
		flags |= 2
	}
	if preview.Trust.UpdatesEnabled {
		flags |= 4
	}
	out[offset] = flags
	offset++
	binary.BigEndian.PutUint64(out[offset:], preview.Inspection.Generation)
	offset += 8
	binary.BigEndian.PutUint64(out[offset:], uint64(preview.Inspection.ValidUntil))
	return out, nil
}

func lineageFingerprint(providerID, lineageID string) string {
	digest := sha256.Sum256([]byte("kurd-android-lineage-v1\x00" + providerID + "\x00" + lineageID))
	return hex.EncodeToString(digest[:])
}

func encodeIngressKind(kind envelope.IngressKind) (byte, bool) {
	switch kind {
	case envelope.IngressFile:
		return 1, true
	case envelope.IngressURI:
		return 2, true
	case envelope.IngressClipboard:
		return 3, true
	case envelope.IngressQRChunks:
		return 4, true
	case envelope.IngressSubscription:
		return 5, true
	default:
		return 0, false
	}
}

func decodeIngressKind(value byte) (envelope.IngressKind, bool) {
	switch value {
	case 1:
		return envelope.IngressFile, true
	case 2:
		return envelope.IngressURI, true
	case 3:
		return envelope.IngressClipboard, true
	case 4:
		return envelope.IngressQRChunks, true
	case 5:
		return envelope.IngressSubscription, true
	default:
		return "", false
	}
}

func encodeArtifactClass(class envelope.ArtifactClass) (byte, bool) {
	switch class {
	case envelope.ArtifactSignedPublic:
		return 1, true
	case envelope.ArtifactProviderGroup:
		return 2, true
	case envelope.ArtifactDeviceRecipient:
		return 3, true
	case envelope.ArtifactEncryptedBackup:
		return 4, true
	default:
		return 0, false
	}
}

func decodeArtifactClass(value byte) (envelope.ArtifactClass, bool) {
	switch value {
	case 1:
		return envelope.ArtifactSignedPublic, true
	case 2:
		return envelope.ArtifactProviderGroup, true
	case 3:
		return envelope.ArtifactDeviceRecipient, true
	case 4:
		return envelope.ArtifactEncryptedBackup, true
	default:
		return "", false
	}
}
