// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"io"
	"time"

	"kurdistan/internal/product/enrollment"
)

const MaxRecipientValiditySeconds = uint32(enrollment.MaxValiditySeconds)

// RecipientCredentials contains the exact public enrollment request and the
// matching device-private capability. It never crosses the public bridge as a
// decoded object. Callers receive only the two canonical byte encodings.
type RecipientCredentials struct {
	Request enrollment.PublicRequestV1
	Private enrollment.PrivateBundleV1
}

func (credentials RecipientCredentials) Clone() RecipientCredentials {
	return RecipientCredentials{
		Request: cloneRecipientRequest(credentials.Request),
		Private: cloneRecipientPrivate(credentials.Private),
	}
}

func (credentials *RecipientCredentials) Destroy() {
	if credentials == nil {
		return
	}
	clear(credentials.Request.RecipientPublic)
	clear(credentials.Request.ClientAuthPublic)
	clear(credentials.Request.Nonce)
	clear(credentials.Request.Signature)
	clear(credentials.Private.RecipientPrivate)
	clear(credentials.Private.ClientAuthSeed)
	*credentials = RecipientCredentials{}
}

type recipientHandle struct{ credentials RecipientCredentials }

func (state *recipientHandle) Destroy() {
	if state == nil {
		return
	}
	state.credentials.Destroy()
}

func CreateRecipient(registry *HandleRegistry, now time.Time, validity time.Duration, random io.Reader) (Handle, ErrorCode) {
	if registry == nil || now.IsZero() || random == nil || validity <= 0 || validity > time.Duration(MaxRecipientValiditySeconds)*time.Second {
		return 0, CodeInvalidArgument
	}
	request, private, err := enrollment.Generate(now.UTC(), validity, random)
	if err != nil {
		return 0, CodeInternalFailure
	}
	credentials := RecipientCredentials{Request: request, Private: private}
	if err := validateRecipientCredentials(credentials); err != nil {
		credentials.Destroy()
		return 0, CodeInternalFailure
	}
	handle, code := registry.Open(HandleRecipient, &recipientHandle{credentials: credentials})
	if code != CodeOK {
		credentials.Destroy()
	}
	return handle, code
}

func RecipientRequest(registry *HandleRegistry, handle Handle) ([]byte, ErrorCode) {
	state, code := recipientState(registry, handle)
	if code != CodeOK {
		return nil, code
	}
	encoded, err := enrollment.EncodeRequestV1(state.credentials.Request)
	if err != nil {
		return nil, CodeInternalFailure
	}
	return encoded, CodeOK
}

func RecipientPrivateExport(registry *HandleRegistry, handle Handle) ([]byte, ErrorCode) {
	state, code := recipientState(registry, handle)
	if code != CodeOK {
		return nil, code
	}
	encoded, err := enrollment.EncodePrivateBundleV1(state.credentials.Private)
	if err != nil {
		return nil, CodeInternalFailure
	}
	return encoded, CodeOK
}

func DecodeRecipientCredentials(requestBytes, privateBytes []byte) (RecipientCredentials, ErrorCode) {
	request, err := enrollment.DecodeRequestV1(requestBytes)
	if err != nil {
		return RecipientCredentials{}, CodeVerificationRejected
	}
	private, err := enrollment.DecodePrivateBundleV1(privateBytes)
	if err != nil {
		return RecipientCredentials{}, CodeVerificationRejected
	}
	credentials := RecipientCredentials{Request: request, Private: private}
	if err := validateRecipientCredentials(credentials); err != nil {
		credentials.Destroy()
		return RecipientCredentials{}, CodeVerificationRejected
	}
	return credentials, CodeOK
}

func recipientState(registry *HandleRegistry, handle Handle) (*recipientHandle, ErrorCode) {
	if registry == nil {
		return nil, CodeInvalidHandle
	}
	value, code := registry.Get(handle, HandleRecipient)
	if code != CodeOK {
		return nil, code
	}
	state, ok := value.(*recipientHandle)
	if !ok || state == nil {
		return nil, CodeInternalFailure
	}
	return state, CodeOK
}

func validateRecipientCredentials(credentials RecipientCredentials) error {
	requestBytes, err := enrollment.EncodeRequestV1(credentials.Request)
	if err != nil {
		return err
	}
	defer clear(requestBytes)
	privateBytes, err := enrollment.EncodePrivateBundleV1(credentials.Private)
	if err != nil {
		return err
	}
	defer clear(privateBytes)

	privateCopy := bytes.Clone(credentials.Private.RecipientPrivate)
	recipientPrivate, err := hpke.DHKEM(ecdh.P256()).NewPrivateKey(privateCopy)
	clear(privateCopy)
	if err != nil || !bytes.Equal(recipientPrivate.PublicKey().Bytes(), credentials.Request.RecipientPublic) {
		return enrollmentError{}
	}
	clientPrivate := ed25519.NewKeyFromSeed(credentials.Private.ClientAuthSeed)
	defer clear(clientPrivate)
	if !bytes.Equal(clientPrivate.Public().(ed25519.PublicKey), credentials.Request.ClientAuthPublic) {
		return enrollmentError{}
	}
	return nil
}

type enrollmentError struct{}

func (enrollmentError) Error() string { return "androidbridge: recipient credentials rejected" }

func cloneRecipientRequest(request enrollment.PublicRequestV1) enrollment.PublicRequestV1 {
	request.RecipientPublic = bytes.Clone(request.RecipientPublic)
	request.ClientAuthPublic = bytes.Clone(request.ClientAuthPublic)
	request.Nonce = bytes.Clone(request.Nonce)
	request.Signature = bytes.Clone(request.Signature)
	return request
}

func cloneRecipientPrivate(private enrollment.PrivateBundleV1) enrollment.PrivateBundleV1 {
	private.RecipientPrivate = bytes.Clone(private.RecipientPrivate)
	private.ClientAuthSeed = bytes.Clone(private.ClientAuthSeed)
	return private
}
