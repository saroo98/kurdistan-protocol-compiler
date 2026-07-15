// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
)

const (
	handshakeVersion uint16 = 1
	clientHelloType  uint16 = 1
	serverHelloType  uint16 = 2
	clientFinishType uint16 = 3
	serverFinishType uint16 = 4
	maxHandshakeBody        = 1 << 20
)

var ErrHandshake = errors.New("authenticated first contact failed")

type FailureCode string

const (
	FailureInvalidEncoding     FailureCode = "invalid_encoding"
	FailureUnsupportedVersion  FailureCode = "unsupported_version"
	FailureOutOfOrder          FailureCode = "handshake_out_of_order"
	FailureUnknownIdentity     FailureCode = "unknown_identity"
	FailureUntrustedIdentity   FailureCode = "untrusted_identity"
	FailureSignatureInvalid    FailureCode = "signature_invalid"
	FailureProfileMismatch     FailureCode = "profile_mismatch"
	FailurePolicyFloorRejected FailureCode = "policy_floor_rejected"
	FailurePolicyMismatch      FailureCode = "policy_mismatch"
	FailureEphemeralInvalid    FailureCode = "ephemeral_invalid"
	FailureEntropy             FailureCode = "entropy_failed"
	FailureKeyAgreement        FailureCode = "key_agreement_failed"
	FailureKeyConfirmation     FailureCode = "key_confirmation_failed"
	FailureReplay              FailureCode = "handshake_replay"
	// FailureTimeout is reserved for a future transport-I/O construction. The
	// synchronous local candidate has no timeout path.
	FailureTimeout       FailureCode = "handshake_timeout"
	FailureInternalLimit FailureCode = "internal_limit"
)

type HandshakeError struct{ Code FailureCode }

func (e *HandshakeError) Error() string {
	return "authenticated first contact failed: " + string(e.Code)
}
func (e *HandshakeError) Unwrap() error { return ErrHandshake }

func fail(code FailureCode) error { return &HandshakeError{Code: code} }

type State string

const (
	StateNew            State = "new"
	StateNegotiating    State = "negotiating"
	StateAuthenticating State = "authenticating"
	StateEstablished    State = "established"
	StateRekeyPending   State = "rekey_pending"
	StateClosing        State = "closing"
	StateClosed         State = "closed"
)

type IdentityProvider interface {
	// Local transfers ownership of a fresh caller-owned private-key copy. The
	// handshake wipes the returned slice after validating and copying it.
	Local(identityID string) (ed25519.PrivateKey, error)
}

type TrustProvider interface {
	Peer(identityID string) (ed25519.PublicKey, error)
}

type Dependencies struct {
	Identity IdentityProvider `json:"-"`
	Trust    TrustProvider    `json:"-"`
}

// PeerParameters are public, profile-derived inputs. Secret identity material
// is deliberately supplied only through Dependencies.
type PeerParameters struct {
	IdentityID           string
	ProfileID            string
	ProfileHash          [32]byte
	OfferPolicy          ir.EffectiveSecurityPolicy
	FloorPolicy          ir.EffectiveSecurityPolicy
	OfferedCapabilities  []string
	RequiredCapabilities []string
	modeBinding          security.HandshakeModeBinding
	seal                 [32]byte
}

// NewPeerParameters seals every mode-specific field from an actually validated
// profile. Callers cannot supply an independent, matching-but-uncommitted mode
// binding alongside a different authenticated profile hash.
func NewPeerParameters(identityID string, profile *ir.Profile, offerPolicy, floorPolicy ir.EffectiveSecurityPolicy, offered, required []string) (PeerParameters, error) {
	if identityID == "" || profile == nil || ir.Validate(profile) != nil ||
		ir.ValidateEffectiveSecurityPolicy(offerPolicy) != nil ||
		ir.ValidateEffectiveSecurityPolicy(floorPolicy) != nil {
		return PeerParameters{}, fail(FailureProfileMismatch)
	}
	hash, err := ir.CanonicalHash(profile)
	if err != nil {
		return PeerParameters{}, fail(FailureProfileMismatch)
	}
	profileHash, err := decodeProfileHash(hash)
	if err != nil || offerPolicy.ProfileID != profile.ID || floorPolicy.ProfileID != profile.ID || offerPolicy.ProfileHash != hash || floorPolicy.ProfileHash != hash {
		return PeerParameters{}, fail(FailureProfileMismatch)
	}
	normalizedOffered, err := normalizeCapabilitySet(offered)
	if err != nil {
		return PeerParameters{}, fail(FailurePolicyMismatch)
	}
	normalizedRequired, err := normalizeCapabilitySet(required)
	if err != nil {
		return PeerParameters{}, fail(FailurePolicyFloorRejected)
	}
	binding, err := modeBindingFromProfile(profile, offerPolicy, profileHash)
	if err != nil {
		return PeerParameters{}, err
	}
	peer := PeerParameters{
		IdentityID: identityID, ProfileID: profile.ID, ProfileHash: profileHash,
		OfferPolicy: offerPolicy.Clone(), FloorPolicy: floorPolicy.Clone(),
		OfferedCapabilities: normalizedOffered, RequiredCapabilities: normalizedRequired,
		modeBinding: binding,
	}
	peer.seal, err = sealPeerParameters(peer)
	if err != nil {
		return PeerParameters{}, fail(FailureProfileMismatch)
	}
	return peer, nil
}

type FirstContactInput struct {
	Client               PeerParameters
	Server               PeerParameters
	SelectedPolicy       ir.EffectiveSecurityPolicy
	SelectedCapabilities []string
	ClientDependencies   Dependencies          `json:"-"`
	ServerDependencies   Dependencies          `json:"-"`
	Replay               *HandshakeReplayCache `json:"-"`
	// InboundClientHello models a captured wire message arriving on a new
	// simulated connection. Normal local initiations leave it empty.
	InboundClientHello []byte
}

type FirstContactResult struct {
	ClientState    State
	ServerState    State
	ClientNonce    [32]byte
	ServerNonce    [32]byte
	ClientPublic   [32]byte
	ServerPublic   [32]byte
	TranscriptHash [32]byte
	ChannelSecret  []byte `json:"-"`
	Messages       [4][]byte
	context        AuthenticatedContextV1
	successSeal    [32]byte
}

// AuthenticatedContextSnapshotV1 is a deep-cloned, nonsecret view of the
// success-only authenticated runtime context.
type AuthenticatedContextSnapshotV1 struct {
	EffectivePolicy              ir.EffectiveSecurityPolicy
	EffectivePolicyHash          [32]byte
	TranscriptHash               [32]byte
	SelectedSuite                security.SelectedSuiteV1
	SelectedCapabilityHash       [32]byte
	ClientProfileHash            [32]byte
	ServerProfileHash            [32]byte
	ClientCompatibilityBlock     security.CompatibilityBlockV1
	ClientCompatibilityBlockHash [32]byte
	ServerCompatibilityBlock     security.CompatibilityBlockV1
	ServerCompatibilityBlockHash [32]byte
	ClientLimitBlock             security.LimitBlockV1
	ClientLimitBlockHash         [32]byte
	ServerLimitBlock             security.LimitBlockV1
	ServerLimitBlockHash         [32]byte
	ClientConfigSourceBlock      security.ConfigSourceBlockV1
	ClientConfigSourceBlockHash  [32]byte
	ServerConfigSourceBlock      security.ConfigSourceBlockV1
	ServerConfigSourceBlockHash  [32]byte
	ClientModeBinding            security.HandshakeModeBinding
	ServerModeBinding            security.HandshakeModeBinding
	ContextHash                  [32]byte
}

// AuthenticatedContextV1 is auth-owned provenance. Its state and seal are
// intentionally opaque outside this package.
type AuthenticatedContextV1 struct {
	snapshot AuthenticatedContextSnapshotV1
	seal     [32]byte
}

// FirstContactPreflightViewV1 is a nonsecret, deep-cloned projection of the
// exact validated public inputs used by FirstContact.
type FirstContactPreflightViewV1 struct {
	ClientOfferPolicy          ir.EffectiveSecurityPolicy
	ClientFloorPolicy          ir.EffectiveSecurityPolicy
	ServerOfferPolicy          ir.EffectiveSecurityPolicy
	ServerFloorPolicy          ir.EffectiveSecurityPolicy
	SelectedPolicy             ir.EffectiveSecurityPolicy
	ClientOfferedCapabilities  []string
	ClientRequiredCapabilities []string
	ServerOfferedCapabilities  []string
	ServerRequiredCapabilities []string
	SelectedCapabilities       []string
	ClientModeBinding          security.HandshakeModeBinding
	ServerModeBinding          security.HandshakeModeBinding
}

// HandshakeReplayCache is intentionally owned by a runtime coordinator, not by
// one connection. It fails closed at capacity and never evicts accepted keys.
type HandshakeReplayCache struct {
	mu       sync.Mutex
	seen     map[[32]byte]struct{}
	capacity int
}

func NewHandshakeReplayCache(capacity int) (*HandshakeReplayCache, error) {
	if capacity <= 0 || capacity > 65536 {
		return nil, fail(FailureInternalLimit)
	}
	return &HandshakeReplayCache{seen: make(map[[32]byte]struct{}), capacity: capacity}, nil
}

func (c *HandshakeReplayCache) record(key [32]byte) error {
	if c == nil {
		return fail(FailureInternalLimit)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return fail(FailureReplay)
	}
	if len(c.seen) >= c.capacity {
		return fail(FailureInternalLimit)
	}
	c.seen[key] = struct{}{}
	return nil
}

type mutationPoint uint8

const (
	mutateClientHello mutationPoint = iota + 1
	mutateServerHello
	mutateClientFinish
	mutateServerFinish
)

type messageMutator func(mutationPoint, []byte) []byte

type executionOptions struct {
	mutateMessage         messageMutator
	mutateClientTH2       func(*[32]byte)
	clientEntropy         io.Reader
	serverEntropy         io.Reader
	replayMessages        *[4][]byte
	observePrivateCopies  func(client, server ed25519.PrivateKey)
	omitTranscriptBinding bool
}

func FirstContact(input FirstContactInput) (FirstContactResult, error) {
	return firstContact(input, nil)
}

func FirstContactWithAuthLabFaultV1(input FirstContactInput, token AuthLabFaultToken) (FirstContactResult, error) {
	if !validAuthLabFaultV1(token) || token.mode > authLabFaultProfileMismatchV1 {
		return closeResult(FirstContactResult{}), errAuthLabFaultInvalidV1
	}
	repaired, err := applyAuthLabInputFaultV1(token, input)
	if err != nil {
		return closeResult(FirstContactResult{}), err
	}
	return firstContactWithOptions(repaired, executionOptions{omitTranscriptBinding: token.mode == authLabFaultNoTranscriptV1})
}

// SnapshotFirstContactInputV1 validates original peer seals before cloning,
// fully validates the cloned public input, and returns no executable
// dependency or replay authority.
func SnapshotFirstContactInputV1(input FirstContactInput) (FirstContactInput, FirstContactPreflightViewV1, error) {
	if err := validateOriginalPeerSeals(input); err != nil {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, err
	}
	if len(input.InboundClientHello) > 4+maxHandshakeBody {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, fail(FailureInvalidEncoding)
	}
	if err := validateFirstContactDependencies(input); err != nil {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, err
	}
	snapshot := cloneFirstContactInput(input)
	var err error
	snapshot.Client.seal, err = sealPeerParameters(snapshot.Client)
	if err != nil {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, fail(FailureProfileMismatch)
	}
	snapshot.Server.seal, err = sealPeerParameters(snapshot.Server)
	if err != nil {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, fail(FailureProfileMismatch)
	}
	if err := validateFirstContactPublicInput(snapshot); err != nil {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, err
	}
	clientBinding, serverBinding, err := projectedModeBindings(snapshot)
	if err != nil {
		return FirstContactInput{}, FirstContactPreflightViewV1{}, err
	}
	view := FirstContactPreflightViewV1{
		ClientOfferPolicy:          snapshot.Client.OfferPolicy.Clone(),
		ClientFloorPolicy:          snapshot.Client.FloorPolicy.Clone(),
		ServerOfferPolicy:          snapshot.Server.OfferPolicy.Clone(),
		ServerFloorPolicy:          snapshot.Server.FloorPolicy.Clone(),
		SelectedPolicy:             snapshot.SelectedPolicy.Clone(),
		ClientOfferedCapabilities:  append([]string(nil), snapshot.Client.OfferedCapabilities...),
		ClientRequiredCapabilities: append([]string(nil), snapshot.Client.RequiredCapabilities...),
		ServerOfferedCapabilities:  append([]string(nil), snapshot.Server.OfferedCapabilities...),
		ServerRequiredCapabilities: append([]string(nil), snapshot.Server.RequiredCapabilities...),
		SelectedCapabilities:       append([]string(nil), snapshot.SelectedCapabilities...),
		ClientModeBinding:          clientBinding.Clone(),
		ServerModeBinding:          serverBinding.Clone(),
	}
	snapshot.ClientDependencies = Dependencies{}
	snapshot.ServerDependencies = Dependencies{}
	snapshot.Replay = nil
	return snapshot, clonePreflightView(view), nil
}

// AuthenticatedContextSnapshotV1 returns context only from an intact,
// success-sealed result and never aliases the stored value.
func (r FirstContactResult) AuthenticatedContextSnapshotV1() (AuthenticatedContextSnapshotV1, bool) {
	if !r.context.valid() || isZero32(r.successSeal) {
		return AuthenticatedContextSnapshotV1{}, false
	}
	want := sealFirstContactResult(r)
	if !hmac.Equal(r.successSeal[:], want[:]) {
		return AuthenticatedContextSnapshotV1{}, false
	}
	return cloneContextSnapshot(r.context.snapshot), true
}

func firstContact(input FirstContactInput, mutate messageMutator) (FirstContactResult, error) {
	return firstContactWithOptions(input, executionOptions{mutateMessage: mutate})
}

func firstContactWithOptions(input FirstContactInput, options executionOptions) (FirstContactResult, error) {
	var result FirstContactResult
	result.ClientState, result.ServerState = StateNew, StateNew
	if err := validateFirstContactInput(input); err != nil {
		return closeResult(result), err
	}
	clientPrivate, clientPeerPublic, err := loadCredentials(input.Client, input.Server, input.ClientDependencies)
	if err != nil {
		return closeResult(result), err
	}
	defer wipe(clientPrivate)
	serverPrivate, serverPeerPublic, err := loadCredentials(input.Server, input.Client, input.ServerDependencies)
	if err != nil {
		return closeResult(result), err
	}
	defer wipe(serverPrivate)
	if options.observePrivateCopies != nil {
		options.observePrivateCopies(clientPrivate, serverPrivate)
	}
	result.ClientState, result.ServerState = StateNegotiating, StateNegotiating

	clientEntropy := options.clientEntropy
	if clientEntropy == nil {
		clientEntropy = rand.Reader
	}
	serverEntropy := options.serverEntropy
	if serverEntropy == nil {
		serverEntropy = rand.Reader
	}
	clientEphemeral, clientPublic, clientNonce, err := freshContribution(clientEntropy)
	if err != nil {
		return closeResult(result), err
	}
	result.ClientPublic, result.ClientNonce = clientPublic, clientNonce
	clientHello, clientSentBody, err := makeClientHello(input.Client, clientPrivate, clientPublic, clientNonce)
	if err != nil {
		return closeResult(result), err
	}
	if len(input.InboundClientHello) != 0 {
		clientHello = append([]byte(nil), input.InboundClientHello...)
	}
	if options.replayMessages != nil {
		clientHello = append([]byte(nil), options.replayMessages[0]...)
	}
	clientHello = applyMutation(options.mutateMessage, mutateClientHello, clientHello)
	parsedClient, receivedClientBody, err := parseClientHello(clientHello)
	if err != nil {
		return closeResult(result), err
	}
	if err := authenticateClientHello(parsedClient, input.Client.IdentityID, serverPeerPublic); err != nil {
		return closeResult(result), err
	}
	replayKey := protocolHash("kurdistan/handshake/v1/replay-key", []byte(parsedClient.identityID), parsedClient.nonce[:], parsedClient.public[:], parsedClient.profileHash[:])
	if err := input.Replay.record(replayKey); err != nil {
		return closeResult(result), err
	}
	if err := validateClientHelloSemantics(parsedClient, input.Client); err != nil {
		return closeResult(result), err
	}
	result.ClientState, result.ServerState = StateAuthenticating, StateAuthenticating

	serverEphemeral, serverPublic, serverNonce, err := freshContribution(serverEntropy)
	if err != nil {
		return closeResult(result), err
	}
	result.ServerPublic, result.ServerNonce = serverPublic, serverNonce
	serverHello, serverSentBody, err := makeServerHello(input, serverPrivate, receivedClientBody, serverPublic, serverNonce)
	if err != nil {
		return closeResult(result), err
	}
	if options.replayMessages != nil {
		serverHello = append([]byte(nil), options.replayMessages[1]...)
	}
	serverHello = applyMutation(options.mutateMessage, mutateServerHello, serverHello)
	parsedServer, receivedServerBody, err := parseServerHello(serverHello)
	if err != nil {
		return closeResult(result), err
	}
	if err := validateServerHello(parsedServer, input, clientPeerPublic, clientSentBody); err != nil {
		return closeResult(result), err
	}

	clientDH, err := sharedSecret(clientEphemeral, parsedServer.public)
	if err != nil {
		return closeResult(result), err
	}
	serverDH, err := sharedSecret(serverEphemeral, parsedClient.public)
	if err != nil {
		return closeResult(result), fail(FailureKeyAgreement)
	}
	defer wipe(clientDH)
	defer wipe(serverDH)
	clientTH2 := protocolHash("kurdistan/handshake/v1/transcript-hello", clientSentBody, receivedServerBody)
	serverTH2 := protocolHash("kurdistan/handshake/v1/transcript-hello", receivedClientBody, serverSentBody)
	if options.omitTranscriptBinding {
		clientTH2, serverTH2 = [32]byte{}, [32]byte{}
	}
	if options.mutateClientTH2 != nil {
		options.mutateClientTH2(&clientTH2)
	}
	clientClientConfirmKey, clientServerConfirmKey, clientHandshakePRK, err := confirmationKeys(clientDH, input.Client.ProfileHash, clientNonce, parsedServer.nonce, clientPublic, parsedServer.public, clientTH2)
	if err != nil {
		return closeResult(result), err
	}
	defer wipe(clientClientConfirmKey)
	defer wipe(clientServerConfirmKey)
	defer wipe(clientHandshakePRK)
	serverClientConfirmKey, serverServerConfirmKey, serverHandshakePRK, err := confirmationKeys(serverDH, parsedClient.profileHash, parsedClient.nonce, serverNonce, parsedClient.public, serverPublic, serverTH2)
	if err != nil {
		return closeResult(result), err
	}
	defer wipe(serverClientConfirmKey)
	defer wipe(serverServerConfirmKey)
	defer wipe(serverHandshakePRK)
	clientFinish, clientFinishSentBody := makeClientFinish(clientPrivate, clientClientConfirmKey, clientTH2)
	if options.replayMessages != nil {
		clientFinish = append([]byte(nil), options.replayMessages[2]...)
	}
	clientFinish = applyMutation(options.mutateMessage, mutateClientFinish, clientFinish)
	receivedClientFinish, err := validateClientFinish(clientFinish, serverPeerPublic, serverClientConfirmKey, serverTH2)
	if err != nil {
		return closeResult(result), err
	}
	clientTH3 := protocolHash("kurdistan/handshake/v1/transcript-client-finish", clientSentBody, receivedServerBody, clientFinishSentBody)
	serverTH3 := protocolHash("kurdistan/handshake/v1/transcript-client-finish", receivedClientBody, serverSentBody, receivedClientFinish)
	serverFinish, serverFinishSentBody := makeServerFinish(serverPrivate, serverServerConfirmKey, serverTH3)
	if options.replayMessages != nil {
		serverFinish = append([]byte(nil), options.replayMessages[3]...)
	}
	serverFinish = applyMutation(options.mutateMessage, mutateServerFinish, serverFinish)
	receivedServerFinish, err := validateServerFinish(serverFinish, clientPeerPublic, clientServerConfirmKey, clientTH3)
	if err != nil {
		return closeResult(result), err
	}
	clientTH4 := protocolHash("kurdistan/handshake/v1/transcript-final", clientSentBody, receivedServerBody, clientFinishSentBody, receivedServerFinish)
	serverTH4 := protocolHash("kurdistan/handshake/v1/transcript-final", receivedClientBody, serverSentBody, receivedClientFinish, serverFinishSentBody)
	clientApplicationSalt := protocolHash("kurdistan/hkdf/v1/application-salt", clientTH4[:], input.Client.ProfileHash[:])
	clientChannelSecret, err := hkdf.Extract(sha256.New, clientHandshakePRK, clientApplicationSalt[:])
	if err != nil {
		return closeResult(result), fail(FailureKeyAgreement)
	}
	defer wipe(clientChannelSecret)
	serverApplicationSalt := protocolHash("kurdistan/hkdf/v1/application-salt", serverTH4[:], parsedClient.profileHash[:])
	serverChannelSecret, err := hkdf.Extract(sha256.New, serverHandshakePRK, serverApplicationSalt[:])
	if err != nil {
		return closeResult(result), fail(FailureKeyAgreement)
	}
	defer wipe(serverChannelSecret)
	if clientTH4 != serverTH4 || !hmac.Equal(clientChannelSecret, serverChannelSecret) {
		return closeResult(result), fail(FailureKeyConfirmation)
	}
	context, err := newAuthenticatedContextV1(input, clientTH4)
	if err != nil {
		return closeResult(result), err
	}
	result.ClientState, result.ServerState = StateEstablished, StateAuthenticating
	result.TranscriptHash = clientTH4
	result.ChannelSecret = append([]byte(nil), clientChannelSecret...)
	result.Messages = [4][]byte{clientHello, serverHello, clientFinish, serverFinish}
	result.context = context
	result.successSeal = sealFirstContactResult(result)
	return result, nil
}

func closeResult(result FirstContactResult) FirstContactResult {
	result.ClientState, result.ServerState = StateClosed, StateClosed
	result.ChannelSecret = nil
	result.context = AuthenticatedContextV1{}
	result.successSeal = [32]byte{}
	return result
}

func applyMutation(mutate messageMutator, point mutationPoint, message []byte) []byte {
	if mutate == nil {
		return message
	}
	return mutate(point, append([]byte(nil), message...))
}

func validateFirstContactInput(input FirstContactInput) error {
	if err := validateFirstContactPublicInput(input); err != nil {
		return err
	}
	return validateFirstContactDependencies(input)
}

func validateOriginalPeerSeals(input FirstContactInput) error {
	for _, peer := range []PeerParameters{input.Client, input.Server} {
		seal, sealErr := sealPeerParameters(peer)
		if sealErr != nil || isZero32(peer.seal) || !hmac.Equal(peer.seal[:], seal[:]) {
			return fail(FailureProfileMismatch)
		}
	}
	return nil
}

func validateFirstContactPublicInput(input FirstContactInput) error {
	if err := validateOriginalPeerSeals(input); err != nil {
		return err
	}
	if len(input.InboundClientHello) > 4+maxHandshakeBody {
		return fail(FailureInvalidEncoding)
	}
	for _, peer := range []PeerParameters{input.Client, input.Server} {
		if peer.IdentityID == "" || peer.ProfileID == "" || isZero32(peer.ProfileHash) {
			return fail(FailureProfileMismatch)
		}
		if err := ir.ValidateEffectiveSecurityPolicy(peer.OfferPolicy); err != nil {
			return fail(FailurePolicyMismatch)
		}
		if err := ir.ValidateEffectiveSecurityPolicy(peer.FloorPolicy); err != nil {
			return fail(FailurePolicyFloorRejected)
		}
		profileHash, err := decodeProfileHash(peer.OfferPolicy.ProfileHash)
		if err != nil || profileHash != peer.ProfileHash || peer.ProfileID != peer.OfferPolicy.ProfileID {
			return fail(FailureProfileMismatch)
		}
	}
	if err := ir.ValidateEffectiveSecurityPolicy(input.SelectedPolicy); err != nil {
		return fail(FailurePolicyMismatch)
	}
	if input.Client.ProfileID != input.Server.ProfileID || input.Client.ProfileHash != input.Server.ProfileHash {
		return fail(FailureProfileMismatch)
	}
	clientModeBinding, serverModeBinding, err := projectedModeBindings(input)
	if err != nil {
		return err
	}
	clientBinding, err := security.CanonicalHandshakeModeBinding(input.Client.OfferPolicy.TranscriptMode, clientModeBinding)
	if err != nil {
		return fail(FailurePolicyMismatch)
	}
	serverBinding, err := security.CanonicalHandshakeModeBinding(input.Server.OfferPolicy.TranscriptMode, serverModeBinding)
	if err != nil || !hmac.Equal(clientBinding, serverBinding) {
		return fail(FailureProfileMismatch)
	}
	if input.Client.OfferPolicy.TranscriptMode != input.Server.OfferPolicy.TranscriptMode || input.SelectedPolicy.TranscriptMode != input.Client.OfferPolicy.TranscriptMode {
		return fail(FailurePolicyMismatch)
	}
	selected, err := security.EncodeStringListV1(input.SelectedCapabilities)
	wantSelected, wantErr := security.EncodeStringListV1(input.SelectedPolicy.SelectedCapabilities)
	if err != nil || wantErr != nil || len(selected) == 0 || !hmac.Equal(selected, wantSelected) {
		return fail(FailurePolicyFloorRejected)
	}
	if !canonicalListEqual(input.Client.RequiredCapabilities, input.SelectedPolicy.ClientMandatoryCapabilities) ||
		!canonicalListEqual(input.Server.RequiredCapabilities, input.SelectedPolicy.ServerMandatoryCapabilities) {
		return fail(FailurePolicyFloorRejected)
	}
	if input.SelectedPolicy.DowngradePolicy == "strict_suite_and_capabilities" &&
		!canonicalListEqual(input.Client.RequiredCapabilities, input.Server.RequiredCapabilities) {
		return fail(FailurePolicyFloorRejected)
	}
	for _, carrier := range []ir.EffectiveSecurityPolicy{input.Client.OfferPolicy, input.Client.FloorPolicy, input.Server.OfferPolicy, input.Server.FloorPolicy} {
		if !canonicalListEqual(carrier.ClientMandatoryCapabilities, input.SelectedPolicy.ClientMandatoryCapabilities) ||
			!canonicalListEqual(carrier.ServerMandatoryCapabilities, input.SelectedPolicy.ServerMandatoryCapabilities) ||
			!canonicalListEqual(carrier.SelectedCapabilities, input.SelectedPolicy.SelectedCapabilities) {
			return fail(FailurePolicyFloorRejected)
		}
	}
	selectedProfileHash, err := decodeProfileHash(input.SelectedPolicy.ProfileHash)
	if err != nil || input.SelectedPolicy.ProfileID != input.Client.ProfileID || selectedProfileHash != input.Client.ProfileHash {
		return fail(FailureProfileMismatch)
	}
	for _, peer := range []PeerParameters{input.Client, input.Server} {
		floorHash, floorErr := decodeProfileHash(peer.FloorPolicy.ProfileHash)
		if floorErr != nil || peer.FloorPolicy.ProfileID != peer.ProfileID || floorHash != peer.ProfileHash {
			return fail(FailurePolicyFloorRejected)
		}
	}
	// WO-005 owns selection. This call validates the supplied selection against
	// its deterministic bilateral capability rule; it does not select PolicyV1.
	selection, err := security.SelectBilateralCapabilities(security.BilateralCapabilityInput{
		LocalOffer:                  security.CapabilitySet{Features: input.Client.OfferedCapabilities},
		PeerOffer:                   security.CapabilitySet{Features: input.Server.OfferedCapabilities},
		LocalFloor:                  security.CapabilitySet{Features: input.Client.RequiredCapabilities},
		PeerFloor:                   security.CapabilitySet{Features: input.Server.RequiredCapabilities},
		CapabilityNegotiationPolicy: input.SelectedPolicy.CapabilityNegotiationPolicy,
		DowngradePolicy:             input.SelectedPolicy.DowngradePolicy,
		LocalSuite:                  policySuite(input.Client.OfferPolicy), PeerSuite: policySuite(input.Server.OfferPolicy),
		LocalTranscriptMode: input.Client.OfferPolicy.TranscriptMode, PeerTranscriptMode: input.Server.OfferPolicy.TranscriptMode,
	})
	computed, computedErr := security.EncodeStringListV1(selection.Features)
	if err != nil || computedErr != nil || !hmac.Equal(computed, selected) {
		return fail(FailurePolicyFloorRejected)
	}
	selectedPolicyRaw, selectedErr := security.EncodePolicyV1(input.SelectedPolicy)
	clientPolicyRaw, clientErr := security.EncodePolicyV1(input.Client.OfferPolicy)
	serverPolicyRaw, serverErr := security.EncodePolicyV1(input.Server.OfferPolicy)
	clientFloorPolicyRaw, clientFloorErr := security.EncodePolicyV1(input.Client.FloorPolicy)
	serverFloorPolicyRaw, serverFloorErr := security.EncodePolicyV1(input.Server.FloorPolicy)
	if selectedErr != nil || clientErr != nil || serverErr != nil || clientFloorErr != nil || serverFloorErr != nil ||
		!hmac.Equal(selectedPolicyRaw, clientPolicyRaw) || !hmac.Equal(selectedPolicyRaw, serverPolicyRaw) ||
		!hmac.Equal(selectedPolicyRaw, clientFloorPolicyRaw) || !hmac.Equal(selectedPolicyRaw, serverFloorPolicyRaw) {
		return fail(FailurePolicyMismatch)
	}
	if err := validateContextSources(input, clientModeBinding, serverModeBinding); err != nil {
		return err
	}
	return nil
}

func validateFirstContactDependencies(input FirstContactInput) error {
	if input.ClientDependencies.Identity == nil || input.ClientDependencies.Trust == nil ||
		input.ServerDependencies.Identity == nil || input.ServerDependencies.Trust == nil || input.Replay == nil {
		return fail(FailureUnknownIdentity)
	}
	return nil
}

func validateContextSources(input FirstContactInput, clientBinding, serverBinding security.HandshakeModeBinding) error {
	policyHash, err := security.EffectivePolicyHashV1(input.SelectedPolicy)
	if err != nil {
		return fail(FailurePolicyMismatch)
	}
	capabilityHash, err := security.SelectedCapabilityHashV1(input.SelectedPolicy.SelectedCapabilities)
	if err != nil {
		return fail(FailurePolicyFloorRejected)
	}
	_, err = security.ContextHashV1(security.AuthenticatedContextHashInputV1{
		EffectivePolicy:     input.SelectedPolicy.Clone(),
		EffectivePolicyHash: policyHash,
		TranscriptHash:      [32]byte{1},
		SelectedSuite: security.SelectedSuiteV1{
			KDFSuite:  input.SelectedPolicy.KDFSuite,
			AEADSuite: input.SelectedPolicy.AEADSuite,
			MACSuite:  input.SelectedPolicy.MACSuite,
		},
		SelectedCapabilityHash: capabilityHash,
		ClientProfileHash:      input.Client.ProfileHash,
		ServerProfileHash:      input.Server.ProfileHash,
		ClientModeBinding:      clientBinding.Clone(),
		ServerModeBinding:      serverBinding.Clone(),
	})
	if err != nil {
		return fail(FailureProfileMismatch)
	}
	return nil
}

func projectedModeBindings(input FirstContactInput) (security.HandshakeModeBinding, security.HandshakeModeBinding, error) {
	client := input.Client.modeBinding.Clone()
	server := input.Server.modeBinding.Clone()
	clientOptional := optionalCapabilities(input.Client.OfferedCapabilities, input.Client.RequiredCapabilities)
	serverOptional := optionalCapabilities(input.Server.OfferedCapabilities, input.Server.RequiredCapabilities)
	client.ClientOptional = append([]string(nil), clientOptional...)
	client.ServerOptional = append([]string(nil), serverOptional...)
	server.ClientOptional = append([]string(nil), clientOptional...)
	server.ServerOptional = append([]string(nil), serverOptional...)
	for _, item := range []struct {
		mode    string
		stored  security.HandshakeModeBinding
		derived security.HandshakeModeBinding
	}{
		{input.Client.OfferPolicy.TranscriptMode, input.Client.modeBinding, client},
		{input.Server.OfferPolicy.TranscriptMode, input.Server.modeBinding, server},
	} {
		derivedRaw, err := security.CanonicalAuthenticatedModeBindingV1(item.mode, item.derived)
		if err != nil {
			return security.HandshakeModeBinding{}, security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
		}
		if len(item.stored.ClientOptional) == 0 && len(item.stored.ServerOptional) == 0 {
			continue
		}
		storedRaw, err := security.CanonicalAuthenticatedModeBindingV1(item.mode, item.stored)
		if err != nil || !hmac.Equal(storedRaw, derivedRaw) {
			return security.HandshakeModeBinding{}, security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
		}
	}
	return client, server, nil
}

func clonePeerParameters(peer PeerParameters) PeerParameters {
	peer.OfferPolicy = peer.OfferPolicy.Clone()
	peer.FloorPolicy = peer.FloorPolicy.Clone()
	peer.OfferedCapabilities = append([]string(nil), peer.OfferedCapabilities...)
	peer.RequiredCapabilities = append([]string(nil), peer.RequiredCapabilities...)
	peer.modeBinding = peer.modeBinding.Clone()
	return peer
}

func cloneFirstContactInput(input FirstContactInput) FirstContactInput {
	input.Client = clonePeerParameters(input.Client)
	input.Server = clonePeerParameters(input.Server)
	input.SelectedPolicy = input.SelectedPolicy.Clone()
	input.SelectedCapabilities = append([]string(nil), input.SelectedCapabilities...)
	input.InboundClientHello = append([]byte(nil), input.InboundClientHello...)
	return input
}

func clonePreflightView(view FirstContactPreflightViewV1) FirstContactPreflightViewV1 {
	view.ClientOfferPolicy = view.ClientOfferPolicy.Clone()
	view.ClientFloorPolicy = view.ClientFloorPolicy.Clone()
	view.ServerOfferPolicy = view.ServerOfferPolicy.Clone()
	view.ServerFloorPolicy = view.ServerFloorPolicy.Clone()
	view.SelectedPolicy = view.SelectedPolicy.Clone()
	view.ClientOfferedCapabilities = append([]string(nil), view.ClientOfferedCapabilities...)
	view.ClientRequiredCapabilities = append([]string(nil), view.ClientRequiredCapabilities...)
	view.ServerOfferedCapabilities = append([]string(nil), view.ServerOfferedCapabilities...)
	view.ServerRequiredCapabilities = append([]string(nil), view.ServerRequiredCapabilities...)
	view.SelectedCapabilities = append([]string(nil), view.SelectedCapabilities...)
	view.ClientModeBinding = view.ClientModeBinding.Clone()
	view.ServerModeBinding = view.ServerModeBinding.Clone()
	return view
}

func newAuthenticatedContextV1(input FirstContactInput, transcriptHash [32]byte) (AuthenticatedContextV1, error) {
	clientBinding, serverBinding, err := projectedModeBindings(input)
	if err != nil {
		return AuthenticatedContextV1{}, err
	}
	effectivePolicyHash, err := security.EffectivePolicyHashV1(input.SelectedPolicy)
	if err != nil {
		return AuthenticatedContextV1{}, fail(FailurePolicyMismatch)
	}
	selectedCapabilityHash, err := security.SelectedCapabilityHashV1(input.SelectedPolicy.SelectedCapabilities)
	if err != nil {
		return AuthenticatedContextV1{}, fail(FailurePolicyFloorRejected)
	}
	suite := security.SelectedSuiteV1{
		KDFSuite:  input.SelectedPolicy.KDFSuite,
		AEADSuite: input.SelectedPolicy.AEADSuite,
		MACSuite:  input.SelectedPolicy.MACSuite,
	}
	hashInput := security.AuthenticatedContextHashInputV1{
		EffectivePolicy:        input.SelectedPolicy.Clone(),
		EffectivePolicyHash:    effectivePolicyHash,
		TranscriptHash:         transcriptHash,
		SelectedSuite:          suite,
		SelectedCapabilityHash: selectedCapabilityHash,
		ClientProfileHash:      input.Client.ProfileHash,
		ServerProfileHash:      input.Server.ProfileHash,
		ClientModeBinding:      clientBinding.Clone(),
		ServerModeBinding:      serverBinding.Clone(),
	}
	contextHash, err := security.ContextHashV1(hashInput)
	if err != nil {
		return AuthenticatedContextV1{}, fail(FailureProfileMismatch)
	}
	snapshot := AuthenticatedContextSnapshotV1{
		EffectivePolicy:              input.SelectedPolicy.Clone(),
		EffectivePolicyHash:          effectivePolicyHash,
		TranscriptHash:               transcriptHash,
		SelectedSuite:                suite,
		SelectedCapabilityHash:       selectedCapabilityHash,
		ClientProfileHash:            input.Client.ProfileHash,
		ServerProfileHash:            input.Server.ProfileHash,
		ClientCompatibilityBlock:     clientBinding.CompatibilityBlock.Clone(),
		ClientCompatibilityBlockHash: clientBinding.CompatibilityBlockHash,
		ServerCompatibilityBlock:     serverBinding.CompatibilityBlock.Clone(),
		ServerCompatibilityBlockHash: serverBinding.CompatibilityBlockHash,
		ClientLimitBlock:             clientBinding.LimitBlock,
		ClientLimitBlockHash:         clientBinding.LimitBlockHash,
		ServerLimitBlock:             serverBinding.LimitBlock,
		ServerLimitBlockHash:         serverBinding.LimitBlockHash,
		ClientConfigSourceBlock:      clientBinding.ConfigSourceBlock,
		ClientConfigSourceBlockHash:  clientBinding.ConfigSourceBlockHash,
		ServerConfigSourceBlock:      serverBinding.ConfigSourceBlock,
		ServerConfigSourceBlockHash:  serverBinding.ConfigSourceBlockHash,
		ClientModeBinding:            clientBinding.Clone(),
		ServerModeBinding:            serverBinding.Clone(),
		ContextHash:                  contextHash,
	}
	context := AuthenticatedContextV1{snapshot: snapshot}
	context.seal = protocolHash("kurdistan/context/v1/provenance-seal", contextHash[:])
	if !context.valid() {
		return AuthenticatedContextV1{}, fail(FailureProfileMismatch)
	}
	return context, nil
}

func (c AuthenticatedContextV1) valid() bool {
	if isZero32(c.seal) || isZero32(c.snapshot.ContextHash) {
		return false
	}
	wantSeal := protocolHash("kurdistan/context/v1/provenance-seal", c.snapshot.ContextHash[:])
	if !hmac.Equal(c.seal[:], wantSeal[:]) || !contextSnapshotBindingsMatch(c.snapshot) {
		return false
	}
	wantHash, err := security.ContextHashV1(contextHashInputFromSnapshot(c.snapshot))
	return err == nil && hmac.Equal(c.snapshot.ContextHash[:], wantHash[:])
}

func contextHashInputFromSnapshot(snapshot AuthenticatedContextSnapshotV1) security.AuthenticatedContextHashInputV1 {
	return security.AuthenticatedContextHashInputV1{
		EffectivePolicy:        snapshot.EffectivePolicy.Clone(),
		EffectivePolicyHash:    snapshot.EffectivePolicyHash,
		TranscriptHash:         snapshot.TranscriptHash,
		SelectedSuite:          snapshot.SelectedSuite,
		SelectedCapabilityHash: snapshot.SelectedCapabilityHash,
		ClientProfileHash:      snapshot.ClientProfileHash,
		ServerProfileHash:      snapshot.ServerProfileHash,
		ClientModeBinding:      snapshot.ClientModeBinding.Clone(),
		ServerModeBinding:      snapshot.ServerModeBinding.Clone(),
	}
}

func contextSnapshotBindingsMatch(snapshot AuthenticatedContextSnapshotV1) bool {
	return compatibilityBlockEqual(snapshot.ClientCompatibilityBlock, snapshot.ClientModeBinding.CompatibilityBlock) &&
		snapshot.ClientCompatibilityBlockHash == snapshot.ClientModeBinding.CompatibilityBlockHash &&
		compatibilityBlockEqual(snapshot.ServerCompatibilityBlock, snapshot.ServerModeBinding.CompatibilityBlock) &&
		snapshot.ServerCompatibilityBlockHash == snapshot.ServerModeBinding.CompatibilityBlockHash &&
		snapshot.ClientLimitBlock == snapshot.ClientModeBinding.LimitBlock &&
		snapshot.ClientLimitBlockHash == snapshot.ClientModeBinding.LimitBlockHash &&
		snapshot.ServerLimitBlock == snapshot.ServerModeBinding.LimitBlock &&
		snapshot.ServerLimitBlockHash == snapshot.ServerModeBinding.LimitBlockHash &&
		snapshot.ClientConfigSourceBlock == snapshot.ClientModeBinding.ConfigSourceBlock &&
		snapshot.ClientConfigSourceBlockHash == snapshot.ClientModeBinding.ConfigSourceBlockHash &&
		snapshot.ServerConfigSourceBlock == snapshot.ServerModeBinding.ConfigSourceBlock &&
		snapshot.ServerConfigSourceBlockHash == snapshot.ServerModeBinding.ConfigSourceBlockHash
}

func compatibilityBlockEqual(left, right security.CompatibilityBlockV1) bool {
	leftRaw, leftErr := security.CanonicalCompatibilityBlockV1(left)
	rightRaw, rightErr := security.CanonicalCompatibilityBlockV1(right)
	return leftErr == nil && rightErr == nil && hmac.Equal(leftRaw, rightRaw)
}

func cloneContextSnapshot(snapshot AuthenticatedContextSnapshotV1) AuthenticatedContextSnapshotV1 {
	snapshot.EffectivePolicy = snapshot.EffectivePolicy.Clone()
	snapshot.ClientCompatibilityBlock = snapshot.ClientCompatibilityBlock.Clone()
	snapshot.ServerCompatibilityBlock = snapshot.ServerCompatibilityBlock.Clone()
	snapshot.ClientModeBinding = snapshot.ClientModeBinding.Clone()
	snapshot.ServerModeBinding = snapshot.ServerModeBinding.Clone()
	return snapshot
}

func sealFirstContactResult(result FirstContactResult) [32]byte {
	return protocolHash("kurdistan/handshake/v1/success-result-seal",
		[]byte(result.ClientState),
		[]byte(result.ServerState),
		result.ClientNonce[:],
		result.ServerNonce[:],
		result.ClientPublic[:],
		result.ServerPublic[:],
		result.TranscriptHash[:],
		result.ChannelSecret,
		result.Messages[0],
		result.Messages[1],
		result.Messages[2],
		result.Messages[3],
		result.context.snapshot.ContextHash[:],
		result.context.seal[:],
	)
}

func loadCredentials(local, peer PeerParameters, deps Dependencies) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateKey, err := deps.Identity.Local(local.IdentityID)
	if err != nil {
		return nil, nil, fail(FailureUnknownIdentity)
	}
	defer wipe(privateKey)
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, fail(FailureUntrustedIdentity)
	}
	canonicalPrivate := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	if !hmac.Equal(privateKey, canonicalPrivate) {
		wipe(canonicalPrivate)
		return nil, nil, fail(FailureUntrustedIdentity)
	}
	wipe(canonicalPrivate)
	publicKey, err := deps.Trust.Peer(peer.IdentityID)
	if err != nil {
		return nil, nil, fail(FailureUnknownIdentity)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fail(FailureUntrustedIdentity)
	}
	var publicNonzero byte
	for _, value := range publicKey {
		publicNonzero |= value
	}
	if publicNonzero == 0 {
		return nil, nil, fail(FailureUntrustedIdentity)
	}
	return append(ed25519.PrivateKey(nil), privateKey...), append(ed25519.PublicKey(nil), publicKey...), nil
}

func freshContribution(entropy io.Reader) (*ecdh.PrivateKey, [32]byte, [32]byte, error) {
	var public, nonce [32]byte
	privateKey, err := ecdh.X25519().GenerateKey(entropy)
	if err != nil {
		return nil, public, nonce, fail(FailureEntropy)
	}
	copy(public[:], privateKey.PublicKey().Bytes())
	if _, err := io.ReadFull(entropy, nonce[:]); err != nil {
		return nil, [32]byte{}, [32]byte{}, fail(FailureEntropy)
	}
	return privateKey, public, nonce, nil
}

type clientHello struct {
	identityID, profileID, securityVersion string
	profileHash, public, nonce             [32]byte
	offer, floor                           []byte
	unsigned, signed                       []byte
	signature                              []byte
}

func makeClientHello(peer PeerParameters, privateKey ed25519.PrivateKey, public, nonce [32]byte) ([]byte, []byte, error) {
	offer, err := encodePolicyOffer(peer.OfferPolicy, peer.OfferedCapabilities)
	if err != nil {
		return nil, nil, fail(FailurePolicyMismatch)
	}
	floor, err := encodeMandatoryFloor(peer.FloorPolicy, peer.RequiredCapabilities)
	if err != nil {
		return nil, nil, fail(FailurePolicyFloorRejected)
	}
	var body bytes.Buffer
	writeU16(&body, handshakeVersion)
	writeU16(&body, clientHelloType)
	writeLP(&body, []byte(peer.IdentityID))
	writeLP(&body, []byte(peer.ProfileID))
	body.Write(peer.ProfileHash[:])
	writeLP(&body, []byte(peer.OfferPolicy.SecurityVersion))
	body.Write(public[:])
	body.Write(nonce[:])
	writeLP(&body, offer)
	writeLP(&body, floor)
	unsigned := body.Bytes()
	signatureHash := protocolHash("kurdistan/handshake/v1/client-hello-signature", unsigned)
	signature := ed25519.Sign(privateKey, signatureHash[:])
	signed := append(append([]byte(nil), unsigned...), signature...)
	return encodeOuter(signed), signed, nil
}

func parseClientHello(message []byte) (clientHello, []byte, error) {
	body, err := decodeOuter(message)
	if err != nil {
		return clientHello{}, nil, err
	}
	r := bytes.NewReader(body)
	version, kind, err := readHeader(r)
	if err != nil {
		return clientHello{}, nil, err
	}
	if version != handshakeVersion {
		return clientHello{}, nil, fail(FailureUnsupportedVersion)
	}
	if kind != clientHelloType {
		return clientHello{}, nil, fail(FailureOutOfOrder)
	}
	var out clientHello
	out.identityID, err = readLPString(r)
	if err != nil {
		return clientHello{}, nil, err
	}
	out.profileID, err = readLPString(r)
	if err != nil {
		return clientHello{}, nil, err
	}
	if err = readFixed(r, out.profileHash[:]); err != nil {
		return clientHello{}, nil, err
	}
	out.securityVersion, err = readLPString(r)
	if err != nil {
		return clientHello{}, nil, err
	}
	if err = readFixed(r, out.public[:]); err != nil {
		return clientHello{}, nil, err
	}
	if err = readFixed(r, out.nonce[:]); err != nil {
		return clientHello{}, nil, err
	}
	out.offer, err = readLP(r)
	if err != nil {
		return clientHello{}, nil, err
	}
	out.floor, err = readLP(r)
	if err != nil {
		return clientHello{}, nil, err
	}
	if r.Len() != ed25519.SignatureSize {
		return clientHello{}, nil, fail(FailureInvalidEncoding)
	}
	out.signature = make([]byte, ed25519.SignatureSize)
	_, _ = io.ReadFull(r, out.signature)
	out.unsigned = append([]byte(nil), body[:len(body)-ed25519.SignatureSize]...)
	out.signed = append([]byte(nil), body...)
	return out, out.signed, nil
}

func authenticateClientHello(message clientHello, expectedIdentity string, trusted ed25519.PublicKey) error {
	if message.identityID != expectedIdentity {
		return fail(FailureUnknownIdentity)
	}
	if isZero32(message.public) {
		return fail(FailureEphemeralInvalid)
	}
	signatureHash := protocolHash("kurdistan/handshake/v1/client-hello-signature", message.unsigned)
	if !ed25519.Verify(trusted, signatureHash[:], message.signature) {
		return fail(FailureSignatureInvalid)
	}
	return nil
}

func validateClientHelloSemantics(message clientHello, expected PeerParameters) error {
	if message.profileID != expected.ProfileID || message.profileHash != expected.ProfileHash || message.securityVersion != expected.OfferPolicy.SecurityVersion {
		return fail(FailureProfileMismatch)
	}
	wantOffer, _ := encodePolicyOffer(expected.OfferPolicy, expected.OfferedCapabilities)
	wantFloor, _ := encodeMandatoryFloor(expected.FloorPolicy, expected.RequiredCapabilities)
	if !hmac.Equal(message.offer, wantOffer) {
		return fail(FailurePolicyMismatch)
	}
	if !hmac.Equal(message.floor, wantFloor) {
		return fail(FailurePolicyFloorRejected)
	}
	return nil
}

type serverHello struct {
	clientHelloHash, public, nonce [32]byte
	identityID                     string
	offer, floor, selected         []byte
	unsigned, signed, signature    []byte
}

func makeServerHello(input FirstContactInput, privateKey ed25519.PrivateKey, clientSigned []byte, public, nonce [32]byte) ([]byte, []byte, error) {
	offer, err := encodePolicyOffer(input.Server.OfferPolicy, input.Server.OfferedCapabilities)
	if err != nil {
		return nil, nil, fail(FailurePolicyMismatch)
	}
	floor, err := encodeMandatoryFloor(input.Server.FloorPolicy, input.Server.RequiredCapabilities)
	if err != nil {
		return nil, nil, fail(FailurePolicyFloorRejected)
	}
	clientFloor, _ := encodeMandatoryFloor(input.Client.FloorPolicy, input.Client.RequiredCapabilities)
	selected, err := encodeSelectedPolicy(input.SelectedPolicy, input.SelectedCapabilities, clientFloor, floor)
	if err != nil {
		return nil, nil, fail(FailurePolicyMismatch)
	}
	clientHash := protocolHash("kurdistan/handshake/v1/client-hello-hash", clientSigned)
	var body bytes.Buffer
	writeU16(&body, handshakeVersion)
	writeU16(&body, serverHelloType)
	body.Write(clientHash[:])
	writeLP(&body, []byte(input.Server.IdentityID))
	body.Write(public[:])
	body.Write(nonce[:])
	writeLP(&body, offer)
	writeLP(&body, floor)
	writeLP(&body, selected)
	unsigned := body.Bytes()
	signatureHash := protocolHash("kurdistan/handshake/v1/server-hello-signature", clientSigned, unsigned)
	signature := ed25519.Sign(privateKey, signatureHash[:])
	signed := append(append([]byte(nil), unsigned...), signature...)
	return encodeOuter(signed), signed, nil
}

func parseServerHello(message []byte) (serverHello, []byte, error) {
	body, err := decodeOuter(message)
	if err != nil {
		return serverHello{}, nil, err
	}
	r := bytes.NewReader(body)
	version, kind, err := readHeader(r)
	if err != nil {
		return serverHello{}, nil, err
	}
	if version != handshakeVersion {
		return serverHello{}, nil, fail(FailureUnsupportedVersion)
	}
	if kind != serverHelloType {
		return serverHello{}, nil, fail(FailureOutOfOrder)
	}
	var out serverHello
	if err = readFixed(r, out.clientHelloHash[:]); err != nil {
		return serverHello{}, nil, err
	}
	out.identityID, err = readLPString(r)
	if err != nil {
		return serverHello{}, nil, err
	}
	if err = readFixed(r, out.public[:]); err != nil {
		return serverHello{}, nil, err
	}
	if err = readFixed(r, out.nonce[:]); err != nil {
		return serverHello{}, nil, err
	}
	out.offer, err = readLP(r)
	if err != nil {
		return serverHello{}, nil, err
	}
	out.floor, err = readLP(r)
	if err != nil {
		return serverHello{}, nil, err
	}
	out.selected, err = readLP(r)
	if err != nil {
		return serverHello{}, nil, err
	}
	if r.Len() != ed25519.SignatureSize {
		return serverHello{}, nil, fail(FailureInvalidEncoding)
	}
	out.signature = make([]byte, ed25519.SignatureSize)
	_, _ = io.ReadFull(r, out.signature)
	out.unsigned = append([]byte(nil), body[:len(body)-ed25519.SignatureSize]...)
	out.signed = append([]byte(nil), body...)
	return out, out.signed, nil
}

func validateServerHello(message serverHello, input FirstContactInput, trusted ed25519.PublicKey, clientSigned []byte) error {
	wantClientHash := protocolHash("kurdistan/handshake/v1/client-hello-hash", clientSigned)
	if message.clientHelloHash != wantClientHash || message.identityID != input.Server.IdentityID {
		return fail(FailureProfileMismatch)
	}
	wantOffer, _ := encodePolicyOffer(input.Server.OfferPolicy, input.Server.OfferedCapabilities)
	wantFloor, _ := encodeMandatoryFloor(input.Server.FloorPolicy, input.Server.RequiredCapabilities)
	clientFloor, _ := encodeMandatoryFloor(input.Client.FloorPolicy, input.Client.RequiredCapabilities)
	wantSelected, _ := encodeSelectedPolicy(input.SelectedPolicy, input.SelectedCapabilities, clientFloor, wantFloor)
	if !hmac.Equal(message.offer, wantOffer) || !hmac.Equal(message.selected, wantSelected) {
		return fail(FailurePolicyMismatch)
	}
	if !hmac.Equal(message.floor, wantFloor) {
		return fail(FailurePolicyFloorRejected)
	}
	if isZero32(message.public) {
		return fail(FailureEphemeralInvalid)
	}
	signatureHash := protocolHash("kurdistan/handshake/v1/server-hello-signature", clientSigned, message.unsigned)
	if !ed25519.Verify(trusted, signatureHash[:], message.signature) {
		return fail(FailureSignatureInvalid)
	}
	return nil
}

func makeClientFinish(privateKey ed25519.PrivateKey, confirmKey []byte, th2 [32]byte) ([]byte, []byte) {
	var body bytes.Buffer
	writeU16(&body, handshakeVersion)
	writeU16(&body, clientFinishType)
	body.Write(th2[:])
	unsigned := append([]byte(nil), body.Bytes()...)
	sigHash := protocolHash("kurdistan/handshake/v1/client-finish-signature", unsigned)
	body.Write(ed25519.Sign(privateKey, sigHash[:]))
	body.Write(confirm(confirmKey, "kurdistan/handshake/v1/client-key-confirm", th2))
	full := body.Bytes()
	return encodeOuter(full), append([]byte(nil), full...)
}

func validateClientFinish(message []byte, trusted ed25519.PublicKey, confirmKey []byte, th2 [32]byte) ([]byte, error) {
	return validateFinish(message, clientFinishType, "kurdistan/handshake/v1/client-finish-signature", "kurdistan/handshake/v1/client-key-confirm", trusted, confirmKey, th2)
}

func makeServerFinish(privateKey ed25519.PrivateKey, confirmKey []byte, th3 [32]byte) ([]byte, []byte) {
	var body bytes.Buffer
	writeU16(&body, handshakeVersion)
	writeU16(&body, serverFinishType)
	body.Write(th3[:])
	unsigned := append([]byte(nil), body.Bytes()...)
	sigHash := protocolHash("kurdistan/handshake/v1/server-finish-signature", unsigned)
	body.Write(ed25519.Sign(privateKey, sigHash[:]))
	body.Write(confirm(confirmKey, "kurdistan/handshake/v1/server-key-confirm", th3))
	full := body.Bytes()
	return encodeOuter(full), append([]byte(nil), full...)
}

func validateServerFinish(message []byte, trusted ed25519.PublicKey, confirmKey []byte, th3 [32]byte) ([]byte, error) {
	return validateFinish(message, serverFinishType, "kurdistan/handshake/v1/server-finish-signature", "kurdistan/handshake/v1/server-key-confirm", trusted, confirmKey, th3)
}

func validateFinish(message []byte, kind uint16, signatureDomain, confirmationDomain string, trusted ed25519.PublicKey, confirmKey []byte, transcript [32]byte) ([]byte, error) {
	body, err := decodeOuter(message)
	if err != nil {
		return nil, err
	}
	if len(body) != 2+2+32+ed25519.SignatureSize+sha256.Size {
		return nil, fail(FailureInvalidEncoding)
	}
	if binary.BigEndian.Uint16(body[:2]) != handshakeVersion {
		return nil, fail(FailureUnsupportedVersion)
	}
	if binary.BigEndian.Uint16(body[2:4]) != kind {
		return nil, fail(FailureOutOfOrder)
	}
	if !hmac.Equal(body[4:36], transcript[:]) {
		return nil, fail(FailureKeyConfirmation)
	}
	unsigned := body[:36]
	sigHash := protocolHash(signatureDomain, unsigned)
	if !ed25519.Verify(trusted, sigHash[:], body[36:100]) {
		return nil, fail(FailureSignatureInvalid)
	}
	want := confirm(confirmKey, confirmationDomain, transcript)
	if !hmac.Equal(body[100:], want) {
		return nil, fail(FailureKeyConfirmation)
	}
	return append([]byte(nil), body...), nil
}

func confirmationKeys(dh []byte, profileHash, clientNonce, serverNonce, clientPublic, serverPublic [32]byte, th2 [32]byte) ([]byte, []byte, []byte, error) {
	salt := protocolHash("kurdistan/hkdf/v1/handshake-salt", profileHash[:], clientNonce[:], serverNonce[:], clientPublic[:], serverPublic[:])
	prk, err := hkdf.Extract(sha256.New, dh, salt[:])
	if err != nil {
		return nil, nil, nil, fail(FailureKeyAgreement)
	}
	clientInfo := keyInfo("kurdistan/hkdf/v1/client-confirm", th2, 0)
	serverInfo := keyInfo("kurdistan/hkdf/v1/server-confirm", th2, 0)
	client, err := hkdf.Expand(sha256.New, prk, string(clientInfo), 32)
	if err != nil {
		wipe(prk)
		return nil, nil, nil, fail(FailureKeyAgreement)
	}
	server, err := hkdf.Expand(sha256.New, prk, string(serverInfo), 32)
	if err != nil {
		wipe(client)
		wipe(prk)
		return nil, nil, nil, fail(FailureKeyAgreement)
	}
	return client, server, prk, nil
}

func keyInfo(label string, transcript [32]byte, epoch uint64) []byte {
	var out bytes.Buffer
	writeLP(&out, []byte(label))
	out.Write(transcript[:])
	writeU64(&out, epoch)
	return out.Bytes()
}

func confirm(key []byte, domain string, transcript [32]byte) []byte {
	mac := hmac.New(sha256.New, key)
	var message bytes.Buffer
	writeLP(&message, []byte(domain))
	message.Write(transcript[:])
	_, _ = mac.Write(message.Bytes())
	return mac.Sum(nil)
}

func sharedSecret(privateKey *ecdh.PrivateKey, peer [32]byte) ([]byte, error) {
	publicKey, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return nil, fail(FailureEphemeralInvalid)
	}
	secret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fail(FailureKeyAgreement)
	}
	return secret, nil
}

func encodePolicyOffer(policy ir.EffectiveSecurityPolicy, capabilities []string) ([]byte, error) {
	policyRaw, err := security.EncodePolicyV1(policy)
	if err != nil {
		return nil, err
	}
	capabilitiesRaw, err := security.EncodeStringListV1(capabilities)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	writeLP(&out, policyRaw)
	writeLP(&out, capabilitiesRaw)
	return out.Bytes(), nil
}

func encodeMandatoryFloor(policy ir.EffectiveSecurityPolicy, capabilities []string) ([]byte, error) {
	return encodePolicyOffer(policy, capabilities)
}

func encodeSelectedPolicy(policy ir.EffectiveSecurityPolicy, capabilities []string, clientFloor, serverFloor []byte) ([]byte, error) {
	policyRaw, err := security.EncodePolicyV1(policy)
	if err != nil {
		return nil, err
	}
	capabilitiesRaw, err := security.EncodeStringListV1(capabilities)
	if err != nil {
		return nil, err
	}
	clientHash := protocolHash("kurdistan/policy/v1/floor", clientFloor)
	serverHash := protocolHash("kurdistan/policy/v1/floor", serverFloor)
	var out bytes.Buffer
	writeLP(&out, policyRaw)
	writeLP(&out, capabilitiesRaw)
	out.Write(clientHash[:])
	out.Write(serverHash[:])
	return out.Bytes(), nil
}

func protocolHash(label string, parts ...[]byte) [32]byte {
	var input bytes.Buffer
	writeLP(&input, []byte(label))
	for _, part := range parts {
		writeLP(&input, part)
	}
	return sha256.Sum256(input.Bytes())
}

func encodeOuter(body []byte) []byte {
	var out bytes.Buffer
	writeU32(&out, uint32(len(body)))
	out.Write(body)
	return out.Bytes()
}

func decodeOuter(message []byte) ([]byte, error) {
	if len(message) < 4 {
		return nil, fail(FailureInvalidEncoding)
	}
	length := binary.BigEndian.Uint32(message[:4])
	if length > maxHandshakeBody || int(length) != len(message)-4 {
		return nil, fail(FailureInvalidEncoding)
	}
	return append([]byte(nil), message[4:]...), nil
}

func readHeader(r *bytes.Reader) (uint16, uint16, error) {
	var raw [4]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, 0, fail(FailureInvalidEncoding)
	}
	return binary.BigEndian.Uint16(raw[:2]), binary.BigEndian.Uint16(raw[2:]), nil
}

func readLPString(r *bytes.Reader) (string, error) {
	raw, err := readLP(r)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", fail(FailureInvalidEncoding)
	}
	for _, value := range raw {
		if value < 0x20 || value > 0x7e {
			return "", fail(FailureInvalidEncoding)
		}
	}
	return string(raw), nil
}

func readLP(r *bytes.Reader) ([]byte, error) {
	var raw [4]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return nil, fail(FailureInvalidEncoding)
	}
	length := binary.BigEndian.Uint32(raw[:])
	if length > maxHandshakeBody || uint64(length) > uint64(r.Len()) {
		return nil, fail(FailureInvalidEncoding)
	}
	value := make([]byte, int(length))
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fail(FailureInvalidEncoding)
	}
	return value, nil
}

func readFixed(r *bytes.Reader, target []byte) error {
	if _, err := io.ReadFull(r, target); err != nil {
		return fail(FailureInvalidEncoding)
	}
	return nil
}

func writeLP(out *bytes.Buffer, value []byte) { writeU32(out, uint32(len(value))); out.Write(value) }
func writeU16(out *bytes.Buffer, value uint16) {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], value)
	out.Write(raw[:])
}
func writeU32(out *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	out.Write(raw[:])
}
func writeU64(out *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	out.Write(raw[:])
}

func decodeProfileHash(value string) ([32]byte, error) {
	var out [32]byte
	if len(value) != 64 {
		return out, fmt.Errorf("invalid profile hash")
	}
	for i := 0; i < 32; i++ {
		var high, low byte
		for index, target := range []struct {
			source byte
			dest   *byte
		}{{value[i*2], &high}, {value[i*2+1], &low}} {
			_ = index
			switch {
			case target.source >= '0' && target.source <= '9':
				*target.dest = target.source - '0'
			case target.source >= 'a' && target.source <= 'f':
				*target.dest = target.source - 'a' + 10
			default:
				return [32]byte{}, fmt.Errorf("invalid profile hash")
			}
		}
		out[i] = high<<4 | low
	}
	return out, nil
}

func modeBindingFromProfile(profile *ir.Profile, policy ir.EffectiveSecurityPolicy, profileHash [32]byte) (security.HandshakeModeBinding, error) {
	hashJSON := func(domain string, value any) ([32]byte, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return [32]byte{}, err
		}
		return protocolHash(domain, raw), nil
	}
	carrierPolicyHash, err := hashJSON("kurdistan/profile/v1/carrier-policy", profile.CarrierPolicy)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	framingHash, err := hashJSON("kurdistan/profile/v1/framing-policy", profile.FrameGrammar)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	stateHash, err := hashJSON("kurdistan/profile/v1/state-machine-policy", struct {
		FirstContact ir.FirstContactSpec
		States       []ir.State
		Transitions  []ir.Transition
	}{profile.FirstContact, profile.States, profile.Transitions})
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	schedulerHash, err := hashJSON("kurdistan/profile/v1/scheduler-policy", profile.Scheduler)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	paddingHash, err := hashJSON("kurdistan/profile/v1/padding-policy", profile.Padding)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	streamHash, err := hashJSON("kurdistan/profile/v1/stream-policy", profile.Stream)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	proxyHash, err := hashJSON("kurdistan/profile/v1/proxy-policy", profile.ProxySemantics)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	carrierContextHash, err := hashJSON("kurdistan/profile/v1/carrier-context", struct {
		Policy  ir.CarrierPolicy
		Adapter ir.AdapterPolicy
	}{profile.CarrierPolicy, profile.AdapterPolicy})
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	suites, err := normalizeASCIISet(profile.Compatibility.SupportedSecuritySuites, true)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	requiredCapabilities, err := normalizeASCIISet(profile.Compatibility.RequiredCapabilities, true)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	carrierFamilies, err := normalizeASCIISet(profile.Compatibility.SupportedCarrierFamilies, true)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	proxyFeatures, err := normalizeASCIISet(profile.Compatibility.SupportedProxyFeatures, false)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	streamFeatures, err := normalizeASCIISet(profile.Compatibility.SupportedStreamFeatures, false)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxEnvelopeBytes, err := positiveU32(profile.Compatibility.MaxEnvelopeBytes)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxStreamCount, err := positiveU32(profile.Compatibility.MaxStreamCount)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxReplayWindow, err := positiveU32(profile.Compatibility.MaxReplayWindow)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	compatibilityBlock := security.CompatibilityBlockV1{
		SchemaVersion:            profile.Compatibility.SchemaVersion,
		CompilerSecurityVersion:  profile.Compatibility.CompilerSecurityVersion,
		MinimumRuntimeVersion:    profile.Compatibility.MinimumRuntimeVersion,
		SupportedSecuritySuites:  suites,
		RequiredCapabilities:     requiredCapabilities,
		SupportedCarrierFamilies: carrierFamilies,
		SupportedProxyFeatures:   proxyFeatures,
		SupportedStreamFeatures:  streamFeatures,
		MaxEnvelopeBytes:         maxEnvelopeBytes,
		MaxStreamCount:           maxStreamCount,
		MaxReplayWindow:          maxReplayWindow,
	}
	compatibilityBlockHash, err := security.CompatibilityBlockHashV1(compatibilityBlock)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxFrameBytes, err := positiveU32(profile.Limits.MaxFrameBytes)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxPayloadBytes, err := positiveU32(profile.Limits.MaxPayloadBytes)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxStates, err := positiveU32(profile.Limits.MaxStates)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxTransitions, err := positiveU32(profile.Limits.MaxTransitions)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	maxSessionMillis, err := positiveU64(profile.Limits.MaxSessionMillis)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	carrierMaxEnvelopeBytes, err := positiveU32(profile.CarrierPolicy.MaxEnvelopeBytes)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	carrierMaxQueueDepth, err := positiveU32(profile.CarrierPolicy.MaxCarrierQueueDepth)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	sessionMaxConcurrentStreams, err := positiveU32(profile.Stream.MaxConcurrentStreams)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	limitBlock := security.LimitBlockV1{
		MaxFrameBytes:               maxFrameBytes,
		MaxPayloadBytes:             maxPayloadBytes,
		MaxStates:                   maxStates,
		MaxTransitions:              maxTransitions,
		MaxSessionMillis:            maxSessionMillis,
		CarrierMaxEnvelopeBytes:     carrierMaxEnvelopeBytes,
		CarrierMaxQueueDepth:        carrierMaxQueueDepth,
		SessionMaxConcurrentStreams: sessionMaxConcurrentStreams,
	}
	limitBlockHash, err := security.LimitBlockHashV1(limitBlock)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	effectivePolicyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailurePolicyMismatch)
	}
	selectedCapabilityHash, err := security.SelectedCapabilityHashV1(policy.SelectedCapabilities)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailurePolicyFloorRejected)
	}
	configSourceBlock := security.ConfigSourceBlockV1{
		ProfileID:       profile.ID,
		ProfileHash:     profileHash,
		SecurityVersion: policy.SecurityVersion,
		SelectedSuite: security.SelectedSuiteV1{
			KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite,
		},
		EffectivePolicyHash:    effectivePolicyHash,
		SelectedCapabilityHash: selectedCapabilityHash,
		AdapterClass:           profile.AdapterPolicy.RuntimeMappingPolicy,
		CompatibilityBlockHash: compatibilityBlockHash,
		LimitBlockHash:         limitBlockHash,
	}
	configSourceBlockHash, err := security.ConfigSourceBlockHashV1(configSourceBlock)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	featureVectors := make([]string, 0, len(carrierFamilies)+len(proxyFeatures)+len(streamFeatures))
	for _, value := range carrierFamilies {
		featureVectors = append(featureVectors, "carrier:"+value)
	}
	for _, value := range proxyFeatures {
		featureVectors = append(featureVectors, "proxy:"+value)
	}
	for _, value := range streamFeatures {
		featureVectors = append(featureVectors, "stream:"+value)
	}
	sort.Strings(featureVectors)
	return security.HandshakeModeBinding{
		FeatureVectors:         featureVectors,
		CarrierFamily:          profile.CarrierPolicy.CarrierFamily,
		CarrierPolicyHash:      carrierPolicyHash,
		EnvelopeLimit:          carrierMaxEnvelopeBytes,
		MaxFrameBytes:          maxFrameBytes,
		LocalAdapterClass:      profile.AdapterPolicy.RuntimeMappingPolicy,
		FramingPolicyHash:      framingHash,
		StateMachinePolicyHash: stateHash,
		SchedulerPolicyHash:    schedulerHash,
		PaddingPolicyHash:      paddingHash,
		StreamPolicyHash:       streamHash,
		ProxyPolicyHash:        proxyHash,
		CarrierContextHash:     carrierContextHash,
		CompatibilityBlock:     compatibilityBlock,
		CompatibilityBlockHash: compatibilityBlockHash,
		LimitBlock:             limitBlock,
		LimitBlockHash:         limitBlockHash,
		ConfigSourceBlock:      configSourceBlock,
		ConfigSourceBlockHash:  configSourceBlockHash,
	}, nil
}

func normalizeASCIISet(values []string, required bool) ([]string, error) {
	if required && len(values) == 0 {
		return nil, fmt.Errorf("empty set")
	}
	if _, err := security.EncodeStringListV1(values); err != nil {
		return nil, err
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out, nil
}

func normalizeCapabilitySet(values []string) ([]string, error) {
	out, err := normalizeASCIISet(values, true)
	if err != nil {
		return nil, err
	}
	if _, err := (security.CapabilitySet{Features: out}).Hash(); err != nil {
		return nil, err
	}
	return out, nil
}

func positiveU32(value int) (uint32, error) {
	if value <= 0 || uint64(value) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("out of U32 range")
	}
	return uint32(value), nil
}

func positiveU64(value int) (uint64, error) {
	if value <= 0 {
		return 0, fmt.Errorf("out of U64 range")
	}
	return uint64(value), nil
}

func sealPeerParameters(peer PeerParameters) ([32]byte, error) {
	offer, err := security.EncodePolicyV1(peer.OfferPolicy)
	if err != nil {
		return [32]byte{}, err
	}
	floor, err := security.EncodePolicyV1(peer.FloorPolicy)
	if err != nil {
		return [32]byte{}, err
	}
	offered, err := security.EncodeStringListV1(peer.OfferedCapabilities)
	if err != nil {
		return [32]byte{}, err
	}
	required, err := security.EncodeStringListV1(peer.RequiredCapabilities)
	if err != nil {
		return [32]byte{}, err
	}
	binding, err := json.Marshal(peer.modeBinding)
	if err != nil {
		return [32]byte{}, err
	}
	return protocolHash("kurdistan/handshake/v1/peer-parameters", []byte(peer.IdentityID), []byte(peer.ProfileID), peer.ProfileHash[:], offer, floor, offered, required, binding), nil
}

func optionalCapabilities(offered, required []string) []string {
	requiredSet := make(map[string]struct{}, len(required))
	for _, value := range required {
		requiredSet[value] = struct{}{}
	}
	out := make([]string, 0, len(offered))
	for _, value := range offered {
		if _, ok := requiredSet[value]; !ok {
			out = append(out, value)
		}
	}
	return out
}

func canonicalListEqual(left, right []string) bool {
	leftRaw, leftErr := security.EncodeStringListV1(left)
	rightRaw, rightErr := security.EncodeStringListV1(right)
	return leftErr == nil && rightErr == nil && hmac.Equal(leftRaw, rightRaw)
}

func policySuite(policy ir.EffectiveSecurityPolicy) security.Suite {
	return security.Suite{KDF: policy.KDFSuite, AEAD: policy.AEADSuite, MAC: policy.MACSuite, Transcript: security.SuiteTranscriptSHA256V1}
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func isZero32(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
