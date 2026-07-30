// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"

	"kurdistan/internal/protocol/ir"
)

// ProcessHandshakeRoleV1 identifies the local owner of one process-separated
// handshake result.
type ProcessHandshakeRoleV1 string

const (
	ProcessHandshakeClientV1 ProcessHandshakeRoleV1 = "client"
	ProcessHandshakeRelayV1  ProcessHandshakeRoleV1 = "relay"
)

// ProcessHandshakeConfigV1 is an opaque, deep-cloned public-input authority.
// It contains no identity private key, replay cache, entropy source, or channel
// secret and can therefore be constructed independently in client and relay
// processes.
type ProcessHandshakeConfigV1 struct {
	input FirstContactInput
}

// ProcessHandshakeEvidenceV1 is a nonsecret, deep-cloned conformance view.
type ProcessHandshakeEvidenceV1 struct {
	Role           ProcessHandshakeRoleV1
	ClientNonce    [32]byte
	ServerNonce    [32]byte
	ClientPublic   [32]byte
	ServerPublic   [32]byte
	TranscriptHash [32]byte
	Messages       [4][]byte
}

// ProcessHandshakeResultV1 retains the local channel secret until it is
// transferred exactly once to the local runtime endpoint.
type ProcessHandshakeResultV1 struct {
	mu       sync.Mutex
	role     ProcessHandshakeRoleV1
	secret   []byte
	context  AuthenticatedContextSnapshotV1
	evidence ProcessHandshakeEvidenceV1
	closed   bool
}

// NewProcessHandshakeConfigV1 validates and snapshots the exact public
// handshake authority shared by the client and relay.
func NewProcessHandshakeConfigV1(client, relay PeerParameters, selected ir.EffectiveSecurityPolicy, capabilities []string) (ProcessHandshakeConfigV1, error) {
	input := FirstContactInput{
		Client:               clonePeerParameters(client),
		Server:               clonePeerParameters(relay),
		SelectedPolicy:       selected.Clone(),
		SelectedCapabilities: append([]string(nil), capabilities...),
	}
	if err := validateFirstContactPublicInput(input); err != nil {
		return ProcessHandshakeConfigV1{}, err
	}
	return ProcessHandshakeConfigV1{input: input}, nil
}

// ContextSnapshotV1 returns the authenticated, nonsecret context projection.
func (result *ProcessHandshakeResultV1) ContextSnapshotV1() (AuthenticatedContextSnapshotV1, bool) {
	if result == nil {
		return AuthenticatedContextSnapshotV1{}, false
	}
	result.mu.Lock()
	defer result.mu.Unlock()
	if result.closed || len(result.secret) == 0 || isZero32(result.context.ContextHash) {
		return AuthenticatedContextSnapshotV1{}, false
	}
	return cloneContextSnapshot(result.context), true
}

// EvidenceV1 returns only public transcript evidence and never aliases retained
// handshake state.
func (result *ProcessHandshakeResultV1) EvidenceV1() (ProcessHandshakeEvidenceV1, bool) {
	if result == nil {
		return ProcessHandshakeEvidenceV1{}, false
	}
	result.mu.Lock()
	defer result.mu.Unlock()
	if result.closed || len(result.secret) == 0 || isZero32(result.evidence.TranscriptHash) {
		return ProcessHandshakeEvidenceV1{}, false
	}
	return cloneProcessHandshakeEvidenceV1(result.evidence), true
}

// TakeChannelSecretV1 transfers ownership of the local channel-secret copy.
// A second call fails closed.
func (result *ProcessHandshakeResultV1) TakeChannelSecretV1() ([]byte, error) {
	if result == nil {
		return nil, fail(FailureOutOfOrder)
	}
	result.mu.Lock()
	defer result.mu.Unlock()
	if result.closed || len(result.secret) == 0 {
		return nil, fail(FailureOutOfOrder)
	}
	secret := result.secret
	result.secret = nil
	result.closed = true
	result.context = AuthenticatedContextSnapshotV1{}
	result.evidence = ProcessHandshakeEvidenceV1{}
	return secret, nil
}

// Close destroys retained secret material when the runtime does not take it.
func (result *ProcessHandshakeResultV1) Close() {
	if result == nil {
		return
	}
	result.mu.Lock()
	defer result.mu.Unlock()
	wipe(result.secret)
	result.secret = nil
	result.context = AuthenticatedContextSnapshotV1{}
	result.evidence = ProcessHandshakeEvidenceV1{}
	result.closed = true
}

type clientProcessHandshakeStageV1 uint8

const (
	clientProcessNewV1 clientProcessHandshakeStageV1 = iota
	clientProcessAwaitServerHelloV1
	clientProcessAwaitServerFinishV1
	clientProcessClosedV1
)

// ClientProcessHandshakeV1 owns only client credentials and client ephemeral
// state. It has no relay private-key or replay-cache authority.
type ClientProcessHandshakeV1 struct {
	mu sync.Mutex

	config     ProcessHandshakeConfigV1
	stage      clientProcessHandshakeStageV1
	privateKey ed25519.PrivateKey
	peerPublic ed25519.PublicKey
	entropy    io.Reader
	ephemeral  *ecdh.PrivateKey

	clientNonce, serverNonce   [32]byte
	clientPublic, serverPublic [32]byte
	clientHello                []byte
	clientSentBody             []byte
	serverHello                []byte
	receivedServerBody         []byte
	clientFinish               []byte
	clientFinishSentBody       []byte
	serverConfirmKey           []byte
	handshakePRK               []byte
}

// NewClientProcessHandshakeV1 creates a role-separated client handshake.
func NewClientProcessHandshakeV1(config ProcessHandshakeConfigV1, dependencies Dependencies) (*ClientProcessHandshakeV1, error) {
	return newClientProcessHandshakeV1(config, dependencies, nil)
}

func newClientProcessHandshakeV1(config ProcessHandshakeConfigV1, dependencies Dependencies, entropy io.Reader) (*ClientProcessHandshakeV1, error) {
	if err := validateFirstContactPublicInput(config.input); err != nil {
		return nil, err
	}
	privateKey, peerPublic, err := loadCredentials(config.input.Client, config.input.Server, dependencies)
	if err != nil {
		return nil, err
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &ClientProcessHandshakeV1{
		config:     cloneProcessHandshakeConfigV1(config),
		stage:      clientProcessNewV1,
		privateKey: privateKey,
		peerPublic: peerPublic,
		entropy:    entropy,
	}, nil
}

// Start creates the signed ClientHello exactly once.
func (client *ClientProcessHandshakeV1) Start() ([]byte, error) {
	if client == nil {
		return nil, fail(FailureOutOfOrder)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.stage != clientProcessNewV1 {
		return nil, client.failLockedV1(FailureOutOfOrder)
	}
	ephemeral, public, nonce, err := freshContribution(client.entropy)
	if err != nil {
		client.closeLockedV1()
		return nil, err
	}
	message, sentBody, err := makeClientHello(client.config.input.Client, client.privateKey, public, nonce)
	if err != nil {
		client.closeLockedV1()
		return nil, err
	}
	client.ephemeral = ephemeral
	client.clientPublic = public
	client.clientNonce = nonce
	client.clientHello = append([]byte(nil), message...)
	client.clientSentBody = append([]byte(nil), sentBody...)
	client.stage = clientProcessAwaitServerHelloV1
	return append([]byte(nil), message...), nil
}

// AcceptServerHello authenticates the relay and returns the signed client
// finish. It cannot be called before Start or more than once.
func (client *ClientProcessHandshakeV1) AcceptServerHello(message []byte) ([]byte, error) {
	if client == nil {
		return nil, fail(FailureOutOfOrder)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.stage != clientProcessAwaitServerHelloV1 || client.ephemeral == nil {
		return nil, client.failLockedV1(FailureOutOfOrder)
	}
	parsed, receivedBody, err := parseServerHello(message)
	if err != nil {
		client.closeLockedV1()
		return nil, err
	}
	if err := validateServerHello(parsed, client.config.input, client.peerPublic, client.clientSentBody); err != nil {
		client.closeLockedV1()
		return nil, err
	}
	dh, err := sharedSecret(client.ephemeral, parsed.public)
	if err != nil {
		client.closeLockedV1()
		return nil, err
	}
	defer wipe(dh)
	th2 := protocolHash("kurdistan/handshake/v1/transcript-hello", client.clientSentBody, receivedBody)
	clientConfirmKey, serverConfirmKey, handshakePRK, err := confirmationKeys(
		dh,
		client.config.input.Client.ProfileHash,
		client.clientNonce,
		parsed.nonce,
		client.clientPublic,
		parsed.public,
		th2,
	)
	if err != nil {
		client.closeLockedV1()
		return nil, err
	}
	finish, finishBody := makeClientFinish(client.privateKey, clientConfirmKey, th2)
	wipe(clientConfirmKey)
	wipe(client.privateKey)
	client.privateKey = nil
	client.ephemeral = nil
	client.serverNonce = parsed.nonce
	client.serverPublic = parsed.public
	client.serverHello = append([]byte(nil), message...)
	client.receivedServerBody = append([]byte(nil), receivedBody...)
	client.clientFinish = append([]byte(nil), finish...)
	client.clientFinishSentBody = append([]byte(nil), finishBody...)
	client.serverConfirmKey = serverConfirmKey
	client.handshakePRK = handshakePRK
	client.stage = clientProcessAwaitServerFinishV1
	return append([]byte(nil), finish...), nil
}

// AcceptServerFinish completes client-side key confirmation.
func (client *ClientProcessHandshakeV1) AcceptServerFinish(message []byte) (*ProcessHandshakeResultV1, error) {
	if client == nil {
		return nil, fail(FailureOutOfOrder)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.stage != clientProcessAwaitServerFinishV1 {
		return nil, client.failLockedV1(FailureOutOfOrder)
	}
	th3 := protocolHash(
		"kurdistan/handshake/v1/transcript-client-finish",
		client.clientSentBody,
		client.receivedServerBody,
		client.clientFinishSentBody,
	)
	receivedServerFinish, err := validateServerFinish(message, client.peerPublic, client.serverConfirmKey, th3)
	if err != nil {
		client.closeLockedV1()
		return nil, err
	}
	th4 := protocolHash(
		"kurdistan/handshake/v1/transcript-final",
		client.clientSentBody,
		client.receivedServerBody,
		client.clientFinishSentBody,
		receivedServerFinish,
	)
	applicationSalt := protocolHash(
		"kurdistan/hkdf/v1/application-salt",
		th4[:],
		client.config.input.Client.ProfileHash[:],
	)
	secret, err := hkdf.Extract(sha256.New, client.handshakePRK, applicationSalt[:])
	if err != nil {
		client.closeLockedV1()
		return nil, fail(FailureKeyAgreement)
	}
	context, err := newAuthenticatedContextV1(client.config.input, th4)
	if err != nil {
		wipe(secret)
		client.closeLockedV1()
		return nil, err
	}
	result := newProcessHandshakeResultV1(
		ProcessHandshakeClientV1,
		secret,
		context,
		ProcessHandshakeEvidenceV1{
			Role:           ProcessHandshakeClientV1,
			ClientNonce:    client.clientNonce,
			ServerNonce:    client.serverNonce,
			ClientPublic:   client.clientPublic,
			ServerPublic:   client.serverPublic,
			TranscriptHash: th4,
			Messages: [4][]byte{
				client.clientHello,
				client.serverHello,
				client.clientFinish,
				message,
			},
		},
	)
	wipe(secret)
	client.closeLockedV1()
	return result, nil
}

// Close destroys incomplete client-side handshake material.
func (client *ClientProcessHandshakeV1) Close() {
	if client == nil {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closeLockedV1()
}

func (client *ClientProcessHandshakeV1) failLockedV1(code FailureCode) error {
	client.closeLockedV1()
	return fail(code)
}

func (client *ClientProcessHandshakeV1) closeLockedV1() {
	wipe(client.privateKey)
	wipe(client.serverConfirmKey)
	wipe(client.handshakePRK)
	client.privateKey = nil
	client.peerPublic = nil
	client.serverConfirmKey = nil
	client.handshakePRK = nil
	client.ephemeral = nil
	client.config = ProcessHandshakeConfigV1{}
	client.entropy = nil
	client.stage = clientProcessClosedV1
}

type relayProcessHandshakeStageV1 uint8

const (
	relayProcessAwaitClientHelloV1 relayProcessHandshakeStageV1 = iota
	relayProcessAwaitClientFinishV1
	relayProcessClosedV1
)

// RelayProcessHandshakeV1 owns only relay credentials, relay ephemeral state,
// and the relay's process-owned replay cache.
type RelayProcessHandshakeV1 struct {
	mu sync.Mutex

	config     ProcessHandshakeConfigV1
	stage      relayProcessHandshakeStageV1
	privateKey ed25519.PrivateKey
	peerPublic ed25519.PublicKey
	replay     *HandshakeReplayCache
	entropy    io.Reader
	ephemeral  *ecdh.PrivateKey

	clientNonce, serverNonce   [32]byte
	clientPublic, serverPublic [32]byte
	clientHello                []byte
	receivedClientBody         []byte
	serverHello                []byte
	serverSentBody             []byte
	clientConfirmKey           []byte
	serverConfirmKey           []byte
	handshakePRK               []byte
}

// NewRelayProcessHandshakeV1 creates a role-separated relay handshake.
func NewRelayProcessHandshakeV1(config ProcessHandshakeConfigV1, dependencies Dependencies, replay *HandshakeReplayCache) (*RelayProcessHandshakeV1, error) {
	return newRelayProcessHandshakeV1(config, dependencies, replay, nil)
}

func newRelayProcessHandshakeV1(config ProcessHandshakeConfigV1, dependencies Dependencies, replay *HandshakeReplayCache, entropy io.Reader) (*RelayProcessHandshakeV1, error) {
	if err := validateFirstContactPublicInput(config.input); err != nil {
		return nil, err
	}
	if replay == nil {
		return nil, fail(FailureInternalLimit)
	}
	privateKey, peerPublic, err := loadCredentials(config.input.Server, config.input.Client, dependencies)
	if err != nil {
		return nil, err
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &RelayProcessHandshakeV1{
		config:     cloneProcessHandshakeConfigV1(config),
		stage:      relayProcessAwaitClientHelloV1,
		privateKey: privateKey,
		peerPublic: peerPublic,
		replay:     replay,
		entropy:    entropy,
	}, nil
}

// AcceptClientHello authenticates and replay-commits the client hello before
// returning the signed relay hello.
func (relay *RelayProcessHandshakeV1) AcceptClientHello(message []byte) ([]byte, error) {
	if relay == nil {
		return nil, fail(FailureOutOfOrder)
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.stage != relayProcessAwaitClientHelloV1 {
		return nil, relay.failLockedV1(FailureOutOfOrder)
	}
	parsed, receivedBody, err := parseClientHello(message)
	if err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	if err := authenticateClientHello(parsed, relay.config.input.Client.IdentityID, relay.peerPublic); err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	replayKey := protocolHash(
		"kurdistan/handshake/v1/replay-key",
		[]byte(parsed.identityID),
		parsed.nonce[:],
		parsed.public[:],
		parsed.profileHash[:],
	)
	if err := relay.replay.record(replayKey); err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	if err := validateClientHelloSemantics(parsed, relay.config.input.Client); err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	ephemeral, public, nonce, err := freshContribution(relay.entropy)
	if err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	serverHello, serverSentBody, err := makeServerHello(relay.config.input, relay.privateKey, receivedBody, public, nonce)
	if err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	dh, err := sharedSecret(ephemeral, parsed.public)
	if err != nil {
		relay.closeLockedV1()
		return nil, fail(FailureKeyAgreement)
	}
	defer wipe(dh)
	th2 := protocolHash("kurdistan/handshake/v1/transcript-hello", receivedBody, serverSentBody)
	clientConfirmKey, serverConfirmKey, handshakePRK, err := confirmationKeys(
		dh,
		parsed.profileHash,
		parsed.nonce,
		nonce,
		parsed.public,
		public,
		th2,
	)
	if err != nil {
		relay.closeLockedV1()
		return nil, err
	}
	relay.ephemeral = ephemeral
	relay.clientNonce = parsed.nonce
	relay.serverNonce = nonce
	relay.clientPublic = parsed.public
	relay.serverPublic = public
	relay.clientHello = append([]byte(nil), message...)
	relay.receivedClientBody = append([]byte(nil), receivedBody...)
	relay.serverHello = append([]byte(nil), serverHello...)
	relay.serverSentBody = append([]byte(nil), serverSentBody...)
	relay.clientConfirmKey = clientConfirmKey
	relay.serverConfirmKey = serverConfirmKey
	relay.handshakePRK = handshakePRK
	relay.stage = relayProcessAwaitClientFinishV1
	return append([]byte(nil), serverHello...), nil
}

// AcceptClientFinish completes relay-side key confirmation and returns the
// relay finish plus an independently owned local result.
func (relay *RelayProcessHandshakeV1) AcceptClientFinish(message []byte) ([]byte, *ProcessHandshakeResultV1, error) {
	if relay == nil {
		return nil, nil, fail(FailureOutOfOrder)
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.stage != relayProcessAwaitClientFinishV1 {
		return nil, nil, relay.failLockedV1(FailureOutOfOrder)
	}
	th2 := protocolHash(
		"kurdistan/handshake/v1/transcript-hello",
		relay.receivedClientBody,
		relay.serverSentBody,
	)
	receivedClientFinish, err := validateClientFinish(message, relay.peerPublic, relay.clientConfirmKey, th2)
	if err != nil {
		relay.closeLockedV1()
		return nil, nil, err
	}
	th3 := protocolHash(
		"kurdistan/handshake/v1/transcript-client-finish",
		relay.receivedClientBody,
		relay.serverSentBody,
		receivedClientFinish,
	)
	serverFinish, serverFinishBody := makeServerFinish(relay.privateKey, relay.serverConfirmKey, th3)
	th4 := protocolHash(
		"kurdistan/handshake/v1/transcript-final",
		relay.receivedClientBody,
		relay.serverSentBody,
		receivedClientFinish,
		serverFinishBody,
	)
	applicationSalt := protocolHash(
		"kurdistan/hkdf/v1/application-salt",
		th4[:],
		relay.config.input.Client.ProfileHash[:],
	)
	secret, err := hkdf.Extract(sha256.New, relay.handshakePRK, applicationSalt[:])
	if err != nil {
		relay.closeLockedV1()
		return nil, nil, fail(FailureKeyAgreement)
	}
	context, err := newAuthenticatedContextV1(relay.config.input, th4)
	if err != nil {
		wipe(secret)
		relay.closeLockedV1()
		return nil, nil, err
	}
	result := newProcessHandshakeResultV1(
		ProcessHandshakeRelayV1,
		secret,
		context,
		ProcessHandshakeEvidenceV1{
			Role:           ProcessHandshakeRelayV1,
			ClientNonce:    relay.clientNonce,
			ServerNonce:    relay.serverNonce,
			ClientPublic:   relay.clientPublic,
			ServerPublic:   relay.serverPublic,
			TranscriptHash: th4,
			Messages: [4][]byte{
				relay.clientHello,
				relay.serverHello,
				message,
				serverFinish,
			},
		},
	)
	wipe(secret)
	relay.closeLockedV1()
	return append([]byte(nil), serverFinish...), result, nil
}

// Close destroys incomplete relay-side handshake material.
func (relay *RelayProcessHandshakeV1) Close() {
	if relay == nil {
		return
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.closeLockedV1()
}

func (relay *RelayProcessHandshakeV1) failLockedV1(code FailureCode) error {
	relay.closeLockedV1()
	return fail(code)
}

func (relay *RelayProcessHandshakeV1) closeLockedV1() {
	wipe(relay.privateKey)
	wipe(relay.clientConfirmKey)
	wipe(relay.serverConfirmKey)
	wipe(relay.handshakePRK)
	relay.privateKey = nil
	relay.peerPublic = nil
	relay.clientConfirmKey = nil
	relay.serverConfirmKey = nil
	relay.handshakePRK = nil
	relay.ephemeral = nil
	relay.replay = nil
	relay.config = ProcessHandshakeConfigV1{}
	relay.entropy = nil
	relay.stage = relayProcessClosedV1
}

func newProcessHandshakeResultV1(role ProcessHandshakeRoleV1, secret []byte, context AuthenticatedContextV1, evidence ProcessHandshakeEvidenceV1) *ProcessHandshakeResultV1 {
	return &ProcessHandshakeResultV1{
		role:     role,
		secret:   append([]byte(nil), secret...),
		context:  cloneContextSnapshot(context.snapshot),
		evidence: cloneProcessHandshakeEvidenceV1(evidence),
	}
}

func cloneProcessHandshakeConfigV1(config ProcessHandshakeConfigV1) ProcessHandshakeConfigV1 {
	return ProcessHandshakeConfigV1{input: cloneFirstContactInput(config.input)}
}

func cloneProcessHandshakeEvidenceV1(evidence ProcessHandshakeEvidenceV1) ProcessHandshakeEvidenceV1 {
	for index := range evidence.Messages {
		evidence.Messages[index] = append([]byte(nil), evidence.Messages[index]...)
	}
	return evidence
}
