// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"errors"
	"sync"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
)

var (
	ErrConfigInvalid           = errors.New("config_invalid")
	errConfigProfileMismatchV1 = errors.New("config_profile_mismatch")
)

const redactionCertificateVersionV1 uint16 = 1

type redactionCertificateV1 struct {
	version uint16
	role    implementationRoleV1
	marker  [16]byte
}

var (
	clientRedactionMarkerV1 = [16]byte{0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x72, 0x65, 0x64, 0x61, 0x63, 0x74, 0x2d, 0x31, 0x00}
	relayRedactionMarkerV1  = [16]byte{0x72, 0x65, 0x6c, 0x61, 0x79, 0x2d, 0x72, 0x65, 0x64, 0x61, 0x63, 0x74, 0x2d, 0x31, 0x00, 0x00}
)

type ClientLocalRuntimeControlsV1 struct {
	RuntimeID     string
	EventCapacity uint32
	QueueCeiling  uint32
}

type RelayLocalRuntimeControlsV1 struct {
	RuntimeID     string
	EventCapacity uint32
	QueueCeiling  uint32
}

type PairInputV1 struct {
	FirstContactInput auth.FirstContactInput
	ClientConfig      ClientStrictSessionConfigV1
	RelayConfig       RelayStrictSessionConfigV1
	ClientControls    ClientLocalRuntimeControlsV1
	RelayControls     RelayLocalRuntimeControlsV1
}

type pairScheduleDeriverV1 func(security.KeyScheduleInput) (security.KeySchedule, error)
type pairConstructorV1 func(pairConstructionInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error)

type pairMaterialHandleV1 struct {
	state *pairMaterialStateV1
	owner *HandshakeRuntime
	epoch [32]byte
}

type pairMaterialStateV1 struct {
	claimMu          sync.Mutex
	claimed          bool
	canceled         bool
	destroyOnce      sync.Once
	owner            *HandshakeRuntime
	epoch            [32]byte
	context          auth.AuthenticatedContextSnapshotV1
	clientSecret     []byte
	relaySecret      []byte
	clientTranscript [32]byte
	relayTranscript  [32]byte
	clientSuite      security.Suite
	relaySuite       security.Suite
	clientConfig     StrictSessionConfigV1
	relayConfig      StrictSessionConfigV1
	clientControls   ClientLocalRuntimeControlsV1
	relayControls    RelayLocalRuntimeControlsV1
	unsafeConfig     bool
}

type pairConstructionInputV1 struct {
	owner          *HandshakeRuntime
	epoch          [32]byte
	context        auth.AuthenticatedContextSnapshotV1
	clientSchedule security.KeySchedule
	relaySchedule  security.KeySchedule
	clientConfig   StrictSessionConfigV1
	relayConfig    StrictSessionConfigV1
	clientControls ClientLocalRuntimeControlsV1
	relayControls  RelayLocalRuntimeControlsV1
}

type pairRoleTagV1 struct {
	marker uint8
}

type pairProfileBindingV1 struct {
	profileID   string
	profileHash [32]byte
}

type pairTerminalCoordinatorV1 struct {
	mu                sync.Mutex
	closed            bool
	context           auth.AuthenticatedContextSnapshotV1
	retiredProfile    pairProfileBindingV1
	destroy           func()
	runtimeEpoch      [32]byte
	owner             *HandshakeRuntime
	ownerTag          *runtimeInstanceTagV1
	clientTag         *pairRoleTagV1
	relayTag          *pairRoleTagV1
	restartInProgress bool
	restartSucceeded  bool
}

type clientAuthenticatedEndpointStateV1 struct {
	coordinator *pairTerminalCoordinatorV1
	schedule    security.KeySchedule
	config      StrictSessionConfigV1
	controls    ClientLocalRuntimeControlsV1
	life        *endpointLifecycleV1
	restartTag  *pairRoleTagV1
}

type relayAuthenticatedEndpointStateV1 struct {
	coordinator *pairTerminalCoordinatorV1
	schedule    security.KeySchedule
	config      StrictSessionConfigV1
	controls    RelayLocalRuntimeControlsV1
	life        *endpointLifecycleV1
	restartTag  *pairRoleTagV1
}

// ClientAuthenticatedEndpointV1 and RelayAuthenticatedEndpointV1 are opaque,
// role-fixed views. Their private schedules never cross the public boundary.
type ClientAuthenticatedEndpointV1 struct {
	state *clientAuthenticatedEndpointStateV1
}
type RelayAuthenticatedEndpointV1 struct {
	state *relayAuthenticatedEndpointStateV1
}

func (endpoint *ClientAuthenticatedEndpointV1) State() auth.State {
	if endpoint == nil || endpoint.state == nil || endpoint.state.coordinator == nil {
		return auth.StateClosed
	}
	endpoint.state.coordinator.mu.Lock()
	defer endpoint.state.coordinator.mu.Unlock()
	if endpoint.state.coordinator.closed {
		return auth.StateClosed
	}
	if endpoint.state.life == nil {
		endpoint.state.coordinator.closeLockedV1()
		return auth.StateClosed
	}
	return endpoint.state.life.stateLockedV1()
}

func (endpoint *RelayAuthenticatedEndpointV1) State() auth.State {
	if endpoint == nil || endpoint.state == nil || endpoint.state.coordinator == nil {
		return auth.StateClosed
	}
	endpoint.state.coordinator.mu.Lock()
	defer endpoint.state.coordinator.mu.Unlock()
	if endpoint.state.coordinator.closed {
		return auth.StateClosed
	}
	if endpoint.state.life == nil {
		endpoint.state.coordinator.closeLockedV1()
		return auth.StateClosed
	}
	return endpoint.state.life.stateLockedV1()
}

func (endpoint *ClientAuthenticatedEndpointV1) Close() {
	if endpoint != nil && endpoint.state != nil && endpoint.state.coordinator != nil {
		endpoint.state.coordinator.close()
	}
}

func (endpoint *RelayAuthenticatedEndpointV1) Close() {
	if endpoint != nil && endpoint.state != nil && endpoint.state.coordinator != nil {
		endpoint.state.coordinator.close()
	}
}

func (coordinator *pairTerminalCoordinatorV1) close() {
	if coordinator == nil {
		return
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.closeLockedV1()
}

func (coordinator *pairTerminalCoordinatorV1) closeLockedV1() {
	if coordinator == nil {
		return
	}
	if coordinator.closed {
		return
	}
	coordinator.closed = true
	if coordinator.destroy != nil {
		coordinator.destroy()
		coordinator.destroy = nil
	}
	coordinator.context = auth.AuthenticatedContextSnapshotV1{}
}

// NewAuthenticatedChannelPair is the sole strict-v1 configured-pair entry.
func (runtime *HandshakeRuntime) NewAuthenticatedChannelPair(input PairInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	if !validHandshakeRuntimeIdentityV1(runtime) || !runtime.strict || runtime.replay == nil {
		return nil, nil, ErrProfileIncompatible
	}
	result, context, err := runtime.strictFirstContactWithContextV1(input.FirstContactInput)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		for i := range result.ChannelSecret {
			result.ChannelSecret[i] = 0
		}
	}()
	if result.ClientState != auth.StateEstablished || result.ServerState != auth.StateAuthenticating || len(result.ChannelSecret) != 32 {
		return nil, nil, ErrProfileIncompatible
	}
	clientConfig, relayConfig := input.ClientConfig.value, input.RelayConfig.value
	if err := validateAuthenticatedPairInputsV1(context, clientConfig, relayConfig, input.ClientControls, input.RelayControls, runtime.clientSupport.redaction, runtime.relaySupport.redaction); err != nil {
		return nil, nil, err
	}
	material, err := runtime.registerPairMaterialV1(context, result.ChannelSecret, clientConfig, relayConfig, input.ClientControls, input.RelayControls)
	if err != nil {
		return nil, nil, err
	}
	client, relay, err := runtime.consumePairMaterialV1(material)
	if err != nil {
		return nil, nil, err
	}
	if !strictPairOwnedByRuntimeV1(runtime, client, relay) {
		closeEndpointPairV1(client, relay)
		return nil, nil, ErrProfileIncompatible
	}
	if err := commitPairProfileGenerationV1(runtime, client, relay, context.ClientConfigSourceBlock.ProfileID, context.ClientProfileHash); err != nil {
		client.Close()
		return nil, nil, ErrProfileRotationRequired
	}
	return client, relay, nil
}

func (runtime *HandshakeRuntime) NewAuthenticatedChannelPairWithAuthLabFaultV1(input PairInputV1, token auth.AuthLabFaultToken) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	return runtime.newAuthenticatedChannelPairV1(input, &token)
}

func (runtime *HandshakeRuntime) newAuthenticatedChannelPairV1(input PairInputV1, token *auth.AuthLabFaultToken) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	if !validHandshakeRuntimeIdentityV1(runtime) || !runtime.strict || runtime.replay == nil {
		return nil, nil, ErrProfileIncompatible
	}
	unsafeConfig := false
	if token != nil {
		capability := auth.RuntimeAcceptsCapabilityDowngradeAuthLabFaultV1(*token, &input.FirstContactInput)
		profile := auth.RuntimeAcceptsProfileMismatchAuthLabFaultV1(*token, &input.FirstContactInput)
		unsafeConfig = auth.UnsafeConfigAllowedAuthLabFaultV1(*token)
		if !capability && !profile && !unsafeConfig {
			return nil, nil, ErrProfileIncompatible
		}
	}
	result, context, err := runtime.strictFirstContactWithContextV1(input.FirstContactInput)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		for i := range result.ChannelSecret {
			result.ChannelSecret[i] = 0
		}
	}()
	if result.ClientState != auth.StateEstablished || result.ServerState != auth.StateAuthenticating || len(result.ChannelSecret) != 32 {
		return nil, nil, ErrProfileIncompatible
	}
	clientConfig := input.ClientConfig.value
	relayConfig := input.RelayConfig.value
	if err := validateAuthenticatedPairInputsV1(context, clientConfig, relayConfig, input.ClientControls, input.RelayControls, runtime.clientSupport.redaction, runtime.relaySupport.redaction); err != nil && !unsafeConfig {
		return nil, nil, err
	}
	material, err := runtime.registerPairMaterialWithUnsafeConfigV1(context, result.ChannelSecret, clientConfig, relayConfig, input.ClientControls, input.RelayControls, unsafeConfig)
	if err != nil {
		return nil, nil, err
	}
	client, relay, err := runtime.consumePairMaterialV1(material)
	if err != nil {
		return nil, nil, err
	}
	if !strictPairOwnedByRuntimeV1(runtime, client, relay) {
		closeEndpointPairV1(client, relay)
		return nil, nil, ErrProfileIncompatible
	}
	if err := commitPairProfileGenerationV1(runtime, client, relay, context.ClientConfigSourceBlock.ProfileID, context.ClientProfileHash); err != nil {
		client.Close()
		return nil, nil, ErrProfileRotationRequired
	}
	return client, relay, nil
}

func (runtime *HandshakeRuntime) registerPairMaterialV1(context auth.AuthenticatedContextSnapshotV1, secret []byte, clientConfig, relayConfig StrictSessionConfigV1, clientControls ClientLocalRuntimeControlsV1, relayControls RelayLocalRuntimeControlsV1) (pairMaterialHandleV1, error) {
	return runtime.registerPairMaterialWithUnsafeConfigV1(context, secret, clientConfig, relayConfig, clientControls, relayControls, false)
}

func (runtime *HandshakeRuntime) registerPairMaterialWithUnsafeConfigV1(context auth.AuthenticatedContextSnapshotV1, secret []byte, clientConfig, relayConfig StrictSessionConfigV1, clientControls ClientLocalRuntimeControlsV1, relayControls RelayLocalRuntimeControlsV1, unsafeConfig bool) (pairMaterialHandleV1, error) {
	if runtime == nil || len(secret) != 32 || zeroRuntimeBytesV1(secret) || zeroRuntimeEpoch(runtime.epoch) {
		return pairMaterialHandleV1{}, ErrProfileIncompatible
	}
	suite, err := strictTrafficSuiteV1(context.SelectedSuite)
	if err != nil {
		return pairMaterialHandleV1{}, err
	}
	state := &pairMaterialStateV1{
		owner: runtime, epoch: runtime.epoch, context: cloneAuthenticatedContextSnapshotV1(context),
		clientSecret: append([]byte(nil), secret...), relaySecret: append([]byte(nil), secret...),
		clientTranscript: context.TranscriptHash, relayTranscript: context.TranscriptHash,
		clientSuite: suite, relaySuite: suite,
		clientConfig: clientConfig, relayConfig: relayConfig,
		clientControls: clientControls, relayControls: relayControls,
		unsafeConfig: unsafeConfig,
	}
	runtime.pairMu.Lock()
	if runtime.pendingPairMaterials == nil {
		runtime.pendingPairMaterials = make(map[*pairMaterialStateV1]struct{})
	}
	runtime.pendingPairMaterials[state] = struct{}{}
	runtime.pairMu.Unlock()
	return pairMaterialHandleV1{state: state, owner: runtime, epoch: runtime.epoch}, nil
}

func (runtime *HandshakeRuntime) consumePairMaterialV1(handle pairMaterialHandleV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	state := handle.state
	if state == nil || !state.claim() {
		return nil, nil, ErrProfileIncompatible
	}
	defer state.destroy()
	owner := state.owner
	registered := burnPairMaterialRegistrationV1(state, runtime, owner, handle.owner)
	if !registered {
		return nil, nil, ErrProfileIncompatible
	}
	if owner == nil || runtime != owner || handle.owner != owner || handle.epoch != state.epoch || state.epoch != owner.epoch || zeroRuntimeEpoch(state.epoch) {
		return nil, nil, ErrProfileIncompatible
	}
	if !security.SuiteSupported(state.clientSuite) || !security.SuiteSupported(state.relaySuite) || state.clientSuite != state.relaySuite ||
		state.clientTranscript != state.context.TranscriptHash || state.relayTranscript != state.context.TranscriptHash {
		return nil, nil, ErrProfileIncompatible
	}
	if err := validateAuthenticatedPairInputsV1(state.context, state.clientConfig, state.relayConfig, state.clientControls, state.relayControls, runtime.clientSupport.redaction, runtime.relaySupport.redaction); err != nil && !state.unsafeConfig {
		return nil, nil, err
	}
	derive := runtime.pairDeriveScheduleV1
	if derive == nil {
		derive = security.DeriveKeyScheduleV1
	}
	clientInputSecret := state.clientSecret
	clientSchedule, err := derive(security.KeyScheduleInput{ApplicationSecret: clientInputSecret, TranscriptHash: state.clientTranscript[:], Suite: state.clientSuite})
	wipeRuntimeBytesV1(clientInputSecret)
	state.clientSecret = nil
	if err != nil {
		clientSchedule.Destroy()
		return nil, nil, err
	}
	clientOwned := true
	defer func() {
		if clientOwned {
			clientSchedule.Destroy()
		}
	}()
	relayInputSecret := state.relaySecret
	relaySchedule, err := derive(security.KeyScheduleInput{ApplicationSecret: relayInputSecret, TranscriptHash: state.relayTranscript[:], Suite: state.relaySuite})
	wipeRuntimeBytesV1(relayInputSecret)
	state.relaySecret = nil
	if err != nil {
		relaySchedule.Destroy()
		return nil, nil, err
	}
	relayOwned := true
	defer func() {
		if relayOwned {
			relaySchedule.Destroy()
		}
	}()
	constructor := runtime.pairConstructV1
	if constructor == nil {
		constructor = constructAuthenticatedPairV1
	}
	client, relay, err := constructor(pairConstructionInputV1{
		owner: runtime, epoch: state.epoch, context: cloneAuthenticatedContextSnapshotV1(state.context),
		clientSchedule: clientSchedule, relaySchedule: relaySchedule,
		clientConfig: state.clientConfig, relayConfig: state.relayConfig,
		clientControls: state.clientControls, relayControls: state.relayControls,
	})
	if err != nil || client == nil || relay == nil {
		return nil, nil, ErrProfileIncompatible
	}
	clientOwned = false
	relayOwned = false
	clientSchedule = security.KeySchedule{}
	relaySchedule = security.KeySchedule{}
	return client, relay, nil
}

func burnPairMaterialRegistrationV1(state *pairMaterialStateV1, owners ...*HandshakeRuntime) bool {
	registered := false
	seen := make(map[*HandshakeRuntime]struct{}, len(owners))
	for _, owner := range owners {
		if owner == nil {
			continue
		}
		if _, ok := seen[owner]; ok {
			continue
		}
		seen[owner] = struct{}{}
		owner.pairMu.Lock()
		if _, ok := owner.pendingPairMaterials[state]; ok {
			registered = true
		}
		delete(owner.pendingPairMaterials, state)
		owner.pairMu.Unlock()
	}
	return registered
}

func (runtime *HandshakeRuntime) drainPendingPairMaterialsV1() {
	if runtime == nil {
		return
	}
	runtime.pairMu.Lock()
	pending := make([]*pairMaterialStateV1, 0, len(runtime.pendingPairMaterials))
	for state := range runtime.pendingPairMaterials {
		pending = append(pending, state)
		delete(runtime.pendingPairMaterials, state)
	}
	runtime.pairMu.Unlock()
	for _, state := range pending {
		state.cancelAndDestroyIfUnclaimedV1()
	}
}

func (state *pairMaterialStateV1) destroy() {
	if state == nil {
		return
	}
	state.destroyOnce.Do(func() {
		wipeRuntimeBytesV1(state.clientSecret)
		wipeRuntimeBytesV1(state.relaySecret)
		state.clientSecret = nil
		state.relaySecret = nil
		state.owner = nil
		state.epoch = [32]byte{}
		state.clientTranscript = [32]byte{}
		state.relayTranscript = [32]byte{}
		state.clientSuite = security.Suite{}
		state.relaySuite = security.Suite{}
		state.clientConfig = StrictSessionConfigV1{}
		state.relayConfig = StrictSessionConfigV1{}
		state.clientControls = ClientLocalRuntimeControlsV1{}
		state.relayControls = RelayLocalRuntimeControlsV1{}
		state.context = auth.AuthenticatedContextSnapshotV1{}
	})
}

func (state *pairMaterialStateV1) claim() bool {
	state.claimMu.Lock()
	defer state.claimMu.Unlock()
	if state.claimed || state.canceled {
		return false
	}
	state.claimed = true
	return true
}

func (state *pairMaterialStateV1) cancelAndDestroyIfUnclaimedV1() bool {
	if state == nil {
		return false
	}
	state.claimMu.Lock()
	if state.claimed || state.canceled {
		state.claimMu.Unlock()
		return false
	}
	state.canceled = true
	state.claimMu.Unlock()
	state.destroy()
	return true
}

func constructAuthenticatedPairV1(input pairConstructionInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	if !validHandshakeRuntimeIdentityV1(input.owner) || zeroRuntimeEpoch(input.epoch) || input.owner.epoch != input.epoch {
		return nil, nil, ErrProfileIncompatible
	}
	profile, ok := authenticatedPairProfileBindingV1(input.context, input.clientConfig, input.relayConfig)
	if !ok {
		return nil, nil, ErrProfileIncompatible
	}
	clientTag := &pairRoleTagV1{marker: 1}
	relayTag := &pairRoleTagV1{marker: 2}
	clientState := &clientAuthenticatedEndpointStateV1{schedule: input.clientSchedule, config: input.clientConfig, controls: input.clientControls, restartTag: clientTag}
	relayState := &relayAuthenticatedEndpointStateV1{schedule: input.relaySchedule, config: input.relayConfig, controls: input.relayControls, restartTag: relayTag}
	coordinator := &pairTerminalCoordinatorV1{
		context: cloneAuthenticatedContextSnapshotV1(input.context), retiredProfile: profile, runtimeEpoch: input.epoch,
		owner: input.owner, ownerTag: input.owner.instanceTag, clientTag: clientTag, relayTag: relayTag,
	}
	clientLife, err := newEndpointLifecycleV1(coordinator, input.owner, &clientState.schedule, input.clientConfig, input.context, lifecycleRoleClientV1, auth.StateEstablished)
	if err != nil {
		return nil, nil, ErrProfileIncompatible
	}
	relayLife, err := newEndpointLifecycleV1(coordinator, input.owner, &relayState.schedule, input.relayConfig, input.context, lifecycleRoleRelayV1, auth.StateAuthenticating)
	if err != nil {
		return nil, nil, ErrProfileIncompatible
	}
	clientState.life = clientLife
	relayState.life = relayLife
	coordinator.destroy = func() {
		clientLife.destroyLockedV1()
		relayLife.destroyLockedV1()
		clientState.config = StrictSessionConfigV1{}
		clientState.controls = ClientLocalRuntimeControlsV1{}
		relayState.config = StrictSessionConfigV1{}
		relayState.controls = RelayLocalRuntimeControlsV1{}
	}
	clientState.coordinator = coordinator
	relayState.coordinator = coordinator
	return &ClientAuthenticatedEndpointV1{state: clientState}, &RelayAuthenticatedEndpointV1{state: relayState}, nil
}

func authenticatedPairProfileBindingV1(context auth.AuthenticatedContextSnapshotV1, clientConfig, relayConfig StrictSessionConfigV1) (pairProfileBindingV1, bool) {
	profile := pairProfileBindingV1{
		profileID:   context.ClientConfigSourceBlock.ProfileID,
		profileHash: context.ClientProfileHash,
	}
	if !validPairProfileBindingV1(profile) ||
		context.ServerConfigSourceBlock.ProfileID != profile.profileID || context.ServerProfileHash != profile.profileHash ||
		clientConfig.ProfileID != profile.profileID || clientConfig.ProfileHash != profile.profileHash ||
		relayConfig.ProfileID != profile.profileID || relayConfig.ProfileHash != profile.profileHash {
		return pairProfileBindingV1{}, false
	}
	return profile, true
}

func validPairProfileBindingV1(profile pairProfileBindingV1) bool {
	return profile.profileID != "" && !zeroRuntimeEpoch(profile.profileHash)
}

// pairRolesMatchProfileBindingLockedV1 validates live role state before the
// first terminal close scrubs redundant endpoint and lifecycle configuration.
func pairRolesMatchProfileBindingLockedV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, profile pairProfileBindingV1) bool {
	if client == nil || relay == nil || client.state == nil || relay.state == nil ||
		client.state.coordinator == nil || client.state.coordinator != relay.state.coordinator ||
		client.state.life == nil || relay.state.life == nil || !validPairProfileBindingV1(profile) {
		return false
	}
	return client.state.config.ProfileID == profile.profileID && client.state.config.ProfileHash == profile.profileHash &&
		relay.state.config.ProfileID == profile.profileID && relay.state.config.ProfileHash == profile.profileHash &&
		client.state.life.config.ProfileID == profile.profileID && client.state.life.config.ProfileHash == profile.profileHash &&
		relay.state.life.config.ProfileID == profile.profileID && relay.state.life.config.ProfileHash == profile.profileHash
}

func validateAuthenticatedPairInputsV1(context auth.AuthenticatedContextSnapshotV1, clientConfig, relayConfig StrictSessionConfigV1, clientControls ClientLocalRuntimeControlsV1, relayControls RelayLocalRuntimeControlsV1, clientCertificate, relayCertificate redactionCertificateV1) error {
	if err := validateAuthenticatedContextForConfiguredPairV1(context); err != nil {
		return ErrProfileIncompatible
	}
	if err := validateStrictSessionConfigV1(clientConfig); err != nil {
		return ErrConfigInvalid
	}
	if err := validateStrictSessionConfigV1(relayConfig); err != nil {
		return ErrConfigInvalid
	}
	wantClient, err := strictConfigFromContextV1(context, true)
	if err != nil {
		return ErrProfileIncompatible
	}
	wantRelay, err := strictConfigFromContextV1(context, false)
	if err != nil {
		return ErrProfileIncompatible
	}
	if clientConfig != wantClient || relayConfig != wantRelay || clientConfig != relayConfig {
		return ErrConfigInvalid
	}
	if !validLocalControlsV1(clientControls.RuntimeID, clientControls.EventCapacity, clientControls.QueueCeiling, context.ClientLimitBlock.CarrierMaxQueueDepth) ||
		!validLocalControlsV1(relayControls.RuntimeID, relayControls.EventCapacity, relayControls.QueueCeiling, context.ServerLimitBlock.CarrierMaxQueueDepth) {
		return ErrConfigInvalid
	}
	return validateAdvancedLocalControlsV1(context.EffectivePolicy.ConfigValidationPolicy, context.ClientLimitBlock.CarrierMaxQueueDepth,
		context.ServerLimitBlock.CarrierMaxQueueDepth, clientControls, relayControls, clientCertificate, relayCertificate)
}

func validateAdvancedLocalControlsV1(policy string, clientRoleCap, relayRoleCap uint32, clientControls ClientLocalRuntimeControlsV1, relayControls RelayLocalRuntimeControlsV1, clientCertificate, relayCertificate redactionCertificateV1) error {
	switch policy {
	case "strict_required":
	case "strict_with_redaction", "strict_profile_bound":
		if !validRedactionCertificateV1(clientCertificate, implementationRoleClientV1) || !validRedactionCertificateV1(relayCertificate, implementationRoleRelayV1) {
			return ErrConfigInvalid
		}
		if policy == "strict_profile_bound" && (clientControls.QueueCeiling != clientRoleCap || relayControls.QueueCeiling != relayRoleCap) {
			return errConfigProfileMismatchV1
		}
	default:
		return ErrConfigInvalid
	}
	return nil
}

func validRedactionCertificateV1(certificate redactionCertificateV1, role implementationRoleV1) bool {
	if certificate.version != redactionCertificateVersionV1 || certificate.role != role {
		return false
	}
	if role == implementationRoleClientV1 {
		return certificate.marker == clientRedactionMarkerV1
	}
	return role == implementationRoleRelayV1 && certificate.marker == relayRedactionMarkerV1
}

func validateAuthenticatedContextForPairV1(context auth.AuthenticatedContextSnapshotV1) error {
	return validateAuthenticatedContextForPairPolicyV1(context, false)
}

func validateAuthenticatedContextForConfiguredPairV1(context auth.AuthenticatedContextSnapshotV1) error {
	return validateAuthenticatedContextForPairPolicyV1(context, true)
}

func validateAuthenticatedContextForPairPolicyV1(context auth.AuthenticatedContextSnapshotV1, advanced bool) error {
	want, err := security.ContextHashV1(security.AuthenticatedContextHashInputV1{
		EffectivePolicy: context.EffectivePolicy, EffectivePolicyHash: context.EffectivePolicyHash,
		TranscriptHash: context.TranscriptHash, SelectedSuite: context.SelectedSuite,
		SelectedCapabilityHash: context.SelectedCapabilityHash,
		ClientProfileHash:      context.ClientProfileHash, ServerProfileHash: context.ServerProfileHash,
		ClientModeBinding: context.ClientModeBinding, ServerModeBinding: context.ServerModeBinding,
	})
	if err != nil || want != context.ContextHash || context.ClientProfileHash != context.ServerProfileHash {
		return ErrProfileIncompatible
	}
	if !validAuthenticatedRoleBlocksV1(
		context.ClientCompatibilityBlock, context.ClientCompatibilityBlockHash,
		context.ClientLimitBlock, context.ClientLimitBlockHash,
		context.ClientConfigSourceBlock, context.ClientConfigSourceBlockHash,
		context.ClientModeBinding,
	) || !validAuthenticatedRoleBlocksV1(
		context.ServerCompatibilityBlock, context.ServerCompatibilityBlockHash,
		context.ServerLimitBlock, context.ServerLimitBlockHash,
		context.ServerConfigSourceBlock, context.ServerConfigSourceBlockHash,
		context.ServerModeBinding,
	) {
		return ErrProfileIncompatible
	}
	clientCompatibility, err := security.CanonicalCompatibilityBlockV1(context.ClientCompatibilityBlock)
	if err != nil {
		return ErrProfileIncompatible
	}
	relayCompatibility, err := security.CanonicalCompatibilityBlockV1(context.ServerCompatibilityBlock)
	if err != nil || !equalRuntimeBytesV1(clientCompatibility, relayCompatibility) {
		return ErrProfileIncompatible
	}
	clientLimits, err := security.CanonicalLimitBlockV1(context.ClientLimitBlock)
	if err != nil {
		return ErrProfileIncompatible
	}
	relayLimits, err := security.CanonicalLimitBlockV1(context.ServerLimitBlock)
	if err != nil || !equalRuntimeBytesV1(clientLimits, relayLimits) {
		return ErrProfileIncompatible
	}
	if (!advanced && (context.EffectivePolicy.ProfileCompatibilityPolicy != "strict_schema" || context.EffectivePolicy.ConfigValidationPolicy != "strict_required")) ||
		(advanced && (!oneOfRuntimePolicyV1(context.EffectivePolicy.ProfileCompatibilityPolicy, "strict_schema", "schema_and_feature", "full_policy_binding") ||
			!oneOfRuntimePolicyV1(context.EffectivePolicy.ConfigValidationPolicy, "strict_required", "strict_with_redaction", "strict_profile_bound"))) {
		return ErrProfileIncompatible
	}
	return nil
}

func oneOfRuntimePolicyV1(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validAuthenticatedRoleBlocksV1(compatibility security.CompatibilityBlockV1, compatibilityHash [32]byte, limits security.LimitBlockV1, limitHash [32]byte, source security.ConfigSourceBlockV1, sourceHash [32]byte, binding security.HandshakeModeBinding) bool {
	compatibilityRaw, err := security.CanonicalCompatibilityBlockV1(compatibility)
	if err != nil {
		return false
	}
	bindingCompatibilityRaw, err := security.CanonicalCompatibilityBlockV1(binding.CompatibilityBlock)
	if err != nil || !equalRuntimeBytesV1(compatibilityRaw, bindingCompatibilityRaw) {
		return false
	}
	wantCompatibilityHash, err := security.CompatibilityBlockHashV1(compatibility)
	if err != nil || wantCompatibilityHash != compatibilityHash || compatibilityHash != binding.CompatibilityBlockHash {
		return false
	}
	limitRaw, err := security.CanonicalLimitBlockV1(limits)
	if err != nil {
		return false
	}
	bindingLimitRaw, err := security.CanonicalLimitBlockV1(binding.LimitBlock)
	if err != nil || !equalRuntimeBytesV1(limitRaw, bindingLimitRaw) {
		return false
	}
	wantLimitHash, err := security.LimitBlockHashV1(limits)
	if err != nil || wantLimitHash != limitHash || limitHash != binding.LimitBlockHash {
		return false
	}
	sourceRaw, err := security.CanonicalConfigSourceBlockV1(source)
	if err != nil {
		return false
	}
	bindingSourceRaw, err := security.CanonicalConfigSourceBlockV1(binding.ConfigSourceBlock)
	if err != nil || !equalRuntimeBytesV1(sourceRaw, bindingSourceRaw) {
		return false
	}
	wantSourceHash, err := security.ConfigSourceBlockHashV1(source)
	return err == nil && wantSourceHash == sourceHash && sourceHash == binding.ConfigSourceBlockHash
}

func strictConfigFromContextV1(context auth.AuthenticatedContextSnapshotV1, client bool) (StrictSessionConfigV1, error) {
	source := context.ServerConfigSourceBlock
	limits := context.ServerLimitBlock
	if client {
		source = context.ClientConfigSourceBlock
		limits = context.ClientLimitBlock
	}
	policy := context.EffectivePolicy
	if policy.ReplayWindowSize <= 0 || policy.MaxSessionMessages <= 0 || policy.MaxKeyLifetimeMessages <= 0 {
		return StrictSessionConfigV1{}, ErrProfileIncompatible
	}
	value := StrictSessionConfigV1{
		ProfileID: source.ProfileID, ProfileHash: source.ProfileHash,
		SelectedSuite: source.SelectedSuite, EffectivePolicyHash: source.EffectivePolicyHash,
		SelectedCapabilityHash: source.SelectedCapabilityHash,
		ReplayWindowSize:       uint32(policy.ReplayWindowSize), MaxSessionMessages: uint64(policy.MaxSessionMessages),
		MaxKeyLifetimeMessages: uint64(policy.MaxKeyLifetimeMessages),
		MaxConcurrentStreams:   limits.SessionMaxConcurrentStreams,
		MaxFrameBytes:          limits.MaxFrameBytes, MaxEnvelopeBytes: limits.CarrierMaxEnvelopeBytes,
	}
	hash, err := ConfigPolicyHashV1(value)
	if err != nil {
		return StrictSessionConfigV1{}, ErrProfileIncompatible
	}
	value.ConfigPolicyHash = hash
	return value, nil
}

func validLocalControlsV1(runtimeID string, eventCapacity, queueCeiling, queueCap uint32) bool {
	return validStrictRuntimeTextV1(runtimeID) && eventCapacity > 0 && eventCapacity <= 1<<20 && queueCeiling > 0 && queueCeiling <= queueCap
}

func strictTrafficSuiteV1(selected security.SelectedSuiteV1) (security.Suite, error) {
	suite := security.DefaultSuite()
	if selected.KDFSuite != suite.KDF || selected.AEADSuite != suite.AEAD || selected.MACSuite != suite.MAC {
		return security.Suite{}, ErrProfileIncompatible
	}
	return suite, nil
}

func cloneAuthenticatedContextSnapshotV1(context auth.AuthenticatedContextSnapshotV1) auth.AuthenticatedContextSnapshotV1 {
	context.EffectivePolicy = context.EffectivePolicy.Clone()
	context.ClientCompatibilityBlock = context.ClientCompatibilityBlock.Clone()
	context.ServerCompatibilityBlock = context.ServerCompatibilityBlock.Clone()
	context.ClientModeBinding = context.ClientModeBinding.Clone()
	context.ServerModeBinding = context.ServerModeBinding.Clone()
	return context
}

func wipeRuntimeBytesV1(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func zeroRuntimeBytesV1(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}

func equalRuntimeBytesV1(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for i := range left {
		different |= left[i] ^ right[i]
	}
	return different == 0
}
