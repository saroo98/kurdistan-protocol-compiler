// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
)

const handshakeReplayCapacity = 65536

type runtimeInstanceTagV1 struct {
	marker uint8
	owner  *HandshakeRuntime
	replay *auth.HandshakeReplayCache
}

// HandshakeRuntime owns replay state across all simulated connections for one
// local runtime lifetime. Recreating it models a restart; no state is persisted.
type HandshakeRuntime struct {
	self                 *HandshakeRuntime
	instanceTag          *runtimeInstanceTagV1
	replay               *auth.HandshakeReplayCache
	epoch                [32]byte
	clientDependencies   auth.Dependencies
	serverDependencies   auth.Dependencies
	strict               bool
	strictEntropy        io.Reader
	strictEntropyFailed  bool
	epochMu              sync.Mutex
	clientSupport        ImplementationSupportV1
	relaySupport         ImplementationSupportV1
	clientRegistry       ClientProfileAuthorizationRegistryV1
	relayRegistry        RelayProfileAuthorizationRegistryV1
	pairMu               sync.Mutex
	pendingPairMaterials map[*pairMaterialStateV1]struct{}
	pairDeriveScheduleV1 pairScheduleDeriverV1
	pairConstructV1      pairConstructorV1
	profileMu            sync.Mutex
	profileGeneration    uint64
	profileSeen          bool
	profileID            string
	profileHash          [32]byte
	profileOverflow      bool
}

func NewHandshakeRuntime(client, server auth.Dependencies) (*HandshakeRuntime, error) {
	return newHandshakeRuntime(client, server, rand.Reader)
}

// NewStrictHandshakeRuntimeV1 constructs the only runtime that may later
// create a strict authenticated pair. Implementation support is package-owned;
// callers supply only the two independent role-typed owner registries.
func NewStrictHandshakeRuntimeV1(client, relay auth.Dependencies, clientRegistry ClientProfileAuthorizationRegistryV1, relayRegistry RelayProfileAuthorizationRegistryV1) (*HandshakeRuntime, error) {
	return newStrictHandshakeRuntimeV1(
		client, relay, clientRegistry, relayRegistry,
		reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1,
		rand.Reader,
	)
}

// newStrictHandshakeRuntimeV1 is the sole test seam for varying immutable
// support and entropy. Owner registries remain mandatory and role-typed.
func newStrictHandshakeRuntimeV1(client, relay auth.Dependencies, clientRegistry ClientProfileAuthorizationRegistryV1, relayRegistry RelayProfileAuthorizationRegistryV1, clientSupport, relaySupport ImplementationSupportV1, entropy io.Reader) (*HandshakeRuntime, error) {
	if client.Identity == nil || client.Trust == nil || relay.Identity == nil || relay.Trust == nil || entropy == nil {
		return nil, fmt.Errorf("%w: handshake runtime dependencies", ErrSecureChannel)
	}
	if !clientRegistry.valid() || !relayRegistry.valid() {
		return nil, fmt.Errorf("%w: %w", ErrSecureChannel, ErrProfileAuthorizationInvalid)
	}
	if err := validateImplementationSupportV1(clientSupport, implementationRoleClientV1); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	if err := validateImplementationSupportV1(relaySupport, implementationRoleRelayV1); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	replay, err := auth.NewHandshakeReplayCache(handshakeReplayCapacity)
	if err != nil {
		return nil, fmt.Errorf("%w: handshake replay state", ErrSecureChannel)
	}
	// Entropy is deliberately retained unread. The strict FirstContact path
	// snapshots and authorizes all public/profile state before establishing the
	// runtime epoch or entering auth's own handshake-entropy boundary.
	runtime := &HandshakeRuntime{
		replay: replay, clientDependencies: client, serverDependencies: relay,
		strict: true, strictEntropy: entropy,
		clientSupport: clientSupport.clone(), relaySupport: relaySupport.clone(),
		clientRegistry: clientRegistry.clone(), relayRegistry: relayRegistry.clone(),
		pendingPairMaterials: make(map[*pairMaterialStateV1]struct{}),
		pairDeriveScheduleV1: security.DeriveKeyScheduleV1,
		pairConstructV1:      constructAuthenticatedPairV1,
	}
	bindHandshakeRuntimeIdentityV1(runtime)
	return runtime, nil
}

func newHandshakeRuntime(client, server auth.Dependencies, entropy io.Reader) (*HandshakeRuntime, error) {
	if client.Identity == nil || client.Trust == nil || server.Identity == nil || server.Trust == nil || entropy == nil {
		return nil, fmt.Errorf("%w: handshake runtime dependencies", ErrSecureChannel)
	}
	var epoch [32]byte
	if _, err := io.ReadFull(entropy, epoch[:]); err != nil || zeroRuntimeEpoch(epoch) {
		return nil, fmt.Errorf("%w: runtime entropy", ErrSecureChannel)
	}
	replay, err := auth.NewHandshakeReplayCache(handshakeReplayCapacity)
	if err != nil {
		return nil, fmt.Errorf("%w: handshake replay state", ErrSecureChannel)
	}
	// The epoch namespaces this cache by runtime ownership only. It is never a
	// wire, signature, transcript, confirmation, or KDF input.
	runtime := &HandshakeRuntime{replay: replay, epoch: epoch, clientDependencies: client, serverDependencies: server}
	bindHandshakeRuntimeIdentityV1(runtime)
	return runtime, nil
}

func bindHandshakeRuntimeIdentityV1(runtime *HandshakeRuntime) {
	if runtime == nil {
		return
	}
	runtime.self = runtime
	runtime.instanceTag = &runtimeInstanceTagV1{marker: 1, owner: runtime, replay: runtime.replay}
}

func validHandshakeRuntimeIdentityV1(runtime *HandshakeRuntime) bool {
	return runtime != nil && runtime.self == runtime && runtime.instanceTag != nil && runtime.instanceTag.marker != 0 &&
		runtime.instanceTag.owner == runtime && runtime.replay != nil && runtime.instanceTag.replay == runtime.replay
}

func (r *HandshakeRuntime) FirstContact(input auth.FirstContactInput) (auth.FirstContactResult, error) {
	if r == nil || r.replay == nil {
		return closedHandshakeResult(), fmt.Errorf("%w: missing handshake runtime", ErrSecureChannel)
	}
	if r.strict {
		return r.strictFirstContactV1(input)
	}
	input.Replay = r.replay
	input.ClientDependencies = r.clientDependencies
	input.ServerDependencies = r.serverDependencies
	result, err := auth.FirstContact(input)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	return result, nil
}

func (r *HandshakeRuntime) strictFirstContactV1(input auth.FirstContactInput) (auth.FirstContactResult, error) {
	result, _, err := r.strictFirstContactWithContextV1(input)
	if err != nil {
		return result, err
	}
	// Preserve the frozen WO-031 public-route recurrence: the ordinary strict
	// FirstContact path independently obtains the success-sealed clone and repeats
	// owner authorization after authentication.
	contextSnapshot, ok := result.AuthenticatedContextSnapshotV1()
	if !ok {
		return closeRuntimeHandshakeResult(result), fmt.Errorf("%w: %w", ErrSecureChannel, ErrProfileMismatch)
	}
	if err := r.verifySupportAndAuthorizationContextV1(contextSnapshot); err != nil {
		return closeRuntimeHandshakeResult(result), fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	return result, nil
}

func (r *HandshakeRuntime) strictFirstContactWithContextV1(input auth.FirstContactInput) (auth.FirstContactResult, auth.AuthenticatedContextSnapshotV1, error) {
	input.Replay = r.replay
	input.ClientDependencies = r.clientDependencies
	input.ServerDependencies = r.serverDependencies
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		return closedHandshakeResult(), auth.AuthenticatedContextSnapshotV1{}, fmt.Errorf("%w: %w", ErrSecureChannel, strictPreflightSentinelV1(err, input))
	}
	if err := r.verifySupportAndAuthorizationPreflightV1(snapshot, view); err != nil {
		return closedHandshakeResult(), auth.AuthenticatedContextSnapshotV1{}, fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	if err := r.ensureStrictEpochV1(); err != nil {
		return closedHandshakeResult(), auth.AuthenticatedContextSnapshotV1{}, err
	}
	// Snapshot strips executable authority by contract. Reattach only the
	// runtime-owned dependencies and replay scope after preflight succeeds.
	snapshot.Replay = r.replay
	snapshot.ClientDependencies = r.clientDependencies
	snapshot.ServerDependencies = r.serverDependencies
	result, err := auth.FirstContact(snapshot)
	if err != nil {
		return result, auth.AuthenticatedContextSnapshotV1{}, fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	contextSnapshot, ok := result.AuthenticatedContextSnapshotV1()
	if !ok {
		return closeRuntimeHandshakeResult(result), auth.AuthenticatedContextSnapshotV1{}, fmt.Errorf("%w: %w", ErrSecureChannel, ErrProfileMismatch)
	}
	if err := r.verifySupportAndAuthorizationContextV1(contextSnapshot); err != nil {
		return closeRuntimeHandshakeResult(result), auth.AuthenticatedContextSnapshotV1{}, fmt.Errorf("%w: %w", ErrSecureChannel, err)
	}
	return result, contextSnapshot, nil
}

func strictPreflightSentinelV1(err error, input auth.FirstContactInput) error {
	var typed *auth.HandshakeError
	if !errors.As(err, &typed) {
		return err
	}
	switch typed.Code {
	case auth.FailureProfileMismatch:
		return ErrProfileMismatch
	case auth.FailurePolicyMismatch:
		return classifyStrictPolicyMismatchV1(input)
	case auth.FailurePolicyFloorRejected:
		if !strictPoliciesValidV1(input) {
			return ErrPolicyInvalid
		}
		// A sealed peer can carry a valid but different offer/floor PolicyV1.
		// Classify that five-copy downgrade before inspecting capability sets;
		// otherwise auth's earlier floor check could mislabel it as a capability
		// selection failure.
		if verifyFiveCopyPolicyV1([]ir.EffectiveSecurityPolicy{
			input.Client.OfferPolicy, input.Client.FloorPolicy,
			input.Server.OfferPolicy, input.Server.FloorPolicy,
			input.SelectedPolicy,
		}) != nil {
			return ErrDowngradeRejected
		}
		// Snapshot has already validated both original peer seals before this
		// classification. The strict-suite literal owns unequal bilateral floors;
		// malformed or mismatched capability selection remains capability-owned.
		floor := unionStringsV1(input.Client.RequiredCapabilities, input.Server.RequiredCapabilities)
		if !containsAllV1(input.Client.OfferedCapabilities, floor) ||
			!containsAllV1(input.Server.OfferedCapabilities, floor) {
			return ErrDowngradeRejected
		}
		if input.SelectedPolicy.DowngradePolicy == "strict_suite_and_capabilities" &&
			!equalStringsV1(input.Client.RequiredCapabilities, input.Server.RequiredCapabilities) {
			return ErrDowngradeRejected
		}
		return ErrCapabilityRejected
	default:
		return err
	}
}

func classifyStrictPolicyMismatchV1(input auth.FirstContactInput) error {
	if !strictPoliciesValidV1(input) {
		return ErrPolicyInvalid
	}
	mode := input.SelectedPolicy.TranscriptMode
	if input.Client.OfferPolicy.TranscriptMode != mode || input.Client.FloorPolicy.TranscriptMode != mode ||
		input.Server.OfferPolicy.TranscriptMode != mode || input.Server.FloorPolicy.TranscriptMode != mode {
		return ErrTranscriptMismatch
	}
	if verifyFiveCopyPolicyV1([]ir.EffectiveSecurityPolicy{
		input.Client.OfferPolicy, input.Client.FloorPolicy,
		input.Server.OfferPolicy, input.Server.FloorPolicy,
		input.SelectedPolicy,
	}) != nil {
		return ErrDowngradeRejected
	}
	return ErrDowngradeRejected
}

func strictPoliciesValidV1(input auth.FirstContactInput) bool {
	for _, policy := range []ir.EffectiveSecurityPolicy{
		input.Client.OfferPolicy, input.Client.FloorPolicy,
		input.Server.OfferPolicy, input.Server.FloorPolicy,
		input.SelectedPolicy,
	} {
		if ir.ValidateEffectiveSecurityPolicy(policy) != nil {
			return false
		}
	}
	return true
}

func (r *HandshakeRuntime) ensureStrictEpochV1() error {
	r.epochMu.Lock()
	defer r.epochMu.Unlock()
	if r.strictEntropyFailed {
		return fmt.Errorf("%w: runtime entropy", ErrSecureChannel)
	}
	if !zeroRuntimeEpoch(r.epoch) {
		return nil
	}
	var epoch [32]byte
	if _, err := io.ReadFull(r.strictEntropy, epoch[:]); err != nil || zeroRuntimeEpoch(epoch) {
		r.strictEntropyFailed = true
		r.strictEntropy = nil
		return fmt.Errorf("%w: runtime entropy", ErrSecureChannel)
	}
	r.epoch = epoch
	return nil
}

func closeRuntimeHandshakeResult(result auth.FirstContactResult) auth.FirstContactResult {
	for i := range result.ChannelSecret {
		result.ChannelSecret[i] = 0
	}
	return closedHandshakeResult()
}

func closedHandshakeResult() auth.FirstContactResult {
	return auth.FirstContactResult{ClientState: auth.StateClosed, ServerState: auth.StateClosed}
}

func zeroRuntimeEpoch(epoch [32]byte) bool {
	var combined byte
	for _, value := range epoch {
		combined |= value
	}
	return combined == 0
}

func (r *HandshakeRuntime) currentProfileGenerationV1() (uint64, bool) {
	if r == nil {
		return 0, true
	}
	r.profileMu.Lock()
	defer r.profileMu.Unlock()
	return r.profileGeneration, r.profileOverflow
}

func (r *HandshakeRuntime) restartAuthenticatedChannelPairV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, input PairInputV1) (*HandshakeRuntime, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	attempt := restartAttemptV1{entropy: rand.Reader}
	fresh, freshClient, freshRelay, _, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(r, client, relay, input)
	if err != nil {
		return nil, nil, nil, err
	}
	return fresh, freshClient, freshRelay, nil
}

type restartSourceSnapshotV1 struct {
	source             *HandshakeRuntime
	tag                *runtimeInstanceTagV1
	replay             *auth.HandshakeReplayCache
	retiredEpoch       [32]byte
	retiredProfile     pairProfileBindingV1
	coordinator        *pairTerminalCoordinatorV1
	client             *ClientAuthenticatedEndpointV1
	relay              *RelayAuthenticatedEndpointV1
	clientRoleTag      *pairRoleTagV1
	relayRoleTag       *pairRoleTagV1
	clientDependencies auth.Dependencies
	relayDependencies  auth.Dependencies
	clientSupport      ImplementationSupportV1
	relaySupport       ImplementationSupportV1
	clientRegistry     ClientProfileAuthorizationRegistryV1
	relayRegistry      RelayProfileAuthorizationRegistryV1
}

type restartRuntimeIdentityV1 struct {
	tag    *runtimeInstanceTagV1
	replay *auth.HandshakeReplayCache
}

// restartAttemptV1 exists only as a call-scoped owner for deterministic test
// entropy. It is never stored on HandshakeRuntime or installed globally.
type restartAttemptV1 struct {
	entropy io.Reader
}

// restartFailedAttemptWitnessV1 is output-only test evidence. Production restart
// discards it, and successful restart never returns one.
type restartFailedAttemptWitnessV1 struct {
	runtime             *HandshakeRuntime
	client              *ClientAuthenticatedEndpointV1
	relay               *RelayAuthenticatedEndpointV1
	retiredProfile      pairProfileBindingV1
	contextProfile      pairProfileBindingV1
	contextProfileValid bool
	clientConfig        StrictSessionConfigV1
	relayConfig         StrictSessionConfigV1
}

func (attempt restartAttemptV1) restartAuthenticatedChannelPairWithEntropyV1(r *HandshakeRuntime, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, input PairInputV1) (fresh *HandshakeRuntime, freshClient *ClientAuthenticatedEndpointV1, freshRelay *RelayAuthenticatedEndpointV1, witness restartFailedAttemptWitnessV1, err error) {
	snapshot, err := r.claimAuthenticatedPairRestartV1(client, relay)
	if err != nil {
		return nil, nil, nil, restartFailedAttemptWitnessV1{}, err
	}
	// Once the old pair is claimed terminally, no pending source transfer may
	// survive into either a retry or the fresh runtime.
	r.drainPendingPairMaterialsV1()

	candidateOwned := false
	committed := false
	defer func() {
		if candidateOwned {
			var retiredProfile, contextProfile pairProfileBindingV1
			var clientConfig, relayConfig StrictSessionConfigV1
			var contextProfileValid bool
			if freshClient != nil && freshRelay != nil && freshClient.state != nil && freshRelay.state != nil &&
				freshClient.state.coordinator != nil && freshClient.state.coordinator == freshRelay.state.coordinator {
				candidateCoordinator := freshClient.state.coordinator
				candidateCoordinator.mu.Lock()
				retiredProfile = candidateCoordinator.retiredProfile
				clientConfig, relayConfig = freshClient.state.config, freshRelay.state.config
				contextProfile, contextProfileValid = authenticatedPairProfileBindingV1(candidateCoordinator.context, freshClient.state.config, freshRelay.state.config)
				candidateCoordinator.mu.Unlock()
			}
			closeEndpointPairV1(freshClient, freshRelay)
			if freshClient != nil && freshRelay != nil && freshClient.state != nil && freshRelay.state != nil &&
				freshClient.state.coordinator != nil && freshClient.state.coordinator == freshRelay.state.coordinator {
				candidateCoordinator := freshClient.state.coordinator
				candidateCoordinator.mu.Lock()
				candidateCoordinator.retiredProfile = pairProfileBindingV1{}
				candidateCoordinator.owner = nil
				candidateCoordinator.ownerTag = nil
				candidateCoordinator.runtimeEpoch = [32]byte{}
				candidateCoordinator.clientTag = nil
				candidateCoordinator.relayTag = nil
				freshClient.state.restartTag = nil
				freshRelay.state.restartTag = nil
				candidateCoordinator.mu.Unlock()
			}
			fresh.drainPendingPairMaterialsV1()
			witness = restartFailedAttemptWitnessV1{
				runtime: fresh, client: freshClient, relay: freshRelay,
				retiredProfile: retiredProfile, contextProfile: contextProfile, contextProfileValid: contextProfileValid,
				clientConfig: clientConfig, relayConfig: relayConfig,
			}
		}
		if committed {
			return
		}
		snapshot.coordinator.mu.Lock()
		snapshot.coordinator.restartInProgress = false
		snapshot.coordinator.mu.Unlock()
		fresh = nil
		freshClient = nil
		freshRelay = nil
	}()

	fresh, err = attempt.newRestartHandshakeRuntimeV1(snapshot)
	if err != nil {
		return
	}
	candidateOwned = true
	identity, ok := pristineRestartRuntimeV1(snapshot, fresh)
	if !ok {
		err = ErrProfileIncompatible
		return
	}
	freshClient, freshRelay, err = fresh.NewAuthenticatedChannelPair(input)
	if err != nil {
		return
	}
	if !validRestartSourceSnapshotV1(snapshot) {
		err = ErrProfileIncompatible
		return
	}
	if !validRestartedPairV1(fresh, freshClient, freshRelay, identity, snapshot.retiredEpoch, snapshot.retiredProfile) {
		err = ErrProfileIncompatible
		return
	}
	if !commitAuthenticatedPairRestartV1(snapshot) {
		err = ErrProfileIncompatible
		return
	}
	committed = true
	candidateOwned = false
	witness = restartFailedAttemptWitnessV1{}
	return
}

func pristineRestartRuntimeV1(snapshot restartSourceSnapshotV1, fresh *HandshakeRuntime) (restartRuntimeIdentityV1, bool) {
	if snapshot.source == nil || snapshot.tag == nil || snapshot.replay == nil ||
		!validHandshakeRuntimeIdentityV1(fresh) || fresh == snapshot.source || !fresh.strict ||
		fresh.instanceTag == snapshot.tag || fresh.replay == nil || fresh.replay == snapshot.replay ||
		fresh.clientDependencies.Identity == nil || fresh.clientDependencies.Trust == nil ||
		fresh.serverDependencies.Identity == nil || fresh.serverDependencies.Trust == nil ||
		!fresh.clientRegistry.valid() || !fresh.relayRegistry.valid() ||
		validateImplementationSupportV1(fresh.clientSupport, implementationRoleClientV1) != nil ||
		validateImplementationSupportV1(fresh.relaySupport, implementationRoleRelayV1) != nil {
		return restartRuntimeIdentityV1{}, false
	}

	fresh.epochMu.Lock()
	epochPristine := zeroRuntimeEpoch(fresh.epoch) && fresh.strictEntropy != nil && !fresh.strictEntropyFailed
	fresh.epochMu.Unlock()
	if !epochPristine {
		return restartRuntimeIdentityV1{}, false
	}

	fresh.pairMu.Lock()
	pairPristine := fresh.pendingPairMaterials != nil && len(fresh.pendingPairMaterials) == 0
	fresh.pairMu.Unlock()
	if !pairPristine || fresh.pairDeriveScheduleV1 == nil || fresh.pairConstructV1 == nil {
		return restartRuntimeIdentityV1{}, false
	}

	fresh.profileMu.Lock()
	profilePristine := fresh.profileGeneration == 0 && !fresh.profileSeen && fresh.profileID == "" &&
		zeroRuntimeEpoch(fresh.profileHash) && !fresh.profileOverflow
	fresh.profileMu.Unlock()
	if !profilePristine {
		return restartRuntimeIdentityV1{}, false
	}
	return restartRuntimeIdentityV1{tag: fresh.instanceTag, replay: fresh.replay}, true
}

func validRestartedPairV1(fresh *HandshakeRuntime, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, identity restartRuntimeIdentityV1, retiredEpoch [32]byte, retiredProfile pairProfileBindingV1) bool {
	if !validHandshakeRuntimeIdentityV1(fresh) || !fresh.strict || identity.tag == nil || identity.replay == nil ||
		fresh.instanceTag != identity.tag || fresh.replay != identity.replay || !validPairProfileBindingV1(retiredProfile) {
		return false
	}
	fresh.pairMu.Lock()
	pairConsumed := fresh.pendingPairMaterials != nil && len(fresh.pendingPairMaterials) == 0
	fresh.pairMu.Unlock()
	if !pairConsumed {
		return false
	}
	fresh.epochMu.Lock()
	epoch := fresh.epoch
	fresh.epochMu.Unlock()
	if zeroRuntimeEpoch(epoch) || epoch == retiredEpoch || !strictPairOwnedByRuntimeV1(fresh, client, relay) {
		return false
	}
	coordinator := client.state.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	profile, ok := authenticatedPairProfileBindingV1(coordinator.context, client.state.config, relay.state.config)
	return ok && profile == retiredProfile && coordinator.retiredProfile == retiredProfile &&
		pairRolesMatchProfileBindingLockedV1(client, relay, retiredProfile)
}

func (attempt restartAttemptV1) newRestartHandshakeRuntimeV1(snapshot restartSourceSnapshotV1) (*HandshakeRuntime, error) {
	if snapshot.source == nil || snapshot.tag == nil || snapshot.replay == nil ||
		!validHandshakeRuntimeIdentityV1(snapshot.source) || !snapshot.source.strict ||
		snapshot.clientDependencies.Identity == nil || snapshot.clientDependencies.Trust == nil ||
		snapshot.relayDependencies.Identity == nil || snapshot.relayDependencies.Trust == nil ||
		!snapshot.clientRegistry.valid() || !snapshot.relayRegistry.valid() ||
		validateImplementationSupportV1(snapshot.clientSupport, implementationRoleClientV1) != nil ||
		validateImplementationSupportV1(snapshot.relaySupport, implementationRoleRelayV1) != nil || attempt.entropy == nil {
		return nil, ErrProfileIncompatible
	}
	return newStrictHandshakeRuntimeV1(
		snapshot.clientDependencies,
		snapshot.relayDependencies,
		snapshot.clientRegistry,
		snapshot.relayRegistry,
		snapshot.clientSupport,
		snapshot.relaySupport,
		attempt.entropy,
	)
}

func (r *HandshakeRuntime) claimAuthenticatedPairRestartV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) (restartSourceSnapshotV1, error) {
	if !validHandshakeRuntimeIdentityV1(r) || client == nil || relay == nil || client.state == nil || relay.state == nil ||
		client.state.coordinator == nil || client.state.coordinator != relay.state.coordinator {
		closeEndpointPairV1(client, relay)
		return restartSourceSnapshotV1{}, ErrProfileIncompatible
	}
	coordinator := client.state.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	wasTerminal := coordinator.closed
	r.epochMu.Lock()
	retiredEpoch := r.epoch
	r.epochMu.Unlock()
	snapshot := restartSourceSnapshotV1{
		source: r, tag: r.instanceTag, replay: r.replay, retiredEpoch: retiredEpoch,
		retiredProfile: coordinator.retiredProfile, coordinator: coordinator, client: client, relay: relay,
		clientRoleTag: coordinator.clientTag, relayRoleTag: coordinator.relayTag,
		clientDependencies: r.clientDependencies, relayDependencies: r.serverDependencies,
		clientSupport: r.clientSupport.clone(), relaySupport: r.relaySupport.clone(),
		clientRegistry: r.clientRegistry.clone(), relayRegistry: r.relayRegistry.clone(),
	}
	if !validHandshakeRuntimeIdentityV1(r) || r.instanceTag != snapshot.tag || r.replay != snapshot.replay ||
		coordinator.owner == nil || coordinator.owner != snapshot.source || coordinator.ownerTag == nil || coordinator.ownerTag != snapshot.tag ||
		coordinator.runtimeEpoch != snapshot.retiredEpoch || zeroRuntimeEpoch(coordinator.runtimeEpoch) ||
		coordinator.retiredProfile != snapshot.retiredProfile || !validPairProfileBindingV1(snapshot.retiredProfile) ||
		coordinator.clientTag == nil || coordinator.relayTag == nil || coordinator.clientTag == coordinator.relayTag ||
		client.state.restartTag != coordinator.clientTag || relay.state.restartTag != coordinator.relayTag ||
		coordinator.restartInProgress || coordinator.restartSucceeded {
		coordinator.closeLockedV1()
		return restartSourceSnapshotV1{}, ErrProfileIncompatible
	}
	if wasTerminal {
		if coordinator.destroy != nil ||
			client.state.config != (StrictSessionConfigV1{}) || relay.state.config != (StrictSessionConfigV1{}) ||
			client.state.controls != (ClientLocalRuntimeControlsV1{}) || relay.state.controls != (RelayLocalRuntimeControlsV1{}) ||
			client.state.life == nil || relay.state.life == nil || client.state.life.config != (StrictSessionConfigV1{}) ||
			relay.state.life.config != (StrictSessionConfigV1{}) {
			return restartSourceSnapshotV1{}, ErrProfileIncompatible
		}
	} else if profile, ok := authenticatedPairProfileBindingV1(coordinator.context, client.state.config, relay.state.config); !ok || profile != snapshot.retiredProfile || !pairRolesMatchProfileBindingLockedV1(client, relay, snapshot.retiredProfile) {
		coordinator.closeLockedV1()
		return restartSourceSnapshotV1{}, ErrProfileIncompatible
	}
	coordinator.restartInProgress = true
	coordinator.closeLockedV1()
	return snapshot, nil
}

func validRestartSourceSnapshotV1(snapshot restartSourceSnapshotV1) bool {
	if snapshot.source == nil || snapshot.coordinator == nil || snapshot.tag == nil || snapshot.replay == nil ||
		!validPairProfileBindingV1(snapshot.retiredProfile) || !validHandshakeRuntimeIdentityV1(snapshot.source) ||
		snapshot.source.instanceTag != snapshot.tag || snapshot.source.replay != snapshot.replay {
		return false
	}
	snapshot.source.epochMu.Lock()
	epochMatches := snapshot.source.epoch == snapshot.retiredEpoch
	snapshot.source.epochMu.Unlock()
	return epochMatches && !zeroRuntimeEpoch(snapshot.retiredEpoch)
}

func commitAuthenticatedPairRestartV1(snapshot restartSourceSnapshotV1) bool {
	if !validRestartSourceSnapshotV1(snapshot) {
		return false
	}
	coordinator := snapshot.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	snapshot.source.epochMu.Lock()
	defer snapshot.source.epochMu.Unlock()
	if !validHandshakeRuntimeIdentityV1(snapshot.source) || snapshot.source.instanceTag != snapshot.tag ||
		snapshot.source.replay != snapshot.replay || snapshot.source.epoch != snapshot.retiredEpoch ||
		!coordinator.closed || coordinator.destroy != nil || !coordinator.restartInProgress || coordinator.restartSucceeded ||
		coordinator.owner != snapshot.source || coordinator.ownerTag != snapshot.tag || coordinator.runtimeEpoch != snapshot.retiredEpoch ||
		coordinator.retiredProfile != snapshot.retiredProfile || coordinator.clientTag != snapshot.clientRoleTag ||
		coordinator.relayTag != snapshot.relayRoleTag || snapshot.clientRoleTag == nil || snapshot.relayRoleTag == nil ||
		snapshot.clientRoleTag == snapshot.relayRoleTag {
		return false
	}
	coordinator.restartInProgress = false
	coordinator.restartSucceeded = true
	coordinator.owner = nil
	coordinator.ownerTag = nil
	coordinator.retiredProfile = pairProfileBindingV1{}
	coordinator.runtimeEpoch = [32]byte{}
	coordinator.clientTag = nil
	coordinator.relayTag = nil
	snapshot.client.state.config = StrictSessionConfigV1{}
	snapshot.client.state.controls = ClientLocalRuntimeControlsV1{}
	snapshot.client.state.restartTag = nil
	snapshot.client.state.life.config = StrictSessionConfigV1{}
	snapshot.relay.state.config = StrictSessionConfigV1{}
	snapshot.relay.state.controls = RelayLocalRuntimeControlsV1{}
	snapshot.relay.state.restartTag = nil
	snapshot.relay.state.life.config = StrictSessionConfigV1{}
	return true
}
