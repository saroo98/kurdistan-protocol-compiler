// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"math"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

type MaintenanceCurrentInputV1 struct {
	VerifyRequest, ActivationRecord, RecipientRequest, RecipientPrivate []byte
}

type MaintenanceConfigV1 struct {
	Limits           selfhost.LiveMaintenanceLimits
	OwnedBudgetBytes uint64
	Now              func() time.Time
	Transport        MaintenanceTransportEnvironmentV1
	UpdateRates      *MaintenanceUpdateRateRegistryV1
	ProbeRates       *runtime.ProbeRateRegistryV1
	ActiveProbes     MaintenanceActiveProbeOwnerV1
	// Supplied external metadata excludes unsafe.Sizeof native owner/op values.
	OutputMetadataBytes uint64
}

type RecipientVerificationEnvironmentAt interface {
	VerifyWithRecipientAt(artifact []byte, class envelope.ArtifactClass,
		credentials RecipientCredentials, now time.Time,
		limits selfhost.LiveMaintenanceLimits,
	) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, error)
}

type MaintenancePlatformOwnerV1 interface {
	Register(parentEpoch uint64, invalidate func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode)
}

type MaintenanceRevisionRegistrationV1 interface {
	Revalidate(context.Context) MaintenanceResultV1
	AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1)
	Close() ErrorCode
}

type MaintenancePublicationLeaseV1 interface {
	IsCurrent() bool
	Close() ErrorCode
}

type maintenanceScopeSlotV1 struct {
	key   [32]byte
	owner *maintenanceAuthorityV1
}

type maintenanceOperationV1 struct {
	output          MaintenanceOutputInvocationV1
	outputPrepared  bool
	epoch           uint64
	ctx             context.Context
	outputContext   context.Context
	probePump       *runtime.ServicePumpV1
	cancel          context.CancelFunc
	done            chan struct{}
	finishOnce      sync.Once
	cancelled       bool
	inPlatform      bool
	deadline        time.Time
	completionGuard func() MaintenanceResultV1
}

type maintenanceAuthorityV1 struct {
	mu           sync.Mutex
	retirementMu sync.Mutex

	registry                     *HandleRegistry
	handle                       Handle
	outputHandle                 Handle
	output                       MaintenanceOutputObserverV1
	outputOwner                  uint64
	outputSlotProductionEpoch    uint64
	parentEpoch                  uint64
	scope                        [32]byte
	now                          func() time.Time
	limits                       selfhost.LiveMaintenanceLimits
	budget                       uint64
	transport                    MaintenanceTransportEnvironmentV1
	network                      MaintenanceNetworkLeaseV1
	networkMode                  runtime.ProbeModeV1
	networkFamilies              uint8
	networkServers               [4]netip.AddrPort
	networkServerCount           int
	transportStop, transportDone chan struct{}
	transportClose               sync.Once
	roots                        *x509.CertPool
	rootBlob                     []byte
	updateRates                  *MaintenanceUpdateRateRegistryV1
	probeRates                   *runtime.ProbeRateRegistryV1
	activeProbes                 MaintenanceActiveProbeOwnerV1
	probeScope                   runtime.AuthenticatedProbeScopeV1

	owner        *selfhost.LiveMaintenanceAdmission
	registration MaintenanceRevisionRegistrationV1
	candidate    *selfhost.LiveMaintenanceCandidate
	candidateID  MaintenanceCandidateID
	nextChildID  MaintenanceCandidateID
	candidateEnd time.Time

	operationEpoch uint64
	operation      *maintenanceOperationV1
	revocationBusy bool
	retirementBusy bool
	retirementDone chan struct{}
	terminal       MaintenanceResultV1
	terminalSet    bool
	lastNow        time.Time
	parentEnd      time.Time
	parentTimerAt  time.Time

	timerWake chan struct{}
	timerStop chan struct{}
	timerDone chan struct{}
	timerSeq  uint64
	timerAt   time.Time
	timerKind uint8

	stopOnce           sync.Once
	resourcesOnce      sync.Once
	closeOnce          sync.Once
	cleanupCode        ErrorCode
	pendingCandidate   *selfhost.LiveMaintenanceCandidate
	pendingCandidateID MaintenanceCandidateID
	cleanupPending     bool
	monotonicNow       func() time.Time
	destroyCandidate   func(*selfhost.LiveMaintenanceCandidate)
	destroyOwner       func(*selfhost.LiveMaintenanceAdmission)
}

const (
	maintenanceTimerNone                 = uint8(0)
	maintenanceTimerCandidate            = uint8(1)
	maintenanceTimerParent               = uint8(2)
	maxMaintenanceOwnerBudget            = uint64(128 << 20)
	maintenanceActivationListFields      = uint64(2)
	maintenanceActivationMaxListElements = uint64(2048)
	maintenanceActivationScalarLeaves    = uint64(32)
	maintenanceControlChannelCount       = uint64(5)
	maintenanceControlBackingPerObject   = uint64(4 << 10)
	maintenanceControlContextCount       = uint64(1)
	maintenanceControlTimerCount         = uint64(1)
	maintenanceControlSupervisorCount    = uint64(1)
	maintenanceCBORMapSlotBytes          = uint64(65)
	maintenanceCBORMapHolderBytes        = uint64(512)
)

type maintenanceBridgeReservationLedgerV1 struct {
	FixedControl       uint64
	VerifyDecode       uint64
	IngressFile        uint64
	IngressURI         uint64
	IngressQR          uint64
	CredentialsRequest uint64
	CredentialsPrivate uint64
	CredentialsCheck   uint64
	CredentialsClone   uint64
	ActivationRecord   uint64
}

type maintenanceCheckedCurrentV1 struct {
	state    lifecycle.VerifiedState
	scope    [32]byte
	artifact []byte
}

func OpenMaintenanceV1(registry *HandleRegistry, current MaintenanceCurrentInputV1,
	environment RecipientVerificationEnvironmentAt, platform MaintenancePlatformOwnerV1,
	config MaintenanceConfigV1,
) (Handle, MaintenanceResultV1) {
	return OpenMaintenanceV1Scoped(registry, current, environment, platform, config, MaintenanceOutputInvocationV1{})
}

func OpenMaintenanceV1Scoped(registry *HandleRegistry, current MaintenanceCurrentInputV1,
	environment RecipientVerificationEnvironmentAt, platform MaintenancePlatformOwnerV1,
	config MaintenanceConfigV1, inv MaintenanceOutputInvocationV1,
) (Handle, MaintenanceResultV1) {
	if registry == nil || environment == nil || platform == nil || config.Now == nil ||
		config.OwnedBudgetBytes == 0 || config.OwnedBudgetBytes > maxMaintenanceOwnerBudget {
		return 0, MaintenanceInvalidRequest
	}
	if result := maintenanceOutputOpeningV1(registry, inv, config.OutputMetadataBytes, config.OwnedBudgetBytes); result != MaintenanceSuccess {
		return 0, result
	}
	bridgeBytes, result := maintenanceBridgeReservation(current)
	if result != MaintenanceSuccess {
		return 0, result
	}
	var outputControlBytes uint64
	if !inv.legacyV1() {
		// A completed scoped probe may retain its expired work context while
		// publishing with one original-cancellation-derived context and timer.
		outputControlBytes = 2 * maintenanceControlBackingPerObject
	}
	bridgeBytes, ok := maintenanceAddV1(bridgeBytes, config.OutputMetadataBytes, uint64(unsafe.Sizeof(inv)), outputControlBytes)
	if !ok {
		return 0, MaintenanceResourceLimit
	}
	if config.Transport != nil {
		transportBytes, ok := maintenanceTransportReservationV1(config.Limits.MaxArtifactBytes)
		if !ok {
			return 0, MaintenanceInvalidRequest
		}
		bridgeBytes, ok = maintenanceAddV1(bridgeBytes, transportBytes)
		if !ok {
			return 0, MaintenanceResourceLimit
		}
	}
	if bridgeBytes >= config.OwnedBudgetBytes {
		return 0, MaintenanceResourceLimit
	}
	limits := config.Limits
	limits.OwnedBudgetBytes = config.OwnedBudgetBytes - bridgeBytes
	now := config.Now()
	verified, bounds, checked, credentials, result := verifyMaintenanceCurrentV1(current, environment, now, limits)
	if result != MaintenanceSuccess {
		return 0, result
	}
	defer credentials.Destroy()
	if bounds.BudgetBytes != limits.OwnedBudgetBytes || bounds.RetainedBytes > bounds.PeakReservedBytes || bounds.PeakReservedBytes > limits.OwnedBudgetBytes {
		destroyMaintenanceVerifiedV1(&verified)
		return 0, MaintenanceInternalFailure
	}
	var probeScope runtime.AuthenticatedProbeScopeV1
	if config.Transport != nil {
		var scopeErr error
		probeScope, scopeErr = runtime.NewAuthenticatedProbeScopeV1(verified.Profile)
		if scopeErr != nil {
			destroyMaintenanceVerifiedV1(&verified)
			return 0, MaintenanceInternalFailure
		}
	}
	destroyMaintenanceVerifiedV1(&verified)
	defer clear(checked.artifact)

	parent := &maintenanceAuthorityV1{
		registry: registry, scope: checked.scope, now: config.Now, limits: limits,
		budget: config.OwnedBudgetBytes, parentEpoch: 0,
		updateRates: config.UpdateRates, probeRates: config.ProbeRates, activeProbes: config.ActiveProbes, probeScope: probeScope,
		timerWake: make(chan struct{}, 1), timerStop: make(chan struct{}), timerDone: make(chan struct{}),
		lastNow: now, cleanupCode: CodeOK, monotonicNow: time.Now,
		destroyCandidate: func(candidate *selfhost.LiveMaintenanceCandidate) { candidate.Destroy() },
		destroyOwner:     func(owner *selfhost.LiveMaintenanceAdmission) { owner.Destroy() },
	}
	if !registry.reserveMaintenanceScope(parent) {
		return 0, MaintenanceResourceLimit
	}
	parent.mu.Lock()
	if !inv.legacyV1() {
		parent.output, parent.outputOwner = inv.observer, inv.owner
		result = normalizeMaintenancePlatformResult(parent.output.BindParentV1(inv.call, parent.parentEpoch))
		if result == MaintenanceSuccess {
			inv.epoch = parent.parentEpoch
			result = normalizeMaintenancePlatformResult(parent.output.BindLaneV1(inv.call, inv.epoch, false))
		}
	}
	parent.mu.Unlock()
	if result != MaintenanceSuccess {
		close(parent.timerDone) // supervisor was not started
		parent.DestroyResult()
		return 0, result
	}
	defer func() {
		if parent.handle == 0 {
			parent.DestroyResult()
		}
	}()
	go parent.runTimerSupervisor()

	openOperation, result := parent.beginOperationOutputV1(inv, true)
	if result != MaintenanceSuccess {
		return 0, result
	}
	parent.mu.Lock()
	openOperation.inPlatform = true
	parent.mu.Unlock()
	registration, code := platform.Register(parent.parentEpoch, func() ErrorCode {
		return parent.invalidateFromPlatform()
	})
	parent.mu.Lock()
	openOperation.inPlatform = false
	parent.mu.Unlock()
	if code != CodeOK || registration == nil {
		parent.finishOperation(openOperation)
		if code != CodeOK {
			parent.noteCleanup(code)
		}
		return 0, MaintenanceInternalFailure
	}
	parent.mu.Lock()
	parent.registration = registration
	cancelled := parent.terminalSet || openOperation.cancelled
	parent.mu.Unlock()
	if cancelled {
		parent.finishOperation(openOperation)
		return 0, MaintenanceCancelled
	}
	if result = parent.revalidatePlatform(openOperation); result != MaintenanceSuccess {
		parent.finishOperation(openOperation)
		return 0, result
	}
	if result = parent.installTransport(openOperation, config.Transport); result != MaintenanceSuccess {
		parent.finishOperation(openOperation)
		return 0, result
	}
	owner, err := selfhost.NewLiveMaintenanceAdmissionForRecipient(
		checked.artifact, now, checked.state, credentials.Request, credentials.Private, limits,
	)
	if err != nil {
		parent.finishOperation(openOperation)
		return 0, maintenanceResultFromError(err)
	}
	authNow, result := parent.trustedNow(openOperation)
	if result != MaintenanceSuccess {
		owner.Destroy()
		parent.finishOperation(openOperation)
		return 0, result
	}
	if err := owner.RevalidateAt(authNow); err != nil {
		result = maintenanceResultFromError(err)
		owner.Destroy()
		parent.finishOperation(openOperation)
		return 0, result
	}
	parentEnd := owner.AuthorityDeadline()
	if result = parent.checkCompletion(openOperation); result != MaintenanceSuccess {
		owner.Destroy()
		parent.finishOperation(openOperation)
		return 0, result
	}
	lease, result := parent.acquirePublication(openOperation)
	if result != MaintenanceSuccess {
		owner.Destroy()
		parent.finishOperation(openOperation)
		return 0, result
	}
	finalNow, finalMonotonicNow, result := parent.trustedNowAndMonotonic(openOperation)
	if result != MaintenanceSuccess {
		if leaseResult := parent.finishPublicationAndRetireDetached(openOperation, lease, nil, owner); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		parent.finishOperation(openOperation)
		return 0, result
	}
	parentTimerAt, ok := maintenanceMonotonicDeadlineV1(finalNow, parentEnd, finalMonotonicNow)
	if !ok {
		result = MaintenanceExpired
		if leaseResult := parent.finishPublicationAndRetireDetached(openOperation, lease, nil, owner); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		parent.finishOperation(openOperation)
		return 0, result
	}
	if result = parent.checkCompletion(openOperation); result != MaintenanceSuccess {
		if closeResult := parent.finishPublicationAndRetireDetached(openOperation, lease, nil, owner); closeResult != MaintenanceSuccess {
			result = closeResult
		}
		parent.finishOperation(openOperation)
		return 0, result
	}
	parent.mu.Lock()
	if parent.terminalSet || openOperation.cancelled || parent.operation != openOperation || !finalNow.Before(parentEnd) {
		parent.mu.Unlock()
		result = MaintenanceCancelled
		if leaseResult := parent.finishPublicationAndRetireDetached(openOperation, lease, nil, owner); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		parent.finishOperation(openOperation)
		return 0, result
	}
	parent.owner = owner
	parent.parentEnd = parentEnd
	parent.parentTimerAt = parentTimerAt
	parent.armTimerAtLocked(parentTimerAt, maintenanceTimerParent)
	parent.mu.Unlock()

	handle, code := registry.Open(HandleMaintenance, parent)
	if code != CodeOK {
		if closeCode := parent.closePublicationLease(openOperation, lease); closeCode != CodeOK {
			parent.publicationCleanupFailure(openOperation, closeCode)
		}
		parent.finishOperation(openOperation)
		return 0, MaintenanceResourceLimit
	}
	parent.mu.Lock()
	parent.outputHandle = handle
	if parent.output != nil {
		result = normalizeMaintenancePlatformResult(parent.output.BindHandleV1(inv.call, inv.epoch, handle))
	}
	if result != MaintenanceSuccess {
		parent.mu.Unlock()
		if closeCode := parent.closePublicationLease(openOperation, lease); closeCode != CodeOK {
			result = parent.publicationCleanupFailure(openOperation, closeCode)
		}
		parent.finishOperation(openOperation)
		registry.Free(handle)
		return 0, result
	}
	if parent.terminalSet {
		result := parent.terminal
		parent.mu.Unlock()
		if closeCode := parent.closePublicationLease(openOperation, lease); closeCode != CodeOK {
			result = parent.publicationCleanupFailure(openOperation, closeCode)
		}
		parent.finishOperation(openOperation)
		registry.Free(handle)
		return 0, result
	}
	parent.handle = handle
	parent.mu.Unlock()
	if code := parent.closePublicationLease(openOperation, lease); code != CodeOK {
		result = parent.publicationCleanupFailure(openOperation, code)
		parent.finishOperation(openOperation)
		registry.Free(handle)
		return 0, result
	}
	if result = parent.checkCompletion(openOperation); result != MaintenanceSuccess {
		parent.finishOperation(openOperation)
		registry.Free(handle)
		return 0, result
	}
	parent.finishOperation(openOperation)
	parent.mu.Lock()
	if parent.terminalSet {
		result := parent.terminal
		parent.mu.Unlock()
		registry.Free(handle)
		return 0, result
	}
	if parent.output != nil {
		result = normalizeMaintenancePlatformResult(parent.output.PrepareV1(inv.call, inv.epoch, 0, parent.parentTimerAt, false))
		if result != MaintenanceSuccess {
			parent.mu.Unlock()
			registry.Free(handle)
			return 0, result
		}
	}
	parent.mu.Unlock()
	return handle, MaintenanceSuccess
}

func maintenanceBridgeReservation(current MaintenanceCurrentInputV1) (uint64, MaintenanceResultV1) {
	if len(current.VerifyRequest) == 0 || len(current.ActivationRecord) == 0 || len(current.RecipientRequest) == 0 || len(current.RecipientPrivate) == 0 {
		return 0, MaintenanceInvalidRequest
	}
	if len(current.VerifyRequest) > MaxVerifyRequestBytes || len(current.ActivationRecord) > MaxBridgeResultBytes ||
		len(current.RecipientRequest) > enrollment.MaxRequestBytes || len(current.RecipientPrivate) > enrollment.MaxPrivateBundleBytes {
		return 0, MaintenanceSizeLimit
	}
	ledger, ok := maintenanceBridgeReservationLedger()
	if !ok {
		return 0, MaintenanceResourceLimit
	}
	peak := maintenanceMaxV1(
		ledger.VerifyDecode, ledger.IngressFile, ledger.IngressURI, ledger.IngressQR,
		ledger.CredentialsRequest, ledger.CredentialsPrivate, ledger.CredentialsCheck,
		ledger.CredentialsClone, ledger.ActivationRecord,
	)
	reservation, ok := maintenanceAddV1(ledger.FixedControl, peak)
	if !ok {
		return 0, MaintenanceResourceLimit
	}
	return reservation, MaintenanceSuccess
}

// maintenanceBridgeReservationLedger is a source-stage ledger for allocations
// owned by this bridge before the bounded selfhost verifier takes ownership.
// A(n)=2n+8 is the accepted conservative clone-capacity envelope for this
// pinned 64-bit target. Stages are mutually exclusive; retained normalized
// artifact and credentials are explicitly carried into later stage totals.
func maintenanceBridgeReservationLedger() (maintenanceBridgeReservationLedgerV1, bool) {
	clone := func(n uint64) (uint64, bool) {
		if n == 0 {
			return 0, true
		}
		if n > (math.MaxUint64-8)/2 {
			return 0, false
		}
		return 2*n + 8, true
	}
	sum := func(terms ...uint64) (uint64, bool) { return maintenanceAddV1(terms...) }
	mapBacking := func(pairs uint64) (uint64, bool) {
		return sum(maintenanceCBORMapHolderBytes, 2*pairs*maintenanceCBORMapSlotBytes)
	}

	verifyCap, artifactCap := uint64(MaxVerifyRequestBytes), uint64(envelope.MaxTotalInputBytes)
	uriCap, chunkCap := uint64(envelope.MaxIngressEncodedChars), uint64(envelope.MaxIngressChunkChars)
	requestCap, privateCap := uint64(enrollment.MaxRequestBytes), uint64(enrollment.MaxPrivateBundleBytes)
	activationCap := uint64(MaxBridgeResultBytes)
	verifyBacking, ok1 := clone(verifyCap)
	artifactBacking, ok2 := clone(artifactCap)
	uriBacking, ok3 := clone(uriCap)
	chunkBacking, ok4 := clone(chunkCap)
	requestBacking, ok5 := clone(requestCap)
	privateBacking, ok6 := clone(privateCap)
	activationBacking, ok7 := clone(activationCap)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return maintenanceBridgeReservationLedgerV1{}, false
	}

	partDescriptors := uint64(MaxVerifySegments) * uint64(unsafe.Sizeof([]byte{}))
	chunkDescriptors := uint64(MaxVerifySegments) * uint64(unsafe.Sizeof(""))
	decodedChunkDescriptors := uint64(MaxVerifySegments) * uint64(unsafe.Sizeof([]byte{}))
	seenBacking, ok := clone(uint64(MaxVerifySegments))
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	verifyDecode, ok := sum(partDescriptors, verifyBacking, verifyBacking)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	ingressFile, ok := sum(partDescriptors, verifyBacking, artifactBacking)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	// URI keeps the copied request part, its string conversion and decoded
	// bytes while comparing a second full canonical base64 string. The final
	// NormalizeProfileIngress clone can overlap the decoded bytes.
	ingressURI, ok := sum(partDescriptors, verifyBacking, uriBacking, artifactBacking, uriBacking, artifactBacking)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	fragmentedDecoded, ok := sum(2*artifactCap, 8*uint64(MaxVerifySegments))
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	// QR retains request copies, copied chunk strings, every decoded fragment,
	// the assembled buffer and the final normalized clone. One current split
	// result and canonical chunk string are the only per-chunk scratch retained.
	ingressQR, ok := sum(
		partDescriptors, verifyBacking, chunkDescriptors, verifyBacking,
		decodedChunkDescriptors, seenBacking, fragmentedDecoded,
		artifactBacking, artifactBacking, 3*uint64(unsafe.Sizeof("")), chunkBacking,
	)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}

	requestMap, ok := mapBacking(15)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	privateMap, ok := mapBacking(3)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	// Request decode: generic canonical tree/output, RawMessage map plus typed
	// leaves, validation identity-map/signature material, canonical roundtrip,
	// and returned leaf clones. Four leaf envelopes plus two bounded maps cover
	// the largest one of those sequential phases.
	requestDecode, ok := sum(4*requestBacking, 2*requestMap)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	// Private decode begins while the returned request remains live. Three
	// private leaf/output envelopes and one three-pair map cover its canonical
	// roundtrip and returned clone overlap.
	privateDecode, ok := sum(requestBacking, 3*privateBacking, privateMap)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	key32, key64 := uint64(2*32+8), uint64(2*64+8)
	// Pair validation retains both typed values, then owns canonical request
	// and private outputs, cloned map leaves, a P-256 private-key copy and the
	// derived Ed25519 private key.
	credentialsCheck, ok := sum(3*requestBacking, 3*privateBacking, requestMap, privateMap, key32, key64)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	// The bridge keeps its decoded capability while passing one owned clone to
	// the accepted bounded verifier adapter.
	credentialsClone, ok := sum(2*requestBacking, 2*privateBacking)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}

	retainedArtifact := artifactBacking
	credentialsRequest, ok := sum(retainedArtifact, requestDecode)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	credentialsPrivate, ok := sum(retainedArtifact, privateDecode)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	credentialsCheck, ok = sum(retainedArtifact, credentialsCheck)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	credentialsClone, ok = sum(retainedArtifact, credentialsClone)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}

	activationLeaves, ok := sum(2*activationCap, 8*(maintenanceActivationListFields*maintenanceActivationMaxListElements+maintenanceActivationScalarLeaves))
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	activationListDescriptors := 2 * maintenanceActivationListFields * maintenanceActivationMaxListElements * uint64(unsafe.Sizeof(""))
	policyBacking, ok := clone(uint64(envelope.MaxCanonicalPolicyBytes))
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}
	activationFixed := 2 * uint64(unsafe.Sizeof(activationRecordWire{}))
	activationRecord, ok := sum(
		retainedArtifact, requestBacking, privateBacking,
		activationLeaves, activationListDescriptors, policyBacking,
		activationBacking, activationFixed,
	)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}

	// Exact Go value storage is charged directly. The only non-value control
	// allowance is itemized by constructed object: timerWake/timerStop/timerDone,
	// operation.done and retirementDone, plus one cancel context, one timer and
	// one supervisor.
	// Scheduler stacks, allocator bookkeeping and runtime/library globals are
	// outside this per-parent application-owned backing claim.
	controlObjects := maintenanceControlChannelCount + maintenanceControlContextCount + maintenanceControlTimerCount + maintenanceControlSupervisorCount
	fixedControl, ok := sum(
		uint64(unsafe.Sizeof(maintenanceAuthorityV1{})),
		uint64(unsafe.Sizeof(maintenanceOperationV1{})),
		controlObjects*maintenanceControlBackingPerObject,
	)
	if !ok {
		return maintenanceBridgeReservationLedgerV1{}, false
	}

	return maintenanceBridgeReservationLedgerV1{
		FixedControl: fixedControl, VerifyDecode: verifyDecode,
		IngressFile: ingressFile, IngressURI: ingressURI, IngressQR: ingressQR,
		CredentialsRequest: credentialsRequest, CredentialsPrivate: credentialsPrivate,
		CredentialsCheck: credentialsCheck, CredentialsClone: credentialsClone,
		ActivationRecord: activationRecord,
	}, true
}

func maintenanceAddV1(terms ...uint64) (uint64, bool) {
	var total uint64
	for _, term := range terms {
		if term > math.MaxUint64-total {
			return 0, false
		}
		total += term
	}
	return total, true
}

func maintenanceMaxV1(values ...uint64) uint64 {
	var maximum uint64
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}

func maintenanceScopeIdentityV1(verified profile.OfflineVerifiedArtifact) [32]byte {
	h := sha256.New()
	h.Write([]byte("kurd-maintenance-profile-scope-v1\x00"))
	for _, value := range []string{verified.Profile.ProfileID, verified.Profile.ProviderID, verified.Profile.LineageID, verified.Profile.RevocationScope} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], verified.Profile.RootEpoch)
	h.Write(epoch[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (r *HandleRegistry) reserveMaintenanceScope(owner *maintenanceAuthorityV1) bool {
	if r == nil || owner == nil || owner.scope == ([32]byte{}) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.maintenanceScopes {
		if r.maintenanceScopes[i].owner != nil && r.maintenanceScopes[i].key == owner.scope {
			return false
		}
	}
	for i := range r.maintenanceScopes {
		if r.maintenanceScopes[i].owner == nil {
			if r.maintenanceEpoch == math.MaxUint64 {
				return false
			}
			r.maintenanceEpoch++
			owner.parentEpoch = r.maintenanceEpoch
			r.maintenanceScopes[i] = maintenanceScopeSlotV1{key: owner.scope, owner: owner}
			return true
		}
	}
	return false
}

func (r *HandleRegistry) releaseMaintenanceScope(owner *maintenanceAuthorityV1) {
	if r == nil || owner == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.maintenanceScopes {
		if r.maintenanceScopes[i].owner == owner {
			r.maintenanceScopes[i] = maintenanceScopeSlotV1{}
			return
		}
	}
}

func maintenanceParentV1(registry *HandleRegistry, handle Handle) (*maintenanceAuthorityV1, MaintenanceResultV1) {
	if registry == nil {
		return nil, MaintenanceInvalidState
	}
	value, code := registry.Get(handle, HandleMaintenance)
	if code == CodeCancelled {
		return nil, MaintenanceCancelled
	}
	if code != CodeOK {
		return nil, MaintenanceInvalidState
	}
	parent, ok := value.(*maintenanceAuthorityV1)
	if !ok || parent == nil {
		return nil, MaintenanceInternalFailure
	}
	parent.mu.Lock()
	live := parent.handle == handle && parent.parentEpoch != 0
	parent.mu.Unlock()
	if !live {
		return nil, MaintenanceInvalidState
	}
	return parent, MaintenanceSuccess
}
