// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"sync"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/selfhost"
)

func TestMaintenancePlatformSynchronousRegisterInvalidationFencesOperationWithoutDeadlock(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	done := make(chan ErrorCode, 1)
	go func() {
		parent.mu.Lock()
		op.inPlatform = true
		parent.mu.Unlock()
		done <- parent.invalidateFromPlatform()
		parent.mu.Lock()
		op.inPlatform = false
		parent.mu.Unlock()
		parent.finishOperation(op)
	}()
	select {
	case got := <-done:
		if got != CodeStateCorrupt {
			t.Fatalf("callback=%d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("synchronous invalidation deadlocked its callback-owned operation")
	}
	if got := parentStatusForTest(parent); got != MaintenanceCancelled {
		t.Fatalf("terminal=%d", got)
	}
}

func TestMaintenanceCancellationJoinsOrdinaryOperation(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	shutdownDone := make(chan bool, 1)
	go func() {
		selfCall := parent.shutdown(MaintenanceCancelled, false)
		select {
		case <-op.done:
			shutdownDone <- selfCall
		default:
			shutdownDone <- true
		}
	}()
	// Cancellation has actually crossed the native fence. The caller retains
	// completion authority; no worker timing or post-finish signal is a join.
	select {
	case <-op.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel the ordinary operation")
	}
	select {
	case <-op.done:
		t.Fatal("cancellation completed the caller-owned operation")
	default:
	}
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before the operation joined")
	default:
	}
	parent.finishOperation(op)
	select {
	case <-op.done:
	default:
		t.Fatal("finishOperation did not publish native completion")
	}
	select {
	case invalid := <-shutdownDone:
		if invalid {
			t.Fatal("ordinary shutdown bypassed its operation completion")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after native operation completion")
	}
}

func TestMaintenanceCallsPlatformWithoutNativeMutexAndClosesRegistrationOnce(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	// The TryLock assertion must observe only the calling goroutine. Stop the
	// independent timer supervisor so its brief state reads cannot masquerade
	// as a platform call made under the native mutex.
	parent.stopSupervisor()
	registration := &maintenanceLockCheckingRegistration{parent: parent}
	registration.invalidate = parent.invalidateFromPlatform
	parent.registration = registration
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	if result := parent.revalidatePlatform(op); result != MaintenanceSuccess {
		t.Fatal(result)
	}
	lease, result := parent.acquirePublication(op)
	if result != MaintenanceSuccess || !lease.IsCurrent() {
		t.Fatalf("lease=%v result=%d", lease, result)
	}
	if code := lease.Close(); code != CodeOK {
		t.Fatal(code)
	}
	parent.finishOperation(op)
	if code := parent.DestroyResult(); code != CodeOK {
		t.Fatal(code)
	}
	if code := parent.DestroyResult(); code != CodeOK {
		t.Fatal(code)
	}
	if registration.closeCount != 1 || registration.lockFailures != 0 {
		t.Fatalf("closes=%d lock failures=%d", registration.closeCount, registration.lockFailures)
	}
}

func TestMaintenanceRegistrationCleanupFailureIsRetained(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	registration := &maintenanceCleanupFailureRegistration{}
	parent.registration = registration

	if code := parent.DestroyResult(); code != CodeStateCorrupt {
		t.Fatalf("first destroy=%d", code)
	}
	if code := parent.DestroyResult(); code != CodeStateCorrupt {
		t.Fatalf("second destroy=%d", code)
	}
	if registration.closeCount != 1 {
		t.Fatalf("registration closes=%d", registration.closeCount)
	}
}

func TestMaintenanceSynchronousInvalidationAcrossPlatformCallsDefersTruthfullyAndRetiresBeforeCompletion(t *testing.T) {
	for _, stage := range []maintenanceCallbackStage{
		maintenanceCallbackRevalidate,
		maintenanceCallbackAcquire,
		maintenanceCallbackIsCurrent,
		maintenanceCallbackLeaseClose,
	} {
		t.Run(stage.String(), func(t *testing.T) {
			parent := newMaintenanceStateFixture(t)
			retiredCandidate := 0
			retiredOwner := 0
			parent.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) { retiredCandidate++ }
			parent.destroyOwner = func(*selfhost.LiveMaintenanceAdmission) { retiredOwner++ }
			parent.candidate = new(selfhost.LiveMaintenanceCandidate)
			parent.candidateID = 1
			parent.candidateEnd = parent.lastNow.Add(time.Minute)
			parent.owner = new(selfhost.LiveMaintenanceAdmission)
			registration := &maintenanceCallbackRegistration{stage: stage}
			registration.invalidate = parent.invalidateFromPlatform
			parent.registration = registration
			op, result := parent.beginOperation()
			if result != MaintenanceSuccess {
				t.Fatal(result)
			}
			done := make(chan MaintenanceResultV1, 1)
			go func() {
				var result MaintenanceResultV1
				switch stage {
				case maintenanceCallbackRevalidate:
					result = parent.revalidatePlatform(op)
				case maintenanceCallbackAcquire, maintenanceCallbackIsCurrent:
					_, result = parent.acquirePublication(op)
				case maintenanceCallbackLeaseClose:
					result = parent.finishPublication(op, &maintenanceCallbackLease{registration: registration})
				}
				parent.finishOperation(op)
				done <- result
			}()
			select {
			case result := <-done:
				if result != MaintenanceCancelled {
					t.Fatalf("result=%d", result)
				}
			case <-time.After(time.Second):
				t.Fatal("synchronous callback self-joined")
			}
			if registration.callbackCode != CodeStateCorrupt || retiredCandidate != 1 || retiredOwner != 1 {
				t.Fatalf("callback=%v candidate retires=%d owner retires=%d", registration.callbackCode, retiredCandidate, retiredOwner)
			}
			if code := parent.DestroyResult(); code != CodeOK {
				t.Fatal(code)
			}
			if code := parent.DestroyResult(); code != CodeOK || registration.closeCount != 1 {
				t.Fatalf("second destroy=%v registration closes=%d", code, registration.closeCount)
			}
		})
	}
}

func TestMaintenancePublicationClosesBeforeDetachedResourceRetirement(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	held := true
	retiredCandidate, retiredOwner := false, false
	parent.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) {
		if held {
			t.Fatal("candidate destruction ran under publication lease")
		}
		retiredCandidate = true
	}
	parent.destroyOwner = func(*selfhost.LiveMaintenanceAdmission) {
		if held {
			t.Fatal("owner destruction ran under publication lease")
		}
		retiredOwner = true
	}
	if result := parent.finishPublicationAndRetireDetached(
		op, &maintenanceHeldLease{held: &held},
		new(selfhost.LiveMaintenanceCandidate), new(selfhost.LiveMaintenanceAdmission),
	); result != MaintenanceSuccess {
		t.Fatal(result)
	}
	parent.finishOperation(op)
	if held || !retiredCandidate || !retiredOwner {
		t.Fatalf("held=%t candidate=%t owner=%t", held, retiredCandidate, retiredOwner)
	}
}

func TestMaintenanceTrustedAndMonotonicSamplesAreAdjacent(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	var calls []string
	trusted := parent.lastNow.Add(time.Second)
	monotonic := time.Unix(500, 0)
	parent.now = func() time.Time {
		calls = append(calls, "trusted")
		return trusted
	}
	parent.monotonicNow = func() time.Time {
		calls = append(calls, "monotonic")
		return monotonic
	}
	gotTrusted, gotMonotonic, result := parent.trustedNowAndMonotonic(op)
	parent.finishOperation(op)
	if result != MaintenanceSuccess || !gotTrusted.Equal(trusted) || !gotMonotonic.Equal(monotonic) {
		t.Fatalf("trusted=%v monotonic=%v result=%d", gotTrusted, gotMonotonic, result)
	}
	if len(calls) != 2 || calls[0] != "trusted" || calls[1] != "monotonic" {
		t.Fatalf("sample order=%v", calls)
	}
}

func TestMaintenanceCandidateMonotonicDeadlineCannotExtendDuringPublicationAcquisition(t *testing.T) {
	trustedCompletion := time.Unix(1_780_000_000, 0).UTC()
	monotonicCompletion := time.Unix(500, 0)
	trustedNow, monotonicNow := trustedCompletion, monotonicCompletion
	parent := newMaintenanceStateFixture(t)
	parent.lastNow = trustedCompletion
	parent.parentEnd = trustedCompletion.Add(2 * time.Minute)
	parent.parentTimerAt = monotonicCompletion.Add(90 * time.Second)
	parent.now = func() time.Time { return trustedNow }
	parent.monotonicNow = func() time.Time { return monotonicNow }
	parent.registration = &maintenanceClockAdvanceRegistration{beforeAcquire: func() {
		monotonicNow = monotonicCompletion.Add(10 * time.Second)
	}}
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	completionTrusted, completionMonotonic, result := parent.trustedNowAndMonotonic(op)
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	trustedDeadline, ok := maintenanceCandidateDeadlineV1(
		completionTrusted, parent.parentEnd, trustedCompletion.Add(2*time.Minute),
	)
	if !ok {
		t.Fatal("trusted candidate deadline was invalid")
	}
	preserved, ok := maintenanceMonotonicDeadlineV1(completionTrusted, trustedDeadline, completionMonotonic)
	if !ok {
		t.Fatal("completion bound was invalid")
	}
	// Acquisition consumed ten monotonic seconds while trusted time remained
	// equal. Publication must preserve M+60, not rebase it to M+70.
	lease, result := parent.acquirePublication(op)
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	publicationTrusted, publicationMonotonic, result := parent.trustedNowAndMonotonic(op)
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	got, ok := maintenanceShortenMonotonicDeadlineV1(
		publicationTrusted, trustedDeadline, publicationMonotonic, preserved, parent.parentTimerAt,
	)
	if !ok || !got.Equal(monotonicCompletion.Add(60*time.Second)) {
		t.Fatalf("publication rebound deadline=%v ok=%t", got, ok)
	}
	if result := parent.finishPublication(op, lease); result != MaintenanceSuccess {
		t.Fatal(result)
	}
	parent.finishOperation(op)

	// The immutable parent monotonic deadline can shorten the candidate.
	got, ok = maintenanceShortenMonotonicDeadlineV1(
		trustedCompletion, trustedDeadline, publicationMonotonic,
		preserved, monotonicCompletion.Add(50*time.Second),
	)
	if !ok || !got.Equal(monotonicCompletion.Add(50*time.Second)) {
		t.Fatalf("parent clamp deadline=%v ok=%t", got, ok)
	}

	// Once acquisition has consumed the preserved child bound, publication is
	// rejected even though the trusted clock has not advanced.
	if got, ok := maintenanceShortenMonotonicDeadlineV1(
		trustedCompletion, trustedDeadline, monotonicCompletion.Add(61*time.Second),
		preserved, monotonicCompletion.Add(90*time.Second),
	); ok || !got.IsZero() {
		t.Fatalf("elapsed preserved deadline=%v ok=%t", got, ok)
	}
}

func TestMaintenanceBridgeReservationAndParentEpochFailClosed(t *testing.T) {
	members := make([]string, maintenanceActivationMaxListElements)
	recordBytes, err := EncodeActivationRecord(profile.ActivationRecord{Profile: envelope.CanonicalProfileV1{
		RelayIDs: members, StrategyIDs: members,
	}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := DecodeActivationRecord(recordBytes)
	if err != nil || len(record.Profile.RelayIDs) != int(maintenanceActivationMaxListElements) || len(record.Profile.StrategyIDs) != int(maintenanceActivationMaxListElements) {
		t.Fatalf("maximal typed activation lists relay=%d strategy=%d err=%v", len(record.Profile.RelayIDs), len(record.Profile.StrategyIDs), err)
	}
	maxURIEncoded := envelope.MaxIngressEncodedChars - len("kurd://artifact/")
	opaque := make([]byte, maxURIEncoded*3/4)
	opaque[0] = 1
	uri, err := envelope.EncodeArtifactURI(opaque)
	if err != nil || len(uri) > envelope.MaxIngressEncodedChars || len(uri) < envelope.MaxIngressEncodedChars-4 {
		t.Fatalf("near-cap URI length=%d err=%v", len(uri), err)
	}
	verifyRequest, err := EncodeVerifyRequest(VerifyRequest{
		Ingress: envelope.IngressURI, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{[]byte(uri)},
	})
	if err != nil {
		t.Fatal(err)
	}
	current := MaintenanceCurrentInputV1{
		VerifyRequest: verifyRequest, ActivationRecord: recordBytes,
		RecipientRequest: []byte{1}, RecipientPrivate: []byte{1},
	}
	reservation, result := maintenanceBridgeReservation(current)
	if result != MaintenanceSuccess || reservation == 0 {
		t.Fatalf("reservation=%d result=%d", reservation, result)
	}
	ledger, ok := maintenanceBridgeReservationLedger()
	if !ok {
		t.Fatal("source-stage ledger overflowed fixed admitted caps")
	}
	want := ledger.FixedControl + maintenanceMaxV1(
		ledger.VerifyDecode, ledger.IngressFile, ledger.IngressURI, ledger.IngressQR,
		ledger.CredentialsRequest, ledger.CredentialsPrivate, ledger.CredentialsCheck,
		ledger.CredentialsClone, ledger.ActivationRecord,
	)
	if reservation != want {
		t.Fatalf("reservation=%d want source-qualified=%d", reservation, want)
	}
	clone := func(n uint64) uint64 { return 2*n + 8 }
	wantURI := uint64(MaxVerifySegments)*uint64(unsafe.Sizeof([]byte{})) +
		clone(uint64(MaxVerifyRequestBytes)) + 2*clone(uint64(envelope.MaxIngressEncodedChars)) +
		2*clone(uint64(envelope.MaxTotalInputBytes))
	if ledger.IngressURI != wantURI {
		t.Fatalf("URI stage=%d want copied-request+URI-text+decoded+canonical+normalized=%d", ledger.IngressURI, wantURI)
	}
	// Five simultaneous channels plus one context, timer and supervisor are
	// eight constructed controls. Keep this literal independent of the source
	// count so omitting retirementDone changes observable reservation behavior.
	wantControl := uint64(unsafe.Sizeof(maintenanceAuthorityV1{})) + uint64(unsafe.Sizeof(maintenanceOperationV1{})) +
		8*maintenanceControlBackingPerObject
	if ledger.FixedControl != wantControl {
		t.Fatalf("fixed control=%d want exact values plus eight named objects=%d", ledger.FixedControl, wantControl)
	}
	minimumActivationLists := 2 * maintenanceActivationListFields * maintenanceActivationMaxListElements * uint64(unsafe.Sizeof(""))
	if ledger.ActivationRecord <= minimumActivationLists {
		t.Fatalf("activation stage=%d did not include retained artifact/credentials, typed leaves and canonical output beyond list descriptors=%d", ledger.ActivationRecord, minimumActivationLists)
	}
	environment := &maintenanceNeverCalledEnvironment{}
	platform := &maintenanceNeverCalledPlatform{}
	for _, budget := range []uint64{reservation - 1, reservation} {
		var registry HandleRegistry
		if handle, result := OpenMaintenanceV1(&registry, current, environment, platform, MaintenanceConfigV1{
			OwnedBudgetBytes: budget,
			Now:              func() time.Time { return time.Unix(1_780_000_000, 0).UTC() },
		}); handle != 0 || result != MaintenanceResourceLimit || environment.called || platform.called {
			t.Fatalf("budget=%d handle=%d result=%d environment=%t platform=%t", budget, handle, result, environment.called, platform.called)
		}
	}

	var registry HandleRegistry
	registry.maintenanceEpoch = ^uint64(0)
	owner := &maintenanceAuthorityV1{scope: [32]byte{1}}
	if registry.reserveMaintenanceScope(owner) || owner.parentEpoch != 0 {
		t.Fatalf("wrapped parent epoch=%d", owner.parentEpoch)
	}
}

func newMaintenanceStateFixture(t testing.TB) *maintenanceAuthorityV1 {
	t.Helper()
	now := time.Now()
	parent := &maintenanceAuthorityV1{
		parentEpoch: 1, now: func() time.Time { return now }, lastNow: now,
		timerWake: make(chan struct{}, 1), timerStop: make(chan struct{}), timerDone: make(chan struct{}),
		cleanupCode: CodeOK, parentEnd: now.Add(time.Hour), parentTimerAt: now.Add(time.Hour),
		monotonicNow:     time.Now,
		destroyCandidate: func(candidate *selfhost.LiveMaintenanceCandidate) { candidate.Destroy() },
		destroyOwner:     func(owner *selfhost.LiveMaintenanceAdmission) { owner.Destroy() },
	}
	go parent.runTimerSupervisor()
	t.Cleanup(func() { parent.DestroyResult() })
	return parent
}

func parentStatusForTest(parent *maintenanceAuthorityV1) MaintenanceResultV1 {
	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.terminalSet {
		return parent.terminal
	}
	return MaintenanceSuccess
}

type maintenanceLockCheckingRegistration struct {
	parent       *maintenanceAuthorityV1
	invalidate   func() ErrorCode
	closeOnce    sync.Once
	closeCount   int
	lockFailures int
}

type maintenanceHeldLease struct{ held *bool }

func (*maintenanceHeldLease) IsCurrent() bool { return true }

func (l *maintenanceHeldLease) Close() ErrorCode {
	*l.held = false
	return CodeOK
}

type maintenanceClockAdvanceRegistration struct{ beforeAcquire func() }

func (*maintenanceClockAdvanceRegistration) Revalidate(context.Context) MaintenanceResultV1 {
	return MaintenanceSuccess
}

func (r *maintenanceClockAdvanceRegistration) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	if r.beforeAcquire != nil {
		r.beforeAcquire()
	}
	return maintenanceClockLease{}, MaintenanceSuccess
}

func (*maintenanceClockAdvanceRegistration) Close() ErrorCode { return CodeOK }

type maintenanceClockLease struct{}

func (maintenanceClockLease) IsCurrent() bool  { return true }
func (maintenanceClockLease) Close() ErrorCode { return CodeOK }

func (r *maintenanceLockCheckingRegistration) unlocked() {
	if !r.parent.mu.TryLock() {
		r.lockFailures++
		return
	}
	r.parent.mu.Unlock()
}
func (r *maintenanceLockCheckingRegistration) Revalidate(context.Context) MaintenanceResultV1 {
	r.unlocked()
	return MaintenanceSuccess
}
func (r *maintenanceLockCheckingRegistration) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	r.unlocked()
	return &maintenanceLockCheckingLease{registration: r}, MaintenanceSuccess
}
func (r *maintenanceLockCheckingRegistration) Close() ErrorCode {
	r.unlocked()
	r.closeCount++
	r.invalidate()
	return CodeOK
}

type maintenanceLockCheckingLease struct {
	registration *maintenanceLockCheckingRegistration
}

func (l *maintenanceLockCheckingLease) IsCurrent() bool {
	l.registration.unlocked()
	return true
}
func (l *maintenanceLockCheckingLease) Close() ErrorCode {
	l.registration.unlocked()
	return CodeOK
}

type maintenanceCleanupFailureRegistration struct {
	closeCount int
}

type maintenanceCallbackStage uint8

const (
	maintenanceCallbackRevalidate maintenanceCallbackStage = iota + 1
	maintenanceCallbackAcquire
	maintenanceCallbackIsCurrent
	maintenanceCallbackLeaseClose
)

func (stage maintenanceCallbackStage) String() string {
	switch stage {
	case maintenanceCallbackRevalidate:
		return "revalidate"
	case maintenanceCallbackAcquire:
		return "acquire"
	case maintenanceCallbackIsCurrent:
		return "is-current"
	case maintenanceCallbackLeaseClose:
		return "lease-close"
	default:
		return "unknown"
	}
}

type maintenanceCallbackRegistration struct {
	stage        maintenanceCallbackStage
	invalidate   func() ErrorCode
	callbackCode ErrorCode
	closeCount   int
}

func (r *maintenanceCallbackRegistration) invoke(stage maintenanceCallbackStage) {
	if r.stage == stage {
		r.callbackCode = r.invalidate()
	}
}

func (r *maintenanceCallbackRegistration) Revalidate(context.Context) MaintenanceResultV1 {
	r.invoke(maintenanceCallbackRevalidate)
	return MaintenanceSuccess
}
func (r *maintenanceCallbackRegistration) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	r.invoke(maintenanceCallbackAcquire)
	return &maintenanceCallbackLease{registration: r}, MaintenanceSuccess
}
func (r *maintenanceCallbackRegistration) Close() ErrorCode {
	r.closeCount++
	return CodeOK
}

type maintenanceCallbackLease struct {
	registration *maintenanceCallbackRegistration
}

func (l *maintenanceCallbackLease) IsCurrent() bool {
	l.registration.invoke(maintenanceCallbackIsCurrent)
	return true
}
func (l *maintenanceCallbackLease) Close() ErrorCode {
	l.registration.invoke(maintenanceCallbackLeaseClose)
	return CodeOK
}

func (*maintenanceCleanupFailureRegistration) Revalidate(context.Context) MaintenanceResultV1 {
	return MaintenanceSuccess
}
func (*maintenanceCleanupFailureRegistration) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	return nil, MaintenanceInternalFailure
}
func (r *maintenanceCleanupFailureRegistration) Close() ErrorCode {
	r.closeCount++
	return CodeStateCorrupt
}

type maintenanceNeverCalledEnvironment struct{ called bool }

func (e *maintenanceNeverCalledEnvironment) VerifyWithRecipientAt([]byte, envelope.ArtifactClass, RecipientCredentials, time.Time, selfhost.LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, error) {
	e.called = true
	return profile.OfflineVerifiedArtifact{}, selfhost.LiveMaintenanceBounds{}, nil
}

type maintenanceNeverCalledPlatform struct{ called bool }

func (p *maintenanceNeverCalledPlatform) Register(uint64, func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	p.called = true
	return nil, CodeInternalFailure
}
