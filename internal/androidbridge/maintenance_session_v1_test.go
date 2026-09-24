// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"testing"
	"time"

	"kurdistan/internal/selfhost"
)

func TestMaintenanceAllowsOnlyOneOperationAndPreservesFirstTerminal(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	first, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	if second, result := parent.beginOperation(); second != nil || result != MaintenanceResourceLimit {
		t.Fatalf("second=%v result=%d", second, result)
	}
	parent.finishOperation(first)
	second, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	parent.finishOperation(second)
	parent.shutdown(MaintenanceRevoked, false)
	parent.shutdown(MaintenanceCancelled, false)
	if got := parentStatusForTest(parent); got != MaintenanceRevoked {
		t.Fatalf("terminal=%d", got)
	}
}

func TestMaintenanceIdleRetirementBlocksNewOwnerAccessAndKeepsOriginalParentTimer(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	parent := newMaintenanceStateFixture(t)
	parent.mu.Lock()
	parent.now = func() time.Time { return now }
	parent.lastNow = now
	parent.parentEnd = now.Add(time.Hour)
	parent.parentTimerAt = time.Now().Add(time.Hour)
	parent.owner = new(selfhost.LiveMaintenanceAdmission)
	parent.destroyOwner = func(*selfhost.LiveMaintenanceAdmission) {}
	parent.candidate = new(selfhost.LiveMaintenanceCandidate)
	parent.candidateID = 1
	parent.candidateEnd = now.Add(-time.Second)
	parent.timerAt = time.Now().Add(time.Minute)
	parent.timerKind = maintenanceTimerCandidate
	parent.timerSeq++
	staleCandidateSeq := parent.timerSeq
	parent.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	parent.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) {
		close(entered)
		<-release
	}
	var registry HandleRegistry
	handle, code := registry.Open(HandleMaintenance, parent)
	if code != CodeOK {
		t.Fatal(code)
	}
	parent.registry = &registry
	parent.handle = handle
	statusDone := make(chan MaintenanceResultV1, 1)
	go func() { statusDone <- MaintenanceStatusV1(&registry, handle) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("candidate retirement did not start")
	}
	if op, result := parent.beginOperation(); op != nil || result != MaintenanceResourceLimit {
		t.Fatalf("operation entered during retirement: op=%v result=%d", op, result)
	}
	close(release)
	if result := <-statusDone; result != MaintenanceSuccess {
		t.Fatalf("status=%d", result)
	}
	if terminal := parent.expireTimer(staleCandidateSeq, maintenanceTimerCandidate); terminal {
		t.Fatal("detached candidate's stale timer reported terminal")
	}
	parent.mu.Lock()
	timerAt, timerKind := parent.timerAt, parent.timerKind
	parent.mu.Unlock()
	if !timerAt.Equal(parent.parentTimerAt) || timerKind != maintenanceTimerParent {
		t.Fatalf("timer=%v kind=%d parent=%v", timerAt, timerKind, parent.parentTimerAt)
	}
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatalf("operation after retirement=%d", result)
	}
	parent.finishOperation(op)
	if code := registry.Free(handle); code != CodeOK {
		t.Fatal(code)
	}
}

func TestMaintenanceStatusDoesNotAccessOwnerDuringTerminalRetirement(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	parent.mu.Lock()
	parent.now = func() time.Time { panic("terminal status sampled the clock") }
	parent.owner = new(selfhost.LiveMaintenanceAdmission)
	parent.terminalSet = true
	parent.terminal = MaintenanceRevoked
	parent.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	parent.destroyOwner = func(*selfhost.LiveMaintenanceAdmission) {
		close(entered)
		<-release
	}
	var registry HandleRegistry
	handle, code := registry.Open(HandleMaintenance, parent)
	if code != CodeOK {
		t.Fatal(code)
	}
	parent.mu.Lock()
	parent.registry = &registry
	parent.handle = handle
	parent.mu.Unlock()
	done := make(chan struct{})
	go func() {
		parent.retireOwnerOnce()
		close(done)
	}()
	<-entered
	if status := MaintenanceStatusV1(&registry, handle); status != MaintenanceRevoked {
		t.Fatalf("status=%d", status)
	}
	close(release)
	<-done
	if code := registry.Free(handle); code != CodeOK {
		t.Fatal(code)
	}
}

func TestMaintenanceTerminalCleanupWaitsForIdleCandidateRetirement(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	parent := newMaintenanceStateFixture(t)
	childEntered := make(chan struct{})
	releaseChild := make(chan struct{})
	ownerEntered := make(chan struct{}, 1)
	parent.mu.Lock()
	parent.now = func() time.Time { return now }
	parent.lastNow = now
	parent.parentEnd = now.Add(time.Hour)
	parent.parentTimerAt = time.Now().Add(time.Hour)
	parent.owner = new(selfhost.LiveMaintenanceAdmission)
	parent.candidate = new(selfhost.LiveMaintenanceCandidate)
	parent.candidateID = 1
	parent.candidateEnd = now.Add(-time.Second)
	parent.scope = [32]byte{1}
	parent.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) {
		close(childEntered)
		<-releaseChild
	}
	parent.destroyOwner = func(*selfhost.LiveMaintenanceAdmission) { ownerEntered <- struct{}{} }
	parent.mu.Unlock()
	var registry HandleRegistry
	if !registry.reserveMaintenanceScope(parent) {
		t.Fatal("scope reservation failed")
	}
	handle, code := registry.Open(HandleMaintenance, parent)
	if code != CodeOK {
		t.Fatal(code)
	}
	parent.mu.Lock()
	parent.registry = &registry
	parent.handle = handle
	parent.mu.Unlock()
	statusDone := make(chan MaintenanceResultV1, 1)
	go func() { statusDone <- MaintenanceStatusV1(&registry, handle) }()
	<-childEntered
	freeDone := make(chan ErrorCode, 1)
	go func() { freeDone <- registry.Free(handle) }()
	select {
	case <-ownerEntered:
		t.Fatal("owner destruction overlapped idle child retirement")
	case <-freeDone:
		t.Fatal("Free returned and released scope before idle retirement completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseChild)
	if result := <-statusDone; result != MaintenanceSuccess {
		t.Fatalf("status=%d", result)
	}
	if code := <-freeDone; code != CodeOK {
		t.Fatal(code)
	}
	select {
	case <-ownerEntered:
	default:
		t.Fatal("owner was not destroyed after idle child retirement")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, slot := range registry.maintenanceScopes {
		if slot.owner == parent {
			t.Fatal("scope remained reserved after joined Free")
		}
	}
}

func TestMaintenanceActiveExpiryRetainsRetirementFenceThroughDestroy(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	now := parent.lastNow
	parent.candidate = new(selfhost.LiveMaintenanceCandidate)
	parent.candidateID = 1
	parent.candidateEnd = now.Add(-time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	parent.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) {
		close(entered)
		<-release
	}
	op, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	go func() {
		<-op.ctx.Done()
		parent.finishOperation(op)
	}()
	done := make(chan struct{})
	go func() {
		parent.expireCandidateIdle(now)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("active expiry did not join and start retirement")
	}
	if next, result := parent.beginOperation(); next != nil || result != MaintenanceResourceLimit {
		t.Fatalf("operation entered during active retirement: op=%v result=%d", next, result)
	}
	close(release)
	<-done
	next, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatalf("operation after active retirement=%d", result)
	}
	parent.finishOperation(next)
}

func TestMaintenanceRevocationCannotEnterAfterRetirementStartsWhileJoiningPriorOperation(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	now := parent.lastNow
	parent.candidate = new(selfhost.LiveMaintenanceCandidate)
	parent.candidateID = 1
	parent.candidateEnd = now.Add(-time.Second)
	retirementEntered := make(chan struct{})
	releaseRetirement := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseRetirement)
		}
	}()
	parent.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) {
		close(retirementEntered)
		<-releaseRetirement
	}
	prior, result := parent.beginOperation()
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	revocationResult := make(chan MaintenanceResultV1, 1)
	go func() {
		op, result := parent.beginRevocationOperation()
		if op != nil {
			parent.finishRevocationOperation(op)
		}
		revocationResult <- result
	}()
	<-prior.ctx.Done()
	expiryDone := make(chan struct{})
	go func() {
		parent.expireCandidateIdle(now)
		close(expiryDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		parent.mu.Lock()
		retirementBusy := parent.retirementBusy
		parent.mu.Unlock()
		if retirementBusy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retirement did not begin while revocation joined")
		}
		time.Sleep(time.Millisecond)
	}
	parent.finishOperation(prior)
	select {
	case <-retirementEntered:
	case <-time.After(time.Second):
		t.Fatal("retirement did not retain its completion fence")
	}
	if result := <-revocationResult; result != MaintenanceResourceLimit {
		t.Fatalf("revocation entered after retirement started: %d", result)
	}
	close(releaseRetirement)
	released = true
	<-expiryDone
}

func TestMaintenanceStaleTimerDoesNotReadUnlockedTerminalOrRetireCurrentState(t *testing.T) {
	parent := newMaintenanceStateFixture(t)
	parent.mu.Lock()
	parent.timerSeq = 2
	parent.timerKind = maintenanceTimerParent
	parent.mu.Unlock()
	if terminal := parent.expireTimer(1, maintenanceTimerCandidate); terminal {
		t.Fatal("stale timer reported terminal")
	}
	if got := parentStatusForTest(parent); got != MaintenanceSuccess {
		t.Fatalf("terminal=%d", got)
	}
}
