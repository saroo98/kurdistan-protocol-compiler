// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"math"
	"testing"
	"time"
	"unsafe"
)

type observedJoinContextV1 struct {
	entered chan struct{}
	done    chan struct{}
}

func (ctx *observedJoinContextV1) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *observedJoinContextV1) Done() <-chan struct{} {
	select {
	case <-ctx.entered:
	default:
		close(ctx.entered)
	}
	return ctx.done
}
func (ctx *observedJoinContextV1) Err() error    { return nil }
func (ctx *observedJoinContextV1) Value(any) any { return nil }

func newTestProductionParentV1(t *testing.T, registry *HandleRegistry, deadline time.Time) *productionParentV1 {
	t.Helper()
	ticket, status := reserveProductionSlotV1(registry)
	if status != int32(productionSuccessV1) {
		t.Fatalf("reserve=%d", status)
	}
	parent, status := newProductionParentV1(ticket, 128*1024*1024, deadline)
	if status != int32(productionSuccessV1) {
		t.Fatalf("new parent=%d", status)
	}
	return parent
}

func TestProductionSlotV1SharesAllLegacyAndMaintenanceCapacity(t *testing.T) {
	registry := &HandleRegistry{}
	legacy := make([]Handle, MaxBridgeHandles/2)
	for index := range legacy {
		kind := HandleType(index%int(HandleMaintenance)) + HandleVerifyPreview
		handle, code := registry.Open(kind, index)
		if code != CodeOK {
			t.Fatalf("legacy open %d=%v", index, code)
		}
		legacy[index] = handle
	}
	private := make([]productionSlotTicketV1, MaxBridgeHandles/2)
	for index := range private {
		ticket, status := reserveProductionSlotV1(registry)
		if status != int32(productionSuccessV1) {
			t.Fatalf("private reserve %d=%d", index, status)
		}
		private[index] = ticket
	}
	if _, code := registry.Open(HandleMaintenance, "overflow"); code != CodeSizeLimit {
		t.Fatalf("legacy exhaustion=%v", code)
	}
	if _, status := reserveProductionSlotV1(registry); status != int32(productionResourceLimitV1) {
		t.Fatalf("private exhaustion=%d", status)
	}
	if _, _, _, ok := decodeHandle(Handle(uint64(private[0].epoch)<<16 | uint64(private[0].index+1))); ok {
		t.Fatal("private ticket unexpectedly decoded as a public handle")
	}
	for _, ticket := range private {
		if status := releaseProductionSlotV1(ticket); status != int32(productionSuccessV1) {
			t.Fatalf("release=%d", status)
		}
	}
	for _, handle := range legacy {
		if code := registry.Free(handle); code != CodeOK {
			t.Fatalf("free=%v", code)
		}
	}
}

func TestProductionSlotV1PreservesLegacyGenerationKindsAndStaleResults(t *testing.T) {
	registry := &HandleRegistry{}
	for kind := HandleVerifyPreview; kind <= HandleMaintenance; kind++ {
		handle, code := registry.Open(kind, kind)
		if code != CodeOK {
			t.Fatalf("kind %d open=%v", kind, code)
		}
		_, generation, encodedKind, ok := decodeHandle(handle)
		if !ok || generation != uint32(kind) || encodedKind != kind {
			t.Fatalf("kind %d decoded=(%d,%d,%v)", kind, generation, encodedKind, ok)
		}
		if code := registry.Free(handle); code != CodeOK {
			t.Fatal(code)
		}
		if _, code := registry.Get(handle, kind); code != CodeAlreadyClosed {
			t.Fatalf("kind %d stale=%v", kind, code)
		}
	}
	registry.slots[0].generation = math.MaxUint32
	handle, code := registry.Open(HandleMaintenance, "wrap")
	if code != CodeOK {
		t.Fatal(code)
	}
	_, generation, kind, ok := decodeHandle(handle)
	if !ok || generation != 1 || kind != HandleMaintenance {
		t.Fatalf("wrapped=(%d,%d,%v)", generation, kind, ok)
	}
}

func TestProductionParentV1ConstructorFailureReleasesOnlyExactTicket(t *testing.T) {
	registry := &HandleRegistry{}
	ticket, status := reserveProductionSlotV1(registry)
	if status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	fixed, _ := productionParentFixedBytesV1()
	if parent, status := newProductionParentV1(ticket, fixed-1, time.Time{}); parent != nil || status != int32(productionSizeLimitV1) {
		t.Fatalf("parent=%v status=%d", parent, status)
	}
	if status := releaseProductionSlotV1(ticket); status != int32(productionInvalidStateV1) {
		t.Fatalf("released constructor ticket repeated=%d", status)
	}
	if _, status := reserveProductionSlotV1(registry); status != int32(productionSuccessV1) {
		t.Fatalf("slot not reusable=%d", status)
	}
}

func TestProductionParentV1RejectsStaleAndBoundConstructorsBeforeAllocation(t *testing.T) {
	registry := &HandleRegistry{}
	stale, status := reserveProductionSlotV1(registry)
	if status != int32(productionSuccessV1) || releaseProductionSlotV1(stale) != int32(productionSuccessV1) {
		t.Fatal("failed to prepare stale ticket")
	}
	var staleStatus int32
	if allocations := testing.AllocsPerRun(100, func() {
		_, staleStatus = newProductionParentV1(stale, 128*1024*1024, time.Time{})
	}); allocations != 0 || staleStatus != int32(productionInvalidStateV1) {
		t.Fatalf("stale allocations/status=%f/%d", allocations, staleStatus)
	}

	parent := newTestProductionParentV1(t, registry, time.Time{})
	var boundStatus int32
	if allocations := testing.AllocsPerRun(100, func() {
		_, boundStatus = newProductionParentV1(parent.ticket, 128*1024*1024, time.Time{})
	}); allocations != 0 || boundStatus != int32(productionInvalidStateV1) {
		t.Fatalf("bound allocations/status=%f/%d", allocations, boundStatus)
	}
}

func TestProductionParentV1ConcurrentCopiedTicketConstructsOnce(t *testing.T) {
	registry := &HandleRegistry{}
	ticket, status := reserveProductionSlotV1(registry)
	if status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	start := make(chan struct{})
	type result struct {
		parent *productionParentV1
		status int32
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			parent, status := newProductionParentV1(ticket, 128*1024*1024, time.Time{})
			results <- result{parent: parent, status: status}
		}()
	}
	close(start)
	var winner *productionParentV1
	successes, rejected := 0, 0
	for range 2 {
		got := <-results
		switch got.status {
		case int32(productionSuccessV1):
			successes++
			winner = got.parent
		case int32(productionInvalidStateV1):
			rejected++
		default:
			t.Fatalf("unexpected constructor status=%d", got.status)
		}
	}
	if successes != 1 || rejected != 1 || winner == nil {
		t.Fatalf("successes/rejected/winner=%d/%d/%v", successes, rejected, winner)
	}
	if winner.cancelV1(int32(productionCancelledV1)) != int32(productionSuccessV1) ||
		winner.joinV1(context.Background()) != int32(productionSuccessV1) ||
		winner.retireV1() != int32(productionSuccessV1) {
		t.Fatal("winner cleanup failed")
	}
}

func TestProductionParentV1FixedInventoryUsesActualStructSizes(t *testing.T) {
	fixed, status := productionParentFixedBytesV1()
	want := uint64(unsafe.Sizeof(productionParentV1{})) + uint64(unsafe.Sizeof(productionBudgetV1{})) + productionRuntimeMetadataAllowanceV1
	if status != int32(productionSuccessV1) || fixed != want {
		t.Fatalf("fixed/status=%d/%d want=%d parent=%d budget=%d allowance=%d", fixed, status, want, unsafe.Sizeof(productionParentV1{}), unsafe.Sizeof(productionBudgetV1{}), productionRuntimeMetadataAllowanceV1)
	}
	if len((productionParentV1{}).uses) != 203 || len((productionBudgetV1{}).records) != 256 ||
		len((productionParentV1{}).controlArena) != 131072 || len((productionParentV1{}).controlDescriptors)+1 != 64 {
		t.Fatal("fixed backing inventory changed")
	}
	t.Logf("fixed=%d parent=%d budget=%d allowance=%d", fixed, unsafe.Sizeof(productionParentV1{}), unsafe.Sizeof(productionBudgetV1{}), productionRuntimeMetadataAllowanceV1)
}

func TestProductionParentV1AllUsesLeaveExactly52PersistentRecords(t *testing.T) {
	p := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	var uses [203]productionUseV1
	for i := range uses {
		var s int32
		uses[i], s = p.beginUseV1(uint16(i), productionBudgetChargeV1{})
		if s != 0 {
			t.Fatal(i, s)
		}
	}
	var tickets [52]productionBudgetTicketV1
	for i := range tickets {
		var s int32
		tickets[i], s = p.budget.reserveV1(productionBudgetChargeV1{})
		if s != 0 {
			t.Fatal(i, s)
		}
	}
	if _, s := p.budget.reserveV1(productionBudgetChargeV1{}); s != int32(productionResourceLimitV1) {
		t.Fatal("grew fixed ledger", s)
	}
	for _, ticket := range tickets {
		if p.budget.releaseV1(ticket) != 0 {
			t.Fatal("release")
		}
	}
	for _, use := range uses {
		if p.finishUseV1(use) != 0 {
			t.Fatal("finish")
		}
	}
}

func TestProductionParentV1CountedUseCancelJoinAndRetire(t *testing.T) {
	registry := &HandleRegistry{}
	parent := newTestProductionParentV1(t, registry, time.Time{})
	legacy := make([]Handle, MaxBridgeHandles-1)
	for index := range legacy {
		handle, code := registry.Open(HandleMaintenance, index)
		if code != CodeOK {
			t.Fatalf("fill legacy %d=%v", index, code)
		}
		legacy[index] = handle
	}
	use, status := parent.beginUseV1(2, productionBudgetChargeV1{owned: 32, queued: 16})
	if status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if _, status := parent.beginUseV1(2, productionBudgetChargeV1{}); status != int32(productionResourceLimitV1) {
		t.Fatalf("duplicate slot=%d", status)
	}
	if status := parent.cancelV1(int32(productionCancelledV1)); status != int32(productionSuccessV1) {
		t.Fatalf("cancel=%d", status)
	}
	joinContext := &observedJoinContextV1{entered: make(chan struct{}), done: make(chan struct{})}
	joinDone := make(chan int32, 1)
	go func() { joinDone <- parent.joinV1(joinContext) }()
	<-joinContext.entered
	select {
	case <-parent.joined:
		t.Fatal("joined closed while exact use remained active")
	default:
	}
	select {
	case status := <-joinDone:
		t.Fatalf("join completed before finish=%d", status)
	default:
	}
	if _, status := reserveProductionSlotV1(registry); status != int32(productionResourceLimitV1) {
		t.Fatalf("blocked parent reservation was reused=%d", status)
	}
	if status := parent.finishUseV1(use); status != int32(productionSuccessV1) {
		t.Fatalf("finish=%d", status)
	}
	if status := <-joinDone; status != int32(productionSuccessV1) {
		t.Fatalf("join=%d", status)
	}
	if status := parent.finishUseV1(use); status != int32(productionInvalidStateV1) {
		t.Fatalf("copied finish=%d", status)
	}
	if status := parent.retireV1(); status != int32(productionSuccessV1) {
		t.Fatalf("retire=%d", status)
	}
	if replacement, status := reserveProductionSlotV1(registry); status != int32(productionSuccessV1) || replacement.index != parent.ticket.index {
		t.Fatalf("retired slot replacement=%+v status=%d", replacement, status)
	}
	if status := parent.retireV1(); status != int32(productionSuccessV1) {
		if status != int32(productionInvalidStateV1) {
			t.Fatalf("repeat retire after replacement=%d", status)
		}
	}
	for _, handle := range legacy {
		if code := registry.Free(handle); code != CodeOK {
			t.Fatal(code)
		}
	}
}

func TestProductionParentV1JoinTimeoutKeepsReservationAndAttemptFence(t *testing.T) {
	registry := &HandleRegistry{}
	parent := newTestProductionParentV1(t, registry, time.Time{})
	parentScoped, _ := parent.beginUseV1(1, productionBudgetChargeV1{})
	attemptScoped, _ := parent.beginUseV1(3, productionBudgetChargeV1{})
	if _, status := parent.nextAttemptV1(); status != int32(productionInvalidStateV1) {
		t.Fatalf("advanced with attempt use=%d", status)
	}
	if status := parent.finishUseV1(attemptScoped); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if epoch, status := parent.nextAttemptV1(); status != int32(productionSuccessV1) || epoch != 2 {
		t.Fatalf("advance=(%d,%d)", epoch, status)
	}
	if status := parent.useCurrentV1(parentScoped); status != int32(productionSuccessV1) {
		t.Fatalf("parent-scoped current=%d", status)
	}
	stale, _ := parent.beginUseV1(4, productionBudgetChargeV1{})
	if status := parent.finishUseV1(stale); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if epoch, status := parent.nextAttemptV1(); status != int32(productionSuccessV1) || epoch != 3 {
		t.Fatalf("second advance=(%d,%d)", epoch, status)
	}
	if status := parent.useCurrentV1(stale); status != int32(productionInvalidStateV1) {
		t.Fatalf("stale use=%d", status)
	}
	if status := parent.cancelV1(int32(productionCancelledV1)); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if status := parent.joinV1(ctx); status != int32(productionTimeoutV1) {
		t.Fatalf("join timeout=%d", status)
	}
	if status := parent.retireV1(); status != int32(productionInvalidStateV1) {
		t.Fatalf("early retire=%d", status)
	}
	if status := parent.finishUseV1(parentScoped); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if status := parent.joinV1(context.Background()); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
}

func TestProductionParentV1DeadlineSequenceAndRetiredIdentity(t *testing.T) {
	registry := &HandleRegistry{}
	expired := newTestProductionParentV1(t, registry, time.Now().Add(-time.Millisecond))
	if _, status := expired.beginUseV1(0, productionBudgetChargeV1{}); status != int32(productionAuthorityExpiredV1) {
		t.Fatalf("expired begin=%d", status)
	}
	if status := expired.joinV1(context.Background()); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	expired.cleanupResult = int32(productionInternalFailureV1)
	if status := expired.retireV1(); status != int32(productionInternalFailureV1) {
		t.Fatalf("cleanup=%d", status)
	}
	if _, status := expired.beginUseV1(0, productionBudgetChargeV1{}); status != int32(productionInvalidStateV1) {
		t.Fatalf("begin after retire=%d", status)
	}
	if status := expired.retireV1(); status != int32(productionInternalFailureV1) {
		t.Fatalf("cleanup repeat=%d", status)
	}
	old := expired.ticket
	replacement, status := reserveProductionSlotV1(registry)
	if status != int32(productionSuccessV1) || replacement.index != old.index {
		t.Fatalf("replacement=%+v status=%d old=%+v", replacement, status, old)
	}
	if status := expired.retireV1(); status != int32(productionInvalidStateV1) {
		t.Fatalf("old tombstone after replacement=%d", status)
	}
	if status := releaseProductionSlotV1(old); status != int32(productionInvalidStateV1) {
		t.Fatalf("old release=%d", status)
	}

	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	parent.attempt = math.MaxUint64
	if epoch, status := parent.nextAttemptV1(); epoch != 0 || status != int32(productionInternalFailureV1) {
		t.Fatalf("attempt exhaustion=(%d,%d)", epoch, status)
	}
}

func TestProductionParentV1FirstTerminalReasonWins(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	if status := parent.cancelV1(int32(productionResourceLimitV1)); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if status := parent.cancelV1(int32(productionAuthorityRevokedV1)); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	parent.mu.Lock()
	reason := parent.terminal
	parent.mu.Unlock()
	if reason != productionResourceLimitV1 {
		t.Fatalf("terminal reason=%d", reason)
	}
}

func TestProductionSlotV1SaturatedPrivateEpochDoesNotBlockLegacy(t *testing.T) {
	registry := &HandleRegistry{}
	registry.slots[0].productionReservationEpoch = math.MaxUint64
	ticket, status := reserveProductionSlotV1(registry)
	if status != int32(productionSuccessV1) || ticket.index != 1 {
		t.Fatalf("private ticket=%+v status=%d", ticket, status)
	}
	handle, code := registry.Open(HandleMaintenance, "legacy")
	if code != CodeOK {
		t.Fatal(code)
	}
	index, _, _, ok := decodeHandle(handle)
	if !ok || index != 0 {
		t.Fatalf("legacy handle index=%d ok=%v", index, ok)
	}
}
