// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func productionControlBodyFixturesV1() map[productionControlKindV1][]byte {
	socket := make([]byte, 14)
	binary.BigEndian.PutUint64(socket[0:8], math.MaxUint64)
	binary.BigEndian.PutUint32(socket[8:12], math.MaxInt32)
	socket[12], socket[13] = 1, 1
	metrics := make([]byte, 42)
	for index := 0; index < 5; index++ {
		binary.BigEndian.PutUint64(metrics[index*8:], uint64(index+1)<<63)
	}
	metrics[40], metrics[41] = 64, 4
	return map[productionControlKindV1][]byte{
		productionControlSocketProtectionRequiredV1: socket,
		productionControlTransportConnectingV1:      {},
		productionControlTransportReadyV1:           {},
		productionControlMetricsUpdatedV1:           metrics,
		productionControlFallbackStartedV1:          {1, 5},
		productionControlReconnectStartedV1:         {4, 2, 5},
		productionControlDegradedV1:                 {3},
		productionControlRevokedV1:                  {},
		productionControlFailedV1:                   {0, byte(productionDNSPolicyRejectedV1)},
		productionControlStoppedV1:                  {},
	}
}

func TestProductionControlV1CompleteSnapshotsSurviveWrapAndShortRetry(t *testing.T) {
	for _, kind := range []productionControlKindV1{4, 6} {
		parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
		var snapshot [productionSnapshotMaxBytesV1]byte
		n, s := encodeProductionSnapshotV1(productionSnapshotFixtureV1(), snapshot[:])
		if s != 0 {
			t.Fatal(s)
		}
		parent.controlWriteOffset = productionControlOrdinaryBytesV1 - 17
		if got := parent.enqueueControlFixedV1(kind, snapshot[:n]); got != 0 {
			t.Fatalf("complete KPN1 kind%d refused: %d", kind, got)
		}
		tiny := bytes.Repeat([]byte{0xa5}, n+31)
		if written, result := parent.nextControlV1(context.Background(), tiny); written != 0 || result != 4 || !bytes.Equal(tiny, bytes.Repeat([]byte{0xa5}, len(tiny))) {
			t.Fatal("short retry consumed or changed output", written, result)
		}
		out := make([]byte, n+32)
		if written, result := parent.nextControlV1(context.Background(), out); written != len(out) || result != 0 || !bytes.Equal(out[32:], snapshot[:n]) || out[5] != byte(kind) || binary.BigEndian.Uint64(out[20:28]) != 1 {
			t.Fatal("complete wrapped snapshot did not survive retry", written, result)
		}
	}
}

func installTestOrdinaryControlLockedV1(parent *productionParentV1, kind productionControlKindV1, body []byte) {
	total := productionControlHeaderBytesV1 + len(body)
	offset := parent.controlWriteOffset
	parent.writeStoredControlAtLockedV1(offset, kind, parent.attempt, body)
	parent.controlDescriptors[parent.controlTail] = productionControlDescriptorV1{kind: kind, epoch: parent.attempt, offset: offset, size: uint32(total)}
	parent.controlTail = (parent.controlTail + 1) % productionControlOrdinaryDescriptorsV1
	parent.controlCount++
	parent.controlBytes += uint32(total)
	parent.controlWriteOffset = (offset + uint32(total)) % productionControlOrdinaryBytesV1
}

func TestProductionControlV1ExactSupportedFixtures(t *testing.T) {
	for kind, body := range productionControlBodyFixturesV1() {
		dst := bytes.Repeat([]byte{0xa5}, productionControlMaxEventBytesV1)
		written, status := encodeProductionControlFixedV1(productionControlRecordV1{kind: kind, epoch: math.MaxUint64, sequence: math.MaxUint64, body: body}, dst)
		if status != int32(productionSuccessV1) || written != productionControlHeaderBytesV1+len(body) {
			t.Fatalf("kind %d written/status=%d/%d", kind, written, status)
		}
		got := dst[:written]
		if string(got[:4]) != "KPC1" || got[4] != 1 || got[5] != byte(kind) || binary.BigEndian.Uint16(got[6:8]) != 0 ||
			binary.BigEndian.Uint32(got[8:12]) != uint32(written) || binary.BigEndian.Uint64(got[12:20]) != math.MaxUint64 ||
			binary.BigEndian.Uint64(got[20:28]) != math.MaxUint64 || binary.BigEndian.Uint32(got[28:32]) != uint32(len(body)) || !bytes.Equal(got[32:], body) {
			t.Fatalf("kind %d malformed bytes=%x", kind, got)
		}
	}
}

func TestProductionControlV1RejectsInvalidBodiesAndMalformedKPNAtomically(t *testing.T) {
	cases := []productionControlRecordV1{
		{kind: 0, epoch: 1, sequence: 1},
		{kind: 13, epoch: 1, sequence: 1},
		{kind: productionControlSocketProtectionRequiredV1, epoch: 1, sequence: 1, body: make([]byte, 13)},
		{kind: productionControlSocketProtectionRequiredV1, epoch: 1, sequence: 1, body: append(make([]byte, 8), 0x80, 0, 0, 0, 1, 0)},
		{kind: productionControlMetricsUpdatedV1, epoch: 1, sequence: 1, body: append(make([]byte, 40), 65, 0)},
		{kind: productionControlFallbackStartedV1, epoch: 1, sequence: 1, body: []byte{0, 1}},
		{kind: productionControlReconnectStartedV1, epoch: 1, sequence: 1, body: []byte{5, 1, 1}},
		{kind: productionControlDegradedV1, epoch: 1, sequence: 1, body: []byte{4}},
		{kind: productionControlFailedV1, epoch: 1, sequence: 1, body: []byte{0, byte(productionEndOfStreamV1)}},
		{kind: productionControlStoppedV1, epoch: 0, sequence: 1},
		{kind: productionControlStoppedV1, epoch: 1, sequence: 0},
	}
	for index, record := range cases {
		dst := bytes.Repeat([]byte{0x5a}, productionControlMaxEventBytesV1)
		before := append([]byte(nil), dst...)
		written, status := encodeProductionControlFixedV1(record, dst)
		if written != 0 || status != int32(productionInvalidRequestV1) || !bytes.Equal(dst, before) {
			t.Fatalf("case %d written/status=%d/%d changed=%v", index, written, status, !bytes.Equal(dst, before))
		}
	}
	for _, kind := range []productionControlKindV1{productionControlRoutePlanReadyV1, productionControlPathChangedV1} {
		dst := bytes.Repeat([]byte{0x33}, productionControlMaxEventBytesV1)
		before := append([]byte(nil), dst...)
		written, status := encodeProductionControlFixedV1(productionControlRecordV1{kind: kind, epoch: 1, sequence: 1, body: []byte("KPN1")}, dst)
		if written != 0 || status != int32(productionInvalidRequestV1) || !bytes.Equal(dst, before) {
			t.Fatalf("kind %d written/status=%d/%d", kind, written, status)
		}
	}
}

func TestProductionControlV1QueueCoalescesMetricsWithoutReordering(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	metrics := productionControlBodyFixturesV1()[productionControlMetricsUpdatedV1]
	newMetrics := append([]byte(nil), metrics...)
	binary.BigEndian.PutUint64(newMetrics, 99)
	for _, item := range []struct {
		kind productionControlKindV1
		body []byte
	}{
		{productionControlDegradedV1, []byte{3}},
		{productionControlMetricsUpdatedV1, metrics},
		{productionControlTransportConnectingV1, nil},
		{productionControlMetricsUpdatedV1, newMetrics},
	} {
		if status := parent.enqueueControlFixedV1(item.kind, item.body); status != int32(productionSuccessV1) {
			t.Fatalf("enqueue kind %d=%d", item.kind, status)
		}
	}
	tiny := bytes.Repeat([]byte{0x77}, 32)
	before := append([]byte(nil), tiny...)
	if written, status := parent.nextControlV1(context.Background(), tiny); written != 0 || status != int32(productionSizeLimitV1) || !bytes.Equal(tiny, before) {
		t.Fatalf("tiny written/status=%d/%d", written, status)
	}
	for index, wantKind := range []productionControlKindV1{productionControlDegradedV1, productionControlMetricsUpdatedV1, productionControlTransportConnectingV1} {
		dst := make([]byte, productionControlMaxEventBytesV1)
		written, status := parent.nextControlV1(context.Background(), dst)
		if status != int32(productionSuccessV1) || dst[5] != byte(wantKind) || binary.BigEndian.Uint64(dst[20:28]) != uint64(index+1) {
			t.Fatalf("item %d kind/sequence/status=%d/%d/%d", index, dst[5], binary.BigEndian.Uint64(dst[20:28]), status)
		}
		if wantKind == productionControlMetricsUpdatedV1 && binary.BigEndian.Uint64(dst[32:40]) != 99 {
			t.Fatalf("metrics not replaced: %x", dst[:written])
		}
	}
}

func TestProductionControlV1OrdinaryLimitsReserveTerminal(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	for index := 0; index < productionControlOrdinaryDescriptorsV1; index++ {
		if status := parent.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); status != int32(productionSuccessV1) {
			t.Fatalf("enqueue %d=%d", index, status)
		}
	}
	if status := parent.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); status != int32(productionResourceLimitV1) {
		t.Fatalf("overflow=%d", status)
	}
	dst := make([]byte, productionControlMaxEventBytesV1)
	written, status := parent.nextControlV1(context.Background(), dst)
	if status != int32(productionSuccessV1) || written != 34 || dst[5] != byte(productionControlFailedV1) || binary.BigEndian.Uint16(dst[32:34]) != uint16(productionResourceLimitV1) {
		t.Fatalf("terminal written/status/kind/body=%d/%d/%d/%x", written, status, dst[5], dst[32:written])
	}
}

func TestProductionControlV1CancellationDiscardsOrdinaryBeforeTerminal(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	if status := parent.enqueueControlFixedV1(productionControlTransportReadyV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if status := parent.enqueueControlFixedV1(productionControlStoppedV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	dst := make([]byte, productionControlMaxEventBytesV1)
	written, status := parent.nextControlV1(context.Background(), dst)
	if status != int32(productionSuccessV1) || written != 32 || dst[5] != byte(productionControlStoppedV1) {
		t.Fatalf("late ordinary publication written/status/kind=%d/%d/%d", written, status, dst[5])
	}
}

func TestProductionControlV1AdmittedPollCannotPublishOrdinaryAfterCancelFence(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	dst := bytes.Repeat([]byte{0x91}, productionControlMaxEventBytesV1)
	before := append([]byte(nil), dst...)
	type result struct {
		written int
		status  int32
	}
	done := make(chan result, 1)
	go func() {
		written, status := parent.nextControlV1(context.Background(), dst)
		done <- result{written: written, status: status}
	}()
	deadline := time.After(time.Second)
	for {
		parent.mu.Lock()
		active := parent.uses[productionUseControlPollV1].live
		parent.mu.Unlock()
		if active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("poll did not become active")
		default:
		}
	}
	parent.mu.Lock()
	installTestOrdinaryControlLockedV1(parent, productionControlTransportReadyV1, nil)
	parent.fenceLockedV1(productionCancelledV1)
	parent.mu.Unlock()
	parent.signalControlV1()
	got := <-done
	parent.cancel()
	if got.written != 0 || got.status != int32(productionCancelledV1) || !bytes.Equal(dst, before) {
		t.Fatalf("cancelled poll written/status/changed=%d/%d/%v", got.written, got.status, !bytes.Equal(dst, before))
	}
}

func TestProductionControlV1PrivateArenaWrapAndBytePressure(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	parent.mu.Lock()
	parent.controlWriteOffset = productionControlOrdinaryBytesV1 - 20
	if status := parent.enqueueOpaqueControlBytesLockedV1(40, 0x6d); status != int32(productionSuccessV1) {
		parent.mu.Unlock()
		t.Fatalf("wrapped opaque enqueue=%d", status)
	}
	desc := parent.controlDescriptors[parent.controlHead]
	if desc.offset != productionControlOrdinaryBytesV1-20 || desc.size != 40 {
		parent.mu.Unlock()
		t.Fatalf("wrapped descriptor=%+v", desc)
	}
	for index := 0; index < 20; index++ {
		if parent.controlArena[productionControlOrdinaryBytesV1-20+index] != 0x6d || parent.controlArena[index] != 0x6d {
			parent.mu.Unlock()
			t.Fatal("wrapped spans not copied")
		}
	}
	parent.clearOrdinaryControlLockedV1()
	if status := parent.enqueueOpaqueControlBytesLockedV1(productionControlOrdinaryBytesV1, 0x2a); status != int32(productionSuccessV1) {
		parent.mu.Unlock()
		t.Fatalf("exact ordinary bytes=%d", status)
	}
	if status := parent.enqueueOpaqueControlBytesLockedV1(1, 0x2b); status != int32(productionResourceLimitV1) {
		parent.mu.Unlock()
		t.Fatalf("ordinary max+1=%d", status)
	}
	parent.mu.Unlock()
}

func TestProductionControlV1FixedEncodeHasNoAllocationAfterWarmup(t *testing.T) {
	dst := make([]byte, productionControlMaxEventBytesV1)
	record := productionControlRecordV1{kind: productionControlMetricsUpdatedV1, epoch: 1, sequence: 1, body: productionControlBodyFixturesV1()[productionControlMetricsUpdatedV1]}
	if written, status := encodeProductionControlFixedV1(record, dst); written != 74 || status != int32(productionSuccessV1) {
		t.Fatalf("warmup=%d/%d", written, status)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		_, _ = encodeProductionControlFixedV1(record, dst)
	}); allocs != 0 {
		t.Fatalf("fixed encode allocations=%f", allocs)
	}
}

func TestProductionControlV1RevocationSupersedesOnlyUnobservedTerminal(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	for index := 0; index <= productionControlOrdinaryDescriptorsV1; index++ {
		_ = parent.enqueueControlFixedV1(productionControlTransportConnectingV1, nil)
	}
	if status := parent.enqueueControlFixedV1(productionControlRevokedV1, nil); status != int32(productionSuccessV1) {
		t.Fatalf("revoked=%d", status)
	}
	parent.mu.Lock()
	reason := parent.terminal
	parent.mu.Unlock()
	if reason != productionAuthorityRevokedV1 {
		t.Fatalf("unobserved overflow terminal was not superseded: %d", reason)
	}
	dst := make([]byte, productionControlMaxEventBytesV1)
	if _, status := parent.nextControlV1(context.Background(), dst); status != int32(productionSuccessV1) || dst[5] != byte(productionControlRevokedV1) {
		t.Fatalf("observed status/kind=%d/%d", status, dst[5])
	}
	if status := parent.enqueueControlFixedV1(productionControlFailedV1, []byte{0, byte(productionInternalFailureV1)}); status != int32(productionAuthorityRevokedV1) {
		t.Fatalf("post-observed enqueue=%d", status)
	}
	if _, status := parent.nextControlV1(context.Background(), dst); status != int32(productionAuthorityRevokedV1) {
		t.Fatalf("post-observed poll=%d", status)
	}

	observed := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	for index := 0; index <= productionControlOrdinaryDescriptorsV1; index++ {
		_ = observed.enqueueControlFixedV1(productionControlTransportConnectingV1, nil)
	}
	if _, status := observed.nextControlV1(context.Background(), dst); status != int32(productionSuccessV1) || dst[5] != byte(productionControlFailedV1) {
		t.Fatalf("observe overflow=%d/%d", status, dst[5])
	}
	if status := observed.enqueueControlFixedV1(productionControlRevokedV1, nil); status != int32(productionCancelledV1) {
		t.Fatalf("observed terminal rewritten status=%d", status)
	}
}

func TestProductionControlV1MetricsDoNotCoalesceAcrossAttempts(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	body := productionControlBodyFixturesV1()[productionControlMetricsUpdatedV1]
	if status := parent.enqueueControlFixedV1(productionControlMetricsUpdatedV1, body); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if epoch, status := parent.nextAttemptV1(); epoch != 2 || status != int32(productionSuccessV1) {
		t.Fatalf("advance=%d/%d", epoch, status)
	}
	if status := parent.enqueueControlFixedV1(productionControlMetricsUpdatedV1, body); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	dst := make([]byte, productionControlMaxEventBytesV1)
	for wantEpoch := uint64(1); wantEpoch <= 2; wantEpoch++ {
		if _, status := parent.nextControlV1(context.Background(), dst); status != int32(productionSuccessV1) || binary.BigEndian.Uint64(dst[12:20]) != wantEpoch {
			t.Fatalf("epoch %d got=%d status=%d", wantEpoch, binary.BigEndian.Uint64(dst[12:20]), status)
		}
	}
}

func TestProductionControlV1AllowsOnlyOnePollAndStoppedIsTerminal(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	done := make(chan int32, 1)
	go func() {
		_, status := parent.nextControlV1(context.Background(), make([]byte, productionControlMaxEventBytesV1))
		done <- status
	}()
	deadline := time.After(time.Second)
	for {
		parent.mu.Lock()
		active := parent.uses[productionUseControlPollV1].live
		parent.mu.Unlock()
		if active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("poll did not become active")
		default:
		}
	}
	if _, status := parent.nextControlV1(context.Background(), make([]byte, productionControlMaxEventBytesV1)); status != int32(productionResourceLimitV1) {
		t.Fatalf("second poll=%d", status)
	}
	if status := parent.enqueueControlFixedV1(productionControlStoppedV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	if status := <-done; status != int32(productionSuccessV1) {
		t.Fatalf("terminal poll=%d", status)
	}
	if _, status := parent.nextControlV1(context.Background(), make([]byte, productionControlMaxEventBytesV1)); status != int32(productionCancelledV1) {
		t.Fatalf("post-stopped poll=%d", status)
	}
}

func TestProductionControlV1WarmedEnqueueDequeueHasNoAllocation(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	body := productionControlBodyFixturesV1()[productionControlMetricsUpdatedV1]
	dst := make([]byte, productionControlMaxEventBytesV1)
	failed := false
	if allocs := testing.AllocsPerRun(1000, func() {
		if parent.enqueueControlFixedV1(productionControlMetricsUpdatedV1, body) != int32(productionSuccessV1) {
			failed = true
			return
		}
		parent.mu.Lock()
		_, status := parent.dequeueControlLockedV1(dst)
		parent.mu.Unlock()
		if status != int32(productionSuccessV1) {
			failed = true
		}
	}); allocs != 0 || failed {
		t.Fatalf("fixed enqueue/dequeue allocations=%f failed=%v", allocs, failed)
	}
}

func TestProductionControlV1SequenceExhaustionPublishesFinalFailure(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	parent.nextControlSequence = math.MaxUint64
	if status := parent.enqueueControlFixedV1(productionControlTransportReadyV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	dst := make([]byte, productionControlMaxEventBytesV1)
	written, status := parent.nextControlV1(context.Background(), dst)
	if status != int32(productionSuccessV1) || written != 34 || dst[5] != byte(productionControlFailedV1) ||
		binary.BigEndian.Uint64(dst[20:28]) != math.MaxUint64 || binary.BigEndian.Uint16(dst[32:34]) != uint16(productionInternalFailureV1) {
		t.Fatalf("written/status/kind/seq/body=%d/%d/%d/%d/%x", written, status, dst[5], binary.BigEndian.Uint64(dst[20:28]), dst[32:written])
	}
	select {
	case <-parent.cancelContext.Done():
	default:
		t.Fatal("sequence exhaustion did not cancel the parent context")
	}
}

func TestProductionControlV1EmptyDeadlineAndCancelWake(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	start := time.Now()
	if written, status := parent.nextControlV1(context.Background(), make([]byte, productionControlMaxEventBytesV1)); written != 0 || status != int32(productionNoEventV1) {
		t.Fatalf("empty written/status=%d/%d", written, status)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("empty poll elapsed=%s", elapsed)
	}

	wakeParent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	done := make(chan int32, 1)
	go func() {
		_, status := wakeParent.nextControlV1(context.Background(), make([]byte, productionControlMaxEventBytesV1))
		done <- status
	}()
	deadline := time.After(time.Second)
	for {
		wakeParent.mu.Lock()
		active := wakeParent.uses[productionUseControlPollV1].live
		wakeParent.mu.Unlock()
		if active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("poll did not become active")
		default:
		}
	}
	if status := wakeParent.cancelV1(int32(productionCancelledV1)); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	select {
	case status := <-done:
		if status != int32(productionCancelledV1) {
			t.Fatalf("cancel wake=%d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not wake poll")
	}
}

func TestProductionControlV1DeadlineFencesQueuedOrdinaryEvent(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	if status := parent.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	parent.mu.Lock()
	parent.deadline = time.Now().Add(-time.Millisecond)
	parent.mu.Unlock()
	dst := bytes.Repeat([]byte{0x44}, productionControlMaxEventBytesV1)
	before := append([]byte(nil), dst...)
	if written, status := parent.nextControlV1(context.Background(), dst); written != 0 || status != int32(productionAuthorityExpiredV1) || !bytes.Equal(dst, before) {
		t.Fatalf("expired queued event written/status/changed=%d/%d/%v", written, status, !bytes.Equal(dst, before))
	}
}

func TestProductionControlV1CanceledCallerCannotPublishQueuedEvent(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	if status := parent.enqueueControlFixedV1(productionControlTransportReadyV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := bytes.Repeat([]byte{0x52}, productionControlMaxEventBytesV1)
	before := append([]byte(nil), dst...)
	if written, status := parent.nextControlV1(ctx, dst); written != 0 || status != int32(productionTimeoutV1) || !bytes.Equal(dst, before) {
		t.Fatalf("canceled queued publication written/status/changed=%d/%d/%v", written, status, !bytes.Equal(dst, before))
	}
}

func TestProductionControlV1AuthorityCrossingFencesAdmittedPollPublication(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	dst := bytes.Repeat([]byte{0x73}, productionControlMaxEventBytesV1)
	before := append([]byte(nil), dst...)
	type result struct {
		written int
		status  int32
	}
	done := make(chan result, 1)
	go func() {
		written, status := parent.nextControlV1(context.Background(), dst)
		done <- result{written: written, status: status}
	}()
	deadline := time.After(time.Second)
	for {
		parent.mu.Lock()
		active := parent.uses[productionUseControlPollV1].live
		parent.mu.Unlock()
		if active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("poll did not become active")
		default:
		}
	}
	parent.mu.Lock()
	installTestOrdinaryControlLockedV1(parent, productionControlTransportReadyV1, nil)
	parent.deadline = time.Now().Add(-time.Millisecond)
	parent.mu.Unlock()
	parent.signalControlV1()
	got := <-done
	if got.written != 0 || got.status != int32(productionAuthorityExpiredV1) || !bytes.Equal(dst, before) {
		t.Fatalf("authority-crossed poll written/status/changed=%d/%d/%v", got.written, got.status, !bytes.Equal(dst, before))
	}
}

func TestProductionControlV1SizeLimitRetryRetainsOriginalPollDeadline(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	if status := parent.enqueueControlFixedV1(productionControlTransportReadyV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	tiny := bytes.Repeat([]byte{0x84}, productionControlHeaderBytesV1-1)
	if written, status := parent.nextControlV1(context.Background(), tiny); written != 0 || status != int32(productionSizeLimitV1) {
		t.Fatalf("initial short buffer=%d/%d", written, status)
	}
	if status := parent.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	parent.mu.Lock()
	deadline := parent.controlRetryDeadline
	retryStatus := parent.controlRetryStatus
	head, tail := parent.controlHead, parent.controlTail
	count, storedBytes := parent.controlCount, parent.controlBytes
	writeOffset, sequence := parent.controlWriteOffset, parent.nextControlSequence
	first := parent.controlDescriptors[head]
	second := parent.controlDescriptors[(head+1)%productionControlOrdinaryDescriptorsV1]
	stored := append([]byte(nil), parent.controlArena[:2*productionControlHeaderBytesV1]...)
	parent.mu.Unlock()
	waitUntilAfterControlRetryDeadlineV1(t, deadline)
	dst := bytes.Repeat([]byte{0x85}, productionControlMaxEventBytesV1)
	before := append([]byte(nil), dst...)
	for retry := 1; retry <= 2; retry++ {
		if written, status := parent.nextControlV1(context.Background(), dst); written != 0 || status != int32(productionTimeoutV1) || !bytes.Equal(dst, before) {
			t.Fatalf("retry %d deadline written/status/changed=%d/%d/%v", retry, written, status, !bytes.Equal(dst, before))
		}
	}
	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.controlHead != head || parent.controlTail != tail || parent.controlCount != count || parent.controlBytes != storedBytes ||
		parent.controlWriteOffset != writeOffset || parent.nextControlSequence != sequence ||
		parent.controlDescriptors[head] != first || parent.controlDescriptors[(head+1)%productionControlOrdinaryDescriptorsV1] != second ||
		!bytes.Equal(parent.controlArena[:2*productionControlHeaderBytesV1], stored) ||
		!parent.controlRetryDeadline.Equal(deadline) || parent.controlRetryStatus != retryStatus {
		t.Fatalf("expired retry changed queued state head/tail/count/bytes/write/sequence/retry=%d/%d/%d/%d/%d/%d/%v/%d", parent.controlHead, parent.controlTail, parent.controlCount, parent.controlBytes, parent.controlWriteOffset, parent.nextControlSequence, parent.controlRetryDeadline, parent.controlRetryStatus)
	}
}

func TestProductionControlV1TerminalRetryRetainsExpiredBoundary(t *testing.T) {
	tests := []struct {
		name     string
		boundary string
		want     productionStatusV1
	}{
		{name: "poll", boundary: "poll", want: productionTimeoutV1},
		{name: "caller", boundary: "caller", want: productionTimeoutV1},
		{name: "authority", boundary: "authority", want: productionAuthorityExpiredV1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
			if status := parent.enqueueControlFixedV1(productionControlStoppedV1, nil); status != int32(productionSuccessV1) {
				t.Fatal(status)
			}
			ctx := context.Background()
			cancel := func() {}
			switch test.boundary {
			case "caller":
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))
			case "authority":
				parent.mu.Lock()
				parent.deadline = time.Now().Add(100 * time.Millisecond)
				parent.mu.Unlock()
			}
			defer cancel()
			tiny := bytes.Repeat([]byte{0x91}, productionControlHeaderBytesV1-1)
			if written, status := parent.nextControlV1(ctx, tiny); written != 0 || status != int32(productionSizeLimitV1) {
				t.Fatalf("initial short buffer=%d/%d", written, status)
			}
			parent.mu.Lock()
			deadline := parent.controlRetryDeadline
			retryStatus := parent.controlRetryStatus
			descriptor := parent.terminalControl
			sequence := parent.nextControlSequence
			stored := append([]byte(nil), parent.controlArena[descriptor.offset:descriptor.offset+descriptor.size]...)
			parent.mu.Unlock()
			waitUntilAfterControlRetryDeadlineV1(t, deadline)
			dst := bytes.Repeat([]byte{0x92}, productionControlMaxEventBytesV1)
			before := append([]byte(nil), dst...)
			for retry := 1; retry <= 2; retry++ {
				if written, status := parent.nextControlV1(context.Background(), dst); written != 0 || status != int32(test.want) || !bytes.Equal(dst, before) {
					t.Fatalf("retry %d written/status/changed=%d/%d/%v", retry, written, status, !bytes.Equal(dst, before))
				}
			}
			parent.mu.Lock()
			defer parent.mu.Unlock()
			if !parent.terminalControlSet || parent.terminalControlObserved || parent.terminalControl != descriptor ||
				parent.nextControlSequence != sequence || !bytes.Equal(parent.controlArena[descriptor.offset:descriptor.offset+descriptor.size], stored) ||
				!parent.controlRetryDeadline.Equal(deadline) || parent.controlRetryStatus != retryStatus {
				t.Fatalf("expired terminal retry changed pending state set/observed/sequence/retry=%v/%v/%d/%v/%d", parent.terminalControlSet, parent.terminalControlObserved, parent.nextControlSequence, parent.controlRetryDeadline, parent.controlRetryStatus)
			}
		})
	}
}

func waitUntilAfterControlRetryDeadlineV1(t *testing.T, deadline time.Time) {
	t.Helper()
	if deadline.IsZero() {
		t.Fatal("retry deadline was not recorded")
	}
	delay := time.Until(deadline) + 25*time.Millisecond
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	<-timer.C
}

func TestProductionControlV1PostJoinTerminalCopyDoesNotReopenCountedUse(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	if status := parent.enqueueControlFixedV1(productionControlStoppedV1, nil); status != int32(productionSuccessV1) {
		t.Fatal(status)
	}
	select {
	case <-parent.joined:
	default:
		t.Fatal("idle cancellation did not close joined")
	}
	parent.budget.mu.Lock()
	type result struct {
		written int
		status  int32
	}
	pollDone := make(chan result, 1)
	go func() {
		dst := make([]byte, productionControlMaxEventBytesV1)
		written, status := parent.nextControlV1(context.Background(), dst)
		pollDone <- result{written: written, status: status}
	}()
	joinDone := make(chan int32, 1)
	go func() { joinDone <- parent.joinV1(context.Background()) }()
	if status := <-joinDone; status != int32(productionSuccessV1) {
		parent.budget.mu.Unlock()
		t.Fatalf("concurrent join=%d", status)
	}
	select {
	case got := <-pollDone:
		parent.budget.mu.Unlock()
		if got.written != 32 || got.status != int32(productionSuccessV1) {
			t.Fatalf("terminal copy=%d/%d", got.written, got.status)
		}
	case <-time.After(200 * time.Millisecond):
		parent.budget.mu.Unlock()
		got := <-pollDone
		t.Fatalf("terminal copy reopened counted budget use before completing: %d/%d", got.written, got.status)
	}
	parent.mu.Lock()
	active := parent.activeUses
	joinedClosed := parent.joinedClosed
	parent.mu.Unlock()
	if active != 0 || !joinedClosed {
		t.Fatalf("post-terminal active/joined=%d/%v", active, joinedClosed)
	}
}
