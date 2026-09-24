// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"errors"
	"math"
	"testing"
	"time"
)

func productionFlowKeyFixtureV1(protocol byte, port uint16) productionFlowKeyV1 {
	return productionFlowKeyV1{family: 4, protocol: protocol, source: [16]byte{10, 0, 0, 2}, destination: [16]byte{8, 8, 8, 8}, sourcePort: port, destinationPort: 53}
}

func TestProductionFlowV1PinsQueueAndWriteLifetime(t *testing.T) {
	f, err := newProductionFlowTableV1(1, 0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.destroyV1)
	now := time.Now()
	a := productionFlowKeyFixtureV1(6, 1)
	b := productionFlowKeyFixtureV1(6, 2)
	r, err := f.reserveV1(a, now)
	if err != nil {
		t.Fatal(err)
	}
	f.acceptV1(r, now)
	second, err := f.reserveV1(a, now.Add(2*time.Second))
	if err != nil || r != second {
		t.Fatal("existing referenced tuple must survive expiry", err)
	}
	if _, err = f.reserveV1(b, now.Add(2*time.Second)); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("in-flight tuple evicted", err)
	}
	f.releaseV1(r)
	if _, err = f.reserveV1(b, now.Add(2*time.Second)); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("premature release", err)
	}
	f.releaseV1(second)
	successor, err := f.reserveV1(b, now.Add(2*time.Second))
	if err != nil || successor == r {
		t.Fatal("successor generation", err)
	}
	f.releaseV1(r)
	if _, err = f.reserveV1(a, now.Add(3*time.Second)); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("stale reference retired successor", err)
	}
	f.releaseV1(successor)
	if _, err = f.reserveV1(a, now.Add(3*time.Second)); err != nil {
		t.Fatal("unused tentative lease leaked", err)
	}
}

func TestProductionFlowV1SeparateLimitsAndCommitReceipt(t *testing.T) {
	f, err := newProductionFlowTableV1(1, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.destroyV1)
	now := time.Now()
	tcp, udp := productionFlowKeyFixtureV1(6, 1), productionFlowKeyFixtureV1(17, 1)
	r, _ := f.reserveV1(tcp, now)
	f.acceptV1(r, now)
	f.releaseV1(r)
	u, err := f.reserveV1(udp, now)
	if err != nil {
		t.Fatal("independent UDP", err)
	}
	f.releaseV1(u)
	receipt := f.lookupV1(tcp, now.Add(time.Second/2))
	if receipt != r {
		t.Fatal("receipt")
	}
	f.refreshV1(receipt, now.Add(time.Second/2))
	if _, err = f.reserveV1(productionFlowKeyFixtureV1(6, 2), now.Add(time.Second)); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("committed return not refreshed")
	}
	successor, err := f.reserveV1(productionFlowKeyFixtureV1(6, 2), now.Add(1500*time.Millisecond))
	if err != nil {
		t.Fatal("exact expiry", err)
	}
	f.acceptV1(successor, now.Add(1500*time.Millisecond))
	f.releaseV1(successor)
	f.refreshV1(receipt, now.Add(2*time.Second))
	if _, err = f.reserveV1(tcp, now.Add(2500*time.Millisecond)); err != nil {
		t.Fatal("stale receipt refreshed successor", err)
	}
	if got := f.lookupV1(productionFlowKeyFixtureV1(17, 3), now); got != (productionFlowRefV1{}) {
		t.Fatal("unknown return acquired lease")
	}
}

func TestProductionFlowV1MaximumStorageAndIdentityExhaustion(t *testing.T) {
	f, err := newProductionFlowTableV1(4096, 2048, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.destroyV1)
	if f.ownedBytesV1() > 1048576 || cap(f.entries) != 6144 || cap(f.index) > 16384 {
		t.Fatal("unbounded backing")
	}
	t.Logf("actual flow owned=%d entries=%d index=%d free=%d", f.ownedBytesV1(), cap(f.entries), cap(f.index), cap(f.free))
	now := time.Now()
	for _, protocol := range []byte{6, 17} {
		count := 4096
		if protocol == 17 {
			count = 2048
		}
		for n := 1; n <= count; n++ {
			r, e := f.reserveV1(productionFlowKeyFixtureV1(protocol, uint16(n)), now)
			if e != nil {
				t.Fatal(n, e)
			}
			f.acceptV1(r, now)
			f.releaseV1(r)
		}
		if _, e := f.reserveV1(productionFlowKeyFixtureV1(protocol, uint16(count+1)), now); !errors.Is(e, ServiceResourceLimitV1) {
			t.Fatal("protocol exceeded cap", e)
		}
	}
	f.destroyV1()
	if f.ownedBytesV1() != 0 {
		t.Fatal("joined destroy retained backing")
	}
	f, _ = newProductionFlowTableV1(1, 0, time.Second)
	defer f.destroyV1()
	f.nextGeneration = math.MaxUint64
	if _, e := f.reserveV1(productionFlowKeyFixtureV1(6, 1), now); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("generation wrapped", e)
	}
	if _, e := f.reserveV1(productionFlowKeyFixtureV1(17, 1), now); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("UDP zero", e)
	}
}
