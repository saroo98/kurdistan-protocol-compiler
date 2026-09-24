// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"math"
	"testing"
)

func TestProductionBudgetV1FixedCapacityBoundaries(t *testing.T) {
	fixed, status := productionParentFixedBytesV1()
	if status != int32(productionSuccessV1) || fixed == 0 {
		t.Fatalf("fixed bytes=(%d,%d)", fixed, status)
	}
	if _, status := newProductionBudgetV1(fixed - 1); status != int32(productionSizeLimitV1) {
		t.Fatalf("one-under status=%d", status)
	}
	ledger, status := newProductionBudgetV1(fixed)
	if status != int32(productionSuccessV1) {
		t.Fatalf("exact status=%d", status)
	}
	if ledger.owned != fixed || ledger.queued != 0 || !ledger.records[0].live {
		t.Fatalf("fixed reservation owned=%d queued=%d live=%v", ledger.owned, ledger.queued, ledger.records[0].live)
	}
	if _, status := newProductionBudgetV1(128*1024*1024 + 1); status != int32(productionInvalidRequestV1) {
		t.Fatalf("max+1 status=%d", status)
	}
}

func TestProductionBudgetV1ChargeLimitsAreAtomic(t *testing.T) {
	fixed, _ := productionParentFixedBytesV1()
	ledger, _ := newProductionBudgetV1(128 * 1024 * 1024)
	cases := []struct {
		name   string
		charge productionBudgetChargeV1
		want   productionStatusV1
	}{
		{"queued-max", productionBudgetChargeV1{owned: 16 * 1024 * 1024, queued: 16 * 1024 * 1024}, productionSuccessV1},
		{"queued-max-plus-one", productionBudgetChargeV1{owned: 16*1024*1024 + 1, queued: 16*1024*1024 + 1}, productionResourceLimitV1},
		{"queued-over-owned", productionBudgetChargeV1{owned: 1, queued: 2}, productionInvalidRequestV1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			beforeOwned, beforeQueued := ledger.owned, ledger.queued
			ticket, status := ledger.reserveV1(tc.charge)
			if status != int32(tc.want) {
				t.Fatalf("status=%d want=%d", status, tc.want)
			}
			if tc.want != productionSuccessV1 {
				if ledger.owned != beforeOwned || ledger.queued != beforeQueued {
					t.Fatalf("failed reserve mutated counters to %d/%d", ledger.owned, ledger.queued)
				}
				return
			}
			if charge, status := ledger.chargeV1(ticket); status != int32(productionSuccessV1) || charge != tc.charge {
				t.Fatalf("charge=(%+v,%d)", charge, status)
			}
			if status := ledger.releaseV1(ticket); status != int32(productionSuccessV1) {
				t.Fatalf("release=%d", status)
			}
		})
	}
	ledger.mu.Lock()
	ledger.owned = math.MaxUint64
	beforeQueued := ledger.queued
	ledger.mu.Unlock()
	if _, status := ledger.reserveV1(productionBudgetChargeV1{owned: 1}); status != int32(productionResourceLimitV1) {
		t.Fatalf("overflow status=%d", status)
	}
	if ledger.owned != math.MaxUint64 || ledger.queued != beforeQueued || fixed == 0 {
		t.Fatal("overflow changed counters")
	}
}

func TestProductionBudgetV1BoundedTicketsAndStaleIdentity(t *testing.T) {
	ledger, _ := newProductionBudgetV1(128 * 1024 * 1024)
	other, _ := newProductionBudgetV1(128 * 1024 * 1024)
	tickets := make([]productionBudgetTicketV1, len(ledger.records)-1)
	for index := range tickets {
		ticket, status := ledger.reserveV1(productionBudgetChargeV1{})
		if status != int32(productionSuccessV1) {
			t.Fatalf("reserve %d status=%d", index, status)
		}
		tickets[index] = ticket
	}
	if _, status := ledger.reserveV1(productionBudgetChargeV1{}); status != int32(productionResourceLimitV1) {
		t.Fatalf("full status=%d", status)
	}
	first := tickets[0]
	if status := other.releaseV1(first); status != int32(productionInvalidStateV1) {
		t.Fatalf("cross-ledger release=%d", status)
	}
	if status := ledger.releaseV1(first); status != int32(productionSuccessV1) {
		t.Fatalf("release=%d", status)
	}
	if status := ledger.releaseV1(first); status != int32(productionInvalidStateV1) {
		t.Fatalf("double release=%d", status)
	}
	replacement, status := ledger.reserveV1(productionBudgetChargeV1{})
	if status != int32(productionSuccessV1) || replacement.index != first.index || replacement.serial == first.serial {
		t.Fatalf("replacement=%+v status=%d first=%+v", replacement, status, first)
	}
	if _, status := ledger.chargeV1(first); status != int32(productionInvalidStateV1) {
		t.Fatalf("stale charge=%d", status)
	}
}

func TestProductionBudgetV1SerialSaturationRetiresRecord(t *testing.T) {
	ledger, _ := newProductionBudgetV1(128 * 1024 * 1024)
	ledger.mu.Lock()
	for index := 1; index < len(ledger.records); index++ {
		ledger.records[index].serial = math.MaxUint64
	}
	ledger.mu.Unlock()
	if _, status := ledger.reserveV1(productionBudgetChargeV1{}); status != int32(productionResourceLimitV1) {
		t.Fatalf("saturated status=%d", status)
	}
}
