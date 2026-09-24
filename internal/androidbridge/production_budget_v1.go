// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"math"
	"sync"
)

const (
	productionBudgetMaximumOwnedV1  = uint64(128 * 1024 * 1024)
	productionBudgetMaximumQueuedV1 = uint64(16 * 1024 * 1024)
	productionBudgetRecordCountV1   = 256
)

type productionBudgetChargeV1 struct {
	owned  uint64
	queued uint64
}

type productionBudgetTicketV1 struct {
	ledger *productionBudgetV1
	index  uint16
	serial uint64
}

type productionBudgetRecordV1 struct {
	serial uint64
	charge productionBudgetChargeV1
	live   bool
}

type productionBudgetV1 struct {
	mu      sync.Mutex
	cap     uint64
	owned   uint64
	queued  uint64
	records [productionBudgetRecordCountV1]productionBudgetRecordV1
}

func newProductionBudgetV1(capacity uint64) (*productionBudgetV1, int32) {
	if capacity == 0 || capacity > productionBudgetMaximumOwnedV1 {
		return nil, int32(productionInvalidRequestV1)
	}
	fixed, status := productionParentFixedBytesV1()
	if status != int32(productionSuccessV1) {
		return nil, status
	}
	if capacity < fixed {
		return nil, int32(productionSizeLimitV1)
	}
	ledger := &productionBudgetV1{cap: capacity, owned: fixed}
	ledger.records[0] = productionBudgetRecordV1{
		serial: 1,
		charge: productionBudgetChargeV1{owned: fixed},
		live:   true,
	}
	return ledger, int32(productionSuccessV1)
}

func (ledger *productionBudgetV1) reserveV1(charge productionBudgetChargeV1) (productionBudgetTicketV1, int32) {
	if ledger == nil {
		return productionBudgetTicketV1{}, int32(productionInvalidStateV1)
	}
	if charge.queued > charge.owned {
		return productionBudgetTicketV1{}, int32(productionInvalidRequestV1)
	}
	if charge.queued > productionBudgetMaximumQueuedV1 {
		return productionBudgetTicketV1{}, int32(productionResourceLimitV1)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if charge.owned > ledger.cap || ledger.owned > ledger.cap-charge.owned ||
		charge.queued > productionBudgetMaximumQueuedV1-ledger.queued ||
		ledger.owned > math.MaxUint64-charge.owned || ledger.queued > math.MaxUint64-charge.queued {
		return productionBudgetTicketV1{}, int32(productionResourceLimitV1)
	}
	for index := 1; index < len(ledger.records); index++ {
		record := &ledger.records[index]
		if record.live || record.serial == math.MaxUint64 {
			continue
		}
		record.serial++
		record.charge = charge
		record.live = true
		ledger.owned += charge.owned
		ledger.queued += charge.queued
		return productionBudgetTicketV1{ledger: ledger, index: uint16(index), serial: record.serial}, int32(productionSuccessV1)
	}
	return productionBudgetTicketV1{}, int32(productionResourceLimitV1)
}

func (ledger *productionBudgetV1) releaseV1(ticket productionBudgetTicketV1) int32 {
	if ledger == nil || ticket.ledger != ledger || ticket.index == 0 || int(ticket.index) >= len(ledger.records) || ticket.serial == 0 {
		return int32(productionInvalidStateV1)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record := &ledger.records[ticket.index]
	if !record.live || record.serial != ticket.serial {
		return int32(productionInvalidStateV1)
	}
	if record.charge.owned > ledger.owned || record.charge.queued > ledger.queued {
		return int32(productionInternalFailureV1)
	}
	ledger.owned -= record.charge.owned
	ledger.queued -= record.charge.queued
	record.charge = productionBudgetChargeV1{}
	record.live = false
	return int32(productionSuccessV1)
}

func (ledger *productionBudgetV1) chargeV1(ticket productionBudgetTicketV1) (productionBudgetChargeV1, int32) {
	if ledger == nil || ticket.ledger != ledger || ticket.index == 0 || int(ticket.index) >= len(ledger.records) || ticket.serial == 0 {
		return productionBudgetChargeV1{}, int32(productionInvalidStateV1)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record := &ledger.records[ticket.index]
	if !record.live || record.serial != ticket.serial {
		return productionBudgetChargeV1{}, int32(productionInvalidStateV1)
	}
	return record.charge, int32(productionSuccessV1)
}
