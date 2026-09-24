// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"errors"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	runtimeengine "kurdistan/internal/runtime"
	"sync"
	"time"
	"unsafe"
)

// The containing current-authority path supplies the real 5a projection and
// disjoint parent residual. This private wrapper is not an opening factory,
// a current-revision receipt, or a decoder for a display-only KPN snapshot.
type productionResourcesV1 struct {
	mu                                              sync.Mutex
	self                                            *productionResourcesV1
	installation                                    *runtimeengine.ProductionClientInstallationV1
	ledger                                          *productionBudgetV1
	preparation, remainder                          productionBudgetTicketV1
	destroyed                                       bool
	done                                            chan struct{}
	status                                          int32
	owner                                           *productionAdmissionV1
	generation                                      uint64
	proxyRetainedBytes, proxyCeilingBytes           uint64
	attachmentScratchBytes, attachmentScratchSerial uint64
}

func productionResourcesHolderBytesV1() uint64 {
	return uint64(unsafe.Sizeof(productionResourcesV1{})) + productionRuntimeMetadataAllowanceV1
}

// available excludes parent/control/authority/credentials/rates/operations and
// the still-borrowed projection backing. Runtime separately charges its detached
// Plan/program copy, so the overlap with that projection is never free.
func prepareProductionResourcesV1(p *productionProjectionV1, ledger *productionBudgetV1, available runtimeengine.ProductionClientAvailableV1, now time.Time, generation uint64) (result *productionResourcesV1, resultStatus int32) {
	if p == nil || ledger == nil || generation == 0 || now.IsZero() {
		return nil, int32(productionInvalidRequestV1)
	}
	holder := productionResourcesHolderBytesV1()
	facts, ok := p.plan.ConstructionFactsV2()
	if !ok {
		return nil, int32(productionResourceLimitV1)
	}
	calculation, ok := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	if !ok || available.AggregateBytes < holder+calculation.SuffixBytes {
		return nil, int32(productionResourceLimitV1)
	}
	proxy := p.effectiveMode != 1
	if proxy && (available.ProxyBytes <= holder || calculation.SuffixBytes > available.ProxyBytes-holder) {
		return nil, int32(productionResourceLimitV1)
	}
	preparation, status := ledger.reserveV1(productionBudgetChargeV1{owned: holder})
	if status != 0 {
		return nil, status
	}
	retained := false
	var remainder productionBudgetTicketV1
	defer func() {
		if !retained {
			if remainder.serial != 0 {
				ledger.releaseV1(remainder)
			}
			ledger.releaseV1(preparation)
		}
	}()
	remainder, status = ledger.reserveV1(productionBudgetChargeV1{owned: calculation.SuffixBytes})
	if status != 0 {
		return nil, status
	}
	policy, e := p.plan.RuntimePolicyAt(now)
	defer policy.Destroy()
	if e != nil || (policy.SchemaVersion != runtimepolicy.SchemaVersionV3 && policy.SchemaVersion != runtimepolicy.SchemaVersionV2) {
		return nil, int32(productionNotAdmittedV1)
	}
	raw := policy.SchemaVersion == runtimepolicy.SchemaVersionV2 && policy.Services == nil
	h := uint8(0)
	if policy.Services != nil && policy.Services.Probes != nil {
		for _, target := range policy.Services.Probes.Targets {
			for _, mode := range target.Modes {
				if mode == uint8(runtimeengine.ProbeActiveRelayV1) {
					h = min(4, policy.Services.Probes.MaxConcurrentOperations)
				}
			}
		}
	}
	policy.Destroy() // Decoder result is retired before construction-ticket transition.
	n := runtimeengine.ProductionClientNarrowingV1{Mode: runtimeengine.ProductionClientModeV1(p.effectiveMode), SessionIdle: time.Duration(p.effectiveSessionIdleMillis) * time.Millisecond, FlowIdle: time.Duration(p.effectiveFlowIdleMillis) * time.Millisecond, ProxyIdle: time.Duration(p.effectiveProxyIdleSeconds) * time.Second, TCPFlows: p.effectiveTCPFlowMax, UDPFlows: p.effectiveUDPFlowMax, StreamLimit: p.effectiveStreamMax, ProbeLimit: h, StreamQueueBytes: p.perDirectionQueueBytes, AggregateCeilingBytes: uint64(p.effectiveAggregateBufferBytes), ProxyCeilingBytes: uint64(p.effectiveProxyBufferBytes)}
	available.AggregateBytes -= holder
	if proxy {
		available.ProxyBytes -= holder
	}
	// Atomically replace scratch with an exclusive construction envelope. The
	// runtime's own preallocation checks spend this same residual, not free bytes.
	if status = resizeProductionResourceTicketV1(ledger, remainder, productionBudgetChargeV1{owned: available.AggregateBytes}); status != 0 {
		return nil, status
	}
	var recipe *runtimeengine.ProductionClientRecipeV1
	if raw {
		recipe, e = runtimeengine.PrepareProductionClientRawPacketV2(p.plan, n, available, now, generation)
	} else {
		recipe, e = runtimeengine.PrepareProductionClientServiceV1(p.plan, n, available, now, generation)
	}
	if e != nil {
		return nil, productionResourceStatusV1(e)
	}
	defer func() {
		if recipe.Close() != nil {
			retained = true
			result = nil
			resultStatus = int32(productionInternalFailureV1)
		}
	}()
	reservation, e := recipe.ReservationV1()
	if e != nil {
		return nil, productionResourceStatusV1(e)
	}
	if reservation.OwnedBytes > available.AggregateBytes || reservation.ProxyAttributedBytes > available.ProxyBytes {
		return nil, int32(productionInternalFailureV1)
	}
	// Construction temporaries have retired. Keep precisely returned lifetime
	// owned/queued bytes; proxy attribution stays independently bounded above.
	status = resizeProductionResourceTicketV1(ledger, remainder, productionBudgetChargeV1{owned: reservation.OwnedBytes, queued: reservation.QueuedBytes})
	if status != 0 {
		return nil, status
	}
	i, e := recipe.InstallV1()
	if e != nil {
		return nil, productionResourceStatusV1(e)
	}
	result = &productionResourcesV1{installation: i, ledger: ledger, preparation: preparation, remainder: remainder, done: make(chan struct{})}
	if proxy {
		result.proxyRetainedBytes = holder + reservation.ProxyAttributedBytes
		result.proxyCeilingBytes = uint64(p.effectiveProxyBufferBytes)
	}
	result.self = result
	// The recipe owns detached bytes; no borrowed Plan remains after Prepare.
	p.Destroy()
	retained = true
	return result, int32(productionSuccessV1)
}

// Both ownership categories transition atomically with no release/reacquire gap.
func resizeProductionResourceTicketV1(ledger *productionBudgetV1, ticket productionBudgetTicketV1, charge productionBudgetChargeV1) int32 {
	if ledger == nil || ticket.ledger != ledger || ticket.index == 0 || int(ticket.index) >= len(ledger.records) || charge.queued > charge.owned {
		return int32(productionInvalidStateV1)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record := &ledger.records[ticket.index]
	if !record.live || record.serial != ticket.serial || record.charge.owned > ledger.owned || record.charge.queued > ledger.queued {
		return int32(productionInvalidStateV1)
	}
	owned, queued := ledger.owned-record.charge.owned, ledger.queued-record.charge.queued
	if charge.owned > ledger.cap || owned > ledger.cap-charge.owned || charge.queued > productionBudgetMaximumQueuedV1 || queued > productionBudgetMaximumQueuedV1-charge.queued {
		return int32(productionResourceLimitV1)
	}
	ledger.owned = owned + charge.owned
	ledger.queued = queued + charge.queued
	record.charge = charge
	return 0
}

func (r *productionResourcesV1) destroyV1() int32 {
	if r == nil || r.self != r {
		return int32(productionInvalidStateV1)
	}
	r.mu.Lock()
	if r.destroyed {
		done := r.done
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		status := r.status
		r.mu.Unlock()
		return status
	}
	// Single close owner; installation Close handles concurrent owner uses and
	// joins outside this wrapper lock before either ledger record is released.
	r.destroyed = true
	i := r.installation
	r.mu.Unlock()
	status := int32(productionSuccessV1)
	defer func() { r.mu.Lock(); r.status = status; r.mu.Unlock(); close(r.done) }()
	if e := i.Close(); e != nil {
		status = productionResourceStatusV1(e)
		return status
	}
	<-i.Done()
	a := r.ledger.releaseV1(r.remainder)
	b := r.ledger.releaseV1(r.preparation)
	if a != 0 || b != 0 {
		status = int32(productionInternalFailureV1)
		return status
	}
	return int32(productionSuccessV1)
}

func productionResourceStatusV1(e error) int32 {
	switch {
	case errors.Is(e, runtimeengine.ServiceNotAdmittedV1):
		return int32(productionNotAdmittedV1)
	case errors.Is(e, runtimeengine.ServiceInvalidRequestV1):
		return int32(productionInvalidRequestV1)
	case errors.Is(e, runtimeengine.ServiceResourceLimitV1):
		return int32(productionResourceLimitV1)
	case errors.Is(e, runtimeengine.ServiceAuthorityExpiredV1):
		return int32(productionAuthorityExpiredV1)
	case errors.Is(e, runtimeengine.ServiceCancelledV1):
		return int32(productionCancelledV1)
	case errors.Is(e, runtimeengine.ErrProfileIncompatible):
		return int32(productionIncompatibleV1)
	default:
		return int32(productionInternalFailureV1)
	}
}
