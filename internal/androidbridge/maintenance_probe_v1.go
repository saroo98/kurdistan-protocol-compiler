// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"errors"
	"kurdistan/internal/runtime"
	"net"
	"net/netip"
	"time"
)

func RunMaintenanceProbeV1(registry *HandleRegistry, parent Handle, request runtime.ProbeRequestV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
	return RunMaintenanceProbeV1Scoped(registry, parent, request, MaintenanceOutputInvocationV1{})
}
func RunMaintenanceProbeV1Scoped(registry *HandleRegistry, parent Handle, request runtime.ProbeRequestV1, inv MaintenanceOutputInvocationV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
	return runMaintenanceProbeV1Scoped(registry, parent, request, inv, nil)
}

func runMaintenanceProbeV1Scoped(registry *HandleRegistry, parent Handle, request runtime.ProbeRequestV1, inv MaintenanceOutputInvocationV1, route maintenanceNumericRouteV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
	p, r := maintenanceParentOutputV1(registry, parent, inv)
	if r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	op, r := p.beginOperationOutputV1(inv, false)
	if r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	defer p.finishOperation(op)
	if request.TargetID == 0 || request.Samples < 1 || request.Samples > 10 || request.AttemptTimeoutMillis < 1000 || request.AttemptTimeoutMillis > 30000 || request.TotalTimeoutMillis < 1000 || request.TotalTimeoutMillis > 30000 {
		return runtime.ProbeAggregateV1{}, MaintenanceInvalidRequest
	}
	if request.Method != 1 {
		return runtime.ProbeAggregateV1{}, MaintenanceNotAdmitted
	}
	if p.network == nil {
		return runtime.ProbeAggregateV1{}, MaintenanceNetworkUnavailable
	}
	if r = p.revalidatePlatform(op); r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	now, mono, r := p.trustedNowAndMonotonic(op)
	if r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	p.mu.Lock()
	owner := p.owner
	p.mu.Unlock()
	if owner == nil {
		return runtime.ProbeAggregateV1{}, MaintenanceInvalidState
	}
	if err := owner.RevalidateAt(now); err != nil {
		result := maintenanceResultFromError(err)
		if result == MaintenanceExpired {
			result = p.failOperation(op, result)
		}
		return runtime.ProbeAggregateV1{}, result
	}
	if r = p.networkStatus(op); r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	if p.networkMode == runtime.ProbeActiveRelayV1 {
		if p.activeProbes == nil {
			return runtime.ProbeAggregateV1{}, MaintenanceNetworkUnavailable
		}
		pump, ok := p.currentProbePump(op)
		if !ok || pump == nil {
			return runtime.ProbeAggregateV1{}, MaintenanceNetworkUnavailable
		}
		op.probePump = pump
		deadline := now.Add(time.Duration(request.TotalTimeoutMillis) * time.Millisecond)
		if p.parentEnd.Before(deadline) {
			deadline = p.parentEnd
		}
		if r = p.boundOperation(op, now, mono, deadline); r != MaintenanceSuccess {
			return runtime.ProbeAggregateV1{}, r
		}
		op.completionGuard = func() MaintenanceResultV1 {
			if r := p.networkStatus(op); r != MaintenanceSuccess {
				return r
			}
			same, current := p.currentProbePump(op)
			if !current || same != pump {
				return p.failOperation(op, MaintenanceNetworkUnavailable)
			}
			at, r := p.trustedNow(op)
			if r != MaintenanceSuccess {
				return r
			}
			if !at.Before(p.parentEnd) {
				return p.failOperation(op, MaintenanceExpired)
			}
			return MaintenanceSuccess
		}
		if r = p.checkCompletion(op); r != MaintenanceSuccess {
			return runtime.ProbeAggregateV1{}, r
		}
		out, result := maintenanceAwaitActiveProbeV1(op.ctx, pump, request, func() MaintenanceResultV1 { return p.checkCompletion(op) })
		r = result
		if inv.legacyV1() {
			r = p.transportOutcome(op, result)
		}
		return p.publishProbe(op, out, r)
	}
	if p.networkMode != runtime.ProbeDisconnectedDefaultV1 {
		return runtime.ProbeAggregateV1{}, MaintenanceNetworkUnavailable
	}
	if p.probeRates == nil {
		return runtime.ProbeAggregateV1{}, MaintenanceResourceLimit
	}
	probe, err := owner.AdmitDisconnectedProbeAt(request, now)
	if err != nil {
		return runtime.ProbeAggregateV1{}, maintenanceResultFromError(err)
	}
	defer probe.Destroy()
	admission, scope, ok := probe.AdmissionV1()
	if !ok {
		return runtime.ProbeAggregateV1{}, MaintenanceInvalidState
	}
	selected := admission.Target()
	address, valid := netip.AddrFromSlice(selected.Address)
	clear(selected.Address)
	clear(selected.Methods)
	clear(selected.Modes)
	family := uint8(2)
	if address.Is4() {
		family = 1
	}
	if !valid || p.networkFamilies&family == 0 {
		return runtime.ProbeAggregateV1{}, MaintenanceDestinationDenied
	}
	if r = p.boundOperation(op, now, mono, probe.Deadline()); r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	op.completionGuard = func() MaintenanceResultV1 {
		if r := p.networkStatus(op); r != MaintenanceSuccess {
			return r
		}
		at, r := p.trustedNow(op)
		if r != MaintenanceSuccess {
			return r
		}
		if !owner.IsProbeOperationAt(probe, at) {
			if !at.Before(p.parentEnd) {
				return p.failOperation(op, MaintenanceExpired)
			}
			return MaintenanceTimeout
		}
		return MaintenanceSuccess
	}
	dial := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		connection, err := (maintenanceDNSOwnerV1{parent: p, op: op, route: route}).DialTCP(ctx, dst)
		if connection == nil {
			return nil, err
		}
		return connection, err
	}
	// The guard captures/accepts trusted time before each rate/start/finish
	// decision. Reuse that sample instead of taking unvalidated clock reads.
	acceptedNow := func() time.Time { p.mu.Lock(); defer p.mu.Unlock(); return p.lastNow }
	out, r, cleanup := maintenanceDisconnectedSamplesV1(op.ctx, admission, scope, p.probeRates, request, probe.Deadline(), acceptedNow, dial, func() MaintenanceResultV1 { return p.checkCompletion(op) })
	if cleanup != CodeOK {
		return runtime.ProbeAggregateV1{}, p.publicationCleanupFailure(op, cleanup)
	}
	if r == MaintenanceExpired {
		r = p.failOperation(op, r)
	}
	if inv.legacyV1() {
		r = p.transportOutcome(op, r)
	}
	return p.publishProbe(op, out, r)
}

func (p *maintenanceAuthorityV1) currentProbePump(op *maintenanceOperationV1) (*runtime.ServicePumpV1, bool) {
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	pump, ok := p.activeProbes.CurrentPump(p.parentEpoch, p.probeScope)
	p.mu.Lock()
	op.inPlatform = false
	live := p.operationCanPublishLocked(op)
	p.mu.Unlock()
	return pump, ok && live
}

type maintenanceProbePumpV1 interface {
	StartProbe(context.Context, runtime.ProbeRequestV1) (uint64, error)
	AwaitProbe(context.Context, uint64) (runtime.ProbeAggregateV1, error)
	CancelProbe(uint64) error
}

// Production passes the concrete same ServicePump from the trusted provider.
// This small synchronous call boundary owns no pump resources or child join.
func maintenanceAwaitActiveProbeV1(ctx context.Context, pump maintenanceProbePumpV1, request runtime.ProbeRequestV1, guard func() MaintenanceResultV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
	if r := guard(); r != MaintenanceSuccess {
		return runtime.ProbeAggregateV1{}, r
	}
	handle, err := pump.StartProbe(ctx, request)
	if err != nil {
		return runtime.ProbeAggregateV1{}, maintenanceProbeResultV1(err)
	}
	out, err := pump.AwaitProbe(ctx, handle)
	r := guard()
	if err != nil || r != MaintenanceSuccess {
		_ = pump.CancelProbe(handle)
	}
	if r != MaintenanceSuccess {
		return out, r
	}
	return out, maintenanceProbeResultV1(err)
}

func (p *maintenanceAuthorityV1) publishProbe(op *maintenanceOperationV1, out runtime.ProbeAggregateV1, r MaintenanceResultV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
	if !op.output.legacyV1() {
		return p.publishScopedProbeV1(op, out, r)
	}
	if r != MaintenanceSuccess {
		return out, r
	}
	lease, r := p.acquirePublication(op)
	if r != MaintenanceSuccess {
		return out, r
	}
	r = p.finishPublication(op, lease)
	return out, r
}

// A completed aggregate has its own authority publication interval. The work
// context/deadline stay expired; outputContext retains the original cancellation
// lineage rather than replacing it with an uncancellable background context.
func (p *maintenanceAuthorityV1) probeOutputLiveLockedV1(op *maintenanceOperationV1) MaintenanceResultV1 {
	if p.terminalSet {
		return p.terminal
	}
	if p.operation != op || op.cancelled || op.outputContext == nil || op.outputContext.Err() != nil {
		return MaintenanceCancelled
	}
	if p.parentTimerAt.IsZero() || !time.Now().Before(p.parentTimerAt) {
		return MaintenanceExpired
	}
	return MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) checkResultOutputAuthorityV1(op *maintenanceOperationV1) MaintenanceResultV1 {
	p.mu.Lock()
	r := p.probeOutputLiveLockedV1(op)
	p.mu.Unlock()
	if r != MaintenanceSuccess {
		return r
	}
	now, mono, r := p.trustedNowAndMonotonic(op)
	if r != MaintenanceSuccess {
		return r
	}
	if !now.Before(p.parentEnd) || !mono.Before(p.parentTimerAt) {
		return p.failOperation(op, MaintenanceExpired)
	}
	if p.owner == nil {
		return MaintenanceInvalidState
	}
	if err := p.owner.RevalidateAt(now); err != nil {
		return p.failOperation(op, maintenanceResultFromError(err))
	}
	p.mu.Lock()
	op.inPlatform = true
	network := p.network
	p.mu.Unlock()
	current := network != nil && network.IsCurrent() && network.Mode() == p.networkMode && network.IPFamilies() == p.networkFamilies
	if current {
		var servers [4]netip.AddrPort
		count, result := network.DNSServersInto(&servers)
		current = result == MaintenanceSuccess && count == p.networkServerCount && servers == p.networkServers
	}
	if current {
		select {
		case <-network.Done():
			current = false
		default:
		}
	}
	p.mu.Lock()
	op.inPlatform = false
	r = p.probeOutputLiveLockedV1(op)
	p.mu.Unlock()
	if r != MaintenanceSuccess {
		return r
	}
	if !current {
		return p.failOperation(op, MaintenanceNetworkUnavailable)
	}
	return MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) checkProbeOutputAuthorityV1(op *maintenanceOperationV1) MaintenanceResultV1 {
	if r := p.checkResultOutputAuthorityV1(op); r != MaintenanceSuccess {
		return r
	}
	p.mu.Lock()
	active := p.networkMode == runtime.ProbeActiveRelayV1
	op.inPlatform = true
	p.mu.Unlock()
	current := true
	if active {
		current = p.activeProbes != nil && op.probePump != nil
		if current {
			pump, ok := p.activeProbes.CurrentPump(p.parentEpoch, p.probeScope)
			current = ok && pump == op.probePump
		}
	}
	p.mu.Lock()
	op.inPlatform = false
	r := p.probeOutputLiveLockedV1(op)
	p.mu.Unlock()
	if r != MaintenanceSuccess {
		return r
	}
	if !current {
		return p.failOperation(op, MaintenanceNetworkUnavailable)
	}
	return MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) publishScopedProbeV1(op *maintenanceOperationV1, out runtime.ProbeAggregateV1, categorical MaintenanceResultV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
	fail := func(r MaintenanceResultV1) (runtime.ProbeAggregateV1, MaintenanceResultV1) {
		return runtime.ProbeAggregateV1{}, r
	}
	if categorical != MaintenanceSuccess && categorical != MaintenanceTimeout && categorical != MaintenanceRateLimited {
		return fail(categorical)
	}
	if r := p.checkProbeOutputAuthorityV1(op); r != MaintenanceSuccess {
		return fail(r)
	}
	p.mu.Lock()
	registration, deadline := p.registration, p.parentTimerAt
	op.inPlatform = true
	p.mu.Unlock()
	if registration == nil {
		p.mu.Lock()
		op.inPlatform = false
		p.mu.Unlock()
		return fail(MaintenanceCancelled)
	}
	publication, cancel := context.WithDeadline(op.outputContext, deadline)
	defer cancel()
	lease, r := registration.AcquirePublication(publication)
	current := false
	if lease != nil && r == MaintenanceSuccess {
		current = lease.IsCurrent()
	}
	p.mu.Lock()
	op.inPlatform = false
	p.mu.Unlock()
	if lease != nil {
		if code := p.closePublicationLease(op, lease); code != CodeOK {
			return fail(p.publicationCleanupFailure(op, code))
		}
	}
	r = normalizeMaintenancePlatformResult(r)
	if r != MaintenanceSuccess {
		return fail(r)
	}
	if lease == nil {
		return fail(MaintenanceInternalFailure)
	}
	if !current {
		return fail(MaintenanceCancelled)
	}
	if r = p.checkProbeOutputAuthorityV1(op); r != MaintenanceSuccess {
		return fail(r)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r = p.probeOutputLiveLockedV1(op); r != MaintenanceSuccess {
		return fail(r)
	}
	if r = p.outputPrepareLockedV1(op.output, 0, deadline, false); r != MaintenanceSuccess {
		return fail(r)
	}
	return out, categorical
}

func maintenanceDisconnectedSamplesV1(ctx context.Context, admission runtime.ProbeAdmissionV1, scope runtime.AuthenticatedProbeScopeV1, rates *runtime.ProbeRateRegistryV1, request runtime.ProbeRequestV1, deadline time.Time, now func() time.Time, dial func(context.Context, netip.AddrPort) (net.Conn, error), guard func() MaintenanceResultV1) (runtime.ProbeAggregateV1, MaintenanceResultV1, ErrorCode) {
	var samples [10]runtime.ProbeSampleV1
	count := 0
	aggregate := func(r MaintenanceResultV1) (runtime.ProbeAggregateV1, MaintenanceResultV1, ErrorCode) {
		out, err := runtime.AggregateProbeSamplesV1(runtime.ProbeDisconnectedTCPConnectV1, samples[:count])
		clear(samples[:])
		if err != nil {
			return runtime.ProbeAggregateV1{}, MaintenanceInternalFailure, CodeOK
		}
		return out, r, CodeOK
	}
	target := admission.Target()
	defer clear(target.Address)
	defer clear(target.Methods)
	defer clear(target.Modes)
	address, ok := netip.AddrFromSlice(target.Address)
	if !ok {
		return aggregate(MaintenanceDestinationDenied)
	}
	check := func() MaintenanceResultV1 {
		if r := guard(); r != MaintenanceSuccess {
			return r
		}
		if r := maintenanceContextResultV1(ctx); r != MaintenanceSuccess {
			return r
		}
		if !now().Before(deadline) {
			return MaintenanceTimeout
		}
		return MaintenanceSuccess
	}
	for count < int(request.Samples) {
		if r := check(); r != MaintenanceSuccess {
			return aggregate(r)
		}
		for {
			at := now()
			err := rates.TryStart(scope, admission, at)
			if err == nil {
				break
			}
			if count == 0 || err != runtime.ErrProbeRateLimitedV1 {
				return aggregate(maintenanceProbeResultV1(err))
			}
			next, err := rates.NextSlot(scope, admission, at, deadline)
			if err != nil {
				return aggregate(maintenanceProbeResultV1(err))
			}
			timer := time.NewTimer(next.Sub(at))
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return aggregate(maintenanceContextResultV1(ctx))
			case <-timer.C:
			}
			if r := check(); r != MaintenanceSuccess {
				return aggregate(r)
			}
		}
		if r := check(); r != MaintenanceSuccess {
			return aggregate(r)
		}
		timeout := time.Duration(request.AttemptTimeoutMillis) * time.Millisecond
		remaining := deadline.Sub(now())
		if remaining < timeout {
			timeout = remaining
		}
		if timeout <= 0 {
			return aggregate(MaintenanceTimeout)
		}
		attempt, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		connection, err := dial(attempt, netip.AddrPortFrom(address, target.Port))
		elapsed := time.Since(started)
		success := err == nil && connection != nil && attempt.Err() == nil && elapsed < timeout
		if connection != nil {
			if closeErr := connection.Close(); closeErr != nil {
				cancel()
				clear(samples[:])
				return runtime.ProbeAggregateV1{}, MaintenanceInternalFailure, CodeStateCorrupt
			}
		}
		cancel()
		if r := check(); r != MaintenanceSuccess {
			return aggregate(r)
		}
		samples[count] = runtime.ProbeSampleV1{Attempted: true, Success: success, AttemptTimeoutMillis: request.AttemptTimeoutMillis}
		if success {
			samples[count].DurationMicros = uint64(elapsed.Microseconds())
		}
		count++
	}
	return aggregate(MaintenanceSuccess)
}
func maintenanceProbeResultV1(err error) MaintenanceResultV1 {
	switch err {
	case nil:
		return MaintenanceSuccess
	case runtime.ServiceNotAdmittedV1:
		return MaintenanceNotAdmitted
	case runtime.ServiceInvalidRequestV1:
		return MaintenanceInvalidRequest
	case runtime.ServiceDestinationDeniedV1:
		return MaintenanceDestinationDenied
	case runtime.ServiceResourceLimitV1:
		return MaintenanceResourceLimit
	case runtime.ServiceTimeoutV1:
		return MaintenanceTimeout
	case runtime.ServiceUnreachableV1:
		return MaintenanceNetworkUnavailable
	case runtime.ServiceCancelledV1:
		return MaintenanceCancelled
	case runtime.ServiceAuthorityExpiredV1, runtime.ErrProbeClockRegressionV1:
		return MaintenanceExpired
	case runtime.ServiceAuthorityRevokedV1:
		return MaintenanceRevoked
	case runtime.ErrProbeRateLimitedV1:
		return MaintenanceRateLimited
	default:
		if errors.Is(err, context.Canceled) {
			return MaintenanceCancelled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return MaintenanceTimeout
		}
		return MaintenanceInternalFailure
	}
}
