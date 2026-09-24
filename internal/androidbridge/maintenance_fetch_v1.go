// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"kurdistan/internal/net/boundeddns"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/selfhost"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"time"
)

func CheckSameDeploymentUpdateV1(registry *HandleRegistry, parent Handle, requestedTimeoutMillis uint16) MaintenanceCandidateResultV1 {
	return CheckSameDeploymentUpdateV1Scoped(registry, parent, requestedTimeoutMillis, MaintenanceOutputInvocationV1{})
}
func CheckSameDeploymentUpdateV1Scoped(registry *HandleRegistry, parent Handle, requestedTimeoutMillis uint16, inv MaintenanceOutputInvocationV1) MaintenanceCandidateResultV1 {
	return checkSameDeploymentUpdateOutputV1(registry, parent, requestedTimeoutMillis, nil, inv)
}

// CheckSameDeploymentUpdateDecisionV1Scoped exposes only the actual admitted
// operation's preparation marker to its typed private wire adapter.
func CheckSameDeploymentUpdateDecisionV1Scoped(registry *HandleRegistry, parent Handle, requestedTimeoutMillis uint16, inv MaintenanceOutputInvocationV1) (MaintenanceCandidateResultV1, bool) {
	return checkSameDeploymentUpdateDecisionV1(registry, parent, requestedTimeoutMillis, nil, inv)
}

// route is a private host-test seam below signed destination validation. The
// public operation always supplies nil; no platform or release input selects it.
func checkSameDeploymentUpdateV1(registry *HandleRegistry, parent Handle, requestedTimeoutMillis uint16, route maintenanceNumericRouteV1) MaintenanceCandidateResultV1 {
	return checkSameDeploymentUpdateOutputV1(registry, parent, requestedTimeoutMillis, route, MaintenanceOutputInvocationV1{})
}
func checkSameDeploymentUpdateOutputV1(registry *HandleRegistry, parent Handle, requestedTimeoutMillis uint16, route maintenanceNumericRouteV1, inv MaintenanceOutputInvocationV1) MaintenanceCandidateResultV1 {
	result, _ := checkSameDeploymentUpdateDecisionV1(registry, parent, requestedTimeoutMillis, route, inv)
	return result
}

// The marker is produced by this admitted operation, not by the wire adapter
// interpreting a numeric M1 result after authority and cleanup have ended.
func checkSameDeploymentUpdateDecisionV1(registry *HandleRegistry, parent Handle, requestedTimeoutMillis uint16, route maintenanceNumericRouteV1, inv MaintenanceOutputInvocationV1) (MaintenanceCandidateResultV1, bool) {
	p, r := maintenanceParentOutputV1(registry, parent, inv)
	if r != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: r}, false
	}
	op, r := p.beginOperationOutputV1(inv, false)
	if r != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: r}, false
	}
	defer p.finishOperation(op)
	fail := func(r MaintenanceResultV1) (MaintenanceCandidateResultV1, bool) {
		return MaintenanceCandidateResultV1{Result: r}, false
	}
	decision := func(stage maintenanceUpdateDecisionStageV1, result MaintenanceResultV1) (MaintenanceCandidateResultV1, bool) {
		if inv.legacyV1() || !maintenanceUpdateDecisionAllowedV1(stage, result) {
			return fail(result)
		}
		if r := p.prepareUpdateDecisionV1(op); r != MaintenanceSuccess {
			return fail(r)
		}
		return MaintenanceCandidateResultV1{Result: result}, true
	}
	p.mu.Lock()
	candidate, owner := p.candidate, p.owner
	p.mu.Unlock()
	if candidate != nil {
		return fail(MaintenanceInvalidState)
	}
	if requestedTimeoutMillis < 1000 || requestedTimeoutMillis > 30000 {
		return fail(MaintenanceInvalidRequest)
	}
	if p.network == nil {
		return fail(MaintenanceNetworkUnavailable)
	}
	if p.updateRates == nil {
		return fail(MaintenanceResourceLimit)
	}
	if r = p.revalidatePlatform(op); r != MaintenanceSuccess {
		return fail(r)
	}
	now, mono, r := p.trustedNowAndMonotonic(op)
	if r != MaintenanceSuccess {
		return fail(r)
	}
	if owner == nil {
		return fail(MaintenanceInvalidState)
	}
	update, err := owner.AdmitUpdateAt(requestedTimeoutMillis, now)
	if err != nil {
		result := maintenanceResultFromError(err)
		if result == MaintenanceExpired {
			result = p.failOperation(op, result)
		}
		return decision(maintenanceUpdateAdmissionDecisionV1, result)
	}
	policy, ok := update.SnapshotV1()
	if !ok {
		return fail(MaintenanceInvalidState)
	}
	if r = p.boundOperation(op, now, mono, policy.Deadline); r != MaintenanceSuccess {
		return fail(r)
	}
	op.completionGuard = func() MaintenanceResultV1 {
		if r := p.networkStatus(op); r != MaintenanceSuccess {
			return r
		}
		at, r := p.trustedNow(op)
		if r != MaintenanceSuccess {
			return r
		}
		if !owner.IsUpdateOperationAt(update, at) {
			if !at.Before(p.parentEnd) {
				return p.failOperation(op, MaintenanceExpired)
			}
			return MaintenanceTimeout
		}
		return MaintenanceSuccess
	}
	if r = p.checkCompletion(op); r != MaintenanceSuccess {
		return fail(r)
	}
	// Reserve body and verifier overlap at construction, before any request
	// allocation. Shared rate history is spent once before root/DNS/socket work.
	startNow, r := p.trustedNow(op)
	if r != MaintenanceSuccess {
		return fail(r)
	}
	if r = p.updateRates.TryStart(policy.Scope, policy.MinCheckIntervalSeconds, startNow); r != MaintenanceSuccess {
		if r == MaintenanceExpired {
			r = p.failOperation(op, r)
		}
		return decision(maintenanceUpdateAdmissionDecisionV1, r)
	}
	if r = p.loadRoots(op); r != MaintenanceSuccess {
		return decision(maintenanceUpdateTransportDecisionV1, p.transportOutcome(op, r))
	}
	body := make([]byte, min(policy.MaxArtifactBytes, p.limits.MaxArtifactBytes))
	defer clear(body)
	n, r := p.fetchBody(op, policy, body, route)
	if r != MaintenanceSuccess {
		return decision(maintenanceUpdateTransportDecisionV1, p.transportOutcome(op, r))
	}
	if r = p.checkCompletion(op); r != MaintenanceSuccess {
		return fail(r)
	}
	// The admitted slot remains held. This private body performs fresh-time
	// authentication and uses the same final publication guard as staging.
	result := p.verifyMaintenanceCandidateV1(op, body[:n])
	if result.Result != MaintenanceSuccess && result.Result != MaintenanceNoChange {
		return decision(maintenanceUpdateCandidateDecisionV1, p.transportOutcome(op, result.Result))
	}
	return result, !inv.legacyV1() && op.outputPrepared
}

type maintenanceUpdateDecisionStageV1 uint8

const (
	maintenanceUpdateAdmissionDecisionV1 maintenanceUpdateDecisionStageV1 = iota + 1
	maintenanceUpdateTransportDecisionV1
	maintenanceUpdateCandidateDecisionV1
)

func maintenanceUpdateDecisionAllowedV1(stage maintenanceUpdateDecisionStageV1, result MaintenanceResultV1) bool {
	if stage < maintenanceUpdateAdmissionDecisionV1 || stage > maintenanceUpdateCandidateDecisionV1 {
		return false
	}
	switch result {
	case MaintenanceNotAdmitted, MaintenanceSizeLimit, MaintenanceResourceLimit, MaintenanceRateLimited,
		MaintenanceTimeout, MaintenanceNetworkUnavailable, MaintenanceDestinationDenied, MaintenanceTLSTrustUnavailable,
		MaintenanceTLSRejected, MaintenanceFetchRejected, MaintenanceSignatureInvalid, MaintenanceWrongRecipient,
		MaintenanceProfileMismatch, MaintenanceRollback, MaintenanceIncompatible, MaintenanceRootRotationRejected, MaintenanceInternalFailure:
		return true
	case MaintenanceExpired, MaintenanceRevoked:
		return stage == maintenanceUpdateCandidateDecisionV1
	default:
		return false
	}
}

func (p *maintenanceAuthorityV1) prepareUpdateDecisionV1(op *maintenanceOperationV1) MaintenanceResultV1 {
	if r := p.checkResultOutputAuthorityV1(op); r != MaintenanceSuccess {
		return r
	}
	p.mu.Lock()
	refused := op.outputPrepared || p.cleanupCode != CodeOK || p.cleanupPending || p.pendingCandidate != nil || p.candidate != nil
	p.mu.Unlock()
	if refused {
		return MaintenanceInternalFailure
	}
	p.mu.Lock()
	registration, deadline := p.registration, p.parentTimerAt
	op.inPlatform = true
	p.mu.Unlock()
	if registration == nil {
		p.mu.Lock()
		op.inPlatform = false
		p.mu.Unlock()
		return MaintenanceCancelled
	}
	publication, cancel := context.WithDeadline(op.outputContext, deadline)
	defer cancel()
	lease, result := registration.AcquirePublication(publication)
	current := lease != nil && result == MaintenanceSuccess && lease.IsCurrent()
	p.mu.Lock()
	op.inPlatform = false
	p.mu.Unlock()
	if lease != nil {
		if code := p.closePublicationLease(op, lease); code != CodeOK {
			return p.publicationCleanupFailure(op, code)
		}
	}
	result = normalizeMaintenancePlatformResult(result)
	if result != MaintenanceSuccess {
		return result
	}
	if lease == nil {
		return MaintenanceInternalFailure
	}
	if !current {
		return MaintenanceCancelled
	}
	if result = p.checkResultOutputAuthorityV1(op); result != MaintenanceSuccess {
		return result
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if result = p.probeOutputLiveLockedV1(op); result != MaintenanceSuccess {
		return result
	}
	if op.outputPrepared || p.cleanupCode != CodeOK || p.cleanupPending || p.pendingCandidate != nil || p.candidate != nil {
		return MaintenanceInternalFailure
	}
	op.outputPrepared = true // a refusal also consumes this one preparation attempt
	return p.outputPrepareLockedV1(op.output, 0, deadline, false)
}

func (p *maintenanceAuthorityV1) boundOperation(op *maintenanceOperationV1, now, mono, deadline time.Time) MaintenanceResultV1 {
	at, ok := maintenanceMonotonicDeadlineV1(now, deadline, mono)
	if !ok {
		return MaintenanceTimeout
	}
	if !p.parentTimerAt.IsZero() && p.parentTimerAt.Before(at) {
		at = p.parentTimerAt
	}
	ctx, cancel := context.WithDeadline(op.ctx, at)
	p.mu.Lock()
	old := op.cancel
	op.ctx = ctx
	op.deadline = at
	op.cancel = func() { cancel(); old() }
	live := !p.terminalSet && !op.cancelled
	p.mu.Unlock()
	if !live {
		cancel()
		return MaintenanceCancelled
	}
	return MaintenanceSuccess
}
func (p *maintenanceAuthorityV1) checkCompletion(op *maintenanceOperationV1) MaintenanceResultV1 {
	p.mu.Lock()
	terminal, r := p.terminalSet, p.terminal
	parentTimerAt := p.parentTimerAt
	p.mu.Unlock()
	if terminal {
		return r
	}
	if !parentTimerAt.IsZero() && !p.monotonicNow().Before(parentTimerAt) {
		return p.failOperation(op, MaintenanceExpired)
	}
	if r = maintenanceContextResultV1(op.ctx); r != MaintenanceSuccess {
		return r
	}
	if op.completionGuard != nil {
		return op.completionGuard()
	}
	return MaintenanceSuccess
}
func (p *maintenanceAuthorityV1) transportOutcome(op *maintenanceOperationV1, fallback MaintenanceResultV1) MaintenanceResultV1 {
	if r := p.checkCompletion(op); r != MaintenanceSuccess {
		return r
	}
	return fallback
}
func (p *maintenanceAuthorityV1) fetchBody(op *maintenanceOperationV1, policy selfhost.LiveMaintenanceUpdatePolicyV1, body []byte, route maintenanceNumericRouteV1) (int, MaintenanceResultV1) {
	u, err := url.Parse(policy.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return 0, MaintenanceInternalFailure
	}
	host := u.Hostname()
	port := uint16(443)
	if value := u.Port(); value != "" {
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil || n == 0 {
			return 0, MaintenanceInternalFailure
		}
		port = uint16(n)
	}
	families := policy.IPFamilies & p.networkFamilies
	if families == 0 {
		return 0, MaintenanceDestinationDenied
	}
	var addresses [16]netip.Addr
	count := 0
	if address, err := netip.ParseAddr(host); err == nil {
		addresses[0] = address
		count = 1
	} else {
		resolver, err := boundeddns.NewResolver(p.networkServers[:p.networkServerCount], maintenanceDNSOwnerV1{parent: p, op: op, route: route}, 1)
		if err != nil {
			return 0, MaintenanceNetworkUnavailable
		}
		// The accepted one-slot and operation charges are reserved together with
		// the body and verifier. Source estimator changes fail closed.
		if resolver.FixedOwnedBytes() > 480 || resolver.OperationOwnedBytes() > 82480 {
			_ = resolver.Close()
			return 0, MaintenanceResourceLimit
		}
		count, err = resolver.ResolveInto(op.ctx, host, boundeddns.FamilyMask(families), &addresses)
		_ = resolver.Close()
		<-resolver.Done()
		if err != nil {
			return 0, maintenanceDNSResultV1(err)
		}
	}
	defer clear(addresses[:])
	count, r := maintenanceFilterAddressesV1(&addresses, count, families)
	if r != MaintenanceSuccess {
		return 0, r
	}
	dialer := (maintenanceDNSOwnerV1{parent: p, op: op}).dialer()
	dial := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		if route != nil {
			dst = route("tcp", dst)
		}
		connection, err := dialer.DialTCP(ctx, "tcp", netip.AddrPort{}, dst)
		if connection == nil {
			return nil, err
		}
		return connection, err
	}
	var cleanup ErrorCode
	var proof *ErrorCode
	if !op.output.legacyV1() {
		proof = &cleanup
	}
	raw, r := maintenanceConnectOwnedV1(op.ctx, &addresses, count, port, dial, func() MaintenanceResultV1 { return p.checkCompletion(op) }, proof)
	if cleanup != CodeOK {
		return 0, p.publicationCleanupFailure(op, cleanup)
	}
	if r != MaintenanceSuccess {
		return 0, r
	}
	n, r := maintenanceHTTPSOwnedV1(op.ctx, raw, policy.URL, host, p.roots, p.now, body, func() MaintenanceResultV1 { return p.checkCompletion(op) }, proof)
	if cleanup != CodeOK {
		clear(body)
		return 0, p.publicationCleanupFailure(op, cleanup)
	}
	return n, r
}

// Only TCP establishment can try a second address. The caller performs one
// TLS/HTTP exchange after this function returns, never a request retry.
func maintenanceConnectV1(ctx context.Context, addresses *[16]netip.Addr, count int, port uint16, dial func(context.Context, netip.AddrPort) (net.Conn, error), guard func() MaintenanceResultV1) (net.Conn, MaintenanceResultV1) {
	return maintenanceConnectOwnedV1(ctx, addresses, count, port, dial, guard, nil)
}
func maintenanceConnectOwnedV1(ctx context.Context, addresses *[16]netip.Addr, count int, port uint16, dial func(context.Context, netip.AddrPort) (net.Conn, error), guard func() MaintenanceResultV1, cleanup *ErrorCode) (net.Conn, MaintenanceResultV1) {
	if cleanup != nil {
		*cleanup = CodeOK
	}
	if count < 1 || count > len(addresses) || port == 0 {
		return nil, MaintenanceInvalidRequest
	}
	for _, address := range addresses[:min(count, 2)] {
		if r := guard(); r != MaintenanceSuccess {
			return nil, r
		}
		raw, err := dial(ctx, netip.AddrPortFrom(address, port))
		if r := guard(); r != MaintenanceSuccess {
			if raw != nil {
				if err := raw.Close(); err != nil && cleanup != nil {
					*cleanup = CodeStateCorrupt
				}
			}
			return nil, r
		}
		if err != nil {
			if raw != nil {
				if err := raw.Close(); err != nil && cleanup != nil {
					*cleanup = CodeStateCorrupt
					return nil, MaintenanceInternalFailure
				}
			}
			continue
		}
		if raw == nil {
			return nil, MaintenanceNetworkUnavailable
		}
		return raw, MaintenanceSuccess
	}
	return nil, MaintenanceNetworkUnavailable
}
func maintenanceFilterAddressesV1(values *[16]netip.Addr, count int, families uint8) (int, MaintenanceResultV1) {
	if count < 0 || count > len(values) {
		return 0, MaintenanceSizeLimit
	}
	n := 0
	for _, a := range values[:count] {
		if !runtimepolicy.IsPublicServiceAddress(a) || a.Is4() && families&1 == 0 || a.Is6() && families&2 == 0 {
			continue
		}
		values[n] = a
		n++
	}
	clear(values[n:])
	if n == 0 {
		return 0, MaintenanceDestinationDenied
	}
	slices.SortFunc(values[:n], func(a, b netip.Addr) int { return a.Compare(b) })
	return n, MaintenanceSuccess
}
func maintenanceHTTPSV1(ctx context.Context, raw net.Conn, signedURL, hostname string, roots *x509.CertPool, now func() time.Time, body []byte, guard func() MaintenanceResultV1) (int, MaintenanceResultV1) {
	return maintenanceHTTPSOwnedV1(ctx, raw, signedURL, hostname, roots, now, body, guard, nil)
}
func maintenanceHTTPSOwnedV1(ctx context.Context, raw net.Conn, signedURL, hostname string, roots *x509.CertPool, now func() time.Time, body []byte, guard func() MaintenanceResultV1, cleanup *ErrorCode) (int, MaintenanceResultV1) {
	socket := newMaintenanceSocketV1(ctx)
	defer func() {
		code := socket.finish()
		if cleanup != nil {
			*cleanup = code
		}
	}()
	if !socket.install(raw) {
		return 0, maintenanceContextResultV1(ctx)
	}
	check := func(fallback MaintenanceResultV1) MaintenanceResultV1 {
		if r := guard(); r != MaintenanceSuccess {
			return r
		}
		if r := maintenanceContextResultV1(ctx); r != MaintenanceSuccess {
			return r
		}
		return fallback
	}
	if r := check(MaintenanceSuccess); r != MaintenanceSuccess {
		return 0, r
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		socket.close()
		return 0, check(MaintenanceInvalidRequest)
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return 0, check(MaintenanceNetworkUnavailable)
	}
	if roots == nil {
		return 0, MaintenanceTLSTrustUnavailable
	}
	connection := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true, Time: now})
	// The joined raw-close hook above continuously guards the synchronous TLS
	// call. WithoutCancel suppresses TLS's otherwise unjoined close callback.
	if err := connection.HandshakeContext(context.WithoutCancel(ctx)); err != nil {
		maintenanceObserveHandshakeFailureV1(ctx, err)
		return 0, check(MaintenanceTLSRejected)
	}
	if r := check(MaintenanceSuccess); r != MaintenanceSuccess {
		return 0, r
	}
	if r := maintenanceWriteHTTPV1(connection, signedURL); r != MaintenanceSuccess {
		return 0, check(r)
	}
	n, r := maintenanceReadHTTPV1(connection, &http.Request{Method: http.MethodGet}, body, socket.close)
	if result := check(r); result != MaintenanceSuccess {
		clear(body)
		return 0, result
	}
	return n, MaintenanceSuccess
}
