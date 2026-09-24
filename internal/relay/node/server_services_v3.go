// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"errors"
	"time"

	"kurdistan/internal/net/boundeddns"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/relay/tun"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
)

func (s *ServerV1) writeFailureSignalV3() <-chan struct{} {
	if s == nil || s.registry == nil {
		return nil
	}
	if control, ok := s.registry.tun.(tun.PacketWriteControlV3); ok {
		return control.WriteFailureV3()
	}
	return nil
}

func (s *ServerV1) writeFailedV3() bool {
	select {
	case <-s.writeFailureSignalV3():
		return true
	default:
		return false
	}
}

func (s *ServerV1) watchWriteHealthV3(ctx context.Context, signal <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return nil
	case <-signal:
		return errors.Join(ErrServerRegistry, tun.ErrWriteHealthV3)
	}
}

// Caller holds stateMu. A scalar fences replaced snapshots without retaining
// old whole views. Same-root equal-status updates still check latest negatives.
func (s *ServerV1) admissionCurrentLockedV3(a selfhost.RelayAdmissionV1, generation uint64) bool {
	return generation == s.authorityGenerationV3 && generation != ^uint64(0) &&
		a.ServiceAuthorityDeadlineV3.After(s.config.Now()) &&
		(s.revocationsV3 == nil || !s.revocationsV3.RevokesV3(a.RevocationSubjectV3, s.config.Now()))
}

func (s *ServerV1) currentStatusV3(status selfhost.RelayRuntimeStatusV1, a selfhost.RelayAdmissionV1, generation uint64, ctx context.Context) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if ctx.Err() != nil || s.snapshot == nil || s.transitionV3 || s.stoppedV3 || !s.health.Snapshot().AcceptingSessions || s.writeFailedV3() {
		return false
	}
	current, ok := s.snapshot.StatusV1()
	return ok && current == status && s.admissionCurrentLockedV3(a, generation)
}

func (s *ServerV1) handleServicesV3(session, handshakeContext context.Context, carrier *tlstcp.Conn, handshake *kruntime.ProcessWireRelayHandshakeV1, plan sessionplan.PlanV2, a selfhost.RelayAdmissionV1, status selfhost.RelayRuntimeStatusV1, authorityGeneration uint64, sessionID string, transientToken uint64, cancel, cancelHandshake context.CancelFunc) error {
	// Before factory success the handler owns all these resources. Afterwards
	// the pump is their sole owner and Done is the retirement fence.
	result, err := acceptRelayHandshakeResultV3(handshakeContext, carrier, handshake)
	if err != nil {
		carrier.Close()
		return ErrServerSession
	}
	defer result.Close()
	if !s.currentStatusV3(status, a, authorityGeneration, session) || a.ProviderID == "" || a.LineageID == "" {
		carrier.Close()
		return ErrServerSession
	}
	budget := s.config.SessionBufferBudget
	services := a.RuntimePolicy.Services
	if !serviceConstructionBudgetV3(plan, services, budget, 0, tlstcp.RecordStreamOwnedBytesV3()) {
		carrier.Close()
		return serverResourceRejectV3(s)
	}
	d, err := s.registry.RegisterV3(SessionSpec{ID: sessionID, ProfileID: a.ProfileID, ClientKeyID: a.ClientAuthKeyID, AssignedIPv4: plan.ClientIPv4, DNSIPv4: plan.DNSIPv4, AssignedIPv6: plan.ClientIPv6, DNSIPv6: plan.DNSIPv6, Cancel: cancel}, SessionDeviceConfigV3{Context: session, MaxPacketBytes: uint32(plan.MTU), AuthorityDeadline: a.ServiceAuthorityDeadlineV3, BudgetBytes: budget, PayloadProtocols: plan.PayloadProtocols, subjectV3: a.RevocationSubjectV3})
	if err != nil {
		carrier.Close()
		return s.rejectSessionV1(sessionRejectRegistryV1(err))
	}
	if err = d.holdAttemptV3(); err != nil {
		carrier.Close()
		d.Close()
		<-d.Done()
		return ErrServerSession
	}
	var pump *kruntime.ServicePumpV1
	defer func() {
		if pump != nil {
			pump.Close()
			<-pump.Done()
		} else {
			carrier.Close()
			d.Close()
		}
		// Destroy the caller's handshake result before releasing counted capacity.
		result.Close()
		handshake.Close()
		cancelHandshake()
		cancel()
		s.releaseTransientV1(sessionID, transientToken)
		d.releaseAttemptV3()
		<-d.Done()
	}()
	s.stateMu.RLock()
	current, ok := selfhost.RelayRuntimeStatusV1{}, false
	if s.snapshot != nil {
		current, ok = s.snapshot.StatusV1()
	}
	currentOK := ok && current == status && session.Err() == nil && !s.transitionV3 && !s.stoppedV3 && s.health.Snapshot().AcceptingSessions && !s.writeFailedV3() && s.admissionCurrentLockedV3(a, authorityGeneration)
	if currentOK {
		s.releaseTransientV1(sessionID, transientToken)
	}
	s.stateMu.RUnlock()
	if !currentOK {
		return ErrServerSession
	}
	cfg := kruntime.ServicePumpConfigV1{PacketIO: d, ExternalPacketIngress: true, PacketOwnedBytes: d.BoundsV3().OwnedBytes, PacketQueuedBytes: 0, BufferBudget: budget, Generation: a.Generation, AuthorityDeadline: a.ServiceAuthorityDeadlineV3, Now: s.config.Now, CheckAuthority: d.checkAuthorityV3}
	if services.Proxy != nil {
		cfg.StreamLimit = services.Proxy.MaxConcurrentStreams
		cfg.StreamQueueBytes = services.Proxy.MaxQueuedBytesPerDirection
	}
	if services.Probes != nil {
		for _, target := range services.Probes.Targets {
			for _, mode := range target.Modes {
				if mode == uint8(kruntime.ProbeActiveRelayV1) {
					cfg.ProbeLimit = services.Probes.MaxConcurrentOperations
				}
			}
		}
	}
	if cfg.ProbeLimit != 0 {
		cfg.ProbeScope, err = kruntime.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: a.ProviderID, LineageID: a.LineageID, ProfileID: a.ProfileID})
		if err != nil || s.probeRatesV3 == nil {
			return ErrServerSession
		}
		cfg.ProbeRates = s.probeRatesV3
	}
	operations := uint64(cfg.StreamLimit) + uint64(cfg.ProbeLimit)
	if operations != 0 {
		if s.resolverV3 == nil {
			return ErrServerSession
		}
		families := boundeddns.IPv4 | boundeddns.IPv6
		switch plan.IPMode {
		case runtimepolicy.IPModeIPv4Only:
			families = boundeddns.IPv4
		case runtimepolicy.IPModeIPv6Only:
			families = boundeddns.IPv6
		case runtimepolicy.IPModeDualStack:
		default:
			return ErrServerSession
		}
		network := relayServiceNetworkV3{device: d, families: families, resolver: s.resolverV3, owner: &s.socketsV3, now: s.config.Now}
		cfg.NetworkOperationBytes = network.operationOwnedBytesV3()
		if cfg.NetworkOperationBytes > 1<<20 || operations*cfg.NetworkOperationBytes+cfg.PacketOwnedBytes+tlstcp.RecordStreamOwnedBytesV3() >= budget {
			return serverResourceRejectV3(s)
		}
		cfg.RelayNetwork = &network
	}
	// Pre-reserve the actual retained carrier estimate before selection. The
	// combined factory includes this same charge before consuming the result.
	cfg.CarrierOwnedBytes = tlstcp.RecordStreamOwnedBytesV3()
	if !serviceConstructionBudgetV3(plan, services, budget, cfg.PacketOwnedBytes, cfg.CarrierOwnedBytes) {
		return serverResourceRejectV3(s)
	}
	idle := plan.IdleTimeout
	if idle <= 0 || idle > s.config.SessionIdleTimeout {
		idle = s.config.SessionIdleTimeout
	}
	stream, err := carrier.SelectRecordStreamV3(session, idle)
	if err != nil {
		return ErrServerSession
	}
	bounds := stream.BoundsV3()
	if bounds.OwnedBytes != cfg.CarrierOwnedBytes || bounds.QueuedPayloadBytes != 0 {
		return ErrServerSession
	}
	cfg.Carrier = stream
	cfg.MaxRecordBytes = bounds.MaxRecordBytes
	pump, err = kruntime.NewRelayServicePumpV1(result, plan, cfg)
	if err != nil {
		return s.rejectSessionV1(servicePumpRejectCategoryV3(err))
	}
	if err = d.AttachReturnIngressV3(pump); err != nil {
		return ErrServerSession
	}
	exporter, err := carrier.CarrierBinding()
	if err != nil {
		return ErrServerSession
	}
	if err = pump.BindV1(handshakeContext, exporter); err != nil {
		return ErrServerSession
	}
	s.observeSessionStageV1(SessionStageKurdReadyV1)
	s.observeSessionStageV1(SessionStagePumpReadyV1)
	// Do not retain the handler's full copied authority alongside the pump.
	a = selfhost.RelayAdmissionV1{}
	plan = sessionplan.PlanV2{}
	services = nil
	err = pump.Run(session)
	if err != nil && session.Err() == nil {
		return s.rejectSessionV1(SessionRejectPacketPumpV1)
	}
	return nil
}

func serviceConstructionBudgetV3(plan sessionplan.PlanV2, services *runtimepolicy.ServicesV1, budget, packet, carrier uint64) bool {
	if !serviceBudgetV3(services, budget) {
		return false
	}
	preparation, err := kruntime.ServicePreparationBoundsForPlanV1(plan, services.Proxy != nil)
	if err != nil {
		return false
	}
	for _, charge := range []uint64{preparation.OwnedBytes, packet, carrier} {
		if charge >= budget {
			return false
		}
		budget -= charge
	}
	return true
}
func servicePumpRejectCategoryV3(err error) SessionRejectCodeV1 {
	if errors.Is(err, kruntime.ServiceResourceLimitV1) {
		return SessionRejectCapacityV1
	}
	return SessionRejectPacketPumpV1
}

func serverResourceRejectV3(s *ServerV1) error { return s.rejectSessionV1(SessionRejectCapacityV1) }
func serviceBudgetV3(services *runtimepolicy.ServicesV1, budget uint64) bool {
	return services != nil && budget > 0 && budget <= 128<<20 && (services.Proxy == nil || budget >= 16<<20 && budget <= uint64(services.Proxy.MaxBufferBytes))
}

type serviceStopActionV3 struct {
	device *SessionDeviceV3
	owner  RelayServiceOwnerV3
	reason error
}

func classifyServiceStopV3(subject selfhost.RelayRevocationSubjectV3, view *selfhost.RelayRevocationViewV3, now, deadline time.Time) error {
	if view != nil && view.RevokesV3(subject, now) {
		return kruntime.ServiceAuthorityRevokedV1
	}
	if !deadline.After(now) {
		return kruntime.ServiceAuthorityExpiredV1
	}
	return kruntime.ServiceCancelledV1
}

// reloadMu protects ownership only. No mutex is held by a transaction while
// invoking external code, including synchronous reentrant owner callbacks.
func (s *ServerV1) reloadServicesV3() error {
	s.reloadMu.Lock()
	if s.reloadInProgressV3 {
		s.reloadMu.Unlock()
		return ErrServerReload
	}
	s.reloadInProgressV3 = true
	s.reloadMu.Unlock()
	defer func() { s.reloadMu.Lock(); s.reloadInProgressV3 = false; s.reloadMu.Unlock() }()
	s.stateMu.RLock()
	stopped := s.stoppedV3
	s.stateMu.RUnlock()
	if stopped {
		return ErrServerReload
	}
	now := s.config.Now().UTC()
	candidate, loadErr := s.config.LoadSnapshot(s.config.DataDir, now)
	var view *selfhost.RelayRevocationViewV3
	if source, ok := candidate.(selfhost.RelayRevocationSourceV3); ok {
		view = source.VerifiedRevocationsV3()
	}
	if loadErr != nil {
		var source selfhost.RelayRevocationSourceV3
		if errors.As(loadErr, &source) {
			view = source.VerifiedRevocationsV3()
		}
	}
	status, valid := selfhost.RelayRuntimeStatusV1{}, false
	state := HealthDegraded
	var result error
	if loadErr != nil || candidate == nil {
		switch {
		case errors.Is(loadErr, selfhost.ErrDrained):
			state = HealthDraining
		case errors.Is(loadErr, selfhost.ErrRelayRuntimeUnavailable):
			state = HealthDisabled
		default:
			result = errors.Join(ErrServerState, loadErr)
		}
	} else {
		status, valid = candidate.StatusV1()
		tlsConfig, tlsErr := candidate.ServerTLSConfigV1()
		tlsValid := tlsErr == nil && validRelayTLSConfigV1(tlsConfig)
		destroyTLSConfigV1(tlsConfig)
		dnsContext, cancel := context.WithTimeout(context.Background(), s.config.HandshakeTimeout)
		dnsReady := s.config.DNSReady != nil && s.config.DNSReady(dnsContext)
		cancel()
		valid = valid && validRelayRuntimeStatusV1(status) && tlsValid && dnsReady
		if !valid {
			result = ErrServerState
			if status.Drained {
				state = HealthDraining
			}
		}
	}
	s.stateMu.Lock()
	if s.stoppedV3 {
		s.stateMu.Unlock()
		if candidate != nil {
			candidate.Close()
		}
		return ErrServerReload
	}
	previous := s.revocationsV3
	differentRoot := false
	// A zero/invalid view cannot establish initial provenance either.
	if view != nil {
		order := view.CompareV3(view)
		if previous != nil {
			order = view.CompareV3(previous)
		}
		differentRoot = order == selfhost.RelayRevocationDifferentRootV3
		if order == selfhost.RelayRevocationInvalidV3 || order == selfhost.RelayRevocationOlderV3 || order == selfhost.RelayRevocationConflictV3 {
			view = nil
			valid = false
			state = HealthDegraded
			result = ErrServerState
		}
	}
	old := s.snapshot
	unchanged := false
	if old != nil && valid {
		current, ok := old.StatusV1()
		unchanged = ok && current == status && !differentRoot
	}
	all := !valid || !unchanged
	s.transitionV3 = true
	// Production reserves this array in NewServerV1. Legacy constructor-only
	// test fixtures have no V3 records and require no action backing.
	r := s.registry
	r.mu.Lock()
	used := 0
	records := 0
	for _, record := range r.sessions {
		if record.v3 != nil {
			records++
		}
	}
	if records > len(s.stopActionsV3) {
		r.mu.Unlock()
		s.transitionV3 = false
		s.stateMu.Unlock()
		if candidate != nil {
			candidate.Close()
		}
		return ErrServerConfig
	}
	for _, record := range r.sessions {
		d := record.v3
		if d == nil {
			continue
		}
		reason := classifyServiceStopV3(d.subjectV3, view, s.config.Now(), d.authorityDeadline)
		if !all && !errors.Is(reason, kruntime.ServiceAuthorityRevokedV1) {
			continue
		}
		if d.reason == nil {
			d.reason = reason
		}
		d.refs++
		s.stopActionsV3[used] = serviceStopActionV3{device: d, owner: d.owner, reason: d.reason}
		used++
	}
	r.mu.Unlock()
	s.stateMu.Unlock()
	// First publish every categorical reason, then perform generic cancellation.
	for i := 0; i < used; i++ {
		action := s.stopActionsV3[i]
		if action.owner != nil {
			action.owner.CancelWithReason(action.reason)
		}
	}
	for i := 0; i < used; i++ {
		s.stopActionsV3[i].device.Close()
	}
	if all {
		s.stopAllTransientsV1()
		r.StopAll()
	}
	s.stateMu.Lock()
	if s.stoppedV3 {
		valid = false
		result = ErrServerReload
	}
	if valid {
		if !unchanged {
			// Never reuse a captured generation. Exhaustion closes only V3
			// admission; the legacy V2 reload and allocator behavior is unchanged.
			if s.authorityGenerationV3 != ^uint64(0) {
				s.authorityGenerationV3++
			}
			s.snapshot = candidate
			candidate = nil
		}
		if view != nil {
			s.revocationsV3 = view
		}
		s.health.SetDrain(false)
		s.health.SetDisabled(false)
		s.health.Update(s.readyRequirementsV1())
	} else {
		s.snapshot = nil
		s.failClosedStateV1(state)
		if view != nil {
			s.revocationsV3 = view
		}
	}
	s.transitionV3 = s.stoppedV3
	s.stateMu.Unlock()
	if old != nil && (!valid || !unchanged) {
		old.Close()
	}
	if candidate != nil {
		candidate.Close()
	}
	// Release the staged reference before waiting. The separate handler ref is
	// what retains pump resources through Done, without a self-joining callback.
	for i := 0; i < used; i++ {
		s.stopActionsV3[i].device.releaseV3()
	}
	for i := 0; i < used; i++ {
		<-s.stopActionsV3[i].device.Done()
		s.stopActionsV3[i] = serviceStopActionV3{}
	}
	// Subjects retain charged identity values, not this complete view. No global
	// draining wait is needed to retire a negative-only comparison snapshot.
	return result
}
