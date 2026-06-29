// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"fmt"
	"sort"

	"kurdistan/internal/carrierrelay"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxyadversary"
	"kurdistan/internal/security"
	ktrace "kurdistan/internal/trace"
)

type HarnessOptions struct {
	Scenario        proxyadversary.Scenario
	CarrierFamily   string
	StreamCount     int
	ClientSecret    []byte
	ServerSecret    []byte
	ClientFeatures  []string
	ServerFeatures  []string
	ReplayInject    bool
	ProfileMismatch *ir.Profile
	LinkQueueDepth  int
}

type HarnessSummary struct {
	ProfileID             string   `json:"profile_id"`
	SessionID             string   `json:"session_id"`
	ClientState           string   `json:"client_state"`
	ServerState           string   `json:"server_state"`
	StreamsOpened         int      `json:"streams_opened"`
	StreamsClosed         int      `json:"streams_closed"`
	FramesClientToServer  int      `json:"frames_client_to_server"`
	FramesServerToClient  int      `json:"frames_server_to_client"`
	CarrierFamily         string   `json:"carrier_family"`
	ProxyTargetsExercised []string `json:"proxy_targets_exercised"`
	SecuritySuite         string   `json:"security_suite"`
	TranscriptMatched     bool     `json:"transcript_matched"`
	CapabilityMatched     bool     `json:"capability_matched"`
	ReplayRejected        int      `json:"replay_rejected"`
	BackpressureEvents    int      `json:"backpressure_events"`
	TargetErrors          int      `json:"target_errors"`
	TargetResets          int      `json:"target_resets"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
}

func RunLocalHarness(ctx context.Context, p *ir.Profile, opts HarnessOptions) (HarnessSummary, []ktrace.Event, error) {
	if err := ctx.Err(); err != nil {
		return HarnessSummary{}, nil, err
	}
	if err := ValidateLoadedProfile(p); err != nil {
		return HarnessSummary{}, nil, err
	}
	if opts.Scenario.Type == "" {
		opts.Scenario = proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets)
	}
	if opts.StreamCount > 0 {
		opts.Scenario.StreamCount = opts.StreamCount
	}
	if opts.CarrierFamily == "" || opts.CarrierFamily == "mixed" {
		opts.CarrierFamily = p.CarrierPolicy.CarrierFamily
	}
	if len(opts.ClientSecret) == 0 {
		opts.ClientSecret = []byte("runtime-secret:" + p.ID)
	}
	if len(opts.ServerSecret) == 0 {
		opts.ServerSecret = opts.ClientSecret
	}
	clientProfile := p
	serverProfile := p
	if opts.ProfileMismatch != nil {
		serverProfile = opts.ProfileMismatch
	}
	clientCfg := DefaultConfig(RoleClient, "client_runtime", opts.ClientSecret)
	serverCfg := DefaultConfig(RoleServer, "server_runtime", opts.ServerSecret)
	if len(opts.ClientFeatures) > 0 {
		clientCfg.RequiredFeatures = opts.ClientFeatures
	}
	if len(opts.ServerFeatures) > 0 {
		serverCfg.RequiredFeatures = opts.ServerFeatures
	}
	client, err := NewRuntime(clientCfg, clientProfile)
	if err != nil {
		return HarnessSummary{}, nil, err
	}
	server, err := NewRuntime(serverCfg, serverProfile)
	if err != nil {
		return HarnessSummary{}, nil, err
	}
	clientSession, serverSession, err := establishPair(client, server)
	events := []ktrace.Event{}
	if err != nil {
		summary := HarnessSummary{ProfileID: p.ID, ClientState: string(clientSession.State), ServerState: string(serverSession.State)}
		events = append(events, RuntimeTraceEvent(p.ID, clientSession, "runtime_session_failed"))
		return summary, events, err
	}
	link := NewMemoryLink(opts.LinkQueueDepth)
	relay, relayEvents, err := carrierrelay.RunProxyScenario(ctx, p, opts.Scenario, opts.CarrierFamily)
	if err != nil {
		_ = clientSession.Fail("carrier_proxysem_failure")
		_ = serverSession.Fail("carrier_proxysem_failure")
		return HarnessSummary{}, events, err
	}
	clientChannel, err := NewSecureChannel(clientSession.SecurityContext, clientSession.KeySchedule, RoleClient)
	if err != nil {
		return HarnessSummary{}, events, err
	}
	serverChannel, err := NewSecureChannel(serverSession.SecurityContext, serverSession.KeySchedule, RoleServer)
	if err != nil {
		return HarnessSummary{}, events, err
	}
	frame, secureEvent, err := secureExchange(clientChannel, serverChannel, p, clientSession.ID, opts.CarrierFamily)
	if err != nil {
		return HarnessSummary{}, events, err
	}
	if err := link.Send(frame); err != nil {
		return HarnessSummary{}, events, err
	}
	delivered, err := link.Deliver("client_to_server")
	if err != nil {
		return HarnessSummary{}, events, err
	}
	if delivered.Sequence != frame.Sequence {
		return HarnessSummary{}, events, fmt.Errorf("%w: sequence mismatch", ErrSecureChannel)
	}
	replayRejected := 0
	if opts.ReplayInject {
		if _, err := serverChannel.Open(frame.Envelope); err != nil {
			replayRejected++
		}
	}
	_ = clientSession.Close("runtime_complete")
	_ = serverSession.Close("runtime_complete")
	events = append(events, RuntimeTraceEvent(p.ID, clientSession, "runtime_state"))
	events = append(events, RuntimeTraceEvent(p.ID, serverSession, "runtime_state"))
	events = append(events, LinkTraceEvent(p.ID, frame), secureEvent)
	events = append(events, relayEvents...)
	summary := HarnessSummary{
		ProfileID:             p.ID,
		SessionID:             clientSession.ID,
		ClientState:           string(clientSession.State),
		ServerState:           string(serverSession.State),
		StreamsOpened:         relay.SemanticMessageCount,
		StreamsClosed:         relay.SemanticMessageCount,
		FramesClientToServer:  1,
		FramesServerToClient:  0,
		CarrierFamily:         relay.Family,
		ProxyTargetsExercised: targetClasses(relayEvents),
		SecuritySuite:         p.Security.KDFSuite + "/" + p.Security.AEADSuite,
		TranscriptMatched:     clientSession.SecurityContext.TranscriptHash == serverSession.SecurityContext.TranscriptHash,
		CapabilityMatched:     clientSession.SecurityContext.CapabilityHash == serverSession.SecurityContext.CapabilityHash,
		ReplayRejected:        replayRejected,
		BackpressureEvents:    relay.TargetBackpressureEvents + relay.CarrierBackpressureEvents,
		TargetErrors:          relay.TargetErrors,
		TargetResets:          relay.TargetResets,
	}
	summary.PayloadLogged = TraceHasSensitive(events, []byte("payload must not leak"))
	summary.SecretLogged = TraceHasSensitive(events, opts.ClientSecret, opts.ServerSecret)
	return summary, events, nil
}

func establishPair(client, server *Runtime) (*Session, *Session, error) {
	cm := NewManager(client)
	sm := NewManager(server)
	cs, _ := cm.CreateSession()
	ss, _ := sm.CreateSession()
	fail := func(reason string, err error) (*Session, *Session, error) {
		_ = cs.Fail(reason)
		_ = ss.Fail(reason)
		return cs, ss, fmt.Errorf("%s: %w", reason, err)
	}
	if err := CheckPeerProfileMatch(client.Profile, server.Profile); err != nil {
		return fail("profile_mismatch", err)
	}
	if err := cs.BeginNegotiation(); err != nil {
		return fail("client_negotiation_state", err)
	}
	if err := ss.BeginNegotiation(); err != nil {
		return fail("server_negotiation_state", err)
	}
	required := security.CapabilitySet{Features: client.Config.RequiredFeatures}
	negotiated, err := NegotiateCapabilities(LocalCapabilities(client.Config.RequiredFeatures), LocalCapabilities(server.Config.RequiredFeatures), required)
	if err != nil {
		return fail("capability_downgrade", err)
	}
	cs.Capabilities = negotiated.Selected
	ss.Capabilities = negotiated.Selected
	if err := CheckRuntimeCompatibility(client.Profile, security.DefaultRuntimeCompatibility()); err != nil {
		return fail("client_compatibility", err)
	}
	if err := CheckRuntimeCompatibility(server.Profile, security.DefaultRuntimeCompatibility()); err != nil {
		return fail("server_compatibility", err)
	}
	_ = cs.BeginSecuring()
	_ = ss.BeginSecuring()
	cs.SecurityContext, cs.KeySchedule, err = BuildSecurityContext(client.Profile, negotiated.Selected, client.Config.SecuritySecret)
	if err != nil {
		return fail("client_security_context", err)
	}
	ss.SecurityContext, ss.KeySchedule, err = BuildSecurityContext(server.Profile, negotiated.Selected, server.Config.SecuritySecret)
	if err != nil {
		return fail("server_security_context", err)
	}
	if cs.SecurityContext.TranscriptHash != ss.SecurityContext.TranscriptHash {
		return fail("transcript_mismatch", ErrSecureChannel)
	}
	_ = cs.MarkOpen()
	_ = ss.MarkOpen()
	return cs, ss, nil
}

func secureExchange(client, server *SecureChannel, p *ir.Profile, sessionID, family string) (LinkFrame, ktrace.Event, error) {
	env, err := client.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "runtime_session", CarrierFamily: family, MetadataClass: "runtime"}, []byte("runtime-local-bytes"))
	if err != nil {
		return LinkFrame{}, ktrace.Event{}, err
	}
	if _, err := server.Open(env); err != nil {
		return LinkFrame{}, ktrace.Event{}, err
	}
	frame := LinkFrame{
		Direction:     "client_to_server",
		SessionID:     sessionID,
		Sequence:      env.Sequence,
		EnvelopeKind:  env.Semantic,
		ByteCount:     env.CiphertextBytes,
		MetadataClass: env.MetadataClass,
		Envelope:      env,
	}
	return frame, SecureTraceEvent(client.Context, env, RoleClient), nil
}

func targetClasses(events []ktrace.Event) []string {
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.TargetClassBucket != "" {
			seen[ev.TargetClassBucket] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
