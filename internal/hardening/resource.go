// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"fmt"

	"kurdistan/internal/adapter"
	"kurdistan/internal/carrier"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxysem"
	kruntime "kurdistan/internal/runtime"
	kstream "kurdistan/internal/stream"
)

func RunResourceLimitChecks(ctx context.Context, profiles []*ir.Profile, opts Options) []CheckResult {
	_ = ctx
	p := firstProfile(profiles)
	return []CheckResult{
		check("audit_profile_count_respected", CategoryResourceLimits, func() error {
			limit := opts.ProfileCount
			if opts.Mode == "quick" && limit > 100 {
				return fmt.Errorf("quick profile count too high")
			}
			if opts.Mode == "full" && limit > 1000 {
				return fmt.Errorf("full profile count too high")
			}
			return nil
		}),
		check("frame_size_limit_enforced", CategoryResourceLimits, func() error {
			payload := make([]byte, p.Limits.MaxPayloadBytes+1)
			if _, err := framing.EncodeOperation(p, framing.Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: payload}, p.Seed); err == nil {
				return fmt.Errorf("oversized frame accepted")
			}
			return nil
		}),
		check("stream_and_session_limits_enforced", CategoryResourceLimits, func() error {
			s, err := kstream.NewSession(kstream.Config{MaxConcurrentStreams: 1, InitialStreamWindowBytes: 4, InitialSessionWindowBytes: 4})
			if err != nil {
				return err
			}
			if _, err := s.OpenStream("interactive"); err != nil {
				return err
			}
			if _, err := s.OpenStream("bulk"); err == nil {
				return fmt.Errorf("stream limit ignored")
			}
			cfg := kruntime.DefaultConfig(kruntime.RoleClient, "rt", []byte("secret"))
			cfg.MaxSessions = 1
			rt, err := kruntime.NewRuntime(cfg, p)
			if err != nil {
				return err
			}
			manager := kruntime.NewManager(rt)
			if _, err := manager.CreateSession(); err != nil {
				return err
			}
			if _, err := manager.CreateSession(); err == nil {
				return fmt.Errorf("session limit ignored")
			}
			return nil
		}),
		check("carrier_queue_depth_enforced", CategoryResourceLimits, func() error {
			link := kruntime.NewMemoryLink(1)
			if err := link.Send(kruntime.LinkFrame{Direction: "client_to_server"}); err != nil {
				return err
			}
			if err := link.Send(kruntime.LinkFrame{Direction: "client_to_server"}); err == nil {
				return fmt.Errorf("link queue depth ignored")
			}
			return nil
		}),
		check("target_request_response_limits_enforced", CategoryResourceLimits, func() error {
			registry := proxysem.DefaultRegistry()
			_, _, err := registry.Run(proxysem.TargetDescriptor{Class: proxysem.TargetEcho}, proxysem.TargetRequest{StreamID: 1, Bytes: proxysem.DefaultMaxRequestBytes + 1}, 1)
			if err == nil {
				return fmt.Errorf("oversized target request accepted")
			}
			if err := registry.Validate(proxysem.TargetDescriptor{Class: proxysem.TargetFixedResponse, Parameters: map[string]string{"bytes": fmt.Sprint(proxysem.DefaultMaxResponseBytes + 1)}}); err == nil {
				return fmt.Errorf("oversized target response accepted")
			}
			return nil
		}),
		check("carrier_envelope_limit_enforced", CategoryResourceLimits, func() error {
			if err := carrier.ValidateEnvelope(p, carrier.Envelope{CarrierFamily: p.CarrierPolicy.CarrierFamily, Sequence: 1, Kind: "data", StreamID: 1, MessageCount: 1, ByteCount: p.CarrierPolicy.MaxEnvelopeBytes + 1}); err == nil {
				return fmt.Errorf("oversized envelope accepted")
			}
			return nil
		}),
		check("adapter_resource_limits_enforced", CategoryResourceLimits, func() error {
			cfg := adapter.DefaultConfig("hardening-adapter", adapter.AdapterKindIngress)
			cfg.MaxFlows = 1
			cfg.MaxBufferedBytes = 128
			h, err := adapter.NewHarness(cfg, adapter.DefaultCapabilities())
			if err != nil {
				return err
			}
			desc := adapter.FlowDescriptor{ID: "flow-1", Class: "synthetic", Direction: "bidirectional", RequestClass: "interactive", PriorityClass: "interactive", MaxReadBytes: 1024, MaxWriteBytes: 1024, MetadataPolicy: "bucketed"}
			if err := h.OpenFlow(desc); err != nil {
				return err
			}
			desc.ID = "flow-2"
			if err := h.OpenFlow(desc); err == nil {
				return fmt.Errorf("adapter max flow limit ignored")
			}
			if _, err := h.ReadFlow("flow-1", 256); err != adapter.ErrBackpressure {
				return fmt.Errorf("adapter buffered byte limit was not surfaced")
			}
			return nil
		}),
	}
}
