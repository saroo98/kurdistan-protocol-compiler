// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"bytes"
	"encoding/json"

	"kurdistan/internal/adapter"
	"kurdistan/internal/carrier"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/localadapter"
	"kurdistan/internal/proxysem"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/security"
	ktrace "kurdistan/internal/trace"
)

func MustNotPanic(name string, fn func()) CheckResult {
	panicked := false
	var recovered any
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				recovered = r
			}
		}()
		fn()
	}()
	if panicked {
		return fail(name, CategoryPanicSafety, "panic recovered", map[string]string{"panic": toString(recovered)})
	}
	return pass(name, CategoryPanicSafety, "no panic", nil)
}

func RunPanicSafetyChecks(profiles []*ir.Profile) []CheckResult {
	p := firstProfile(profiles)
	return []CheckResult{
		MustNotPanic("profile_json_validator_no_panic", func() {
			var profile ir.Profile
			_ = json.Unmarshal([]byte(`{"messages":[`), &profile)
			_ = ir.Validate(&profile)
		}),
		MustNotPanic("frame_decoder_no_panic", func() {
			_, _ = framing.DecodeFrame(p, []byte{0xff, 0, 1, 2, 3})
			_, _, _ = framing.DecodeFrames(p, [][]byte{{0xff, 0, 1}})
		}),
		MustNotPanic("proxy_descriptor_no_panic", func() {
			_ = proxysem.DefaultRegistry().Validate(proxysem.TargetDescriptor{Class: "unknown", Parameters: map[string]string{"url": "blocked"}})
		}),
		MustNotPanic("carrier_envelope_no_panic", func() {
			_ = carrier.ValidateEnvelope(p, carrier.Envelope{CarrierFamily: p.CarrierPolicy.CarrierFamily, Sequence: 0, Kind: "", ByteCount: p.CarrierPolicy.MaxEnvelopeBytes + 1})
		}),
		MustNotPanic("adapter_config_and_flow_no_panic", func() {
			_ = adapter.ValidateConfig(adapter.AdapterConfig{Name: "secret-token", Kind: "bad", RuntimeID: "", MaxFlows: -1})
			_ = adapter.ValidateFlowDescriptor(adapter.FlowDescriptor{ID: "", MaxReadBytes: -1, MaxWriteBytes: -1})
		}),
		MustNotPanic("local_adapter_config_and_chunk_no_panic", func() {
			_ = localadapter.ValidateConfig(localadapter.LocalAdapterConfig{Name: "secret-token", RuntimeID: "", MaxFlows: -1})
			_ = localadapter.ValidateSourceChunk(localadapter.LocalSourceChunk{FlowID: "", Sequence: 0, ByteCount: 1 << 30}, localadapter.DefaultConfig("panic-local"))
		}),
		MustNotPanic("security_config_no_panic", func() {
			_ = security.ValidateConfig(security.SecurityConfig{})
		}),
		MustNotPanic("secure_envelope_no_panic", func() {
			ctx, keys, err := securityContextForProfile(p)
			if err != nil {
				return
			}
			codec, err := security.NewEnvelopeCodec(ctx, keys, "client")
			if err != nil {
				return
			}
			_, _ = codec.Open(security.SecureEnvelope{Sequence: 1, TranscriptHash: "bad"})
		}),
		MustNotPanic("runtime_link_no_panic", func() {
			link := kruntime.NewMemoryLink(1)
			_ = link.Send(kruntime.LinkFrame{})
			link.Close()
			_ = link.Send(kruntime.LinkFrame{Direction: "client_to_server"})
		}),
		MustNotPanic("trace_parser_no_panic", func() {
			_, _ = ktrace.DecodeJSONL(bytes.NewReader([]byte("{bad json\n")))
		}),
		MustNotPanic("audit_json_parser_no_panic", func() {
			var value map[string]any
			_ = json.Unmarshal([]byte(`{"gates":[{"name":1}]`), &value)
		}),
	}
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case error:
		return v.Error()
	default:
		raw, _ := json.Marshal(v)
		return string(raw)
	}
}
