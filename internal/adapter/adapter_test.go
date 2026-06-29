// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import "testing"

func TestConfigValidationAndRedaction(t *testing.T) {
	cfg := DefaultConfig("local-adapter", AdapterKindIngress)
	if err := ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.Name = ""
	if err := ValidateConfig(bad); err == nil {
		t.Fatalf("empty name accepted")
	}
	bad = cfg
	bad.Kind = "external"
	if err := ValidateConfig(bad); err == nil {
		t.Fatalf("bad kind accepted")
	}
	bad = cfg
	bad.MaxFlows = MaxAdapterFlows + 1
	if err := ValidateConfig(bad); err == nil {
		t.Fatalf("unsafe max flows accepted")
	}
	bad = cfg
	bad.Capabilities = append(bad.Capabilities, CapabilityIngress)
	if err := ValidateConfig(bad); err == nil {
		t.Fatalf("duplicate capability accepted")
	}
	bad = cfg
	bad.Name = "raw_secret_value"
	if err := ValidateConfig(bad); err == nil {
		t.Fatalf("secret-like value accepted")
	}
	if got := RedactConfig(bad); got.Name != "redacted" {
		t.Fatalf("secret-like name was not redacted")
	}
}

func TestCapabilities(t *testing.T) {
	hashA, err := CapabilityHash(DefaultCapabilityNames())
	if err != nil {
		t.Fatal(err)
	}
	reordered := append([]string(nil), DefaultCapabilityNames()...)
	for i, j := 0, len(reordered)-1; i < j; i, j = i+1, j-1 {
		reordered[i], reordered[j] = reordered[j], reordered[i]
	}
	hashB, err := CapabilityHash(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("capability hash not canonical")
	}
	if err := RequireCapabilities(DefaultCapabilityNames(), []string{CapabilityIngress}); err == nil {
		t.Fatalf("capability downgrade accepted")
	}
}

func TestFlowLifecycle(t *testing.T) {
	desc := testFlowDescriptor("flow-1")
	flow, err := NewFlow(desc)
	if err != nil {
		t.Fatal(err)
	}
	caps := DefaultCapabilities()
	if err := flow.Open(caps); err != nil {
		t.Fatal(err)
	}
	if err := flow.Transition(FlowHalfClosed, caps); err != nil {
		t.Fatal(err)
	}
	if err := flow.Close(caps); err != nil {
		t.Fatal(err)
	}
	if err := flow.Close(caps); err != nil {
		t.Fatalf("idempotent close failed: %v", err)
	}
	if err := flow.RecordWrite(1); err == nil {
		t.Fatalf("write after close accepted")
	}
	flow, _ = NewFlow(desc)
	caps.SupportsHalfClose = false
	if err := flow.Open(caps); err != nil {
		t.Fatal(err)
	}
	if err := flow.Transition(FlowHalfClosed, caps); err == nil {
		t.Fatalf("half-close without capability accepted")
	}
}

func TestHarnessRoundTripAndBackpressure(t *testing.T) {
	cfg := DefaultConfig("harness", AdapterKindIngress)
	cfg.MaxBufferedBytes = 100
	h, err := NewHarness(cfg, DefaultCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	desc := testFlowDescriptor("flow-1")
	desc.MaxReadBytes = 1024
	desc.MaxWriteBytes = 1024
	if err := h.OpenFlow(desc); err != nil {
		t.Fatal(err)
	}
	chunk, err := h.ReadFlow(desc.ID, 256)
	if err != ErrBackpressure {
		t.Fatalf("ReadFlow error = %v, want ErrBackpressure", err)
	}
	if !chunk.Backpressure {
		t.Fatalf("chunk did not mark backpressure")
	}
	if err := h.WriteFlow(desc.ID, AdapterChunk{FlowID: desc.ID, Sequence: chunk.Sequence, ByteCount: 256}); err != nil {
		t.Fatal(err)
	}
	if err := h.ResetFlow(desc.ID, "test"); err != nil {
		t.Fatal(err)
	}
	summary := h.HarnessSummary()
	if summary.FlowsOpened != 1 || summary.FlowsReset != 1 || summary.PayloadLogged || summary.SecretLogged {
		t.Fatalf("unexpected harness summary: %+v", summary)
	}
}

func FuzzValidateFlowDescriptor(f *testing.F) {
	f.Add("flow-1", 128, 128)
	f.Fuzz(func(t *testing.T, id string, readBytes, writeBytes int) {
		desc := testFlowDescriptor(FlowID(id))
		desc.MaxReadBytes = readBytes
		desc.MaxWriteBytes = writeBytes
		_ = ValidateFlowDescriptor(desc)
	})
}

func BenchmarkHarnessManySmallFlows(b *testing.B) {
	cfg := DefaultConfig("bench", AdapterKindIngress)
	for i := 0; i < b.N; i++ {
		h, err := NewHarness(cfg, DefaultCapabilities())
		if err != nil {
			b.Fatal(err)
		}
		for flow := 0; flow < 8; flow++ {
			desc := testFlowDescriptor(FlowID("flow-bench-" + string(rune('a'+flow))))
			if err := h.OpenFlow(desc); err != nil {
				b.Fatal(err)
			}
			chunk, err := h.ReadFlow(desc.ID, 64)
			if err != nil {
				b.Fatal(err)
			}
			if err := h.WriteFlow(desc.ID, chunk); err != nil {
				b.Fatal(err)
			}
			if err := h.CloseFlow(desc.ID); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func testFlowDescriptor(id FlowID) FlowDescriptor {
	return FlowDescriptor{
		ID:             id,
		Class:          "synthetic",
		Direction:      "bidirectional",
		RequestClass:   "interactive",
		PriorityClass:  "interactive",
		TargetHint:     "synthetic",
		MaxReadBytes:   1024,
		MaxWriteBytes:  1024,
		MetadataPolicy: "bucketed",
	}
}
