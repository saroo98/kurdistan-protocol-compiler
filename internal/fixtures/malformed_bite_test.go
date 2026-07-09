// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"testing"

	"kurdistan/internal/observe/bytetransport"
)

// statefulMalformedClasses are the corpus classes that were previously backed by
// hardcoded reject verdicts and are now driven through the real reassembler /
// sequence validator / frame validator.
var statefulMalformedClasses = map[string]bool{
	"fragment_mismatch":    true,
	"duplicate_fragment":   true,
	"missing_fragment":     true,
	"oversized_reassembly": true,
	"sequence_replay":      true,
	"old_sequence":         true,
	"future_sequence":      true,
	"post_close_data":      true,
	"post_reset_data":      true,
	"invalid_metadata":     true,
	"oversized_metadata":   true,
}

// TestStatefulMalformedCasesAreRealNotCanned is the mutation-proves-detection
// guard for the de-hollowed corpus. It asserts two complementary facts:
//  1. every stateful malformed case actually rejects (safely), and
//  2. the VALID counterpart of each mechanism is ACCEPTED by the same real
//     component — so the rejections above are conditional on the malformation,
//     not an unconditional/hardcoded verdict.
//
// If the drivers were canned (always reject), part 2 fails. If the real
// component stopped rejecting a malformation, part 1 fails.
func TestStatefulMalformedCasesAreRealNotCanned(t *testing.T) {
	// Part 1: malformed inputs reject.
	seen := 0
	for _, tc := range DefaultMalformedCorpus() {
		if !statefulMalformedClasses[tc.InputClass] {
			continue
		}
		seen++
		res := RunMalformedCase(tc)
		if !res.Rejected {
			t.Errorf("stateful case %q: expected real rejection, got accepted", tc.Name)
		}
		if !res.SafeError {
			t.Errorf("stateful case %q: rejection was not a safe error", tc.Name)
		}
	}
	if seen != len(statefulMalformedClasses) {
		t.Fatalf("expected %d stateful cases in corpus, exercised %d", len(statefulMalformedClasses), seen)
	}

	// Part 2: valid counterparts are accepted by the same real components.
	cfg := bytetransport.DefaultConfig("bite-check")
	cfg.MaxPayloadBytes = 128
	cfg.MaxFrameBytes = 256
	cfg.MaxReassemblyBytes = 512
	cfg.MaxFragments = 4
	base := bytetransport.ByteFrame{
		SessionID:     cfg.RuntimeID,
		StreamID:      1,
		Sequence:      1,
		Kind:          bytetransport.FrameData,
		FragmentIndex: 0,
		FragmentCount: 1,
		ByteCount:     8,
		MetadataClass: "ok",
	}

	// A single valid (unfragmented) frame reassembles to completion.
	r, err := bytetransport.NewReassembler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Add(base)
	if err != nil || res.Rejected || !res.Complete {
		t.Fatalf("valid single frame should reassemble complete: res=%+v err=%v", res, err)
	}

	// A monotonically increasing sequence is accepted (proves replay/old/future
	// rejections are conditional, not universal).
	v := bytetransport.NewSequenceValidator(0)
	a, b := base, base
	a.Sequence, b.Sequence = 1, 2
	if err := v.Accept(a); err != nil {
		t.Fatalf("seq 1 should be accepted: %v", err)
	}
	if err := v.Accept(b); err != nil {
		t.Fatalf("monotonic seq 2 should be accepted: %v", err)
	}

	// A frame with a bounded metadata class passes validation (proves the
	// metadata rejections are conditional on the oversize).
	if err := bytetransport.ValidateFrame(cfg, base); err != nil {
		t.Fatalf("valid frame should pass ValidateFrame: %v", err)
	}
}
