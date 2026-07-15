// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package mutant_test

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/lab/runtimeadversary"
	"kurdistan/internal/protocol/compiler"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/testkit/mutant"
)

func TestRealMutantCorpusRedGreenV1(t *testing.T) {
	table := runtimeadversary.RealMutantCorpusTableV1()
	if len(table) != 16 {
		t.Fatalf("rows=%d want 16", len(table))
	}
	seen, families := make(map[string]bool, 16), map[string]int{}
	rows := make(map[string]runtimeadversary.RealMutantCorpusRowV1, 16)
	for _, row := range table {
		if seen[row.Mode] || row.Mode == "" || row.Owner == "" || row.Category == "" || row.Detector == "" {
			t.Fatalf("invalid row=%+v", row)
		}
		seen[row.Mode], families[row.Family] = true, families[row.Family]+1
		rows[row.Mode] = row
	}
	if families["security"] != 8 || families["runtime"] != 8 {
		t.Fatalf("families=%v", families)
	}
	results, err := runtimeadversary.RunRealMutantCorpusV1(17001)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(table) {
		t.Fatalf("results=%d", len(results))
	}
	for _, result := range results {
		row, exists := rows[result.Mode]
		if !exists || result.Category != row.Category || result.Detector != row.Detector || result.Count != row.ExpectedCount || !result.UnsafeObserved || !result.DetectorRed || !result.ControlGreen {
			t.Fatalf("mode %s did not produce real red/green evidence: %+v", result.Mode, result)
		}
	}
}

func TestRealMutantCorpusNoStampedResultV1(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "lab", "runtimeadversary", "runner.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start, end := strings.Index(text, "func RunRealMutantCorpusV1"), strings.Index(text, "func RunScenario(")
	if start < 0 || end < 0 || start >= end {
		t.Fatal("real-corpus source boundary missing")
	}
	path := text[start:end]
	for _, forbidden := range []string{"RunMutantScenarioCorpus", "runReplayFaultScenario", "Correct = false", "Correct = true", "Summary.", "ProfileID", "payload", "secret", "ciphertext", "destination"} {
		if strings.Contains(path, forbidden) {
			t.Fatalf("real corpus contains stamped/sensitive path %q", forbidden)
		}
	}
}

func TestConcreteFaultTokenForgeRejectedV1(t *testing.T) {
	authToken, err := mutant.AcquireAuthFaultV1(mutant.ModeUnsafeConfigAllowed)
	if err != nil {
		t.Fatal(err)
	}
	runtimeToken, err := mutant.AcquireRuntimeLabFaultV1(mutant.ModeRuntimeAcceptsReplay)
	if err != nil {
		t.Fatal(err)
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%10v", "%.3v", "%+-#10.3v"}
	for _, token := range []any{authToken, runtimeToken} {
		want := fmt.Sprintf(formats[0], token)
		if want == "" {
			t.Fatal("empty redaction")
		}
		for _, format := range formats[1:] {
			if got := fmt.Sprintf(format, token); got != want {
				t.Fatalf("format %q=%q want constant %q", format, got, want)
			}
		}
		if _, err := json.Marshal(token); err == nil {
			t.Fatalf("JSON encoded %T", token)
		}
		var encoded bytes.Buffer
		if err := gob.NewEncoder(&encoded).Encode(token); err == nil {
			t.Fatalf("gob encoded %T", token)
		}
	}
	var zeroAuth auth.AuthLabFaultToken
	if err := json.Unmarshal([]byte(`{}`), &zeroAuth); err == nil {
		t.Fatal("JSON reconstructed auth token")
	}
	if err := zeroAuth.UnmarshalText([]byte("x")); err == nil {
		t.Fatal("text reconstructed auth token")
	}
	if err := zeroAuth.UnmarshalBinary([]byte("x")); err == nil {
		t.Fatal("binary reconstructed auth token")
	}
	if auth.UnsafeConfigAllowedAuthLabFaultV1(zeroAuth) {
		t.Fatal("zero auth token accepted")
	}
	copyAuth := authToken
	if !auth.UnsafeConfigAllowedAuthLabFaultV1(copyAuth) {
		t.Fatal("valid by-value auth copy rejected")
	}
	if _, err := mutant.AcquireAuthFaultV1("unknown"); !errors.Is(err, mutant.ErrInvalidLabFault) {
		t.Fatal("unknown auth mode accepted")
	}
	if _, err := mutant.AcquireRuntimeLabFaultV1("unknown"); !errors.Is(err, mutant.ErrInvalidLabFault) {
		t.Fatal("unknown runtime mode accepted")
	}
}

func TestSecurityMutantMintAllowlistV1(t *testing.T) {
	authModes := []string{mutant.ModeNoTranscriptBinding, mutant.ModeAcceptsDowngrade, mutant.ModeCapabilityMismatchAccepted, mutant.ModeProfileMismatchAccepted, mutant.ModeUnsafeConfigAllowed, mutant.ModeRuntimeAcceptsCapabilityDowngrade, mutant.ModeRuntimeAcceptsProfileMismatch}
	runtimeModes := []string{mutant.ModeReusedNonce, mutant.ModeAcceptsReplay, mutant.ModeSecretTraceLeak, mutant.ModeRuntimeAcceptsReplay, mutant.ModeRuntimeIgnoresBackpressure, mutant.ModeRuntimeLeaksSecretTrace, mutant.ModeRuntimeLeaksPayloadTrace, mutant.ModeRuntimeNoStateValidation, mutant.ModeRuntimePaddingOnlyDiversity}
	seen := map[string]bool{}
	for _, mode := range authModes {
		if seen[mode] {
			t.Fatalf("duplicate %s", mode)
		}
		seen[mode] = true
		if _, err := mutant.AcquireAuthFaultV1(mode); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if _, err := mutant.AcquireRuntimeLabFaultV1(mode); !errors.Is(err, mutant.ErrInvalidLabFault) {
			t.Fatalf("runtime mint accepted auth mode %s", mode)
		}
	}
	for _, mode := range runtimeModes {
		if seen[mode] {
			t.Fatalf("duplicate %s", mode)
		}
		seen[mode] = true
		if _, err := mutant.AcquireRuntimeLabFaultV1(mode); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if _, err := mutant.AcquireAuthFaultV1(mode); !errors.Is(err, mutant.ErrInvalidLabFault) {
			t.Fatalf("auth mint accepted runtime mode %s", mode)
		}
	}
	if len(seen) != 16 {
		t.Fatalf("modes=%d", len(seen))
	}
	if _, err := mutant.AcquireAuthFaultV1("unknown"); !errors.Is(err, mutant.ErrInvalidLabFault) {
		t.Fatal("unknown auth mode accepted")
	}
	if _, err := mutant.AcquireRuntimeLabFaultV1("unknown"); !errors.Is(err, mutant.ErrInvalidLabFault) {
		t.Fatal("unknown runtime mode accepted")
	}
}

func TestSerializedUnsafePolicyCannotAcquireLabFault(t *testing.T) {
	p, err := compiler.Generate(412)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.ReplayPolicy = "accept_all"
	p.GenerationHash = ""
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unsafe-profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := kruntime.LoadProfile(path, p.ID); err == nil {
		t.Fatal("serialized unsafe replay policy reached normal runtime loading")
	}
}

func TestStrictNormalNoFaultV1(t *testing.T) {
	p, err := compiler.Generate(411)
	if err != nil {
		t.Fatal(err)
	}
	ctx, keys, err := kruntime.BuildSecurityContext(p, security.DefaultCapabilities(), []byte("lab-fault-test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	sender, err := kruntime.NewSecureChannel(ctx, keys, kruntime.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	normal, err := kruntime.NewSecureChannel(ctx, keys, kruntime.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	first, err := sender.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "data", CarrierFamily: "stream_carrier"}, []byte("synthetic-lab-payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Open(first); err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Open(first); !errors.Is(err, security.ErrReplay) {
		t.Fatalf("normal channel duplicate error = %v, want ErrReplay", err)
	}

}
