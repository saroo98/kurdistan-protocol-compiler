// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package auth

import (
	"bytes"
	"fmt"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/liveprogram"
	"runtime"
	"strings"
	"testing"
)

func projectedResultV3(t *testing.T) (*ProcessHandshakeResultV1, liveprogram.ProgramV1) {
	t.Helper()
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	f := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	p := projectedProcessProgramV1(f.input.SelectedPolicy)
	return projectedResultProgramV3(t, p)
}
func projectedResultProgramV3(t *testing.T, p liveprogram.ProgramV1) (*ProcessHandshakeResultV1, liveprogram.ProgramV1) {
	t.Helper()
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	f := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	cfg, err := NewProjectedProcessHandshakeConfigV1(f.input.Client.IdentityID, f.input.Server.IdentityID, p, "tls13-tcp")
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClientProcessHandshakeV1(cfg, f.input.ClientDependencies, bytes.NewReader(bytes.Repeat([]byte{49}, 1024)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	cache, _ := NewHandshakeReplayCache(64)
	r, err := newRelayProcessHandshakeV1(cfg, f.input.ServerDependencies, cache, bytes.NewReader(bytes.Repeat([]byte{146}, 1024)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ch, err := c.Start()
	if err != nil {
		t.Fatal(err)
	}
	sh, err := r.AcceptClientHello(ch)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := c.AcceptServerHello(sh)
	if err != nil {
		t.Fatal(err)
	}
	sf, rr, err := r.AcceptClientFinish(cf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rr.Close)
	cr, err := c.AcceptServerFinish(sf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cr.Close)
	return cr, p
}

func TestProjectedContextV3BindsActualHandshakeAndRejectsOtherPrograms(t *testing.T) {
	result, p := projectedResultV3(t)
	s, ok := result.ContextSnapshotV1()
	if !ok {
		t.Fatal("snapshot")
	}
	if err := ValidateProjectedProcessContextV3(s, p, "tls13-tcp"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*liveprogram.ProgramV1){
		"frame": func(p *liveprogram.ProgramV1) { p.Frame.Compiled.DataTypeTag[0] ^= 64 },
		"padding": func(p *liveprogram.ProgramV1) {
			p.Padding = liveprogram.PaddingV1{Mode: "bounded", MaxPaddingBytes: 10}
		},
		"limit":    func(p *liveprogram.ProgramV1) { p.Limits.MaxFrameBytes++ },
		"message":  func(p *liveprogram.ProgramV1) { p.Messages[0].MaxPayloadBytes-- },
		"security": func(p *liveprogram.ProgramV1) { p.Security.Policy.ReplayWindowSize++ },
	} {
		t.Run(name, func(t *testing.T) {
			other := p.Clone()
			mutate(&other)
			if liveprogram.ValidateV1(other) != nil {
				t.Fatal("invalid mutation")
			}
			if ValidateProjectedProcessContextV3(s, other, "tls13-tcp") == nil {
				t.Fatal("different program accepted")
			}
		})
	}
	for _, mutate := range []func(*AuthenticatedContextSnapshotV1){func(s *AuthenticatedContextSnapshotV1) { s.ContextHash[0] ^= 1 }, func(s *AuthenticatedContextSnapshotV1) { s.ServerProfileHash[0] ^= 1 }, func(s *AuthenticatedContextSnapshotV1) { s.ServerLimitBlock.MaxFrameBytes++ }, func(s *AuthenticatedContextSnapshotV1) { s.ServerModeBinding.FramingPolicyHash[0] ^= 1 }} {
		other := cloneContextSnapshot(s)
		mutate(&other)
		if ValidateProjectedProcessContextV3(other, p, "tls13-tcp") == nil {
			t.Fatal("tampered context")
		}
	}
	if ValidateProjectedProcessContextV3(s, p, "other") == nil {
		t.Fatal("carrier")
	}
	if _, ok = result.ContextSnapshotV1(); !ok {
		t.Fatal("validation consumed secret")
	}
}

func TestProjectedContextV3SnapshotGuardsAndOwnership(t *testing.T) {
	result, p := projectedResultV3(t)
	for _, budget := range []uint64{0, ProjectedContextValidationBytesV3 - 1} {
		if _, e := result.ProjectedContextSnapshotV3(p, "tls13-tcp", budget); e == nil {
			t.Fatal("short budget")
		}
	}
	for name, mutate := range map[string]func(*AuthenticatedContextSnapshotV1, *liveprogram.ProgramV1){
		"program text": func(_ *AuthenticatedContextSnapshotV1, p *liveprogram.ProgramV1) {
			p.SourceSchemaVersion = strings.Repeat("a", 257)
		},
		"snapshot text": func(s *AuthenticatedContextSnapshotV1, _ *liveprogram.ProgramV1) {
			s.ClientModeBinding.CarrierFamily = strings.Repeat("a", 257)
		},
		"list": func(s *AuthenticatedContextSnapshotV1, _ *liveprogram.ProgramV1) {
			s.ClientModeBinding.FeatureVectors = make([]string, 65)
		},
		"bytes": func(_ *AuthenticatedContextSnapshotV1, p *liveprogram.ProgramV1) {
			p.Frame.Compiled.DataTypeTag = make([]byte, 511)
		},
		"aggregate": func(s *AuthenticatedContextSnapshotV1, _ *liveprogram.ProgramV1) {
			s.ClientModeBinding.FeatureVectors = make([]string, 64)
			for i := range s.ClientModeBinding.FeatureVectors {
				s.ClientModeBinding.FeatureVectors[i] = strings.Repeat("a", 256)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			result.mu.Lock()
			saved := result.context
			other := p.Clone()
			mutate(&result.context, &other)
			result.mu.Unlock()
			defer func() { result.mu.Lock(); result.context = saved; result.mu.Unlock() }()
			if _, e := result.ProjectedContextSnapshotV3(other, "tls13-tcp", ProjectedContextValidationBytesV3); e == nil {
				t.Fatal("unguarded input")
			}
			if len(result.secret) == 0 {
				t.Fatal("consumed secret")
			}
		})
	}
	s, e := result.ProjectedContextSnapshotV3(p, "tls13-tcp", ProjectedContextValidationBytesV3)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.EffectivePolicy.SelectedCapabilities) != cap(s.EffectivePolicy.SelectedCapabilities) {
		t.Fatal("descriptor excess capacity")
	}
	s.EffectivePolicy.SelectedCapabilities[0] = "changed"
	if result.context.EffectivePolicy.SelectedCapabilities[0] == "changed" {
		t.Fatal("descriptor alias")
	}
	result.Close()
	if _, e = result.ProjectedContextSnapshotV3(p, "tls13-tcp", ProjectedContextValidationBytesV3); e == nil {
		t.Fatal("closed result")
	}
}

func TestProjectedContextV3ConstructionAllowance(t *testing.T) {
	_, ordinary := projectedResultV3(t)
	worst := ordinary.Clone()
	worst.SourceSchemaVersion = strings.Repeat("s", 256)
	worst.Security.CompilerSecurityVersion = strings.Repeat("c", 256)
	worst.Security.MinimumRuntimeVersion = strings.Repeat("r", 256)
	worst.Security.Policy.SecurityVersion = strings.Repeat("v", 256)
	worst.Scheduler.PriorityMode = strings.Repeat("<", 256)
	worst.Messages[0].WireSymbol = strings.Repeat("a", 96)
	worst.Messages[1].WireSymbol = strings.Repeat("b", 96)
	worst.Frame.Compiled.DataTypeTag = bytes.Repeat([]byte{1}, 255)
	worst.Frame.Compiled.PaddingTypeTag = bytes.Repeat([]byte{2}, 255)
	// All ten recognized capabilities, maximum tag/text inputs and full context
	// mode exercise all nested retained/canonical blocks on a genuine handshake.
	all := []string{"adapter_interface", "carrier_abstraction", "carrier_backpressure", "carrier_loss_recovery", "generated_backend", "multi_stream", "nonce_schedule", "proxy_semantics", "replay_window", "transcript_binding"}
	worst.Security.SelectedCapabilities = all
	worst.Security.ClientMandatoryCapabilities = []string{"multi_stream"}
	worst.Security.RelayMandatoryCapabilities = []string{"multi_stream"}
	for name, p := range map[string]liveprogram.ProgramV1{"ordinary": ordinary, "max_supported_fields": worst} {
		t.Run(name, func(t *testing.T) {
			r, p := projectedResultProgramV3(t, p)
			if _, e := r.ProjectedContextSnapshotV3(p, "tls13-tcp", ProjectedContextValidationBytesV3); e != nil {
				t.Fatal(e)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			var retained AuthenticatedContextSnapshotV1
			for i := 0; i < 20; i++ {
				var e error
				retained, e = r.ProjectedContextSnapshotV3(p, "tls13-tcp", ProjectedContextValidationBytesV3)
				if e != nil {
					t.Fatal(e)
				}
			}
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(retained)
			bytesPer := (after.TotalAlloc - before.TotalAlloc) / 20
			t.Logf("snapshot+validation total allocation %d bytes/call", bytesPer)
			if bytesPer > ProjectedContextValidationBytesV3 {
				t.Fatal("construction reserve exceeded")
			}
		})
	}
}

func TestProjectedContextV3MaxGuardedMalformedAllowance(t *testing.T) {
	r, p := projectedResultV3(t)
	s, ok := r.ContextSnapshotV1()
	if !ok {
		t.Fatal("snapshot")
	}
	base := s
	// Maximize one canonical mode list up to the aggregate guard, without
	// allowing oversized input to reach canonical encoders. This is a negative
	// context-identity test, not a fabricated authenticated success.
	width := 0
	for n := 3; n <= 256; n++ {
		candidate := base
		candidate.ClientModeBinding.FeatureVectors = make([]string, 64)
		for i := range candidate.ClientModeBinding.FeatureVectors {
			candidate.ClientModeBinding.FeatureVectors[i] = fmt.Sprintf("%02d", i) + strings.Repeat("x", n-2)
		}
		if !boundedProjectionInputV3(candidate, p) {
			break
		}
		s = candidate
		width = n
	}
	if width < 100 || width == 256 {
		t.Fatal("aggregate stress fixture", width)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 20; i++ {
		if ValidateProjectedProcessContextV3(s, p, "tls13-tcp") == nil {
			t.Fatal("forged context accepted")
		}
	}
	runtime.ReadMemStats(&after)
	per := (after.TotalAlloc - before.TotalAlloc) / 20
	t.Logf("max guarded 64x%d mode list: %d bytes/call", width, per)
	if per > ProjectedContextValidationBytesV3 {
		t.Fatal("guarded failure allocation reserve")
	}
}
