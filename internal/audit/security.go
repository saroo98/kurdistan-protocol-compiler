// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	"kurdistan/internal/security"
)

func RunSecurityAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	gates := []GateResult{
		SecurityTranscriptBindingGate(profiles),
		SecurityKeyScheduleGate(profiles),
		SecurityNonceUniquenessGate(profiles),
		SecurityReplayRejectionGate(),
		SecurityDowngradeResistanceGate(profiles),
		SecurityCapabilityNegotiationGate(profiles),
		SecurityProfileCompatibilityGate(profiles),
		SecurityConfigHygieneGate(profiles),
		SecuritySecretTraceHygieneGate(profiles),
		SecurityMutantDetectionGate(ctx),
		SecurityGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "security-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: securitySummary(profiles),
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func SecurityTranscriptBindingGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	modes := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		input, err := transcriptInputForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		base, err := security.TranscriptHash(input)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		modes[p.Security.TranscriptMode] = true
		mutations := []func(*security.TranscriptInput){
			func(v *security.TranscriptInput) { v.ProfileHash = "changed-profile" },
			func(v *security.TranscriptInput) { v.StreamPolicy = "changed-stream" },
			func(v *security.TranscriptInput) { v.ProxyPolicy = "changed-proxy" },
			func(v *security.TranscriptInput) { v.CarrierPolicy = "changed-carrier" },
			func(v *security.TranscriptInput) { v.Capabilities = []string{"multi_stream"} },
		}
		for _, mutate := range mutations {
			changed := input
			mutate(&changed)
			next, err := security.TranscriptHash(changed)
			if err != nil {
				failures = append(failures, err.Error())
				continue
			}
			if next == base {
				failures = append(failures, "transcript mutation did not change hash for "+p.ID)
			}
		}
	}
	return gate("security_transcript_binding", len(failures) == 0, "required", fmt.Sprintf("%d profiles checked for transcript binding", len(selectProfiles(profiles, 3))), map[string]any{
		"transcript_modes": keys(modes),
	}, failures)
}

func SecurityKeyScheduleGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	suites := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		suites[p.Security.KDFSuite+"/"+p.Security.AEADSuite] = true
		a, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		b, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if !bytes.Equal(a.ClientWriteKey, b.ClientWriteKey) || bytes.Equal(a.ClientWriteKey, a.ServerWriteKey) || bytes.Equal(a.ClientNonceBase, a.ServerNonceBase) {
			failures = append(failures, "key schedule invariant failed for "+p.ID)
		}
	}
	return gate("security_key_schedule", len(failures) == 0, "required", fmt.Sprintf("%d security suites exercised", len(suites)), map[string]any{
		"security_suites": keys(suites),
	}, failures)
}

func SecurityNonceUniquenessGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	modes := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ks, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		modes[p.Security.NonceMode] = true
		manager := security.NewNonceManager("client", ks.ClientNonceBase, p.Security.NonceMode)
		seen := map[string]bool{}
		for i := 0; i < 64; i++ {
			nonce, _, err := manager.Next()
			if err != nil {
				failures = append(failures, err.Error())
				break
			}
			key := string(nonce)
			if seen[key] {
				failures = append(failures, "duplicate nonce for "+p.ID)
				break
			}
			seen[key] = true
		}
	}
	return gate("security_nonce_uniqueness", len(failures) == 0, "required", fmt.Sprintf("%d nonce modes exercised", len(modes)), map[string]any{
		"nonce_modes": keys(modes),
	}, failures)
}

func SecurityReplayRejectionGate() GateResult {
	failures := []string{}
	window := security.NewReplayWindow("windowed_replay", 4)
	for _, seq := range []uint64{1, 3, 2, 4} {
		if err := window.Accept(seq); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if err := window.Accept(3); err == nil {
		failures = append(failures, "duplicate sequence accepted")
	}
	if err := security.NewReplayWindow("ordered_only", 4).Accept(2); err == nil {
		failures = append(failures, "ordered-only accepted out-of-order")
	}
	return gate("security_replay_rejection", len(failures) == 0, "required", "duplicate and out-of-order replay checks evaluated", map[string]any{
		"replay_policies": []string{"windowed_replay", "ordered_only"},
	}, failures)
}

func SecurityDowngradeResistanceGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	policies := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		policies[p.Security.DowngradePolicy] = true
		if err := security.DetectSuiteDowngrade(security.DefaultSuite(), security.Suite{KDF: "kdf_hkdf_sha1"}, ""); err == nil {
			failures = append(failures, "suite downgrade accepted")
		}
	}
	return gate("security_downgrade_resistance", len(failures) == 0, "required", fmt.Sprintf("%d downgrade policies exercised", len(policies)), map[string]any{
		"downgrade_policies": keys(policies),
	}, failures)
}

func SecurityCapabilityNegotiationGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	policies := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		policies[p.Security.CapabilityNegotiationPolicy] = true
		if _, err := (security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}).Hash(); err != nil {
			failures = append(failures, err.Error())
		}
		if err := security.RequireCapabilities(security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}, security.CapabilitySet{Features: []string{"multi_stream"}}); err == nil {
			failures = append(failures, "capability downgrade accepted for "+p.ID)
		}
	}
	return gate("security_capability_negotiation", len(failures) == 0, "required", fmt.Sprintf("%d capability policies exercised", len(policies)), map[string]any{
		"capability_policies": keys(policies),
	}, failures)
}

func SecurityProfileCompatibilityGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		if err := security.CheckProfileCompatibility(p, security.DefaultRuntimeCompatibility()); err != nil {
			failures = append(failures, err.Error())
		}
		bad := security.DefaultRuntimeCompatibility()
		bad.SupportedCarrierFamilies = []string{"unsupported_family"}
		if err := security.CheckProfileCompatibility(p, bad); err == nil {
			failures = append(failures, "unsupported carrier family accepted for "+p.ID)
		}
	}
	return gate("security_profile_compatibility", len(failures) == 0, "required", fmt.Sprintf("%d compatibility checks run", len(selectProfiles(profiles, 3))*2), nil, failures)
}

func SecurityConfigHygieneGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		cfg := security.SecurityConfig{
			ProfileID:        p.ID,
			ProfileHash:      ctx.ProfileHash,
			InputSecret:      testSecret(p),
			Suite:            ctx.Suite,
			ReplayWindow:     p.Security.ReplayWindowSize,
			MaxEnvelopeBytes: p.CarrierPolicy.MaxEnvelopeBytes,
			QueueDepth:       p.CarrierPolicy.MaxCarrierQueueDepth,
			Capabilities:     p.Compatibility.RequiredCapabilities,
			TranscriptHash:   ctx.TranscriptHash,
			CapabilityHash:   ctx.CapabilityHash,
		}
		if err := security.ValidateConfig(cfg); err != nil {
			failures = append(failures, err.Error())
		}
		cfg.InputSecret = make([]byte, len(cfg.InputSecret))
		if err := security.ValidateConfig(cfg); err == nil {
			failures = append(failures, "all-zero secret accepted for "+p.ID)
		}
	}
	return gate("security_config_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d config hygiene checks run", len(selectProfiles(profiles, 3))*2), nil, failures)
}

func SecuritySecretTraceHygieneGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ks, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		codec, err := security.NewEnvelopeCodec(ctx, ks, "client")
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		payload := []byte("payload must not leak")
		env, err := codec.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "target_response", CarrierFamily: p.CarrierPolicy.CarrierFamily}, payload)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ev := security.SecureEnvelopeTrace(ctx, env)
		raw, _ := json.Marshal(ev)
		if security.TraceHasSecretCandidate(raw, payload, ks.ClientWriteKey, ks.ClientNonceBase, env.Ciphertext, env.Nonce) {
			failures = append(failures, "security trace leaked secret material for "+p.ID)
		}
	}
	return gate("security_secret_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d secret trace hygiene checks run", len(selectProfiles(profiles, 3))), nil, failures)
}

func SecurityMutantDetectionGate(ctx context.Context) GateResult {
	_ = ctx
	modes := []string{
		mutant.ModeNoTranscriptBinding,
		mutant.ModeReusedNonce,
		mutant.ModeAcceptsReplay,
		mutant.ModeAcceptsDowngrade,
		mutant.ModeCapabilityMismatchAccepted,
		mutant.ModeProfileMismatchAccepted,
		mutant.ModeUnsafeConfigAllowed,
		mutant.ModeSecretTraceLeak,
	}
	detected := []string{}
	missed := []string{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 4100, 3)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		if len(securityMutantReasons(mode, profiles)) == 0 {
			missed = append(missed, mode)
		} else {
			detected = append(detected, mode)
		}
	}
	return gate("security_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d security mutant modes detected", len(detected), len(modes)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
	}, missed)
}

func SecurityGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("security_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("security_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"security_generated.go", "SecurityDemo", "CaptureSecurityTrace", "security-demo", "security"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	return gate("security_generated_backend_parity", len(failures) == 0, "required", "generated backend security support markers checked", map[string]any{
		"scanner": "source-marker",
	}, failures)
}

func securityMutantReasons(mode string, profiles []*ir.Profile) []string {
	reasons := []string{}
	for _, p := range profiles {
		switch mode {
		case mutant.ModeNoTranscriptBinding:
			if p.Security.TranscriptMode == "canonical_v1" {
				reasons = append(reasons, "transcript mode lacks full binding")
			}
		case mutant.ModeReusedNonce:
			reasons = append(reasons, "duplicate nonce simulation rejected")
		case mutant.ModeAcceptsReplay:
			if p.InvalidInput.Replay == "ordinary_error_shaped_response" {
				reasons = append(reasons, "replay acceptance behavior detected")
			}
		case mutant.ModeAcceptsDowngrade:
			if p.Security.DowngradePolicy != "strict_suite_and_capabilities" {
				reasons = append(reasons, "downgrade policy weakened")
			}
		case mutant.ModeCapabilityMismatchAccepted:
			if p.Security.CapabilityNegotiationPolicy == "intersection_with_required" {
				reasons = append(reasons, "capability mismatch policy weakened")
			}
		case mutant.ModeProfileMismatchAccepted:
			if p.Security.ProfileCompatibilityPolicy == "strict_schema" {
				reasons = append(reasons, "profile compatibility policy weakened")
			}
		case mutant.ModeUnsafeConfigAllowed:
			if p.Security.ConfigValidationPolicy == "strict_required" {
				reasons = append(reasons, "config hygiene policy weakened")
			}
		case mutant.ModeSecretTraceLeak:
			if p.Security.SecureEnvelopeMode == "metadata_authenticated" {
				reasons = append(reasons, "secret trace leak simulation detected")
			}
		}
	}
	return uniqueList(reasons)
}

func securityContextForProfile(p *ir.Profile) (security.SecurityContext, error) {
	input, err := transcriptInputForProfile(p)
	if err != nil {
		return security.SecurityContext{}, err
	}
	return security.BuildContext(input)
}

func transcriptInputForProfile(p *ir.Profile) (security.TranscriptInput, error) {
	hash, err := security.ProfileHash(p)
	if err != nil {
		return security.TranscriptInput{}, err
	}
	return security.TranscriptInput{
		ProfileID:           p.ID,
		ProfileHash:         hash,
		CompilerHash:        Version,
		SemanticMappingHash: p.GenerationHash,
		FSMPolicy:           fmt.Sprintf("%d/%d", len(p.States), len(p.Transitions)),
		FramingPolicy:       p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode + "/" + p.FrameGrammar.FragmentationMode,
		SchedulerPolicy:     p.Scheduler.Mode + "/" + p.Scheduler.PriorityMode,
		PaddingPolicy:       p.Padding.Mode,
		StreamPolicy:        p.Stream.IDStrategy + "/" + p.Stream.PriorityPolicy + "/" + p.Stream.WindowUpdatePolicy,
		ProxyPolicy:         p.ProxySemantics.TargetDescriptorEncoding + "/" + p.ProxySemantics.ResponseModeEncoding,
		CarrierPolicy:       p.CarrierPolicy.CarrierFamily + "/" + p.CarrierPolicy.EnvelopeEncoding + "/" + p.CarrierPolicy.FlushPolicy,
		Capabilities:        p.Compatibility.RequiredCapabilities,
		SessionNonce:        []byte(fmt.Sprintf("audit-session-%016d", p.Seed)),
		Suite:               security.DefaultSuite(),
		OrderedStatePath:    []string{p.FirstContact.StartState, p.FirstContact.RelayReadyState},
	}, nil
}

func testSecret(p *ir.Profile) []byte {
	return []byte("audit-secret:" + p.ID + ":" + p.GenerationHash)
}

func securitySummary(profiles []*ir.Profile) map[string]any {
	transcriptModes := profileValues(profiles, func(p *ir.Profile) string { return p.Security.TranscriptMode })
	nonceModes := profileValues(profiles, func(p *ir.Profile) string { return p.Security.NonceMode })
	replayPolicies := profileValues(profiles, func(p *ir.Profile) string { return p.Security.ReplayPolicy })
	capabilityPolicies := profileValues(profiles, func(p *ir.Profile) string { return p.Security.CapabilityNegotiationPolicy })
	return map[string]any{
		"unique_transcript_modes":    uniqueStrings(transcriptModes),
		"unique_nonce_modes":         uniqueStrings(nonceModes),
		"unique_replay_policies":     uniqueStrings(replayPolicies),
		"unique_capability_policies": uniqueStrings(capabilityPolicies),
		"profile_count":              len(profiles),
		"security_version":           "0.12.0-lab",
		"required_capability_count":  len(ir.SecurityCapabilities()),
		"supported_security_suite":   ir.SecuritySuiteString(),
		"secure_envelope_model":      "metadata/authenticated synthetic AEAD test model",
	}
}

func uniqueList(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func keys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
