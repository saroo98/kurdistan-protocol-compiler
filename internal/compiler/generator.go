// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"

	"kurdistan/internal/ir"
)

func Generate(seed int64) (*ir.Profile, error) {
	rng := rand.New(rand.NewSource(seed))
	id := profileID(seed)
	pattern := firstContactPatterns()[rng.Intn(len(firstContactPatterns()))]
	states, transitions, steps, proofMessage := buildStateMachine(rng, pattern)

	lengthModes := []string{"varint_prefix", "fixed_2_prefix", "fixed_4_prefix", "length_suffix_lab"}
	typeModes := []string{"explicit_generated_tag", "derived_from_state", "derived_from_header_order", "table_indexed_symbol"}
	headerOrders := [][]string{
		{"length", "type", "stream", "flags"},
		{"type", "length", "flags", "stream"},
		{"stream", "type", "length", "flags"},
		{"flags", "stream", "type", "length"},
	}
	fragmentModes := []string{"no_fragmentation_for_small_payloads", "fixed_size_chunks", "bounded_variable_chunks", "scheduler_controlled_chunks"}
	paddingPlacements := []string{"none", "prefix", "suffix", "inter_frame", "probabilistic"}

	schedulerModes := []string{"max_speed", "balanced", "interactive_first", "bulk_first"}
	mode := schedulerModes[rng.Intn(len(schedulerModes))]
	scheduler := schedulerForMode(rng, mode)
	placement := paddingPlacements[rng.Intn(len(paddingPlacements))]
	stream := streamPolicy(rng)
	proxy := proxySemanticsPolicy(rng)
	carrier := carrierPolicy(rng)
	security := securityPolicy(rng)

	p := &ir.Profile{
		Version: ir.SupportedVersion,
		ID:      id,
		Seed:    seed,
		RolePolicy: ir.RolePolicy{
			ClientRole: ir.RoleClient,
			ServerRole: ir.RoleServer,
		},
		Carrier:     ir.CarrierSpec{Type: "lab_tcp"},
		States:      states,
		Transitions: transitions,
		FirstContact: ir.FirstContactSpec{
			PatternID:       pattern.Name,
			StartState:      states[0].ID,
			RelayReadyState: states[len(states)-2].ID,
			Steps:           steps,
		},
		Messages: generatedMessages(rng),
		FrameGrammar: ir.FrameGrammar{
			LengthMode:        lengthModes[rng.Intn(len(lengthModes))],
			TypeMode:          typeModes[rng.Intn(len(typeModes))],
			HeaderOrder:       headerOrders[rng.Intn(len(headerOrders))],
			FragmentationMode: fragmentModes[rng.Intn(len(fragmentModes))],
			ChecksumMode:      []string{"none", "crc32"}[rng.Intn(2)],
			PaddingPlacement:  placement,
		},
		Auth: ir.AuthSpec{
			Mode:         "hmac-sha256-transcript-test-only",
			KeyID:        "test-only-" + randomSymbol(rng, 5),
			TestKeyHex:   testKeyHex(seed, id),
			NonceBytes:   16,
			ProofMessage: proofMessage,
		},
		Scheduler:      scheduler,
		Stream:         stream,
		ProxySemantics: proxy,
		CarrierPolicy:  carrier,
		Security:       security,
		Compatibility:  compatibilityMetadata(stream, carrier, security),
		Padding:        paddingForPlacement(rng, placement),
		InvalidInput: ir.InvalidInputPolicy{
			UnknownFirstMessage: []string{"silent_close", "delayed_close", "generated_decoy_response", "ordinary_error_shaped_response"}[rng.Intn(4)],
			MalformedFrame:      []string{"close", "ignore", "delayed_close", "generated_malformed_response"}[rng.Intn(4)],
			FailedAuth:          []string{"close", "delayed_close", "decoy_path", "fixed_local_only_rejection"}[rng.Intn(4)],
			Replay:              []string{"close", "delayed_close", "reject_nonce", "ordinary_error_shaped_response"}[rng.Intn(4)],
			DelayMsMin:          rng.Intn(10),
			DelayMsMax:          10 + rng.Intn(40),
		},
		Limits: ir.SafetyLimits{
			MaxFrameBytes:    64 * 1024,
			MaxPayloadBytes:  2 * 1024 * 1024,
			MaxStates:        32,
			MaxTransitions:   64,
			MaxSessionMillis: 30000,
		},
	}
	hash, err := ir.CanonicalHash(p)
	if err != nil {
		return nil, err
	}
	p.GenerationHash = hash
	if err := ir.Validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

func ValidateDeterministic(p *ir.Profile) error {
	if p == nil {
		return fmt.Errorf("nil profile")
	}
	regen, err := Generate(p.Seed)
	if err != nil {
		return err
	}
	if regen.GenerationHash != p.GenerationHash || regen.ID != p.ID {
		return fmt.Errorf("profile is not deterministic under seed %d", p.Seed)
	}
	return nil
}

type contactPattern struct {
	Name  string
	Roles []string
	Decoy map[int]bool
}

func firstContactPatterns() []contactPattern {
	return []contactPattern{
		{Name: "C-S-C-PROOF", Roles: []string{ir.RoleClient, ir.RoleServer, ir.RoleClient}},
		{Name: "C-C-S-PROOF", Roles: []string{ir.RoleClient, ir.RoleClient, ir.RoleServer, ir.RoleClient}},
		{Name: "C-S-S-PROOF", Roles: []string{ir.RoleClient, ir.RoleServer, ir.RoleServer, ir.RoleClient}},
		{Name: "C-DECOY-C-S-PROOF", Roles: []string{ir.RoleClient, ir.RoleServer, ir.RoleClient, ir.RoleServer, ir.RoleClient}, Decoy: map[int]bool{1: true}},
	}
}

func buildStateMachine(rng *rand.Rand, pattern contactPattern) ([]ir.State, []ir.Transition, []ir.FirstContactStep, string) {
	statePrefix := "s_" + randomSymbol(rng, 5)
	states := []ir.State{{ID: statePrefix + "_start", Role: ir.RoleShared}}
	transitions := make([]ir.Transition, 0, len(pattern.Roles))
	steps := make([]ir.FirstContactStep, 0, len(pattern.Roles))
	current := states[0].ID
	proofMessage := ""
	for i, role := range pattern.Roles {
		next := fmt.Sprintf("%s_%02d_%s", statePrefix, i, randomSymbol(rng, 4))
		if i == len(pattern.Roles)-1 {
			next = statePrefix + "_relay_ready"
		}
		states = append(states, ir.State{ID: next, Role: ir.RoleShared})
		message := fmt.Sprintf("fc_%02d_%s", i, randomSymbol(rng, 5))
		wire := randomWireSymbol(rng, 12)
		proof := i == len(pattern.Roles)-1
		if proof {
			proofMessage = message
		}
		step := ir.FirstContactStep{
			Role:        role,
			Direction:   directionForRole(role),
			Message:     message,
			WireSymbol:  wire,
			FromState:   current,
			ToState:     next,
			PayloadSize: payloadSizeForStep(rng, proof, i == 0 && role == ir.RoleClient),
			Proof:       proof,
			Decoy:       pattern.Decoy != nil && pattern.Decoy[i],
		}
		steps = append(steps, step)
		transitions = append(transitions, ir.Transition{
			From:         current,
			To:           next,
			Role:         role,
			OnMessage:    message,
			EmitsMessage: message,
			RequiresAuth: proof,
			Description:  "generated first-contact transition",
		})
		current = next
	}
	states = append(states, ir.State{ID: statePrefix + "_terminal", Role: ir.RoleShared, Terminal: true})
	transitions = append(transitions, ir.Transition{
		From:         current,
		To:           statePrefix + "_terminal",
		Role:         ir.RoleClient,
		OnMessage:    "session_close",
		EmitsMessage: "session_close",
		Description:  "generated terminal transition",
	})
	return states, transitions, steps, proofMessage
}

func generatedMessages(rng *rand.Rand) []ir.MessageSymbol {
	messages := make([]ir.MessageSymbol, 0, len(ir.RelaySemantics()))
	for _, semantic := range ir.RelaySemantics() {
		messages = append(messages, ir.MessageSymbol{
			Semantic:       semantic,
			WireSymbol:     randomWireSymbol(rng, 14),
			Direction:      "bidirectional",
			MinPayloadSize: 0,
			MaxPayloadSize: 2 * 1024 * 1024,
		})
	}
	return messages
}

func schedulerForMode(rng *rand.Rand, mode string) ir.SchedulerPolicy {
	flush := 0
	switch mode {
	case "max_speed":
		flush = rng.Intn(6)
	case "balanced":
		flush = 5 + rng.Intn(16)
	case "interactive_first":
		flush = 1 + rng.Intn(10)
	case "bulk_first":
		flush = 10 + rng.Intn(31)
	}
	return ir.SchedulerPolicy{
		Mode:              mode,
		MaxBatchBytes:     []int{4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024}[rng.Intn(4)],
		FlushIntervalMs:   flush,
		MaxInFlightFrames: []int{4, 8, 16, 32}[rng.Intn(4)],
		PriorityMode:      map[string]string{"max_speed": "fifo", "balanced": "mixed", "interactive_first": "small_first", "bulk_first": "large_first"}[mode],
	}
}

func streamPolicy(rng *rand.Rand) ir.StreamPolicy {
	strategies := []string{"sequential_odd_even", "randomized_bounded_ids", "table_mapped_ids", "varint_ids"}
	encodingByStrategy := map[string]string{
		"sequential_odd_even":    "fixed32_be",
		"randomized_bounded_ids": "profile_xor32",
		"table_mapped_ids":       "table_mapped32_le",
		"varint_ids":             "varint",
	}
	strategy := strategies[rng.Intn(len(strategies))]
	maxConcurrent := []int{2, 4, 8, 16}[rng.Intn(4)]
	streamWindow := []int{16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024}[rng.Intn(4)]
	multiplier := []int{2, 3, 4, 6, 8}[rng.Intn(5)]
	sessionWindow := streamWindow * multiplier
	minSession := streamWindow * min(maxConcurrent, 4)
	if sessionWindow < minSession {
		sessionWindow = minSession
	}
	if sessionWindow > 2*1024*1024 {
		sessionWindow = 2 * 1024 * 1024
	}
	return ir.StreamPolicy{
		IDStrategy:                strategy,
		IDEncodingMode:            encodingByStrategy[strategy],
		MaxConcurrentStreams:      maxConcurrent,
		InitialStreamWindowBytes:  streamWindow,
		InitialSessionWindowBytes: sessionWindow,
		WindowUpdatePolicy:        []string{"threshold_update", "periodic_update", "per_frame_update", "hybrid_update"}[rng.Intn(4)],
		PriorityPolicy:            []string{"fifo", "interactive_first", "weighted_round_robin", "smallest_pending_first"}[rng.Intn(4)],
		ClosePolicy:               []string{"explicit_close", "half_close", "close_after_ack"}[rng.Intn(3)],
		ResetPolicy:               []string{"immediate_reset", "reset_with_error_code", "delayed_reset"}[rng.Intn(3)],
		MaxStreamID:               1 << 24,
	}
}

func proxySemanticsPolicy(rng *rand.Rand) ir.ProxySemanticsPolicy {
	requestLimit := []int{32 * 1024, 64 * 1024, 128 * 1024, 256 * 1024}[rng.Intn(4)]
	responseLimit := []int{128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024}[rng.Intn(4)]
	if responseLimit < requestLimit {
		responseLimit = requestLimit
	}
	return ir.ProxySemanticsPolicy{
		RelayIntentEncoding:      []string{"descriptor_before_open", "descriptor_after_open", "split_descriptor", "table_mapped_descriptor", "state_derived_descriptor"}[rng.Intn(5)],
		TargetDescriptorEncoding: []string{"compact_enum", "generated_table_index", "split_fields", "state_derived_class", "padded_descriptor_block"}[rng.Intn(5)],
		RequestClassEncoding:     []string{"interactive", "bulk", "control", "error_test", "generated_bucket"}[rng.Intn(5)],
		ResponseModeEncoding:     []string{"immediate", "chunked", "delayed", "resettable", "errorable", "large_object"}[rng.Intn(6)],
		TargetErrorPolicy:        []string{"explicit_target_error", "close_with_error", "reset_with_error", "delayed_error", "metadata_error"}[rng.Intn(5)],
		TargetClosePolicy:        []string{"explicit_close", "implicit_close_after_response", "close_after_ack", "half_close_compatible"}[rng.Intn(4)],
		TargetResetPolicy:        []string{"immediate_reset", "reset_with_reason", "delayed_reset", "reset_after_partial_response"}[rng.Intn(4)],
		TargetMetadataPolicy:     []string{"none", "pre_response_metadata", "post_response_metadata", "metadata_as_control_frame"}[rng.Intn(4)],
		RelayOpenOrderingPolicy:  []string{"intent_before_stream", "stream_before_intent", "descriptor_split_around_open", "metadata_before_descriptor"}[rng.Intn(4)],
		RelayIntentPaddingPolicy: []string{"none", "bounded", "descriptor_padding", "metadata_padding"}[rng.Intn(4)],
		TargetClassMapping:       []string{"direct_generated", "table_mapped", "state_derived", "bucketed"}[rng.Intn(4)],
		TargetClasses:            ir.SyntheticTargetClasses(),
		MaxRequestBytes:          requestLimit,
		MaxResponseBytes:         responseLimit,
	}
}

func carrierPolicy(rng *rand.Rand) ir.CarrierPolicy {
	family := ir.CarrierFamilies()[rng.Intn(len(ir.CarrierFamilies()))]
	return ir.CarrierPolicy{
		CarrierFamily:          family,
		EnvelopeEncoding:       []string{"single_semantic", "coalesced_semantics", "split_semantic", "table_mapped_envelope", "state_derived_envelope"}[rng.Intn(5)],
		FlushPolicy:            []string{"flush_each", "flush_on_threshold", "flush_on_priority", "flush_on_state_transition", "delayed_flush_bucket"}[rng.Intn(5)],
		BatchPolicy:            []string{"no_batch", "fixed_batch", "profile_bucket_batch", "priority_split_batch", "state_transition_batch"}[rng.Intn(5)],
		ChunkingPolicy:         []string{"no_chunk", "fixed_chunk", "profile_bucket_chunk", "priority_aware_chunk", "state_derived_chunk"}[rng.Intn(5)],
		ReliabilityPolicy:      []string{"ordered_only", "ack_required", "retry_bounded", "drop_detect", "reorder_recover"}[rng.Intn(5)],
		ReorderPolicy:          []string{"none", "stable", "deterministic_reorder", "lossy_reorder", "recoverable_reorder"}[rng.Intn(5)],
		BackpressurePolicy:     []string{"carrier_queue_backpressure", "stream_window_backpressure", "session_window_backpressure", "priority_backpressure", "drop_or_delay_metadata"}[rng.Intn(5)],
		PriorityMappingPolicy:  []string{"direct_priority", "bucketed_priority", "state_derived_priority", "interactive_bias"}[rng.Intn(4)],
		EnvelopePaddingPolicy:  []string{"none", "small_bucket", "state_bucket", "priority_bucket", "carrier_family_bucket"}[rng.Intn(5)],
		TimingBucketPolicy:     []string{"none", "flush_bucket", "poll_cycle_bucket", "retry_bucket"}[rng.Intn(4)],
		MaxEnvelopeBytes:       []int{1024, 2048, 4096, 8192, 16 * 1024}[rng.Intn(5)],
		MaxMessagesPerEnvelope: []int{1, 2, 4, 8}[rng.Intn(4)],
		MaxCarrierQueueDepth:   []int{4, 8, 16, 32}[rng.Intn(4)],
		MaxRetryCount:          []int{0, 1, 2, 3}[rng.Intn(4)],
	}
}

func securityPolicy(rng *rand.Rand) ir.SecurityPolicy {
	maxSession := []int{1 << 14, 1 << 15, 1 << 16, 1 << 17}[rng.Intn(4)]
	keyLifetime := []int{1 << 12, 1 << 13, 1 << 14}[rng.Intn(3)]
	if keyLifetime > maxSession {
		keyLifetime = maxSession
	}
	return ir.SecurityPolicy{
		SecurityVersion:             "0.12.0-lab",
		TranscriptMode:              []string{"canonical_v1", "canonical_with_capabilities_v1", "canonical_with_carrier_binding_v1", "canonical_full_binding_v1"}[rng.Intn(4)],
		KDFSuite:                    "kdf_hkdf_sha256",
		AEADSuite:                   "aead_aes_256_gcm",
		MACSuite:                    "mac_hmac_sha256",
		NonceMode:                   []string{"counter_xor_base", "counter_append_base", "directional_counter", "stream_partitioned_counter"}[rng.Intn(4)],
		ReplayPolicy:                []string{"ordered_only", "bounded_reorder", "windowed_replay"}[rng.Intn(3)],
		ReplayWindowSize:            []int{32, 64, 128, 256}[rng.Intn(4)],
		DowngradePolicy:             []string{"strict_suite_and_capabilities", "strict_capabilities", "suite_bound_transcript"}[rng.Intn(3)],
		CapabilityNegotiationPolicy: []string{"strict_required", "intersection_with_required", "profile_declared_required"}[rng.Intn(3)],
		ProfileCompatibilityPolicy:  []string{"strict_schema", "schema_and_feature", "full_policy_binding"}[rng.Intn(3)],
		KeyRotationPolicy:           []string{"session_only", "message_lifetime_bound", "profile_lifetime_bound"}[rng.Intn(3)],
		ConfigValidationPolicy:      []string{"strict_required", "strict_with_redaction", "strict_profile_bound"}[rng.Intn(3)],
		SecureEnvelopeMode:          []string{"metadata_authenticated", "synthetic_aead_test", "full_context_bound_envelope"}[rng.Intn(3)],
		MaxSessionMessages:          maxSession,
		MaxKeyLifetimeMessages:      keyLifetime,
	}
}

func compatibilityMetadata(stream ir.StreamPolicy, carrier ir.CarrierPolicy, security ir.SecurityPolicy) ir.CompatibilityMetadata {
	return ir.CompatibilityMetadata{
		SchemaVersion:            ir.SupportedVersion,
		CompilerSecurityVersion:  security.SecurityVersion,
		MinimumRuntimeVersion:    "0.12.0-lab",
		SupportedSecuritySuites:  []string{ir.SecuritySuiteString()},
		RequiredCapabilities:     ir.SecurityCapabilities(),
		SupportedCarrierFamilies: ir.CarrierFamilies(),
		SupportedProxyFeatures:   ir.ProxySemantics(),
		SupportedStreamFeatures:  []string{"open_stream", "data", "close_stream", "reset_stream", "window_update", "session_close"},
		MaxEnvelopeBytes:         carrier.MaxEnvelopeBytes,
		MaxStreamCount:           stream.MaxConcurrentStreams,
		MaxReplayWindow:          security.ReplayWindowSize,
	}
}

func paddingForPlacement(rng *rand.Rand, placement string) ir.PaddingPolicy {
	if placement == "none" {
		return ir.PaddingPolicy{Mode: "none"}
	}
	minPad := rng.Intn(8)
	maxPad := minPad + 8 + rng.Intn(48)
	switch placement {
	case "probabilistic":
		return ir.PaddingPolicy{Mode: "probabilistic", MinPaddingBytes: minPad, MaxPaddingBytes: maxPad, Probability: 0.5}
	case "inter_frame":
		return ir.PaddingPolicy{Mode: "inter_frame", MinPaddingBytes: minPad, MaxPaddingBytes: maxPad, Probability: 1}
	default:
		return ir.PaddingPolicy{Mode: "bounded", MinPaddingBytes: minPad, MaxPaddingBytes: maxPad, Probability: 1}
	}
}

func directionForRole(role string) string {
	if role == ir.RoleClient {
		return "client_to_server"
	}
	return "server_to_client"
}

func payloadSizeForStep(rng *rand.Rand, proof, firstClient bool) int {
	if proof {
		return 32
	}
	size := 12 + rng.Intn(40)
	if firstClient && size < 16 {
		size = 16
	}
	return size
}

func profileID(seed int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("kurdistan-profile:%d", seed)))
	return "kp_" + hex.EncodeToString(sum[:])[:16]
}

func testKeyHex(seed int64, id string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("test-only-key:%s:%d", id, seed)))
	return hex.EncodeToString(sum[:])
}

func randomSymbol(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = alphabet[rng.Intn(len(alphabet))]
		}
		symbol := string(buf)
		upper := strings.ToUpper(symbol)
		if strings.Contains(upper, "HELLO") || strings.Contains(upper, "AUTH") || strings.Contains(upper, "OPEN") || strings.Contains(upper, "KURD") || strings.Contains(upper, "VPN") || strings.Contains(upper, "PROXY") || strings.Contains(upper, "CONNECT") {
			continue
		}
		return symbol
	}
}

func randomWireSymbol(rng *rand.Rand, n int) string {
	for {
		symbol := randomSymbol(rng, n)
		if len(symbol) > 0 && symbol[0] != 'w' {
			return symbol
		}
	}
}
