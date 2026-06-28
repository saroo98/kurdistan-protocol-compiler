// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir

import (
	"fmt"
	"strings"
)

var forbiddenWireConstants = []string{"HELLO", "AUTH", "OPEN", "KURD", "VPN", "PROXY", "CONNECT"}

func Validate(p *Profile) error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}
	if p.Version == "" {
		return fmt.Errorf("version is required")
	}
	if p.Version != SupportedVersion {
		return fmt.Errorf("unsupported version %q", p.Version)
	}
	if p.ID == "" {
		return fmt.Errorf("profile id is required")
	}
	if p.Carrier.Type != "lab_tcp" {
		return fmt.Errorf("carrier must be lab_tcp")
	}
	if p.GenerationHash != "" {
		got, err := CanonicalHash(p)
		if err != nil {
			return err
		}
		if got != p.GenerationHash {
			return fmt.Errorf("generation hash mismatch")
		}
	}
	if err := validateLimits(p); err != nil {
		return err
	}
	if err := validateStates(p); err != nil {
		return err
	}
	if err := validateMessages(p); err != nil {
		return err
	}
	if err := validateFrameGrammar(p); err != nil {
		return err
	}
	if err := validateScheduler(p.Scheduler); err != nil {
		return err
	}
	if err := validateStreamPolicy(p.Stream, p.Limits); err != nil {
		return err
	}
	if err := validateProxySemanticsPolicy(p.ProxySemantics, p.Limits, p.Messages); err != nil {
		return err
	}
	if err := validatePadding(p.Padding); err != nil {
		return err
	}
	if err := validateInvalidInput(p.InvalidInput); err != nil {
		return err
	}
	if p.Auth.Mode != "hmac-sha256-transcript-test-only" {
		return fmt.Errorf("unsupported auth mode %q", p.Auth.Mode)
	}
	if p.Auth.TestKeyHex == "" || p.Auth.NonceBytes < 8 || p.Auth.ProofMessage == "" {
		return fmt.Errorf("auth key, nonce size, and proof message are required")
	}
	return nil
}

func validateLimits(p *Profile) error {
	if p.Limits.MaxFrameBytes <= 0 || p.Limits.MaxFrameBytes > 1<<20 {
		return fmt.Errorf("invalid max frame bytes")
	}
	if p.Limits.MaxPayloadBytes <= 0 || p.Limits.MaxPayloadBytes > 8<<20 {
		return fmt.Errorf("invalid max payload bytes")
	}
	if p.Limits.MaxStates <= 0 || len(p.States) > p.Limits.MaxStates {
		return fmt.Errorf("state count exceeds limits")
	}
	if p.Limits.MaxTransitions <= 0 || len(p.Transitions) > p.Limits.MaxTransitions {
		return fmt.Errorf("transition count exceeds limits")
	}
	if p.Limits.MaxSessionMillis <= 0 {
		return fmt.Errorf("max session duration is required")
	}
	return nil
}

func validateStates(p *Profile) error {
	stateRoles := map[string]string{}
	hasTerminal := false
	for _, st := range p.States {
		if st.ID == "" {
			return fmt.Errorf("empty state id")
		}
		if st.Role != RoleClient && st.Role != RoleServer && st.Role != RoleShared {
			return fmt.Errorf("invalid state role %q", st.Role)
		}
		if _, ok := stateRoles[st.ID]; ok {
			return fmt.Errorf("duplicate state %q", st.ID)
		}
		stateRoles[st.ID] = st.Role
		hasTerminal = hasTerminal || st.Terminal
	}
	if _, ok := stateRoles[p.FirstContact.StartState]; !ok {
		return fmt.Errorf("start state is missing")
	}
	if _, ok := stateRoles[p.FirstContact.RelayReadyState]; !ok {
		return fmt.Errorf("relay-ready state is missing")
	}
	if !hasTerminal {
		return fmt.Errorf("terminal state is required")
	}
	if len(p.FirstContact.Steps) == 0 {
		return fmt.Errorf("first-contact steps are required")
	}

	edges := map[string][]string{}
	seenClient, seenServer := false, false
	for _, tr := range p.Transitions {
		if _, ok := stateRoles[tr.From]; !ok {
			return fmt.Errorf("transition from unknown state %q", tr.From)
		}
		if _, ok := stateRoles[tr.To]; !ok {
			return fmt.Errorf("transition to unknown state %q", tr.To)
		}
		if tr.Role != RoleClient && tr.Role != RoleServer {
			return fmt.Errorf("invalid transition role %q", tr.Role)
		}
		if tr.OnMessage == "" {
			return fmt.Errorf("transition message is required")
		}
		edges[tr.From] = append(edges[tr.From], tr.To)
		seenClient = seenClient || tr.Role == RoleClient
		seenServer = seenServer || tr.Role == RoleServer
	}
	if !seenClient || !seenServer {
		return fmt.Errorf("client and server transition paths are required")
	}
	if !reachable(edges, p.FirstContact.StartState, p.FirstContact.RelayReadyState) {
		return fmt.Errorf("relay-ready state is unreachable")
	}
	for _, step := range p.FirstContact.Steps {
		if _, ok := stateRoles[step.FromState]; !ok {
			return fmt.Errorf("first-contact step has unknown from state")
		}
		if _, ok := stateRoles[step.ToState]; !ok {
			return fmt.Errorf("first-contact step has unknown to state")
		}
		if step.WireSymbol == "" || step.Message == "" || step.PayloadSize < 0 {
			return fmt.Errorf("invalid first-contact step")
		}
	}
	if len(p.FirstContact.Steps) > 0 {
		first := p.FirstContact.Steps[0]
		if first.Role != RoleClient {
			return fmt.Errorf("first-contact must begin with client")
		}
		if first.PayloadSize < p.Auth.NonceBytes {
			return fmt.Errorf("first-contact nonce payload is too small")
		}
	}
	return nil
}

func reachable(edges map[string][]string, start, want string) bool {
	queue := []string{start}
	seen := map[string]bool{start: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == want {
			return true
		}
		for _, next := range edges[cur] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false
}

func validateMessages(p *Profile) error {
	seenWire := map[string]string{}
	seenSemantic := map[string]bool{}
	for _, msg := range p.Messages {
		if msg.Semantic == "" || msg.WireSymbol == "" {
			return fmt.Errorf("semantic and wire symbols are required")
		}
		if msg.MinPayloadSize < 0 || msg.MaxPayloadSize < msg.MinPayloadSize || msg.MaxPayloadSize > p.Limits.MaxPayloadBytes {
			return fmt.Errorf("invalid payload bounds for %q", msg.Semantic)
		}
		upper := strings.ToUpper(msg.WireSymbol)
		for _, forbidden := range forbiddenWireConstants {
			if strings.Contains(upper, forbidden) {
				return fmt.Errorf("forbidden wire symbol constant %q", forbidden)
			}
		}
		if previous, ok := seenWire[msg.WireSymbol]; ok {
			return fmt.Errorf("duplicate wire symbol %q for %q and %q", msg.WireSymbol, previous, msg.Semantic)
		}
		seenWire[msg.WireSymbol] = msg.Semantic
		seenSemantic[msg.Semantic] = true
	}
	for _, semantic := range RelaySemantics() {
		if !seenSemantic[semantic] {
			return fmt.Errorf("missing semantic message %q", semantic)
		}
	}
	for _, step := range p.FirstContact.Steps {
		if _, ok := seenWire[step.WireSymbol]; ok {
			return fmt.Errorf("first-contact wire symbol collides with frame symbol")
		}
	}
	return nil
}

func validateFrameGrammar(p *Profile) error {
	if !oneOf(p.FrameGrammar.LengthMode, "varint_prefix", "fixed_2_prefix", "fixed_4_prefix", "length_suffix_lab") {
		return fmt.Errorf("invalid length mode")
	}
	if !oneOf(p.FrameGrammar.TypeMode, "explicit_generated_tag", "derived_from_state", "derived_from_header_order", "table_indexed_symbol") {
		return fmt.Errorf("invalid type mode")
	}
	if !oneOf(p.FrameGrammar.FragmentationMode, "no_fragmentation_for_small_payloads", "fixed_size_chunks", "bounded_variable_chunks", "scheduler_controlled_chunks") {
		return fmt.Errorf("invalid fragmentation mode")
	}
	if !oneOf(p.FrameGrammar.ChecksumMode, "none", "crc32") {
		return fmt.Errorf("invalid checksum mode")
	}
	if !oneOf(p.FrameGrammar.PaddingPlacement, "none", "prefix", "suffix", "inter_frame", "probabilistic") {
		return fmt.Errorf("invalid padding placement")
	}
	seen := map[string]bool{}
	for _, field := range p.FrameGrammar.HeaderOrder {
		if !oneOf(field, "length", "type", "stream", "flags") {
			return fmt.Errorf("invalid header field %q", field)
		}
		seen[field] = true
	}
	for _, field := range []string{"length", "type", "stream", "flags"} {
		if !seen[field] {
			return fmt.Errorf("header order missing %q", field)
		}
	}
	return nil
}

func validateScheduler(p SchedulerPolicy) error {
	if !oneOf(p.Mode, "max_speed", "balanced", "interactive_first", "bulk_first") {
		return fmt.Errorf("invalid scheduler mode")
	}
	if p.MaxBatchBytes <= 0 || p.MaxBatchBytes > 32*1024 {
		return fmt.Errorf("invalid scheduler batch size")
	}
	if p.FlushIntervalMs < 0 || p.FlushIntervalMs > 1000 {
		return fmt.Errorf("invalid flush interval")
	}
	if !oneOfInt(p.MaxInFlightFrames, 4, 8, 16, 32) {
		return fmt.Errorf("invalid max in-flight frame count")
	}
	if p.PriorityMode == "" {
		return fmt.Errorf("priority mode is required")
	}
	return nil
}

func validateStreamPolicy(p StreamPolicy, limits SafetyLimits) error {
	if !oneOf(p.IDStrategy, "sequential_odd_even", "randomized_bounded_ids", "table_mapped_ids", "varint_ids") {
		return fmt.Errorf("invalid stream id strategy")
	}
	if !oneOf(p.IDEncodingMode, "fixed32_be", "profile_xor32", "table_mapped32_le", "varint") {
		return fmt.Errorf("invalid stream id encoding mode")
	}
	if !oneOfInt(p.MaxConcurrentStreams, 2, 4, 8, 16) {
		return fmt.Errorf("invalid max concurrent streams")
	}
	if !oneOfInt(p.InitialStreamWindowBytes, 16*1024, 32*1024, 64*1024, 128*1024) {
		return fmt.Errorf("invalid stream window")
	}
	if p.InitialSessionWindowBytes < p.InitialStreamWindowBytes {
		return fmt.Errorf("session window must be at least one stream window")
	}
	if p.InitialSessionWindowBytes > 2*1024*1024 {
		return fmt.Errorf("session window exceeds lab safety limit")
	}
	if limits.MaxPayloadBytes > 0 && p.InitialSessionWindowBytes > limits.MaxPayloadBytes {
		return fmt.Errorf("session window exceeds payload limit")
	}
	if !oneOf(p.WindowUpdatePolicy, "threshold_update", "periodic_update", "per_frame_update", "hybrid_update") {
		return fmt.Errorf("invalid window update policy")
	}
	if !oneOf(p.PriorityPolicy, "fifo", "interactive_first", "weighted_round_robin", "smallest_pending_first") {
		return fmt.Errorf("invalid stream priority policy")
	}
	if !oneOf(p.ClosePolicy, "explicit_close", "half_close", "close_after_ack") {
		return fmt.Errorf("invalid stream close policy")
	}
	if !oneOf(p.ResetPolicy, "immediate_reset", "reset_with_error_code", "delayed_reset") {
		return fmt.Errorf("invalid stream reset policy")
	}
	if p.MaxStreamID == 0 || p.MaxStreamID > 1<<30 {
		return fmt.Errorf("invalid max stream id")
	}
	if uint64(p.MaxConcurrentStreams) > uint64(p.MaxStreamID) {
		return fmt.Errorf("max stream id cannot represent concurrent streams")
	}
	return nil
}

func validateProxySemanticsPolicy(p ProxySemanticsPolicy, limits SafetyLimits, messages []MessageSymbol) error {
	if !oneOf(p.RelayIntentEncoding, "descriptor_before_open", "descriptor_after_open", "split_descriptor", "table_mapped_descriptor", "state_derived_descriptor") {
		return fmt.Errorf("invalid relay intent encoding")
	}
	if !oneOf(p.TargetDescriptorEncoding, "compact_enum", "generated_table_index", "split_fields", "state_derived_class", "padded_descriptor_block") {
		return fmt.Errorf("invalid target descriptor encoding")
	}
	if !oneOf(p.RequestClassEncoding, "interactive", "bulk", "control", "error_test", "generated_bucket") {
		return fmt.Errorf("invalid request class encoding")
	}
	if !oneOf(p.ResponseModeEncoding, "immediate", "chunked", "delayed", "resettable", "errorable", "large_object") {
		return fmt.Errorf("invalid response mode encoding")
	}
	if !oneOf(p.TargetErrorPolicy, "explicit_target_error", "close_with_error", "reset_with_error", "delayed_error", "metadata_error") {
		return fmt.Errorf("invalid target error policy")
	}
	if !oneOf(p.TargetClosePolicy, "explicit_close", "implicit_close_after_response", "close_after_ack", "half_close_compatible") {
		return fmt.Errorf("invalid target close policy")
	}
	if !oneOf(p.TargetResetPolicy, "immediate_reset", "reset_with_reason", "delayed_reset", "reset_after_partial_response") {
		return fmt.Errorf("invalid target reset policy")
	}
	if !oneOf(p.TargetMetadataPolicy, "none", "pre_response_metadata", "post_response_metadata", "metadata_as_control_frame") {
		return fmt.Errorf("invalid target metadata policy")
	}
	if !oneOf(p.RelayOpenOrderingPolicy, "intent_before_stream", "stream_before_intent", "descriptor_split_around_open", "metadata_before_descriptor") {
		return fmt.Errorf("invalid relay open ordering policy")
	}
	if !oneOf(p.RelayIntentPaddingPolicy, "none", "bounded", "descriptor_padding", "metadata_padding") {
		return fmt.Errorf("invalid relay intent padding policy")
	}
	if !oneOf(p.TargetClassMapping, "direct_generated", "table_mapped", "state_derived", "bucketed") {
		return fmt.Errorf("invalid target class mapping")
	}
	if p.MaxRequestBytes <= 0 || p.MaxResponseBytes <= 0 {
		return fmt.Errorf("proxy semantics byte limits are required")
	}
	if limits.MaxPayloadBytes > 0 && (p.MaxRequestBytes > limits.MaxPayloadBytes || p.MaxResponseBytes > limits.MaxPayloadBytes) {
		return fmt.Errorf("proxy semantics limits exceed payload limit")
	}
	if p.MaxRequestBytes > 512*1024 || p.MaxResponseBytes > 2*1024*1024 {
		return fmt.Errorf("proxy semantics limits exceed lab safety bound")
	}
	if len(p.TargetClasses) == 0 {
		return fmt.Errorf("proxy target classes are required")
	}
	known := map[string]bool{}
	for _, class := range SyntheticTargetClasses() {
		known[class] = true
	}
	seenClasses := map[string]bool{}
	for _, class := range p.TargetClasses {
		if !known[class] {
			return fmt.Errorf("unknown synthetic target class %q", class)
		}
		if seenClasses[class] {
			return fmt.Errorf("duplicate synthetic target class %q", class)
		}
		seenClasses[class] = true
	}
	seenProxySemantics := map[string]bool{}
	for _, msg := range messages {
		if !seenProxySemantics[msg.Semantic] {
			seenProxySemantics[msg.Semantic] = false
		}
	}
	for _, semantic := range ProxySemantics() {
		count := 0
		for _, msg := range messages {
			if msg.Semantic == semantic {
				count++
			}
		}
		if count != 1 {
			return fmt.Errorf("proxy semantic %q has %d mappings", semantic, count)
		}
	}
	return nil
}

func validatePadding(p PaddingPolicy) error {
	if !oneOf(p.Mode, "none", "bounded", "probabilistic", "fixed", "inter_frame") {
		return fmt.Errorf("invalid padding mode")
	}
	if p.MinPaddingBytes < 0 || p.MaxPaddingBytes < p.MinPaddingBytes {
		return fmt.Errorf("invalid padding bounds")
	}
	if p.Mode == "none" && (p.MinPaddingBytes != 0 || p.MaxPaddingBytes != 0 || p.Probability != 0) {
		return fmt.Errorf("no-padding policy must have zero bounds and probability")
	}
	if p.Probability < 0 || p.Probability > 1 {
		return fmt.Errorf("invalid padding probability")
	}
	return nil
}

func validateInvalidInput(p InvalidInputPolicy) error {
	if !oneOf(p.UnknownFirstMessage, "silent_close", "delayed_close", "generated_decoy_response", "ordinary_error_shaped_response") {
		return fmt.Errorf("invalid unknown-first-message behavior")
	}
	if !oneOf(p.MalformedFrame, "close", "ignore", "delayed_close", "generated_malformed_response") {
		return fmt.Errorf("invalid malformed-frame behavior")
	}
	if !oneOf(p.FailedAuth, "close", "delayed_close", "decoy_path", "fixed_local_only_rejection") {
		return fmt.Errorf("invalid failed-auth behavior")
	}
	if !oneOf(p.Replay, "close", "delayed_close", "reject_nonce", "ordinary_error_shaped_response") {
		return fmt.Errorf("invalid replay behavior")
	}
	if p.DelayMsMin < 0 || p.DelayMsMax < p.DelayMsMin {
		return fmt.Errorf("invalid invalid-input delay bounds")
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func oneOfInt(value int, allowed ...int) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
