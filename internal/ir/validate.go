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
	if err := validateCarrierPolicy(p.CarrierPolicy, p.Limits); err != nil {
		return err
	}
	if err := validateAdapterPolicy(p.AdapterPolicy, p.Stream, p.Limits); err != nil {
		return err
	}
	if err := validateSecurityPolicy(p.Security); err != nil {
		return err
	}
	if err := validateCompatibility(p.Compatibility, p.Security, p.Stream, p.CarrierPolicy, p.Limits); err != nil {
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

func validateCarrierPolicy(p CarrierPolicy, limits SafetyLimits) error {
	if !oneOf(p.CarrierFamily, CarrierFamilies()...) {
		return fmt.Errorf("invalid carrier family")
	}
	if !oneOf(p.EnvelopeEncoding, "single_semantic", "coalesced_semantics", "split_semantic", "table_mapped_envelope", "state_derived_envelope") {
		return fmt.Errorf("invalid carrier envelope encoding")
	}
	if !oneOf(p.FlushPolicy, "flush_each", "flush_on_threshold", "flush_on_priority", "flush_on_state_transition", "delayed_flush_bucket") {
		return fmt.Errorf("invalid carrier flush policy")
	}
	if !oneOf(p.BatchPolicy, "no_batch", "fixed_batch", "profile_bucket_batch", "priority_split_batch", "state_transition_batch") {
		return fmt.Errorf("invalid carrier batch policy")
	}
	if !oneOf(p.ChunkingPolicy, "no_chunk", "fixed_chunk", "profile_bucket_chunk", "priority_aware_chunk", "state_derived_chunk") {
		return fmt.Errorf("invalid carrier chunking policy")
	}
	if !oneOf(p.ReliabilityPolicy, "ordered_only", "ack_required", "retry_bounded", "drop_detect", "reorder_recover") {
		return fmt.Errorf("invalid carrier reliability policy")
	}
	if !oneOf(p.ReorderPolicy, "none", "stable", "deterministic_reorder", "lossy_reorder", "recoverable_reorder") {
		return fmt.Errorf("invalid carrier reorder policy")
	}
	if !oneOf(p.BackpressurePolicy, "carrier_queue_backpressure", "stream_window_backpressure", "session_window_backpressure", "priority_backpressure", "drop_or_delay_metadata") {
		return fmt.Errorf("invalid carrier backpressure policy")
	}
	if !oneOf(p.PriorityMappingPolicy, "direct_priority", "bucketed_priority", "state_derived_priority", "interactive_bias") {
		return fmt.Errorf("invalid carrier priority mapping policy")
	}
	if !oneOf(p.EnvelopePaddingPolicy, "none", "small_bucket", "state_bucket", "priority_bucket", "carrier_family_bucket") {
		return fmt.Errorf("invalid carrier envelope padding policy")
	}
	if !oneOf(p.TimingBucketPolicy, "none", "flush_bucket", "poll_cycle_bucket", "retry_bucket") {
		return fmt.Errorf("invalid carrier timing bucket policy")
	}
	if p.MaxEnvelopeBytes <= 0 || p.MaxEnvelopeBytes > limits.MaxFrameBytes {
		return fmt.Errorf("invalid carrier envelope byte limit")
	}
	if p.MaxMessagesPerEnvelope <= 0 || p.MaxMessagesPerEnvelope > 32 {
		return fmt.Errorf("invalid carrier max messages per envelope")
	}
	if p.MaxCarrierQueueDepth <= 0 || p.MaxCarrierQueueDepth > 256 {
		return fmt.Errorf("invalid carrier queue depth")
	}
	if p.MaxRetryCount < 0 || p.MaxRetryCount > 8 {
		return fmt.Errorf("invalid carrier retry count")
	}
	return nil
}

func validateAdapterPolicy(p AdapterPolicy, _ StreamPolicy, limits SafetyLimits) error {
	if !oneOf(p.FlowLifecyclePolicy, "strict", "half_close_aware", "drain_before_close", "reset_terminal") {
		return fmt.Errorf("invalid adapter flow lifecycle policy")
	}
	if !oneOf(p.RuntimeMappingPolicy, "one_flow_one_stream", "priority_mapped_stream", "metadata_bound_stream", "state_derived_mapping") {
		return fmt.Errorf("invalid adapter runtime mapping policy")
	}
	if !oneOf(p.TracePolicy, "safe_buckets", "metadata_only", "strict_hygiene") {
		return fmt.Errorf("invalid adapter trace policy")
	}
	if !oneOf(p.ErrorMappingPolicy, "flow_error", "flow_reset", "metadata_error", "close_with_error") {
		return fmt.Errorf("invalid adapter error mapping policy")
	}
	if !oneOf(p.BackpressurePolicy, "adapter_queue", "runtime_stream", "carrier_chain", "priority_backpressure") {
		return fmt.Errorf("invalid adapter backpressure policy")
	}
	if p.MaxFlows <= 0 || p.MaxFlows > 256 {
		return fmt.Errorf("invalid adapter max flows")
	}
	if p.MaxFlowBytes <= 0 || p.MaxFlowBytes > limits.MaxPayloadBytes {
		return fmt.Errorf("invalid adapter max flow bytes")
	}
	if p.MaxBufferedBytes <= 0 || p.MaxBufferedBytes > 16*1024*1024 {
		return fmt.Errorf("invalid adapter max buffered bytes")
	}
	if p.MaxEvents <= 0 || p.MaxEvents > 1<<20 {
		return fmt.Errorf("invalid adapter max events")
	}
	if len(p.RequiredCapabilities) == 0 {
		return fmt.Errorf("adapter required capabilities are missing")
	}
	known := map[string]bool{}
	for _, capability := range AdapterCapabilities() {
		known[capability] = true
	}
	seen := map[string]bool{}
	for _, capability := range p.RequiredCapabilities {
		if !known[capability] {
			return fmt.Errorf("unknown adapter capability %q", capability)
		}
		if seen[capability] {
			return fmt.Errorf("duplicate adapter capability %q", capability)
		}
		seen[capability] = true
	}
	return nil
}

func validateSecurityPolicy(p SecurityPolicy) error {
	if p.SecurityVersion == "" {
		return fmt.Errorf("security version is required")
	}
	if !oneOf(p.TranscriptMode, "canonical_v1", "canonical_with_capabilities_v1", "canonical_with_carrier_binding_v1", "canonical_full_binding_v1") {
		return fmt.Errorf("invalid transcript mode")
	}
	if p.KDFSuite != "kdf_hkdf_sha256" {
		return fmt.Errorf("invalid KDF suite")
	}
	if p.AEADSuite != "aead_aes_256_gcm" {
		return fmt.Errorf("invalid AEAD suite")
	}
	if p.MACSuite != "mac_hmac_sha256" {
		return fmt.Errorf("invalid MAC suite")
	}
	if !oneOf(p.NonceMode, "counter_xor_base", "counter_append_base", "directional_counter", "stream_partitioned_counter") {
		return fmt.Errorf("invalid nonce mode")
	}
	if !oneOf(p.ReplayPolicy, "ordered_only", "bounded_reorder", "windowed_replay") {
		return fmt.Errorf("invalid replay policy")
	}
	if p.ReplayWindowSize <= 1 || p.ReplayWindowSize > 4096 {
		return fmt.Errorf("invalid replay window size")
	}
	if !oneOf(p.DowngradePolicy, "strict_suite_and_capabilities", "strict_capabilities", "suite_bound_transcript") {
		return fmt.Errorf("invalid downgrade policy")
	}
	if !oneOf(p.CapabilityNegotiationPolicy, "strict_required", "intersection_with_required", "profile_declared_required") {
		return fmt.Errorf("invalid capability negotiation policy")
	}
	if !oneOf(p.ProfileCompatibilityPolicy, "strict_schema", "schema_and_feature", "full_policy_binding") {
		return fmt.Errorf("invalid profile compatibility policy")
	}
	if !oneOf(p.KeyRotationPolicy, "session_only", "message_lifetime_bound", "profile_lifetime_bound") {
		return fmt.Errorf("invalid key rotation policy")
	}
	if !oneOf(p.ConfigValidationPolicy, "strict_required", "strict_with_redaction", "strict_profile_bound") {
		return fmt.Errorf("invalid config validation policy")
	}
	if !oneOf(p.SecureEnvelopeMode, "metadata_authenticated", "synthetic_aead_test", "full_context_bound_envelope") {
		return fmt.Errorf("invalid secure envelope mode")
	}
	if p.MaxSessionMessages <= 0 || p.MaxSessionMessages > 1<<24 {
		return fmt.Errorf("invalid max session messages")
	}
	if p.MaxKeyLifetimeMessages <= 0 || p.MaxKeyLifetimeMessages > p.MaxSessionMessages {
		return fmt.Errorf("invalid max key lifetime messages")
	}
	return nil
}

func validateCompatibility(c CompatibilityMetadata, sec SecurityPolicy, stream StreamPolicy, carrier CarrierPolicy, limits SafetyLimits) error {
	if c.SchemaVersion != SupportedVersion {
		return fmt.Errorf("invalid compatibility schema version")
	}
	if c.CompilerSecurityVersion == "" || c.MinimumRuntimeVersion == "" {
		return fmt.Errorf("compatibility versions are required")
	}
	if !oneOf(SecuritySuiteString(), c.SupportedSecuritySuites...) {
		return fmt.Errorf("required security suite is not supported")
	}
	if len(c.RequiredCapabilities) == 0 {
		return fmt.Errorf("required capabilities are missing")
	}
	knownCapabilities := map[string]bool{}
	for _, capability := range SecurityCapabilities() {
		knownCapabilities[capability] = true
	}
	seenCapabilities := map[string]bool{}
	for _, capability := range c.RequiredCapabilities {
		if !knownCapabilities[capability] {
			return fmt.Errorf("unknown required capability %q", capability)
		}
		if seenCapabilities[capability] {
			return fmt.Errorf("duplicate required capability %q", capability)
		}
		seenCapabilities[capability] = true
	}
	if !oneOf(carrier.CarrierFamily, c.SupportedCarrierFamilies...) {
		return fmt.Errorf("profile carrier family missing from compatibility metadata")
	}
	for _, family := range c.SupportedCarrierFamilies {
		if !oneOf(family, CarrierFamilies()...) {
			return fmt.Errorf("unknown compatibility carrier family %q", family)
		}
	}
	if c.MaxEnvelopeBytes <= 0 || c.MaxEnvelopeBytes > limits.MaxFrameBytes {
		return fmt.Errorf("invalid compatibility envelope limit")
	}
	if c.MaxStreamCount <= 0 || c.MaxStreamCount < stream.MaxConcurrentStreams || c.MaxStreamCount > 16 {
		return fmt.Errorf("invalid compatibility stream count")
	}
	if c.MaxReplayWindow <= 1 || c.MaxReplayWindow < sec.ReplayWindowSize || c.MaxReplayWindow > 4096 {
		return fmt.Errorf("invalid compatibility replay window")
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
