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
