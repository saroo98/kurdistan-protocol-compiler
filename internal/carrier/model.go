// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import (
	"fmt"
	"sort"

	"kurdistan/internal/ir"
)

type profileModel struct {
	profile *ir.Profile
	family  string
	policy  ir.CarrierPolicy
}

func NewModel(p *ir.Profile, family string) (Model, error) {
	if p == nil {
		return nil, fmt.Errorf("profile is nil")
	}
	if family == "" {
		family = p.CarrierPolicy.CarrierFamily
	}
	if !familyAllowed(family) {
		return nil, fmt.Errorf("unknown carrier family %q", family)
	}
	cp := *p
	cp.GenerationHash = ""
	cp.CarrierPolicy.CarrierFamily = family
	if err := ir.Validate(&cp); err != nil {
		return nil, err
	}
	return profileModel{profile: &cp, family: family, policy: cp.CarrierPolicy}, nil
}

func (m profileModel) Name() string { return m.family }

func (m profileModel) Validate() error {
	if !familyAllowed(m.family) {
		return fmt.Errorf("unknown carrier family %q", m.family)
	}
	return nil
}

func (m profileModel) Encode(messages []SemanticMessage) ([]Envelope, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if len(messages) == 0 {
		return nil, nil
	}
	ordered := append([]SemanticMessage(nil), messages...)
	for i := range ordered {
		if ordered[i].Semantic == "" || ordered[i].ByteCount < 0 {
			return nil, fmt.Errorf("invalid semantic message")
		}
		ordered[i].OriginalIndex = i + 1
	}
	if m.family == FamilyInteractive {
		sort.SliceStable(ordered, func(i, j int) bool {
			return priorityRank(ordered[i].PriorityClass) < priorityRank(ordered[j].PriorityClass)
		})
	}
	envelopes := []Envelope{}
	switch m.family {
	case FamilyStream, FamilyMessage:
		envelopes = m.encodeCoalesced(ordered, kindForFamily(m.family))
	case FamilyDatagramLike, FamilyLossyReordered:
		envelopes = m.encodeCoalesced(ordered, "datagram")
	case FamilyChunked:
		envelopes = m.encodeChunked(ordered)
	case FamilyBatch, FamilyInteractive:
		envelopes = m.encodeCoalesced(ordered, "batch")
	case FamilyLongPollStyle:
		envelopes = m.encodeLongPoll(ordered)
	default:
		return nil, fmt.Errorf("unsupported carrier family %q", m.family)
	}
	for i := range envelopes {
		m.decorate(&envelopes[i], i)
		if err := ValidateEnvelope(m.profile, envelopes[i]); err != nil {
			return nil, err
		}
	}
	return envelopes, nil
}

func (m profileModel) Decode(envelopes []Envelope) ([]SemanticMessage, error) {
	for _, env := range envelopes {
		if err := ValidateEnvelope(m.profile, env); err != nil {
			return nil, err
		}
	}
	ordered := append([]Envelope(nil), envelopes...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Sequence < ordered[j].Sequence
	})
	byIndex := map[int]SemanticMessage{}
	order := []int{}
	for _, env := range ordered {
		for _, msg := range env.Messages {
			if msg.OriginalIndex == 0 {
				msg.OriginalIndex = len(order) + 1
			}
			if _, ok := byIndex[msg.OriginalIndex]; !ok {
				order = append(order, msg.OriginalIndex)
				byIndex[msg.OriginalIndex] = SemanticMessage{
					StreamID:      msg.StreamID,
					Semantic:      msg.Semantic,
					PriorityClass: msg.PriorityClass,
					MetadataClass: msg.MetadataClass,
					OriginalIndex: msg.OriginalIndex,
				}
			}
			cur := byIndex[msg.OriginalIndex]
			cur.ByteCount += msg.ByteCount
			byIndex[msg.OriginalIndex] = cur
		}
	}
	sort.Ints(order)
	out := make([]SemanticMessage, 0, len(order))
	for _, idx := range order {
		out = append(out, byIndex[idx])
	}
	return out, nil
}

func (m profileModel) encodeCoalesced(messages []SemanticMessage, kind string) []Envelope {
	maxMessages := max(1, m.policy.MaxMessagesPerEnvelope)
	if m.family == FamilyMessage || m.policy.BatchPolicy == "no_batch" {
		maxMessages = 1
	}
	envelopes := []Envelope{}
	batch := []SemanticMessage{}
	batchBytes := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		envelopes = append(envelopes, Envelope{
			CarrierFamily: m.family,
			Sequence:      uint64(len(envelopes) + 1),
			Kind:          kind,
			StreamID:      batch[0].StreamID,
			MessageCount:  len(batch),
			ByteCount:     batchBytes,
			FinalChunk:    true,
			Messages:      append([]SemanticMessage(nil), batch...),
		})
		batch = nil
		batchBytes = 0
	}
	for _, msg := range messages {
		chunks := m.splitMessage(msg)
		for _, chunk := range chunks {
			if len(batch) > 0 && (len(batch) >= maxMessages || batchBytes+chunk.ByteCount > m.policy.MaxEnvelopeBytes) {
				flush()
			}
			batch = append(batch, chunk)
			batchBytes += chunk.ByteCount
			if kind != "batch" && kind != "coalesced" {
				flush()
			}
		}
	}
	flush()
	return envelopes
}

func (m profileModel) encodeChunked(messages []SemanticMessage) []Envelope {
	envelopes := []Envelope{}
	for _, msg := range messages {
		chunks := m.splitMessage(msg)
		for i, chunk := range chunks {
			envelopes = append(envelopes, Envelope{
				CarrierFamily: m.family,
				Sequence:      uint64(len(envelopes) + 1),
				Kind:          "chunk",
				StreamID:      chunk.StreamID,
				MessageCount:  1,
				ByteCount:     chunk.ByteCount,
				ChunkIndex:    i,
				FinalChunk:    i == len(chunks)-1,
				Messages:      []SemanticMessage{chunk},
			})
		}
	}
	return envelopes
}

func (m profileModel) encodeLongPoll(messages []SemanticMessage) []Envelope {
	envelopes := []Envelope{}
	for _, msg := range messages {
		for i, chunk := range m.splitMessage(msg) {
			kind := "poll_response"
			if i == 0 && msg.Semantic == ir.SemanticOpenRelay {
				kind = "poll_request"
			}
			envelopes = append(envelopes, Envelope{
				CarrierFamily: m.family,
				Sequence:      uint64(len(envelopes) + 1),
				Kind:          kind,
				StreamID:      chunk.StreamID,
				MessageCount:  1,
				ByteCount:     chunk.ByteCount,
				ChunkIndex:    i,
				FinalChunk:    true,
				Messages:      []SemanticMessage{chunk},
			})
		}
	}
	return envelopes
}

func (m profileModel) splitMessage(msg SemanticMessage) []SemanticMessage {
	limit := max(1, m.policy.MaxEnvelopeBytes)
	if m.policy.ChunkingPolicy == "no_chunk" && msg.ByteCount <= limit {
		return []SemanticMessage{msg}
	}
	chunkSize := limit
	switch m.policy.ChunkingPolicy {
	case "fixed_chunk":
		chunkSize = max(1, limit/2)
	case "profile_bucket_chunk", "state_derived_chunk":
		chunkSize = max(1, limit/3)
	case "priority_aware_chunk":
		if msg.PriorityClass == "interactive" || msg.PriorityClass == "control" {
			chunkSize = max(1, limit/2)
		}
	}
	remaining := msg.ByteCount
	if remaining == 0 {
		return []SemanticMessage{msg}
	}
	chunks := []SemanticMessage{}
	for remaining > 0 {
		size := chunkSize
		if size > remaining {
			size = remaining
		}
		chunk := msg
		chunk.ByteCount = size
		chunks = append(chunks, chunk)
		remaining -= size
	}
	return chunks
}

func (m profileModel) decorate(env *Envelope, index int) {
	env.FlushClass = m.policy.FlushPolicy
	env.PaddingClass = m.policy.EnvelopePaddingPolicy
	env.EncodingClass = m.policy.EnvelopeEncoding
	env.BatchClass = m.policy.BatchPolicy
	env.ChunkingClass = m.policy.ChunkingPolicy
	env.PriorityClass = m.policy.PriorityMappingPolicy
	env.TimingBucket = timingBucket(m.policy.TimingBucketPolicy, m.family, index)
	env.QueueDepth = (index % max(1, m.policy.MaxCarrierQueueDepth)) + 1
	env.Backpressure = env.QueueDepth == m.policy.MaxCarrierQueueDepth || m.policy.BackpressurePolicy == "drop_or_delay_metadata"
	env.Reliability.AckRequired = m.policy.ReliabilityPolicy == "ack_required" || m.policy.ReliabilityPolicy == "retry_bounded" || m.family == FamilyLossyReordered
	if env.Reliability.AckRequired {
		env.Reliability.AckSequence = env.Sequence
	}
	if m.family == FamilyDatagramLike && m.policy.ReorderPolicy != "none" && index%3 == 1 {
		env.Reliability.Reordered = true
	}
	if m.family == FamilyLossyReordered {
		if index%2 == 1 {
			env.Reliability.Reordered = true
		}
		if index%4 == 2 {
			env.Reliability.Dropped = true
			env.Reliability.RetryCount = max(1, min(m.policy.MaxRetryCount, 1))
			env.Kind = "retry"
		}
	}
}

func kindForFamily(family string) string {
	if family == FamilyStream {
		return "coalesced"
	}
	return "data"
}

func timingBucket(policy, family string, index int) string {
	switch policy {
	case "poll_cycle_bucket":
		return fmt.Sprintf("poll_%d", index%3)
	case "retry_bucket":
		return fmt.Sprintf("retry_%d", index%2)
	case "flush_bucket":
		return fmt.Sprintf("flush_%d", index%4)
	default:
		return family
	}
}

func priorityRank(value string) int {
	switch value {
	case "control":
		return 0
	case "interactive":
		return 1
	default:
		return 2
	}
}

func SemanticallyEquivalent(a, b []SemanticMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].StreamID != b[i].StreamID ||
			a[i].Semantic != b[i].Semantic ||
			a[i].ByteCount != b[i].ByteCount ||
			a[i].PriorityClass != b[i].PriorityClass ||
			a[i].MetadataClass != b[i].MetadataClass {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
