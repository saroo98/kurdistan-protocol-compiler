// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import "kurdistan/internal/ir"

type RoundTripResult struct {
	Family          string     `json:"family"`
	EnvelopeCount   int        `json:"envelope_count"`
	Backpressure    int        `json:"backpressure"`
	AckRequired     int        `json:"ack_required"`
	RetryCount      int        `json:"retry_count"`
	Reordered       int        `json:"reordered"`
	Dropped         int        `json:"dropped"`
	Reconstructed   bool       `json:"reconstructed"`
	DecodedMessages int        `json:"decoded_messages"`
	Envelopes       []Envelope `json:"-"`
}

func RoundTrip(p *ir.Profile, family string, messages []SemanticMessage) (RoundTripResult, error) {
	model, err := NewModel(p, family)
	if err != nil {
		return RoundTripResult{}, err
	}
	envelopes, err := model.Encode(messages)
	if err != nil {
		return RoundTripResult{}, err
	}
	decoded, err := model.Decode(envelopes)
	if err != nil {
		return RoundTripResult{}, err
	}
	acks, retries, reordered, dropped := ReliabilityStats(envelopes)
	return RoundTripResult{
		Family:          model.Name(),
		EnvelopeCount:   len(envelopes),
		Backpressure:    BackpressureCount(envelopes),
		AckRequired:     acks,
		RetryCount:      retries,
		Reordered:       reordered,
		Dropped:         dropped,
		Reconstructed:   SemanticallyEquivalent(messages, decoded),
		DecodedMessages: len(decoded),
		Envelopes:       envelopes,
	}, nil
}
