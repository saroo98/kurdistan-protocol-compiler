// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

func TraceEvent(p *ir.Profile, cfg LocalAdapterConfig, eventType, scenario string, sum LocalAdapterSummary) ktrace.Event {
	profileID := ""
	if p != nil {
		profileID = p.ID
	}
	return ktrace.Event{
		ProfileID:                    profileID,
		EventType:                    eventType,
		AdapterNameBucket:            "local",
		AdapterKind:                  "ingress-egress",
		AdapterScenario:              scenario,
		LocalAdapterScenario:         scenario,
		LocalAdapterSourceModel:      sum.SourceModel,
		LocalAdapterSinkModel:        sum.SinkModel,
		LocalFlowState:               "mapped",
		LocalSourceChunkCountBucket:  countBucket(sum.SourceChunks),
		LocalSinkChunkCountBucket:    countBucket(sum.SinkChunks),
		LocalSourceByteBucket:        byteBucket(sum.SourceBytes),
		LocalSinkByteBucket:          byteBucket(sum.SinkBytes),
		LocalSequenceIntegrityResult: "passed",
		LocalPostCloseRejections:     sum.PostCloseRejected,
		LocalBackpressureCount:       sum.BackpressureEvents,
		LocalQueuePressureCount:      sum.QueuePressureEvents,
		PayloadHygiene:               !sum.PayloadLogged,
		SecretHygiene:                !sum.SecretLogged,
	}
}

func countBucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n <= 2:
		return "small"
	case n <= 8:
		return "medium"
	default:
		return "large"
	}
}

func byteBucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n <= 1024:
		return "small"
	case n <= 64*1024:
		return "medium"
	default:
		return "large"
	}
}
