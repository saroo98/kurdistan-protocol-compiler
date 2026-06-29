// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import (
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

func TraceEvent(p *ir.Profile, scenario string, summary ByteTransportSummary) ktrace.Event {
	profileID := ""
	if p != nil {
		profileID = p.ID
	}
	return ktrace.Event{
		ProfileID:                    profileID,
		EventType:                    "byte_transport",
		ByteTransportScenario:        scenario,
		ByteFrameKindBucket:          "mixed",
		ByteFrameCountBucket:         bucket(summary.FramesEncoded),
		ByteFragmentCountBucket:      bucket(summary.FragmentsCreated),
		ByteCountBucket:              bucket(summary.BytesWritten),
		BytePipeQueuePressureBucket:  bucket(summary.BackpressureEvents),
		ByteReassemblyResult:         boolResult(summary.ReassemblyRejected == 0),
		ByteSequenceRejectionCount:   summary.SequenceRejected,
		ByteCorruptionRejectionCount: summary.CorruptionRejected,
		ByteMalformedRejectionCount:  summary.MalformedRejected,
		ByteCloseResetEventBucket:    bucket(summary.TargetResets),
		PayloadHygiene:               !summary.PayloadLogged,
		SecretHygiene:                !summary.SecretLogged,
	}
}

func bucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n < 4:
		return "small"
	case n < 16:
		return "medium"
	default:
		return "large"
	}
}

func boolResult(ok bool) string {
	if ok {
		return "passed"
	}
	return "failed"
}
