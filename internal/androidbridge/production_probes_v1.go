// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"encoding/binary"
	runtimeengine "kurdistan/internal/runtime"
)

func RunProductionProbeV1(r *HandleRegistry, h Handle, request, out []byte) (int, int32) {
	return RunProductionProbeV1Scoped(r, h, request, out, ProductionOutputInvocationV1{})
}
func RunProductionProbeV1Scoped(r *HandleRegistry, h Handle, request, out []byte, inv ProductionOutputInvocationV1) (int, int32) {
	if len(out) < 21 {
		return 0, 4
	}
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return 0, s
	}
	if len(request) != 9 || request[0] != 1 || request[3] != 1 {
		return 0, 2
	}
	q := runtimeengine.ProbeRequestV1{TargetID: binary.BigEndian.Uint16(request[1:3]), Method: request[3], AttemptTimeoutMillis: binary.BigEndian.Uint16(request[4:6]), TotalTimeoutMillis: binary.BigEndian.Uint16(request[6:8]), Samples: request[8]}
	if q.TargetID == 0 || q.AttemptTimeoutMillis < 1000 || q.AttemptTimeoutMillis > 30000 || q.TotalTimeoutMillis < 1000 || q.TotalTimeoutMillis > 30000 || q.Samples == 0 || q.Samples > 10 {
		return 0, 2
	}
	if v.projection.probeMaxConcurrent == 0 {
		return 0, 1
	}
	for index := uint16(198); index < 202; index++ {
		use, ctx, s := v.beginIOOutputV1(index, 256, inv, false)
		if s == 5 {
			continue
		}
		if s != 0 {
			return 0, s
		}
		defer v.parent.finishUseV1(use)
		if v.pump == nil {
			return 0, 1
		}
		probe, err := v.pump.StartProbe(ctx, q)
		if err != nil {
			return 0, productionOperationStatusV1(err)
		}
		result, err := v.pump.AwaitProbe(ctx, probe)
		return v.publishProbeOutputV1(use, q, result, err, out, inv)
	}
	return 0, 5
}

// Completed aggregate publication is bounded by parent/attempt authority, not
// the elapsed work timeout represented categorically in its payload.
func (v *productionSessionV1) publishProbeOutputV1(use productionUseV1, q runtimeengine.ProbeRequestV1, result runtimeengine.ProbeAggregateV1, err error, out []byte, inv ProductionOutputInvocationV1) (int, int32) {
	v.parent.mu.Lock()
	s := v.liveLockedV1(use)
	v.parent.mu.Unlock()
	if s != 0 {
		return 0, s
	}
	completion := productionOperationStatusV1(err)
	encoded, s := encodeProbeAggregateWireV1(q, result, completion, runtimeengine.ProbeActiveRelayEndToEndV1)
	if s != 0 {
		return 0, s
	}
	v.parent.mu.Lock()
	s = v.liveLockedV1(use)
	if s == 0 {
		s = v.parent.outputPrepareLockedV1(inv, use.attempt, 0, 0, v.parent.admission.monotonicDeadline, false)
	}
	if s == 0 {
		copy(out, encoded[:])
	}
	v.parent.mu.Unlock()
	if s != 0 {
		return 0, s
	}
	return 21, 0
}

// Shared fixed aggregate encoding. Callers retain their own actual authority
// and preparation fences; this pure byte function grants no publication right.
func encodeProbeAggregateWireV1(q runtimeengine.ProbeRequestV1, result runtimeengine.ProbeAggregateV1, completion int32, path runtimeengine.ProbePathV1) ([21]byte, int32) {
	var encoded [21]byte
	if completion != 0 && completion != 8 && completion != 6 {
		return encoded, completion
	}
	if result.Attempted == 0 {
		if completion == 0 {
			completion = 18
		}
		return encoded, completion
	}
	if q.Samples > 10 || result.Attempted > q.Samples || result.Path != path || (path != runtimeengine.ProbeActiveRelayEndToEndV1 && path != runtimeengine.ProbeDisconnectedTCPConnectV1) || result.LossPermille > 1000 || result.LatencyMicros > 30000000 || result.JitterMicros > 30000000 {
		return encoded, 18
	}
	// With at most ten actual samples, floor(failed*1000/attempted)
	// uniquely identifies the integral failed count without retaining samples.
	failed := uint8((uint32(result.LossPermille)*uint32(result.Attempted) + 999) / 1000)
	succeeded := result.Attempted - failed
	if result.HasLatency != (succeeded > 0) || result.HasJitter != (succeeded > 1) {
		return encoded, 18
	}
	encoded[0] = 1
	encoded[1] = byte(path)
	encoded[2] = 1
	encoded[3] = result.Attempted
	encoded[4] = succeeded
	encoded[5] = failed
	encoded[6] = q.Samples - result.Attempted
	if result.HasLatency {
		encoded[7] |= 1
		binary.BigEndian.PutUint32(encoded[8:12], uint32(result.LatencyMicros))
	}
	if result.HasJitter {
		encoded[7] |= 2
		binary.BigEndian.PutUint32(encoded[12:16], uint32(result.JitterMicros))
	}
	binary.BigEndian.PutUint16(encoded[16:18], result.LossPermille)
	if result.Attempted >= 3 {
		encoded[18] = 2
		if failed == 0 && result.JitterMicros <= result.LatencyMicros/4 {
			encoded[18] = 1
		}
	}
	binary.BigEndian.PutUint16(encoded[19:21], uint16(completion))
	return encoded, 0
}
