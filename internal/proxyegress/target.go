// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

func TargetClasses() []EgressTargetClass {
	return []EgressTargetClass{
		EgressTargetEchoSynthetic,
		EgressTargetFixedResponse,
		EgressTargetChunkedResponse,
		EgressTargetSlowResponse,
		EgressTargetLargeObject,
		EgressTargetResetMidstream,
		EgressTargetErrorResponse,
		EgressTargetDripResponse,
		EgressTargetBlackholeSynthetic,
	}
}

func IsSyntheticTargetClass(target EgressTargetClass) bool {
	for _, allowed := range TargetClasses() {
		if target == allowed {
			return true
		}
	}
	return false
}

func TargetDescriptorFor(s EgressLifecycleScenario) EgressTargetDescriptor {
	desc := EgressTargetDescriptor{
		TargetID:           "target_" + s.ScenarioID,
		TargetClass:        s.TargetClass,
		ResponsePlanClass:  "synthetic_" + string(s.TargetClass),
		ChunkPlanClass:     chunkClass(s.TargetClass),
		LatencyBucket:      latencyBucket(s.TargetClass),
		FailureBucket:      failureBucket(s.TargetClass),
		ResetBucket:        resetBucket(s.TargetClass),
		BackpressureBucket: backpressureBucket(s.TargetClass),
	}
	desc.TargetHash = HashValue(desc)
	return desc
}

func chunkClass(target EgressTargetClass) string {
	switch target {
	case EgressTargetChunkedResponse, EgressTargetDripResponse:
		return "multi_chunk"
	case EgressTargetLargeObject:
		return "large_windowed_chunks"
	default:
		return "single_summary_chunk"
	}
}

func latencyBucket(target EgressTargetClass) string {
	switch target {
	case EgressTargetSlowResponse, EgressTargetDripResponse:
		return "logical_slow"
	case EgressTargetBlackholeSynthetic:
		return "no_progress"
	default:
		return "logical_immediate"
	}
}

func failureBucket(target EgressTargetClass) string {
	switch target {
	case EgressTargetErrorResponse:
		return "target_error"
	case EgressTargetBlackholeSynthetic:
		return "blackhole_like"
	default:
		return "none"
	}
}

func resetBucket(target EgressTargetClass) string {
	if target == EgressTargetResetMidstream {
		return "midstream_reset"
	}
	return "none"
}

func backpressureBucket(target EgressTargetClass) string {
	switch target {
	case EgressTargetSlowResponse, EgressTargetLargeObject, EgressTargetDripResponse:
		return "target_pressure"
	default:
		return "none"
	}
}
