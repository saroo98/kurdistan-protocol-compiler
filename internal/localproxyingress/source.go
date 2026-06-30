// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import (
	"fmt"

	"kurdistan/internal/proxyingress"
)

const (
	ScenarioSingleConnectEcho       = "single_connect_echo"
	ScenarioManySmallConnects       = "many_small_connects"
	ScenarioLargeRequestFragmented  = "large_request_fragmented"
	ScenarioMixedRequestClasses     = "mixed_request_classes"
	ScenarioSlowDripRequest         = "slow_drip_request"
	ScenarioResetMidRequest         = "reset_mid_request"
	ScenarioTargetErrorAfterOpen    = "target_error_after_open"
	ScenarioBackpressurePressure    = "backpressure_pressure"
	ScenarioInvalidTargetRejection  = "invalid_target_rejection"
	ScenarioLifecycleViolation      = "lifecycle_violation_rejection"
	ScenarioQueueOverflowRejection  = "queue_overflow_rejection"
	ScenarioDuplicateEventRejection = "duplicate_event_rejection"
)

func QuickScenarios() []string {
	return []string{ScenarioSingleConnectEcho, ScenarioManySmallConnects, ScenarioBackpressurePressure}
}

func FullScenarios() []string {
	return []string{
		ScenarioSingleConnectEcho,
		ScenarioManySmallConnects,
		ScenarioLargeRequestFragmented,
		ScenarioMixedRequestClasses,
		ScenarioSlowDripRequest,
		ScenarioResetMidRequest,
		ScenarioTargetErrorAfterOpen,
		ScenarioBackpressurePressure,
		ScenarioInvalidTargetRejection,
		ScenarioLifecycleViolation,
		ScenarioQueueOverflowRejection,
		ScenarioDuplicateEventRejection,
	}
}

func GenerateEvents(scenario string) ([]SyntheticIngressEvent, error) {
	targets := proxyingress.ValidTargetDescriptors()
	if len(targets) < 3 {
		return nil, ErrInvalidEvent
	}
	switch scenario {
	case ScenarioSingleConnectEcho:
		return requestEvents("req_local_alpha", targets[0], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventClose}, "bucket_4k"), nil
	case ScenarioManySmallConnects:
		events := []SyntheticIngressEvent{}
		for i := 0; i < 4; i++ {
			events = append(events, requestEvents(fmt.Sprintf("req_local_small_%d", i), targets[i%len(targets)], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventClose}, "bucket_1k")...)
		}
		return events, nil
	case ScenarioLargeRequestFragmented:
		return requestEvents("req_local_large", targets[1], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventData, RequestEventData, RequestEventClose}, "bucket_64k"), nil
	case ScenarioMixedRequestClasses:
		events := []SyntheticIngressEvent{}
		events = append(events, requestEvents("req_local_mixed_a", targets[0], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventClose}, "bucket_4k")...)
		events = append(events, requestEvents("req_local_mixed_b", targets[1], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventData, RequestEventClose}, "bucket_16k")...)
		events = append(events, requestEvents("req_local_mixed_c", targets[2], []RequestEventKind{RequestEventOpen, RequestEventReset}, "bucket_1k")...)
		return events, nil
	case ScenarioSlowDripRequest:
		return requestEvents("req_local_drip", targets[0], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventData, RequestEventData, RequestEventData, RequestEventClose}, "bucket_1k"), nil
	case ScenarioResetMidRequest:
		return requestEvents("req_local_reset", targets[1], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventReset}, "bucket_4k"), nil
	case ScenarioTargetErrorAfterOpen:
		return requestEvents("req_local_error", targets[2], []RequestEventKind{RequestEventOpen, RequestEventTargetErr}, "bucket_4k"), nil
	case ScenarioBackpressurePressure:
		return requestEvents("req_local_pressure", targets[1], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventBackpress, RequestEventData, RequestEventClose}, "bucket_64k"), nil
	case ScenarioInvalidTargetRejection:
		bad := targets[0]
		bad.DescriptorID = "invalid_descriptor_class"
		bad.TargetKind = "invalid_descriptor_class"
		return requestEvents("req_local_invalid", bad, []RequestEventKind{RequestEventOpen}, "bucket_1k"), nil
	case ScenarioLifecycleViolation:
		return requestEvents("req_local_violation", targets[0], []RequestEventKind{RequestEventData, RequestEventClose}, "bucket_1k"), nil
	case ScenarioQueueOverflowRejection:
		events := []SyntheticIngressEvent{}
		for i := 0; i < 110; i++ {
			events = append(events, SyntheticIngressEvent{EventID: fmt.Sprintf("queue_overflow_%03d", i), RequestID: "req_local_overflow", Kind: RequestEventData, Target: targets[0], ByteCountBucket: "bucket_1k", ChunkClass: "chunk_small", FlowClass: "interactive", LogicalTick: i})
		}
		return events, nil
	case ScenarioDuplicateEventRejection:
		events := requestEvents("req_local_duplicate", targets[0], []RequestEventKind{RequestEventOpen, RequestEventData, RequestEventClose}, "bucket_1k")
		events[1].EventID = events[0].EventID
		return events, nil
	default:
		return nil, fmt.Errorf("%w: unknown scenario", ErrInvalidEvent)
	}
}

func requestEvents(requestID string, target proxyingress.TargetDescriptor, kinds []RequestEventKind, bucket string) []SyntheticIngressEvent {
	events := make([]SyntheticIngressEvent, 0, len(kinds))
	for i, kind := range kinds {
		events = append(events, SyntheticIngressEvent{
			EventID:         fmt.Sprintf("%s_event_%03d", requestID, i),
			RequestID:       requestID,
			Kind:            kind,
			Target:          target,
			ByteCountBucket: bucket,
			ChunkClass:      chunkClass(bucket),
			FlowClass:       "interactive",
			ErrorClass:      "none",
			ResetClass:      "none",
			LogicalTick:     i,
		})
		if kind == RequestEventTargetErr {
			events[len(events)-1].ErrorClass = "target_error_synthetic"
		}
		if kind == RequestEventReset {
			events[len(events)-1].ResetClass = "stream_reset_synthetic"
		}
	}
	return events
}

func chunkClass(bucket string) string {
	switch bucket {
	case "bucket_64k":
		return "chunk_large"
	case "bucket_16k":
		return "chunk_medium"
	default:
		return "chunk_small"
	}
}
