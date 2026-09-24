// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"encoding/binary"
	runtimeengine "kurdistan/internal/runtime"
)

func RunMaintenanceProbeWireV1Scoped(registry *HandleRegistry, parent Handle, request, output []byte, inv MaintenanceOutputInvocationV1) (int, int32) {
	return runMaintenanceProbeWireV1Scoped(registry, parent, request, output, inv, nil)
}

func runMaintenanceProbeWireV1Scoped(registry *HandleRegistry, parent Handle, request, output []byte, inv MaintenanceOutputInvocationV1, route maintenanceNumericRouteV1) (int, int32) {
	if len(output) < 21 {
		return 0, 4
	}
	if len(request) != 9 || request[0] != 1 || request[3] != 1 {
		return 0, 2
	}
	q := runtimeengine.ProbeRequestV1{TargetID: binary.BigEndian.Uint16(request[1:3]), Method: request[3], AttemptTimeoutMillis: binary.BigEndian.Uint16(request[4:6]), TotalTimeoutMillis: binary.BigEndian.Uint16(request[6:8]), Samples: request[8]}
	if q.TargetID == 0 || q.AttemptTimeoutMillis < 1000 || q.AttemptTimeoutMillis > 30000 || q.TotalTimeoutMillis < 1000 || q.TotalTimeoutMillis > 30000 || q.Samples == 0 || q.Samples > 10 {
		return 0, 2
	}
	p, result := maintenanceParentOutputV1(registry, parent, inv)
	if result != MaintenanceSuccess {
		return 0, productionMaintenanceStatusV1(result)
	}
	p.mu.Lock()
	disconnected := p.networkMode == runtimeengine.ProbeDisconnectedDefaultV1
	p.mu.Unlock()
	if !disconnected {
		return 0, 1
	}
	aggregate, result := runMaintenanceProbeV1Scoped(registry, parent, q, inv, route)
	encoded, status := encodeProbeAggregateWireV1(q, aggregate, productionMaintenanceStatusV1(result), runtimeengine.ProbeDisconnectedTCPConnectV1)
	if status != 0 {
		return 0, status
	}
	copy(output, encoded[:])
	return 21, 0
}

// This synchronous adapter borrows the canonical decoder's exact spans. Neither
// a second parser nor a caller-supplied current-generation assertion is used.
func decodeMaintenanceOpeningV1(input []byte) (MaintenanceCurrentInputV1, []byte, uint64, int32) {
	view, status := decodeProductionOpenV1(input)
	if status != 0 {
		return MaintenanceCurrentInputV1{}, nil, 0, int32(status)
	}
	if view.purpose != 2 {
		return MaintenanceCurrentInputV1{}, nil, 0, 2
	}
	settings, status := decodeProductionSettingsV1(view.settings)
	if status != 0 {
		return MaintenanceCurrentInputV1{}, nil, 0, int32(status)
	}
	budget := uint64(settings.memoryMiB) << 20
	if budget == 0 {
		budget = 80 << 20
	}
	budget = min(budget, maxMaintenanceOwnerBudget)
	return MaintenanceCurrentInputV1{view.verify, view.activation, view.recipientRequest, view.recipientPrivate}, view.settings, budget, 0
}

// Only the trusted platform can match all five rows against its retained capture.
type MaintenanceCapturePlatformV1 interface {
	MaintenancePlatformOwnerV1
	MatchMaintenanceCaptureV1(MaintenanceCurrentInputV1, []byte) int32
}

// OpenMaintenanceWireV1Scoped is the typed private-package KPO bridge. The
// existing admitted operation remains responsible for all current authority,
// registration, network, budget and output preparation fences.
func OpenMaintenanceWireV1Scoped(registry *HandleRegistry, input []byte,
	environment RecipientVerificationEnvironmentAt, platform MaintenanceCapturePlatformV1,
	config MaintenanceConfigV1, inv MaintenanceOutputInvocationV1) (Handle, int32) {
	current, settings, budget, status := decodeMaintenanceOpeningV1(input)
	if status != 0 {
		return 0, status
	}
	if platform == nil {
		return 0, 2
	}
	// The trusted charge includes the exact bounded capture-copy owner before
	// that match can allocate. Full native admission still follows the match.
	if result := maintenanceOutputOpeningV1(registry, inv, config.OutputMetadataBytes, budget); result != MaintenanceSuccess {
		return 0, productionMaintenanceStatusV1(result)
	}
	if status = platform.MatchMaintenanceCaptureV1(current, settings); status != 0 {
		if !validProductionOpeningStatusV1(productionStatusV1(status)) {
			return 0, 18
		}
		return 0, status
	}
	config.OwnedBudgetBytes = budget
	parent, result := OpenMaintenanceV1Scoped(registry, current, environment, platform, config, inv)
	return parent, productionMaintenanceStatusV1(result)
}
