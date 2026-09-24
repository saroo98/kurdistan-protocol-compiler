//go:build cgo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include "production_scoped_exports_v1.h"
*/
import "C"

import (
	"encoding/binary"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/selfhost"
	"time"
	"unsafe"
)

//export kvpn_go_maintenance_materialize_v1
func kvpn_go_maintenance_materialize_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, candidate C.uint64_t, output *C.uint8_t, capacity C.uint32_t, written *C.uint32_t) C.int32_t {
	if written == nil {
		return 2
	}
	*written = 0
	if output == nil || capacity == 0 || capacity > 1052763 || candidate == 0 {
		return 2
	}
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	n, result := androidbridge.MaterializeMaintenanceCandidateV1Scoped(&registry, androidbridge.Handle(parent), androidbridge.MaintenanceCandidateID(candidate), unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), inv)
	if n < 0 || n > int(capacity) {
		return 18
	}
	*written = C.uint32_t(n)
	return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
}

//export kvpn_go_maintenance_release_update_v1
func kvpn_go_maintenance_release_update_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, candidate C.uint64_t) C.int32_t {
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	return C.int32_t(androidbridge.MaintenanceResultP1V1(androidbridge.ReleaseMaintenanceCandidateV1Scoped(&registry, androidbridge.Handle(parent), androidbridge.MaintenanceCandidateID(candidate), inv)))
}

//export kvpn_go_maintenance_run_probe_v1
func kvpn_go_maintenance_run_probe_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, request *C.uint8_t, length C.uint32_t, output *C.uint8_t, written *C.uint32_t) C.int32_t {
	if written == nil {
		return 2
	}
	*written = 0
	if request == nil || length != 9 || output == nil {
		return 2
	}
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	n, status := maintenanceProbeWireV1(androidbridge.Handle(parent), unsafe.Slice((*byte)(unsafe.Pointer(request)), 9), unsafe.Slice((*byte)(unsafe.Pointer(output)), 21), inv)
	if n < 0 || n > 21 {
		return 18
	}
	*written = C.uint32_t(n)
	return C.int32_t(status)
}

//export kvpn_go_maintenance_check_update_v1
func kvpn_go_maintenance_check_update_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, request *C.uint8_t, length C.uint32_t, out *C.kvpn_maintenance_decision_v1) C.int32_t {
	if out == nil {
		return 2
	}
	*out = C.kvpn_maintenance_decision_v1{}
	if request == nil || length != 3 {
		return 2
	}
	wire := unsafe.Slice((*byte)(unsafe.Pointer(request)), 3)
	if wire[0] != 1 {
		return 2
	}
	timeout := binary.BigEndian.Uint16(wire[1:])
	if timeout < 1000 || timeout > 30000 {
		return 2
	}
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	decision, prepared := maintenanceCheckDecisionV1(androidbridge.Handle(parent), timeout, inv)
	// Preserve any actual acquired child even when later proof fails, so the
	// retained C caller can use its exact native cleanup receipt.
	out.candidate = C.uint64_t(decision.Candidate)
	if !prepared {
		status := androidbridge.MaintenanceResultP1V1(decision.Result)
		if status == 0 {
			return 18
		}
		return C.int32_t(status)
	}
	out.result = C.uint16_t(decision.Result)
	p := decision.Preview
	out.generation, out.artifact_length = C.uint64_t(p.Generation), C.uint32_t(p.ArtifactLength)
	if p.DeploymentMatch {
		out.deployment = 1
	}
	out.expiry, out.rotation = C.uint8_t(p.ExpiryCategory), C.uint8_t(p.RotationFlags)
	out.revocation, out.compatibility = C.uint8_t(p.RevocationCategory), C.uint8_t(p.CompatibilityCategory)
	for i, count := range p.ChangedCategories {
		out.changes[i] = C.uint8_t(count)
	}
	return 0
}

//export kvpn_go_discard_maintenance_candidate_v1
func kvpn_go_discard_maintenance_candidate_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent, child C.uint64_t) C.int32_t {
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	return C.int32_t(androidbridge.MaintenanceResultP1V1(androidbridge.DiscardMaintenanceCandidateOutputV1(inv, androidbridge.Handle(parent), androidbridge.MaintenanceCandidateID(child))))
}

//export kvpn_go_maintenance_open_v1
func kvpn_go_maintenance_open_v1(table *C.kvpn_output_callbacks_v1, platform *C.kvpn_android_callbacks_v1,
	owner, call, epoch C.uint64_t, request *C.uint8_t, length C.uint32_t, external C.uint64_t,
	parent *C.uint64_t, holder *C.uint8_t) C.int32_t {
	if parent == nil || holder == nil {
		return 2
	}
	*parent, *holder = 0, 0
	if request == nil || length == 0 || length > 2721575 || epoch != 0 || external == 0 {
		return 2
	}
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), 0)
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	p, code := newAndroidPlatformV1(platform, uint64(owner), 2)
	if code != androidbridge.CodeOK {
		if code == androidbridge.CodeStateCorrupt {
			*holder = 2
		}
		return C.int32_t(bridgeFailureP1V1(code, nil))
	}
	*holder = 1
	config, code := androidMaintenanceRuntimeConfigV1(p, androidbridge.MaintenanceConfigV1{
		Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}, Now: time.Now}, uint64(external))
	if code != androidbridge.CodeOK {
		return C.int32_t(bridgeFailureP1V1(code, nil))
	}
	h, status := androidbridge.OpenMaintenanceWireV1Scoped(&registry, unsafe.Slice((*byte)(unsafe.Pointer(request)), int(length)), selfHostedBridgeEnvironment{}, p, config, inv)
	*parent = C.uint64_t(h)
	return C.int32_t(status)
}

//export kvpn_go_discard_maintenance_parent_v1
func kvpn_go_discard_maintenance_parent_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t) C.int32_t {
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	return C.int32_t(androidbridge.MaintenanceResultP1V1(androidbridge.DiscardMaintenanceParentOutputV1(inv, androidbridge.Handle(parent))))
}

//export kvpn_go_maintenance_cancel_v1
func kvpn_go_maintenance_cancel_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t) C.int32_t {
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	return C.int32_t(androidbridge.MaintenanceResultP1V1(androidbridge.CancelMaintenanceV1Scoped(&registry, androidbridge.Handle(parent), inv)))
}

//export kvpn_go_maintenance_close_v1
func kvpn_go_maintenance_close_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t) C.int32_t {
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	return C.int32_t(androidbridge.MaintenanceResultP1V1(androidbridge.CloseMaintenanceV1Scoped(&registry, androidbridge.Handle(parent), inv)))
}

//export kvpn_go_maintenance_retired_result_v1
func kvpn_go_maintenance_retired_result_v1(parent C.uint64_t) C.int32_t {
	result, _ := androidbridge.RetiredMaintenanceParentResultV1(&registry, androidbridge.Handle(parent))
	return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
}

//export kvpn_go_maintenance_retirement_publish_v1
func kvpn_go_maintenance_retirement_publish_v1(parent C.uint64_t, result C.int32_t) {
	actual := androidbridge.MaintenanceInternalFailure
	if result == 0 {
		actual = androidbridge.MaintenanceSuccess
	}
	androidbridge.PublishRetiredMaintenanceParentResultV1(&registry, androidbridge.Handle(parent), actual)
}
