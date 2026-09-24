//go:build cgo && phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include "production_scoped_exports_v1.h"
*/
import "C"

import (
	"kurdistan/internal/androidbridge"
	"unsafe"
)

//export kvpn_task7_maintenance_run_v1
func kvpn_task7_maintenance_run_v1(table *C.kvpn_output_callbacks_v1, owner, call, epoch, parent C.uint64_t, caseID C.uint32_t, output *C.int64_t, length C.uint32_t) C.int32_t {
	if output == nil || length != 24 || ((caseID < 1 || caseID > 3) && caseID != 301 && caseID != 302) {
		return 2
	}
	inv, result := newMaintenanceCOutputInvocationV1(table, uint64(owner), uint64(call), uint64(epoch))
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	values, result := androidbridge.Task7MaintenanceFixtureRunV1(&registry, androidbridge.Handle(parent), uint32(caseID), inv)
	if result != 0 {
		return C.int32_t(androidbridge.MaintenanceResultP1V1(result))
	}
	copy(unsafe.Slice((*int64)(unsafe.Pointer(output)), 24), values[:])
	return 0
}
