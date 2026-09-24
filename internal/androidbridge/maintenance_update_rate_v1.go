// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"kurdistan/internal/runtime"
	"sync"
	"time"
	"unsafe"
)

// MaintenanceUpdateRateRegistryV1 is process-owned, shared across recreated
// parents, and never copied after first use. It retains no URL or authority.
type MaintenanceUpdateRateRegistryV1 struct {
	mu        sync.Mutex
	entries   []maintenanceUpdateRateEntryV1
	lastClock time.Time
}
type maintenanceUpdateRateEntryV1 struct {
	scope runtime.AuthenticatedProbeScopeV1
	start time.Time
}

func NewMaintenanceUpdateRateRegistryV1(capacity int) (*MaintenanceUpdateRateRegistryV1, MaintenanceResultV1) {
	if capacity < 1 || capacity > 4096 {
		return nil, MaintenanceResourceLimit
	}
	return &MaintenanceUpdateRateRegistryV1{entries: make([]maintenanceUpdateRateEntryV1, capacity)}, MaintenanceSuccess
}
func (r *MaintenanceUpdateRateRegistryV1) OwnedBytes() uint64 {
	if r == nil {
		return 0
	}
	return uint64(unsafe.Sizeof(*r)) + uint64(cap(r.entries))*uint64(unsafe.Sizeof(maintenanceUpdateRateEntryV1{}))
}
func (r *MaintenanceUpdateRateRegistryV1) TryStart(scope runtime.AuthenticatedProbeScopeV1, interval uint32, now time.Time) MaintenanceResultV1 {
	if r == nil || scope == (runtime.AuthenticatedProbeScopeV1{}) || interval < 60 || interval > 604800 || now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return MaintenanceInvalidRequest
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) < 1 || len(r.entries) > 4096 {
		return MaintenanceInvalidState
	}
	if now.Before(r.lastClock) {
		return MaintenanceExpired
	}
	r.lastClock = now
	free := -1
	for i := range r.entries {
		e := &r.entries[i]
		if !e.start.IsZero() && !now.Before(e.start.Add(604800*time.Second)) {
			*e = maintenanceUpdateRateEntryV1{}
		}
		if e.start.IsZero() {
			if free < 0 {
				free = i
			}
			continue
		}
		if e.scope == scope {
			if now.Before(e.start.Add(time.Duration(interval) * time.Second)) {
				return MaintenanceRateLimited
			}
			e.start = now
			return MaintenanceSuccess
		}
	}
	if free < 0 {
		return MaintenanceResourceLimit
	}
	r.entries[free] = maintenanceUpdateRateEntryV1{scope: scope, start: now}
	return MaintenanceSuccess
}
