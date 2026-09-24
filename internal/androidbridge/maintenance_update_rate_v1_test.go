// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/runtime"
	"testing"
	"time"
)

func updateScope(t *testing.T, id string) runtime.AuthenticatedProbeScopeV1 {
	t.Helper()
	s, err := runtime.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: "provider", LineageID: "lineage", ProfileID: id})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestMaintenanceUpdateRateRetainsSevenDayHistoryAndNeverEvictsEarly(t *testing.T) {
	r, result := NewMaintenanceUpdateRateRegistryV1(1)
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	now := time.Unix(1780000000, 0)
	a, b := updateScope(t, "a"), updateScope(t, "b")
	if got := r.TryStart(a, 60, now); got != MaintenanceSuccess {
		t.Fatal(got)
	}
	if got := r.TryStart(a, 604800, now.Add(time.Hour)); got != MaintenanceRateLimited {
		t.Fatal(got)
	}
	if got := r.TryStart(b, 60, now.Add(6*24*time.Hour)); got != MaintenanceResourceLimit {
		t.Fatal(got)
	}
	if got := r.TryStart(a, 60, now.Add(2*time.Hour)); got != MaintenanceExpired {
		t.Fatal(got)
	}
	if got := r.TryStart(b, 60, now.Add(7*24*time.Hour)); got != MaintenanceSuccess {
		t.Fatal(got)
	}
	if got := r.TryStart(b, 60, now.Add(7*24*time.Hour)); got != MaintenanceRateLimited {
		t.Fatal(got)
	}
}
func TestMaintenanceUpdateRateRejectsInvalidBeforeState(t *testing.T) {
	for _, n := range []int{0, 4097} {
		if r, result := NewMaintenanceUpdateRateRegistryV1(n); r != nil || result != MaintenanceResourceLimit {
			t.Fatal(n, result)
		}
	}
	r, _ := NewMaintenanceUpdateRateRegistryV1(1)
	if got := r.TryStart(runtime.AuthenticatedProbeScopeV1{}, 60, time.Now()); got != MaintenanceInvalidRequest {
		t.Fatal(got)
	}
}
