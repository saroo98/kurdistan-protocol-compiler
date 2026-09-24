// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"errors"
	"testing"

	"kurdistan/internal/selfhost"
)

func TestMaintenanceResultV1NumbersAndFailureMapping(t *testing.T) {
	want := []MaintenanceResultV1{
		MaintenanceSuccess, MaintenanceNoChange, MaintenanceNotAdmitted,
		MaintenanceInvalidRequest, MaintenanceInvalidState, MaintenanceSizeLimit,
		MaintenanceResourceLimit, MaintenanceRateLimited, MaintenanceCancelled,
		MaintenanceTimeout, MaintenanceNetworkUnavailable, MaintenanceDestinationDenied,
		MaintenanceTLSTrustUnavailable, MaintenanceTLSRejected, MaintenanceFetchRejected,
		MaintenanceSignatureInvalid, MaintenanceWrongRecipient, MaintenanceProfileMismatch,
		MaintenanceRollback, MaintenanceExpired, MaintenanceRevoked, MaintenanceIncompatible,
		MaintenanceRootRotationRejected, MaintenanceInternalFailure,
	}
	for index, result := range want {
		if result != MaintenanceResultV1(index) {
			t.Fatalf("result[%d]=%d", index, result)
		}
	}

	for _, test := range []struct {
		reason selfhost.LiveMaintenanceFailureV1
		want   MaintenanceResultV1
	}{
		{selfhost.LiveMaintenanceNotAdmitted, MaintenanceNotAdmitted},
		{selfhost.LiveMaintenanceInvalidRequest, MaintenanceInvalidRequest},
		{selfhost.LiveMaintenanceInvalidState, MaintenanceInvalidState},
		{selfhost.LiveMaintenanceSizeLimit, MaintenanceSizeLimit},
		{selfhost.LiveMaintenanceResourceLimit, MaintenanceResourceLimit},
		{selfhost.LiveMaintenanceSignatureInvalid, MaintenanceSignatureInvalid},
		{selfhost.LiveMaintenanceWrongRecipient, MaintenanceWrongRecipient},
		{selfhost.LiveMaintenanceProfileMismatch, MaintenanceProfileMismatch},
		{selfhost.LiveMaintenanceRollback, MaintenanceRollback},
		{selfhost.LiveMaintenanceExpired, MaintenanceExpired},
		{selfhost.LiveMaintenanceRevoked, MaintenanceRevoked},
		{selfhost.LiveMaintenanceIncompatible, MaintenanceIncompatible},
		{selfhost.LiveMaintenanceRootRotationRejected, MaintenanceRootRotationRejected},
		{selfhost.LiveMaintenanceInternalFailure, MaintenanceInternalFailure},
	} {
		if got := maintenanceResultFromFailure(test.reason); got != test.want {
			t.Fatalf("reason=%d result=%d want=%d", test.reason, got, test.want)
		}
	}
	if got := maintenanceResultFromFailure(0); got != MaintenanceInternalFailure {
		t.Fatalf("zero failure result=%d", got)
	}
	if got := maintenanceResultFromFailure(255); got != MaintenanceInternalFailure {
		t.Fatalf("unknown failure result=%d", got)
	}
	if got := maintenanceResultFromError(errors.New("opaque")); got != MaintenanceInternalFailure {
		t.Fatalf("unknown error result=%d", got)
	}
}

func TestMaintenanceHandleAppendsWithoutRenumberingLegacyKinds(t *testing.T) {
	want := []HandleType{
		HandleVerifyPreview, HandleActivation, HandleDiagnostic, HandleBackup,
		HandleRuntimeSession, HandleRecipient, HandleMaintenance,
	}
	for index, kind := range want {
		if kind != HandleType(index+1) {
			t.Fatalf("kind[%d]=%d", index, kind)
		}
	}
	var registry HandleRegistry
	handle, code := registry.Open(HandleMaintenance, new(int))
	if code != CodeOK || handle == 0 {
		t.Fatalf("open handle=%d code=%v", handle, code)
	}
	if _, code := registry.Get(handle, HandleMaintenance); code != CodeOK {
		t.Fatalf("get code=%v", code)
	}
}
