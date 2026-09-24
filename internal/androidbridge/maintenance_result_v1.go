// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"errors"

	"kurdistan/internal/selfhost"
)

type MaintenanceResultV1 uint8
type MaintenanceCandidateID uint64

type MaintenanceCandidateResultV1 struct {
	Result    MaintenanceResultV1
	Candidate MaintenanceCandidateID
	Preview   selfhost.LiveMaintenancePreviewV1
}

const (
	MaintenanceSuccess              MaintenanceResultV1 = 0
	MaintenanceNoChange             MaintenanceResultV1 = 1
	MaintenanceNotAdmitted          MaintenanceResultV1 = 2
	MaintenanceInvalidRequest       MaintenanceResultV1 = 3
	MaintenanceInvalidState         MaintenanceResultV1 = 4
	MaintenanceSizeLimit            MaintenanceResultV1 = 5
	MaintenanceResourceLimit        MaintenanceResultV1 = 6
	MaintenanceRateLimited          MaintenanceResultV1 = 7
	MaintenanceCancelled            MaintenanceResultV1 = 8
	MaintenanceTimeout              MaintenanceResultV1 = 9
	MaintenanceNetworkUnavailable   MaintenanceResultV1 = 10
	MaintenanceDestinationDenied    MaintenanceResultV1 = 11
	MaintenanceTLSTrustUnavailable  MaintenanceResultV1 = 12
	MaintenanceTLSRejected          MaintenanceResultV1 = 13
	MaintenanceFetchRejected        MaintenanceResultV1 = 14
	MaintenanceSignatureInvalid     MaintenanceResultV1 = 15
	MaintenanceWrongRecipient       MaintenanceResultV1 = 16
	MaintenanceProfileMismatch      MaintenanceResultV1 = 17
	MaintenanceRollback             MaintenanceResultV1 = 18
	MaintenanceExpired              MaintenanceResultV1 = 19
	MaintenanceRevoked              MaintenanceResultV1 = 20
	MaintenanceIncompatible         MaintenanceResultV1 = 21
	MaintenanceRootRotationRejected MaintenanceResultV1 = 22
	MaintenanceInternalFailure      MaintenanceResultV1 = 23
)

func validMaintenanceResult(result MaintenanceResultV1) bool {
	return result <= MaintenanceInternalFailure
}

func maintenanceResultFromFailure(reason selfhost.LiveMaintenanceFailureV1) MaintenanceResultV1 {
	switch reason {
	case selfhost.LiveMaintenanceNotAdmitted:
		return MaintenanceNotAdmitted
	case selfhost.LiveMaintenanceInvalidRequest:
		return MaintenanceInvalidRequest
	case selfhost.LiveMaintenanceInvalidState:
		return MaintenanceInvalidState
	case selfhost.LiveMaintenanceSizeLimit:
		return MaintenanceSizeLimit
	case selfhost.LiveMaintenanceResourceLimit:
		return MaintenanceResourceLimit
	case selfhost.LiveMaintenanceSignatureInvalid:
		return MaintenanceSignatureInvalid
	case selfhost.LiveMaintenanceWrongRecipient:
		return MaintenanceWrongRecipient
	case selfhost.LiveMaintenanceProfileMismatch:
		return MaintenanceProfileMismatch
	case selfhost.LiveMaintenanceRollback:
		return MaintenanceRollback
	case selfhost.LiveMaintenanceExpired:
		return MaintenanceExpired
	case selfhost.LiveMaintenanceRevoked:
		return MaintenanceRevoked
	case selfhost.LiveMaintenanceIncompatible:
		return MaintenanceIncompatible
	case selfhost.LiveMaintenanceRootRotationRejected:
		return MaintenanceRootRotationRejected
	case selfhost.LiveMaintenanceInternalFailure:
		return MaintenanceInternalFailure
	default:
		return MaintenanceInternalFailure
	}
}

func maintenanceResultFromError(err error) MaintenanceResultV1 {
	if err == nil {
		return MaintenanceSuccess
	}
	var verification *selfhost.LiveMaintenanceVerificationError
	if errors.As(err, &verification) {
		return maintenanceResultFromFailure(verification.Reason())
	}
	return MaintenanceInternalFailure
}

func normalizeMaintenancePlatformResult(result MaintenanceResultV1) MaintenanceResultV1 {
	if !validMaintenanceResult(result) || result == MaintenanceNoChange {
		return MaintenanceInternalFailure
	}
	return result
}
