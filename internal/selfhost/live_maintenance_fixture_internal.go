//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package selfhost

import (
	"bytes"
	"time"
)

// Task7FixtureSignedRoundTripV1 is internal-build fixture evidence, not update
// admission or candidate publication. Credentials never leave their owner.
// Its two bounded buffers belong to the fixture, not a product reservation.
func (o *LiveMaintenanceAdmission) Task7FixtureSignedRoundTripV1(now time.Time, fetch func([]byte) ([]byte, error)) (int, error) {
	if o == nil || fetch == nil || len(o.artifact) == 0 || len(o.artifact) > 65536 {
		return 0, maintenanceFailure(LiveMaintenanceInvalidRequest)
	}
	if err := o.RevalidateAt(now); err != nil {
		return 0, err
	}
	sent := bytes.Clone(o.artifact)
	defer clear(sent)
	received, err := fetch(sent)
	defer clear(received)
	if err != nil {
		return 0, err
	}
	if len(received) > 65536 || !bytes.Equal(received, o.artifact) {
		return 0, maintenanceFailure(LiveMaintenanceProfileMismatch)
	}
	// This fixed round trip verifies only this already bounded current artifact.
	// Do not reserve for the parent's maximum future update, or alter its limits.
	limits := o.limits
	limits.MaxArtifactBytes = uint32(len(received))
	verified, _, err := VerifyLiveMaintenanceCurrentForRecipient(received, now, o.value.Generation, o.request, o.private, limits)
	if err != nil {
		return 0, err
	}
	defer destroyLiveMaintenanceOffline(&verified)
	if err = o.RevalidateAt(now); err != nil {
		return 0, err
	}
	return len(received), nil
}
