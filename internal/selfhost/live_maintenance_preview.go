// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"kurdistan/internal/product/envelope"
)

type LiveMaintenancePreviewV1 struct {
	DeploymentMatch                           bool
	Generation                                uint64
	ExpiryCategory, RotationFlags             uint8
	RevocationCategory, CompatibilityCategory uint8
	ChangedCategories                         [10]uint8
	ArtifactLength                            uint32
}

func maintenancePreview(old envelope.CanonicalProfileV1, current liveProfileBundleV2, next envelope.CanonicalProfileV1, candidate liveProfileBundleV2, n int, now time.Time) (LiveMaintenancePreviewV1, error) {
	var left, right map[uint64]cbor.RawMessage
	if decodeCanonicalFields(old.Policy, &left, 65536, 64) != nil || decodeCanonicalFields(next.Policy, &right, 65536, 64) != nil {
		return LiveMaintenancePreviewV1{}, maintenanceFailure(LiveMaintenanceInternalFailure)
	}
	defer func() {
		for _, b := range left {
			clear(b)
		}
		for _, b := range right {
			clear(b)
		}
	}()
	result := LiveMaintenancePreviewV1{DeploymentMatch: true, Generation: next.Generation, ArtifactLength: uint32(n)}
	if time.Unix(next.ValidUntil, 0).Sub(now) <= 7*24*time.Hour {
		result.ExpiryCategory = 1
	}
	changed := func(labels ...uint64) uint8 {
		for _, label := range labels {
			if !bytes.Equal(left[label], right[label]) {
				return 1
			}
		}
		return 0
	}
	if current.IssuerKey != candidate.IssuerKey || !bytes.Equal(current.IssuerPublicDER, candidate.IssuerPublicDER) {
		result.ChangedCategories[0] = 1
		result.RotationFlags |= 1
	}
	result.ChangedCategories[1] = changed(13)
	result.ChangedCategories[2] = changed(14, 16, 20, 21)
	result.ChangedCategories[3] = changed(18)
	result.ChangedCategories[4] = changed(15, 17, 19)
	// Already canonical ordered string-list equality is equivalent to equality
	// of its canonical encoding, without allocating another list encoding.
	if !slices.Equal(old.StrategyIDs, next.StrategyIDs) || !slices.Equal(old.RelayIDs, next.RelayIDs) {
		result.ChangedCategories[5] = 1
	}
	result.ChangedCategories[6] = changed(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	if result.ChangedCategories[6] != 0 {
		result.RotationFlags |= 4
	}
	result.ChangedCategories[7] = changed(22, 23, 24)
	result.ChangedCategories[8] = changed(26)
	if old.ValidFrom != next.ValidFrom || old.ValidUntil != next.ValidUntil || old.RevocationEpoch != next.RevocationEpoch || old.RequiredSafetyFloor != next.RequiredSafetyFloor {
		result.ChangedCategories[9] = 1
	}
	return result, nil
}
