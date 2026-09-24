//go:build phase18productiontest && phase18outputtest && phase18jnitest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import "testing"

func TestProductionJNIHostGenuineStreamReceiptsAndFINV1(t *testing.T) {
	testProductionFacadeGenuineStreamV1(t, "", testProductionJNIHostOpenStreamV1, testProductionJNIHostStreamReceiveV1, testProductionJNIHostProbeV1)
}

func TestProductionJNIHostGenuinePacketReceiptsV1(t *testing.T) {
	testProductionFacadeGenuinePacketReceiptsV1(t, testProductionJNIHostReceivePacketV1, false)
}

func TestProductionJNIHostGenuinePacketMetadataFailureV1(t *testing.T) {
	testProductionFacadeGenuinePacketReceiptsV1(t, testProductionJNIHostReceivePacketFailureV1, true)
}
