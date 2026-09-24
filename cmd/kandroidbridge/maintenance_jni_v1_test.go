//go:build phase18jnitest && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"kurdistan/internal/selfhost"
	"testing"
	"time"
)

func TestMaintenanceJNIHostMaterializeConsumesBeforeMetadataV1(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "delivered"
		if failure {
			name = "undelivered"
		}
		t.Run(name, func(t *testing.T) {
			request, fixture := maintenanceFacadeOpeningWithFixtureV1(t)
			next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase, Now: time.Now().UTC(), ValidFor: 12 * time.Hour, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(next.Artifact)
			testMaintenanceCanonicalCandidateV1(t, request, next.Artifact, false, func(parent, child uint64) {
				output := bytes.Repeat([]byte{0xa5}, len(next.Artifact))
				defer clear(output)
				n, status := testMaintenanceJNIHostMaterializeV1(parent, child, output, failure)
				if failure {
					if status != 18 || n != 0 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, len(output))) {
						t.Fatal("metadata failure published artifact", n, status)
					}
				} else if status != 0 || n != len(next.Artifact) || !bytes.Equal(output, next.Artifact) {
					t.Fatal("actual JNI artifact", n, status)
				}
				if n, status := testMaintenanceJNIHostMaterializeV1(parent, child, output, false); n != 0 || status != 3 {
					t.Fatal("consumed JNI candidate resurrected", n, status)
				}
			})
		})
	}
}

func TestMaintenanceJNIHostGenuineFetchCandidate38AndDiscardV1(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "delivered"
		if failure {
			name = "undelivered"
		}
		t.Run(name, func(t *testing.T) {
			maintenanceGenuineFetchCandidateHostV1(t, func(parent uint64, output []byte) (int, int32) {
				return testMaintenanceJNIHostUpdateCallV1(t, parent, output, failure)
			}, failure)
		})
	}
}

func TestMaintenanceJNIHostOpeningAndMetadataFailureV1(t *testing.T) {
	for _, failure := range []bool{false, true} {
		request := maintenanceFacadeOpeningFixtureV1(t)
		testMaintenanceJNIHostOpeningV1(t, request, failure)
	}
}
