//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/selfhost"
	"testing"
	"time"
)

func maintenanceFacadeOpeningFixtureV1(t *testing.T) []byte {
	request, _ := maintenanceFacadeOpeningWithFixtureV1(t)
	return request
}

func maintenanceFacadeOpeningWithFixtureV1(t *testing.T) ([]byte, releaseMaintenanceFixture) {
	return maintenanceFacadeOpeningAtMemoryV1(t, 128)
}

func maintenanceFacadeOpeningAtMemoryV1(t *testing.T, memory uint16) ([]byte, releaseMaintenanceFixture) {
	return maintenanceFacadeOpeningWithProbesV1(t, memory, nil)
}

func maintenanceFacadeOpeningWithProbesV1(t *testing.T, memory uint16, probes *runtimepolicy.ProbesV1) ([]byte, releaseMaintenanceFixture) {
	return maintenanceFacadeOpeningWithProbesAtV1(t, memory, probes, time.Now().UTC().Add(-2*time.Second))
}

func maintenanceFacadeOpeningWithProbesAtV1(t *testing.T, memory uint16, probes *runtimepolicy.ProbesV1, setupNow time.Time) ([]byte, releaseMaintenanceFixture) {
	fixture := newReleaseMaintenanceFixtureWithProbesAt(t, setupNow, probes)
	settings, err := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000800000000102012a382a390410012c0020001e0001000100000000")
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(settings[53:55], memory)
	rows := [5][]byte{fixture.current.VerifyRequest, fixture.current.ActivationRecord, fixture.current.RecipientRequest, fixture.current.RecipientPrivate, settings}
	ordered := [5][]byte{rows[4], rows[0], rows[1], rows[2], rows[3]}
	request := make([]byte, 32)
	copy(request, "KPO1")
	request[4], request[5] = 1, 2
	for i := 0; i < 3; i++ {
		binary.BigEndian.PutUint32(request[12+4*i:], uint32(len(ordered[i])))
	}
	binary.BigEndian.PutUint16(request[24:], uint16(len(ordered[3])))
	binary.BigEndian.PutUint16(request[26:], uint16(len(ordered[4])))
	for _, row := range ordered {
		request = append(request, row...)
	}
	binary.BigEndian.PutUint32(request[8:], uint32(len(request)))
	t.Cleanup(func() { clear(request) })
	testAndroidResetV1()
	testAndroidCaptureV1(t, rows)
	return request, fixture
}

func TestMaintenanceFacadeV1VerifiedCandidateMaterializeAndRelease(t *testing.T) {
	for _, release := range []bool{false, true} {
		name := "materialize"
		if release {
			name = "release"
		}
		t.Run(name, func(t *testing.T) {
			request, fixture := maintenanceFacadeOpeningWithFixtureV1(t)
			next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase, Now: time.Now().UTC(), ValidFor: 12 * time.Hour, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir})
			if err != nil {
				t.Fatal(err)
			}
			testMaintenanceCanonicalCandidateV1(t, request, next.Artifact, release, nil)
			clear(next.Artifact)
		})
	}
}

func TestMaintenanceFacadeV1CanonicalOpenAndRetirement(t *testing.T) {
	testMaintenanceCanonicalOpenLifecycleV1(t, maintenanceFacadeOpeningFixtureV1(t))
}
func TestMaintenanceFacadeV1RejectsDifferentCapturedMaterialAndSettings(t *testing.T) {
	for _, settings := range []bool{true, false} {
		t.Run(fmt.Sprint(settings), func(t *testing.T) {
			request := maintenanceFacadeOpeningFixtureV1(t)
			if settings {
				binary.BigEndian.PutUint16(request[32+53:32+55], 80)
			} else {
				request[len(request)-1] ^= 1
			}
			testMaintenanceCanonicalCaptureRefusalV1(t, request, 22, 1)
		})
	}
}
func TestMaintenanceFacadeV1InvalidBudgetPrecedesCaptureAllocation(t *testing.T) {
	request := maintenanceFacadeOpeningFixtureV1(t)
	// One MiB is below the canonical forty-MiB minimum. The parser must
	// refuse it without asking the retained capture to allocate or copy.
	binary.BigEndian.PutUint16(request[32+53:32+55], 1)
	testMaintenanceCanonicalCaptureRefusalV1(t, request, 2, 0)
}
func TestMaintenanceFacadeV1DirectBackingAndMalformedOpening(t *testing.T) {
	testMaintenanceCanonicalRefusalsV1(t)
}
