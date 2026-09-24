//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package selfhost

import (
	"bytes"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"testing"
)

func TestTask7SignedRoundTripReverifiesAndWipesFixtureBuffers(t *testing.T) {
	issued, request, private, now, _ := resourceRecipientFixture(t, servicesForIssuanceV3())
	_, _, resolver, opener, err := liveRecipientProvidersWithResourceMode(issued.Artifact, now, 1, request, private, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Destroy()
	activation, err := liveActivationRequestWithResourceMode(issued.Artifact, now, lifecycle.VerifiedState{}, resolver, opener, liveResourceTypedFirstV1)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := profile.VerifyInitialActivationAdmission(activation)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Destroy()
	owner, err := NewLiveMaintenanceAdmissionForRecipient(issued.Artifact, now, admitted.CurrentState(), request, private,
		LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Destroy()
	// Installed owners reserve for the actual current input, not a future
	// maximum-sized artifact. Recreate that genuine constructor boundary.
	workspace, err := maintenanceInputWorkspaceV1(issued.Artifact, owner.limits)
	if err != nil {
		t.Fatal(err)
	}
	limits := owner.limits
	limits.OwnedBudgetBytes = owner.Bounds().RetainedBytes + workspace
	bounded, err := NewLiveMaintenanceAdmissionForRecipient(issued.Artifact, now, admitted.CurrentState(), request, private, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer bounded.Destroy()
	owner = bounded
	var sent, received []byte
	n, err := owner.Task7FixtureSignedRoundTripV1(now, func(b []byte) ([]byte, error) { sent = b; received = bytes.Clone(b); return received, nil })
	if err != nil || n != len(issued.Artifact) {
		t.Fatal("valid signed round trip rejected", n, err)
	}
	if !bytes.Equal(sent, make([]byte, len(sent))) || !bytes.Equal(received, make([]byte, len(received))) {
		t.Fatal("fixture buffers not wiped")
	}
	if !bytes.Equal(owner.artifact, issued.Artifact) {
		t.Fatal("borrowed owner artifact overwritten")
	}
	// Corrupt the retained input deliberately: byte equality alone must not pass.
	owner.artifact[len(owner.artifact)/2] ^= 1
	_, err = owner.Task7FixtureSignedRoundTripV1(now, func(b []byte) ([]byte, error) { return bytes.Clone(b), nil })
	if err == nil {
		t.Fatal("round trip bypassed fresh cryptographic verification")
	}
}
