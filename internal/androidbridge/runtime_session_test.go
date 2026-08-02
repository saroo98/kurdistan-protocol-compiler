// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
)

func TestRuntimeSessionReverifiesActivatedProfileAndNarrowsPolicy(t *testing.T) {
	request, activation := runtimeFixture(t)
	registry := HandleRegistry{}
	handle, snapshot, code := OpenRuntimeSession(
		&registry,
		mustRuntimeOpenRequest(t, request, activation, RuntimePolicyRequest{
			SelectionMode: RuntimeSelectionAutomatic,
			PerAppMode:    RuntimePerAppIncludeOnly,
			Packages:      []string{"org.kurdistanvpn.app.internal"},
			IPMode:        RuntimeIPAuto,
			DNSMode:       RuntimeDNSInternal,
			MTU:           1400,
		}),
		fixtureVerificationEnvironment{},
	)
	if code != CodeOK {
		t.Fatalf("open code=%v", code)
	}
	defer registry.Free(handle)
	if snapshot.Generation != activation.Profile.Generation || snapshot.MTU != 1400 ||
		snapshot.SelectionMode != RuntimeSelectionAutomatic ||
		snapshot.PerAppMode != RuntimePerAppIncludeOnly ||
		!snapshot.LoopbackOnly || snapshot.PlanDigest == ([32]byte{}) ||
		len(snapshot.Packages) != 1 || snapshot.Packages[0] != "org.kurdistanvpn.app.internal" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	payload := []byte("authority-bound-round-trip")
	roundTripped, code := RuntimeSessionRoundTrip(
		&registry,
		handle,
		payload,
		func(value []byte) ([]byte, ErrorCode) { return bytes.Clone(value), CodeOK },
	)
	if code != CodeOK || !bytes.Equal(roundTripped, payload) {
		t.Fatalf("round trip code=%v value=%q", code, roundTripped)
	}
}

func TestRuntimeSessionFailsClosedOnAuthorityOrPolicyMutation(t *testing.T) {
	request, activation := runtimeFixture(t)
	valid := RuntimePolicyRequest{
		SelectionMode: RuntimeSelectionAutomatic,
		PerAppMode:    RuntimePerAppAllApps,
		IPMode:        RuntimeIPAuto,
		DNSMode:       RuntimeDNSInternal,
		MTU:           1500,
	}
	cases := []struct {
		name        string
		request     []byte
		environment VerificationEnvironment
	}{
		{
			name:    "missing trust",
			request: mustRuntimeOpenRequest(t, request, activation, valid),
		},
		{
			name: "forged activation receipt",
			request: func() []byte {
				forged := activation
				forged.State.Generation++
				return mustRuntimeOpenRequest(t, request, forged, valid)
			}(),
			environment: fixtureVerificationEnvironment{},
		},
		{
			name: "forbidden manual strategy",
			request: mustRuntimeOpenRequest(t, request, activation, RuntimePolicyRequest{
				SelectionMode:    RuntimeSelectionManual,
				ManualStrategyID: "strategy.not-permitted",
				PerAppMode:       RuntimePerAppAllApps,
				IPMode:           RuntimeIPAuto,
				DNSMode:          RuntimeDNSInternal,
				MTU:              1500,
			}),
			environment: fixtureVerificationEnvironment{},
		},
		{
			name: "unsupported external dns",
			request: mustRuntimeOpenRequest(t, request, activation, RuntimePolicyRequest{
				SelectionMode: RuntimeSelectionAutomatic,
				PerAppMode:    RuntimePerAppAllApps,
				IPMode:        RuntimeIPAuto,
				DNSMode:       RuntimeDNSCustom,
				CustomDNS:     "1.1.1.1",
				MTU:           1500,
			}),
			environment: fixtureVerificationEnvironment{},
		},
		{
			name: "inert lan widening",
			request: mustRuntimeOpenRequest(t, request, activation, RuntimePolicyRequest{
				SelectionMode: RuntimeSelectionAutomatic,
				PerAppMode:    RuntimePerAppAllApps,
				IPMode:        RuntimeIPAuto,
				DNSMode:       RuntimeDNSInternal,
				MTU:           1500,
				AllowLAN:      true,
			}),
			environment: fixtureVerificationEnvironment{},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			registry := HandleRegistry{}
			if handle, _, code := OpenRuntimeSession(&registry, test.request, test.environment); code == CodeOK || handle != 0 {
				t.Fatalf("accepted handle=%d code=%v", handle, code)
			}
		})
	}
}

func TestRuntimeSessionHandleRejectsReplayAndUseAfterClose(t *testing.T) {
	request, activation := runtimeFixture(t)
	registry := HandleRegistry{}
	handle, _, code := OpenRuntimeSession(
		&registry,
		mustRuntimeOpenRequest(t, request, activation, RuntimePolicyRequest{
			SelectionMode: RuntimeSelectionAutomatic,
			PerAppMode:    RuntimePerAppAllApps,
			IPMode:        RuntimeIPAuto,
			DNSMode:       RuntimeDNSInternal,
			MTU:           1500,
		}),
		fixtureVerificationEnvironment{},
	)
	if code != CodeOK {
		t.Fatalf("open code=%v", code)
	}
	if code := registry.Free(handle); code != CodeOK {
		t.Fatalf("free code=%v", code)
	}
	if _, code := RuntimeSessionRoundTrip(&registry, handle, []byte{1}, func(v []byte) ([]byte, ErrorCode) {
		return v, CodeOK
	}); code != CodeAlreadyClosed {
		t.Fatalf("use-after-close code=%v", code)
	}
}

func runtimeFixture(t *testing.T) ([]byte, profile.ActivationRecord) {
	t.Helper()
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := EncodeVerifyRequest(VerifyRequest{
		Ingress: envelope.IngressFile,
		Class:   spec.Class,
		Parts:   [][]byte{artifact},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, code := VerifyAndPreview(request, fixtureVerificationEnvironment{})
	if code != CodeOK {
		t.Fatalf("verify code=%v", code)
	}
	digest := sha256.Sum256(verified.Verified.ExactSignedObject)
	receipt := lifecycle.VerifiedReceipt{
		ContentID:                   verified.Verified.Profile.ContentID,
		ProviderID:                  verified.Verified.Profile.ProviderID,
		LineageID:                   verified.Verified.Profile.LineageID,
		AuthenticatedArtifactSHA256: bytesToHex(digest[:]),
		RootEpoch:                   verified.Verified.Profile.RootEpoch,
		RevocationEpoch:             verified.Verified.Profile.RevocationEpoch,
		RecipientEpoch:              verified.Verified.Metadata.RecipientEpoch,
	}
	return request, profile.ActivationRecord{
		Artifact:     bytes.Clone(verified.Verified.ExactArtifact),
		SignedObject: bytes.Clone(verified.Verified.ExactSignedObject),
		Profile:      verified.Verified.Profile,
		State: lifecycle.VerifiedState{
			State: lifecycle.State{
				Status:            lifecycle.Admitted,
				ProfileID:         verified.Verified.Profile.ProfileID,
				Scope:             verified.Verified.Profile.RevocationScope,
				EvidenceReference: receipt.AuthenticatedArtifactSHA256,
				Generation:        verified.Verified.Profile.Generation,
			},
			Receipt: receipt,
		},
	}
}

func mustRuntimeOpenRequest(
	t *testing.T,
	verifyRequest []byte,
	record profile.ActivationRecord,
	policy RuntimePolicyRequest,
) []byte {
	t.Helper()
	activation, err := EncodeActivationRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRuntimeOpenRequest(RuntimeOpenRequest{
		VerifyRequest:    verifyRequest,
		ActivationRecord: activation,
		Policy:           policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bytesToHex(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for index, item := range value {
		out[index*2] = digits[item>>4]
		out[index*2+1] = digits[item&0x0f]
	}
	return string(out)
}
