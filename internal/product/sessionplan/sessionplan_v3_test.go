// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
)

func fixtureRequestV3(t *testing.T) RequestV2 {
	t.Helper()
	r := fixtureRequestV2(t)
	r.RuntimePolicy.SchemaVersion = runtimepolicy.SchemaVersionV3
	r.RuntimePolicy.Services = &runtimepolicy.ServicesV1{Version: 1, Update: &runtimepolicy.UpdateV1{
		URL: "https://updates.example/profile", ProfileID: r.Profile.ProfileID, MaxArtifactBytes: 65536,
		TimeoutMillis: 1000, MinCheckIntervalSeconds: 60,
	}}
	bindPolicyV3(t, &r)
	return r
}

func bindPolicyV3(t *testing.T, r *RequestV2) {
	t.Helper()
	var err error
	r.RuntimePolicy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestRuntimeAt(r.RuntimePolicy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.Profile.Policy, err = runtimepolicy.EncodeRuntimeAt(r.RuntimePolicy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestV3PlanRetainsCompleteSignedPolicyAndRelayParity(t *testing.T) {
	r := fixtureRequestV3(t)
	now := time.Now()
	plan, err := BuildV2At(r, now)
	if err != nil {
		t.Fatalf("signed V3 plan rejected: %v", err)
	}
	if !bytes.Equal(plan.runtimePolicyBytes, r.Profile.Policy) || plan.RuntimePolicyDigest != sha256.Sum256(r.Profile.Policy) {
		t.Fatal("plan lost exact signed V3 bytes")
	}
	policy, err := plan.RuntimePolicyAt(now)
	if err != nil || !reflect.DeepEqual(policy.Services, r.RuntimePolicy.Services) {
		t.Fatalf("retained services unavailable: %v", err)
	}
	policy.Services.Update.TimeoutMillis++
	again, err := plan.RuntimePolicyAt(now)
	if err != nil || again.Services.Update.TimeoutMillis != 1000 {
		t.Fatal("retained authority aliased caller")
	}
	preface, err := NewRelayAdmissionPrefaceV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeRelayAdmissionPrefaceV1(preface)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRelayAdmissionPrefaceV1(wire)
	if err != nil {
		t.Fatal(err)
	}
	authority := RelayAuthorityV2{ProfileContentID: r.Profile.ContentID, ProfileGeneration: r.Profile.Generation,
		ValidFrom: r.Profile.ValidFrom, ValidUntil: r.Profile.ValidUntil, RuntimePolicy: r.RuntimePolicy,
		StrategyIDs: r.Profile.StrategyIDs, RelayIDs: r.Profile.RelayIDs}
	rebuilt, err := BuildRelayV2At(authority, decoded, now)
	profileBytes, profileErr := envelope.EncodeCanonicalProfileV1(r.Profile)
	defer clear(profileBytes)
	clientFacts, clientOK := plan.ConstructionFactsV2()
	relayFacts, relayOK := rebuilt.ConstructionFactsV2()
	if profileErr != nil || !clientOK || !relayOK || clientFacts.ProfileBytes != uint32(len(profileBytes)) || relayFacts.ProfileBytes != envelope.MaxPayloadBytes || relayFacts.ProxyBufferBytes != clientFacts.ProxyBufferBytes {
		t.Fatal("builder provenance diverged")
	}
	// Conservative relay sizing metadata is not part of wire/digest authority.
	rebuilt.admittedProfileBytes = plan.admittedProfileBytes
	if err != nil || !reflect.DeepEqual(rebuilt, plan) {
		t.Fatalf("relay parity failed: %v", err)
	}
	for _, mode := range []string{"service-substitution", "downgrade", "digest-tamper"} {
		t.Run(mode, func(t *testing.T) {
			changed := authority.Clone()
			claim := decoded.Clone()
			switch mode {
			case "service-substitution":
				changed.RuntimePolicy.Services.Update.TimeoutMillis++
			case "downgrade":
				changed.RuntimePolicy.SchemaVersion = 2
				changed.RuntimePolicy.Services = nil
			case "digest-tamper":
				claim.PlanDigest[0] ^= 1
			}
			changed.RuntimePolicy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestRuntimeAt(changed.RuntimePolicy, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BuildRelayV2At(changed, claim, now); err == nil {
				t.Fatal("different relay authority admitted caller digest")
			}
		})
	}
}

func TestV3PlanRejectsServiceTamperSubstitutionAndProfileMismatch(t *testing.T) {
	for _, mode := range []string{"stale-digest", "different-signed-services", "profile-mismatch", "downgrade"} {
		t.Run(mode, func(t *testing.T) {
			r := fixtureRequestV3(t)
			var err error
			switch mode {
			case "stale-digest":
				r.RuntimePolicy.Services.Update.TimeoutMillis++
			case "different-signed-services":
				r.RuntimePolicy.Services.Update.TimeoutMillis++
				r.RuntimePolicy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV3(r.RuntimePolicy)
			case "profile-mismatch":
				r.RuntimePolicy.Services.Update.ProfileID = "profiles.other"
				bindPolicyV3(t, &r)
			case "downgrade":
				r.RuntimePolicy.SchemaVersion = 2
				r.RuntimePolicy.Services = nil
				r.RuntimePolicy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV2(r.RuntimePolicy)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BuildV2(r); err == nil {
				t.Fatal("unsigned or mismatched service authority admitted")
			}
		})
	}
}
