// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package strategy

import (
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
)

func admitted() lifecycle.State {
	return lifecycle.State{Status: lifecycle.Admitted, ProfileID: "profile-1", Scope: "device", EvidenceReference: "evidence-1", Generation: 1}
}
func candidate(family string) Candidate {
	return Candidate{Family: family, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 3}
}
func validRequest() Request {
	d := carrierreview.DefaultDescriptors()
	s := admitted()
	return Request{Lifecycle: s, Policy: Policy{Version: Version, ProfileID: s.ProfileID, Scope: s.Scope, EvidenceReference: s.EvidenceReference, Generation: s.Generation, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 3, Permitted: []Candidate{candidate(d[0].Family), candidate(d[4].Family)}}, Client: Client{SupportedVersion: Version, SupportedFamilies: []string{d[0].Family, d[4].Family}, Capabilities: []string{"cap-a"}, SafetyFloor: 2, PrivacyFloor: 3}}
}

func TestSelectUsesProfileOrderAndIsDeterministic(t *testing.T) {
	req := validRequest()
	want, err := Select(req)
	if err != nil {
		t.Fatal(err)
	}
	if want.Outcome != OutcomeSelected || want.SelectedFamily != req.Policy.Permitted[0].Family || want.Reason != ReasonSelected {
		t.Fatalf("result=%+v", want)
	}
	for i := 0; i < 20; i++ {
		got, err := Select(req)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("repeat=%+v err=%v", got, err)
		}
	}
}

func TestManualPreferenceIsConstrained(t *testing.T) {
	req := validRequest()
	req.ManualPreference = req.Policy.Permitted[1].Family
	got, err := Select(req)
	if err != nil || got.SelectedFamily != req.ManualPreference {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	req.ManualPreference = "unlisted"
	if got, err = Select(req); err == nil || got != (Result{}) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	req = validRequest()
	req.Client.SupportedFamilies = req.Client.SupportedFamilies[:1]
	req.ManualPreference = req.Policy.Permitted[1].Family
	if got, err = Select(req); err == nil || got != (Result{}) {
		t.Fatalf("unsupported preference got=%+v err=%v", got, err)
	}
}

func TestNoSafeCandidateIsExplicitlyBlocked(t *testing.T) {
	req := validRequest()
	req.Client.SafetyFloor = 1
	got, err := Select(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != OutcomeBlocked || got.SelectedFamily != "" || got.Reason != ReasonNoSafe {
		t.Fatalf("got=%+v", got)
	}
	if (Result{}).Outcome == OutcomeSelected {
		t.Fatal("zero value must not be selected")
	}
}

func TestCapabilitiesAndCandidateFloors(t *testing.T) {
	req := validRequest()
	req.Policy.Permitted[0].RequiredCapabilities = []string{"missing"}
	got, err := Select(req)
	if err != nil || got.SelectedFamily != req.Policy.Permitted[1].Family {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	req = validRequest()
	req.Policy.Permitted[0].MinimumPrivacyFloor = 4
	got, err = Select(req)
	if err != nil || got.SelectedFamily != req.Policy.Permitted[1].Family {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestRejectsNonAdmittedAndMalformedInputs(t *testing.T) {
	statuses := []lifecycle.Status{"", lifecycle.Absent, lifecycle.Superseded, lifecycle.Revoked, lifecycle.Disabled, "future"}
	for _, status := range statuses {
		req := validRequest()
		req.Lifecycle.Status = status
		if got, err := Select(req); err == nil || got != (Result{}) {
			t.Fatalf("status=%q got=%+v err=%v", status, got, err)
		}
	}
	cases := []func(*Request){
		func(r *Request) { r.Lifecycle.ProfileID = "" }, func(r *Request) { r.Lifecycle.Generation = 0 },
		func(r *Request) { r.Policy.ProfileID = "" }, func(r *Request) { r.Policy.ProfileID = "other" },
		func(r *Request) { r.Policy.Scope = "" }, func(r *Request) { r.Policy.Scope = "other" },
		func(r *Request) { r.Policy.EvidenceReference = "" }, func(r *Request) { r.Policy.EvidenceReference = "other" },
		func(r *Request) { r.Policy.Generation = 0 }, func(r *Request) { r.Lifecycle.Generation++ },
		func(r *Request) { r.Policy.Version = "future" }, func(r *Request) { r.Client.SupportedVersion = "future" },
		func(r *Request) { r.Policy.Permitted = nil }, func(r *Request) { r.Policy.Permitted = append(r.Policy.Permitted, r.Policy.Permitted[0]) },
		func(r *Request) { r.Policy.Permitted[0].Family = "unknown" }, func(r *Request) { r.Client.SupportedFamilies = nil },
		func(r *Request) { r.Client.Capabilities = []string{"x", "x"} }, func(r *Request) { r.Policy.MinimumSafetyFloor = 0 },
	}
	for i, mutate := range cases {
		req := validRequest()
		mutate(&req)
		if got, err := Select(req); err == nil || got != (Result{}) {
			t.Fatalf("case %d got=%+v err=%v", i, got, err)
		}
	}
}

func TestCarrierReviewIsASafetyCeiling(t *testing.T) {
	policyFamilies := []string{
		carrierreview.FamilyDNSSurvival,
		carrierreview.FamilyExperimentalUDPQUIC,
		carrierreview.FamilyDomesticMediaRisk,
		carrierreview.FamilyUnsafeControl,
		"unknown",
	}
	for _, family := range policyFamilies {
		req := validRequest()
		req.Policy.Permitted[0].Family = family
		if got, err := Select(req); err == nil || got != (Result{}) {
			t.Fatalf("policy family=%q got=%+v err=%v", family, got, err)
		}
	}
	req := validRequest()
	req.Client.SupportedFamilies = append(req.Client.SupportedFamilies, "unknown")
	if got, err := Select(req); err == nil || got != (Result{}) {
		t.Fatalf("unknown client family got=%+v err=%v", got, err)
	}
}

func TestRejectedFutureInputCannotOverwriteLastSafeResult(t *testing.T) {
	req := validRequest()
	lastSafe, err := Select(req)
	if err != nil {
		t.Fatal(err)
	}
	future := req
	future.Policy.Version = "permitted-fallback-v2"
	if got, err := Select(future); err == nil || got != (Result{}) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if lastSafe.Outcome != OutcomeSelected || lastSafe.SelectedFamily == "" {
		t.Fatalf("last safe changed: %+v", lastSafe)
	}
}

func TestRejectsOverlongInputsWithoutEcho(t *testing.T) {
	secret := "SECRET-CANARY-" + strings.Repeat("x", maxBindingBytes+1)
	cases := []struct {
		name   string
		mutate func(*Request)
	}{
		{"lifecycle status", func(r *Request) { r.Lifecycle.Status = lifecycle.Status(secret) }},
		{"lifecycle profile", func(r *Request) { r.Lifecycle.ProfileID = secret }},
		{"lifecycle scope", func(r *Request) { r.Lifecycle.Scope = secret }},
		{"lifecycle evidence", func(r *Request) { r.Lifecycle.EvidenceReference = secret }},
		{"policy version", func(r *Request) { r.Policy.Version = secret }},
		{"policy profile", func(r *Request) { r.Policy.ProfileID = secret }},
		{"policy scope", func(r *Request) { r.Policy.Scope = secret }},
		{"policy evidence", func(r *Request) { r.Policy.EvidenceReference = secret }},
		{"client version", func(r *Request) { r.Client.SupportedVersion = secret }},
		{"client family", func(r *Request) { r.Client.SupportedFamilies[0] = secret }},
		{"client capability", func(r *Request) { r.Client.Capabilities[0] = secret }},
		{"candidate family", func(r *Request) { r.Policy.Permitted[0].Family = secret }},
		{"required capability", func(r *Request) { r.Policy.Permitted[0].RequiredCapabilities = []string{secret} }},
		{"manual preference", func(r *Request) { r.ManualPreference = secret }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mutate(&req)
			assertRejectedWithoutEcho(t, req, secret)
		})
	}
}

func TestRejectsSecretLikeInputsWithoutEcho(t *testing.T) {
	secret := "TOKEN-secret-canary"
	cases := []struct {
		name   string
		mutate func(*Request)
	}{
		{"policy binding", func(r *Request) { r.Policy.EvidenceReference = secret }},
		{"policy version", func(r *Request) { r.Policy.Version = secret }},
		{"client family", func(r *Request) { r.Client.SupportedFamilies[0] = secret }},
		{"candidate family", func(r *Request) { r.Policy.Permitted[0].Family = secret }},
		{"manual preference", func(r *Request) { r.ManualPreference = secret }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.mutate(&req)
			assertRejectedWithoutEcho(t, req, secret)
		})
	}
}

func assertRejectedWithoutEcho(t *testing.T, req Request, secret string) {
	t.Helper()
	got, err := Select(req)
	if err == nil || got != (Result{}) {
		t.Fatalf("expected zero result and error, got=%+v err=%v", got, err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(got.Outcome, secret) ||
		strings.Contains(got.SelectedFamily, secret) || strings.Contains(got.Reason, secret) {
		t.Fatalf("rejection echoed input: got=%+v err=%q", got, err)
	}
}
