// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaydescriptor

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/strategy"
)

func validRequest(t *testing.T) Request {
	t.Helper()
	s := lifecycle.State{Status: lifecycle.Admitted, ProfileID: "profile-1", Scope: "device", EvidenceReference: "evidence-1", Generation: 7}
	sr := strategy.Request{
		Lifecycle: s,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: s.ProfileID, Scope: s.Scope, EvidenceReference: s.EvidenceReference, Generation: s.Generation,
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			Permitted: []strategy.Candidate{{Family: carrierreview.FamilyHTTPSLikeTCP, RequiredCapabilities: []string{"cap-a"}, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2}},
		},
		Client: strategy.Client{
			SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
			Capabilities: []string{"cap-a"}, SafetyFloor: 2, PrivacyFloor: 2,
		},
	}
	selected, err := strategy.Select(sr)
	if err != nil {
		t.Fatal(err)
	}
	d := Descriptor{
		Version: Version, DescriptorID: "relay-1", ProfileID: s.ProfileID, Scope: s.Scope,
		EvidenceReference: s.EvidenceReference, Generation: s.Generation, Family: selected.SelectedFamily,
		ClientID: "client-1", ClientCapabilities: []string{"cap-a"},
		EndpointReference: "relayref:node_A7", NotBefore: 90, ExpiresAt: 110,
		Metadata: []Metadata{{Name: "region", Value: "opaque-region"}},
	}
	return Request{
		Version: Version, StrategyRequest: sr, ClaimedResult: selected, EvaluationTime: 100,
		Client: ClientBinding{ID: "client-1"},
		Policy: Policy{
			Version: Version, ProfileID: s.ProfileID, Scope: s.Scope, EvidenceReference: s.EvidenceReference, Generation: s.Generation,
			FallbackPolicy: sr.Policy, SelectedFamily: selected.SelectedFamily, ClientCapabilities: []string{"cap-a"},
			AuthorizedClientIDs: []string{"client-1"}, AuthorizedDescriptors: []Descriptor{d},
		},
		Revocation: RevocationState{
			Version: Version, Complete: true, ProfileID: s.ProfileID, Scope: s.Scope,
			EvidenceReference: s.EvidenceReference, Generation: s.Generation, EvaluatedAt: 100,
		},
		Descriptors: []Descriptor{d},
	}
}

func TestAdmitDeterministicBoundAndNonMutating(t *testing.T) {
	req := validRequest(t)
	before := validRequest(t)
	first, err := Admit(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Admit(req)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated admission differs: first=%+v second=%+v err=%v", first, second, err)
	}
	if !reflect.DeepEqual(req, before) {
		t.Fatal("Admit mutated caller input")
	}
	if first.Version != Version || first.ProfileID != req.StrategyRequest.Lifecycle.ProfileID || first.ClientID != req.Client.ID ||
		first.SelectedFamily != req.ClaimedResult.SelectedFamily || len(first.Descriptors) != 1 ||
		first.Descriptors[0].DescriptorID != "relay-1" || first.Descriptors[0].EndpointReference != req.Descriptors[0].EndpointReference {
		t.Fatalf("unexpected admission: %+v", first)
	}
	first.Descriptors[0].DescriptorID = "changed"
	if req.Descriptors[0].DescriptorID != "relay-1" {
		t.Fatal("output aliases caller input")
	}
}

func TestAdmitRecomputesExactStrategyProof(t *testing.T) {
	tests := map[string]func(*Request){
		"detached result":   func(r *Request) { r.ClaimedResult.SelectedFamily = carrierreview.FamilyRelayBridgeRotation },
		"altered lifecycle": func(r *Request) { r.StrategyRequest.Lifecycle.Generation++ },
		"altered policy":    func(r *Request) { r.StrategyRequest.Policy.MinimumSafetyFloor++ },
		"altered family order": func(r *Request) {
			r.StrategyRequest.Policy.Permitted = append(r.StrategyRequest.Policy.Permitted, strategy.Candidate{Family: carrierreview.FamilyRelayBridgeRotation, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2})
			r.StrategyRequest.Policy.Permitted[0], r.StrategyRequest.Policy.Permitted[1] = r.StrategyRequest.Policy.Permitted[1], r.StrategyRequest.Policy.Permitted[0]
		},
		"altered capabilities": func(r *Request) { r.StrategyRequest.Client.Capabilities = nil },
		"altered floor":        func(r *Request) { r.StrategyRequest.Client.SafetyFloor = 1 },
		"altered preference":   func(r *Request) { r.StrategyRequest.ManualPreference = carrierreview.FamilyRelayBridgeRotation },
		"blocked result": func(r *Request) {
			r.StrategyRequest.Client.SafetyFloor = 1
			r.ClaimedResult = strategy.Result{Outcome: strategy.OutcomeBlocked, Reason: strategy.ReasonNoSafe}
		},
		"zero result":     func(r *Request) { r.ClaimedResult = strategy.Result{} },
		"unknown outcome": func(r *Request) { r.ClaimedResult.Outcome = "unknown" },
		"selector error":  func(r *Request) { r.StrategyRequest.Policy.Version = "future" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			got, err := Admit(req)
			if err == nil || !reflect.DeepEqual(got, Admission{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestAdmitRejectsPolicyClientAndDescriptorSubstitution(t *testing.T) {
	tests := map[string]func(*Request){
		"fallback policy":       func(r *Request) { r.Policy.FallbackPolicy.MinimumPrivacyFloor++ },
		"profile":               func(r *Request) { r.Policy.ProfileID = "profile-2" },
		"generation":            func(r *Request) { r.Policy.Generation++ },
		"family":                func(r *Request) { r.Policy.SelectedFamily = carrierreview.FamilyRelayBridgeRotation },
		"capability order":      func(r *Request) { r.Policy.ClientCapabilities = []string{"cap-b"} },
		"unauthorized client":   func(r *Request) { r.Client.ID = "client-2" },
		"descriptor client":     func(r *Request) { r.Descriptors[0].ClientID = "client-2" },
		"descriptor capability": func(r *Request) { r.Descriptors[0].ClientCapabilities = []string{"cap-b"} },
		"descriptor profile":    func(r *Request) { r.Descriptors[0].ProfileID = "profile-2" },
		"descriptor generation": func(r *Request) { r.Descriptors[0].Generation++ },
		"descriptor family":     func(r *Request) { r.Descriptors[0].Family = carrierreview.FamilyRelayBridgeRotation },
		"descriptor not exact":  func(r *Request) { r.Descriptors[0].EndpointReference = "relayref:node_B8" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			got, err := Admit(req)
			if err == nil || !reflect.DeepEqual(got, Admission{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestAdmitTimeVersionRevocationAndAllOrNothing(t *testing.T) {
	tests := map[string]func(*Request){
		"zero version":             func(r *Request) { r.Version = "" },
		"older version":            func(r *Request) { r.Version = "offline-relay-descriptor-admission-v0" },
		"newer version":            func(r *Request) { r.Version = "offline-relay-descriptor-admission-v2" },
		"zero time":                func(r *Request) { r.EvaluationTime = 0 },
		"before":                   func(r *Request) { r.EvaluationTime, r.Revocation.EvaluatedAt = 89, 89 },
		"expiry boundary":          func(r *Request) { r.EvaluationTime, r.Revocation.EvaluatedAt = 110, 110 },
		"reversed window":          func(r *Request) { r.Descriptors[0].NotBefore = 120 },
		"incomplete revocation":    func(r *Request) { r.Revocation.Complete = false },
		"stale revocation":         func(r *Request) { r.Revocation.Generation-- },
		"revocation time mismatch": func(r *Request) { r.Revocation.EvaluatedAt-- },
		"revoked":                  func(r *Request) { r.Revocation.RevokedDescriptorIDs = []string{"relay-1"} },
		"duplicate requested":      func(r *Request) { r.Descriptors = append(r.Descriptors, r.Descriptors[0]) },
		"duplicate authorized": func(r *Request) {
			r.Policy.AuthorizedDescriptors = append(r.Policy.AuthorizedDescriptors, r.Policy.AuthorizedDescriptors[0])
		},
		"duplicate client": func(r *Request) { r.Policy.AuthorizedClientIDs = []string{"client-1", "client-1"} },
		"bad second descriptor": func(r *Request) {
			second := r.Descriptors[0]
			second.DescriptorID = "relay-2"
			second.EndpointReference = "opaque-second"
			r.Descriptors = append(r.Descriptors, second)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			got, err := Admit(req)
			if err == nil || !reflect.DeepEqual(got, Admission{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestAdmitBoundsOrderAndNonEchoingErrors(t *testing.T) {
	req := validRequest(t)
	second := req.Descriptors[0]
	second.DescriptorID = "relay-2"
	second.EndpointReference = "relayref:node_B8"
	req.Policy.AuthorizedDescriptors = append(req.Policy.AuthorizedDescriptors, second)
	req.Descriptors = []Descriptor{second, req.Descriptors[0]}
	got, err := Admit(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Descriptors[0].DescriptorID != "relay-2" || got.Descriptors[1].DescriptorID != "relay-1" {
		t.Fatalf("input order not preserved: %+v", got.Descriptors)
	}

	secret := "SECRET-ATTACKER-CONTROLLED"
	req = validRequest(t)
	req.Descriptors[0].EndpointReference = secret + strings.Repeat("x", maxReferenceBytes)
	got, err = Admit(req)
	if err == nil || !reflect.DeepEqual(got, Admission{}) || strings.Contains(err.Error(), secret) {
		t.Fatalf("got=%+v err=%v", got, err)
	}

	req = validRequest(t)
	req.Policy.AuthorizedClientIDs = make([]string, maxListItems+1)
	for i := range req.Policy.AuthorizedClientIDs {
		req.Policy.AuthorizedClientIDs[i] = "client-" + string(rune('A'+i%26)) + string(rune('a'+i/26))
	}
	if got, err := Admit(req); err == nil || !reflect.DeepEqual(got, Admission{}) {
		t.Fatalf("oversized list got=%+v err=%v", got, err)
	}

	req = validRequest(t)
	req.Descriptors[0].Metadata = make([]Metadata, maxMetadataItems+1)
	if got, err := Admit(req); err == nil || !reflect.DeepEqual(got, Admission{}) {
		t.Fatalf("oversized metadata got=%+v err=%v", got, err)
	}
}

func TestAdmitRejectsInterpretableOrSensitiveEndpointReferences(t *testing.T) {
	secret := "ATTACKER-CONTROLLED"
	tests := map[string]string{
		"URL":             "https://example.invalid/relay",
		"hostname":        "relay.example.invalid",
		"IP":              "192.0.2.1",
		"port":            "relayref:node:443",
		"at sign":         "relayref:user@node",
		"path":            "relayref:group/node",
		"whitespace":      "relayref:node A7",
		"query":           "relayref:node?region=x",
		"fragment":        "relayref:node#fragment",
		"secret marker":   "relayref:client-secret-value",
		"key marker":      "relayref:private_key_value",
		"token marker":    "relayref:access_token_value",
		"password marker": "relayref:password_value",
		"payload marker":  "relayref:payload_value",
		"overlength":      "relayref:" + strings.Repeat("x", maxIdentifierBytes+1),
		"non-prefixed":    secret,
	}
	for name, endpointReference := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			req.Descriptors[0].EndpointReference = endpointReference
			got, err := Admit(req)
			if err == nil || !reflect.DeepEqual(got, Admission{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if strings.Contains(err.Error(), endpointReference) || strings.Contains(err.Error(), secret) {
				t.Fatalf("error echoed caller input: %v", err)
			}
		})
	}
}

func TestAdmitExactStringBoundsAndOneOver(t *testing.T) {
	tests := []struct {
		name  string
		exact int
		apply func(*Request, string)
	}{
		{"descriptor ID", maxIdentifierBytes, func(r *Request, v string) {
			r.Descriptors[0].DescriptorID, r.Policy.AuthorizedDescriptors[0].DescriptorID = v, v
		}},
		{"profile ID", maxReferenceBytes, setProfileID},
		{"scope", maxStrategyIDBytes, setScope},
		{"evidence reference", maxReferenceBytes, setEvidenceReference},
		{"client ID", maxIdentifierBytes, setClientID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exact := strings.Repeat("a", tt.exact)
			req := validRequest(t)
			tt.apply(&req, exact)
			assertAdmission(t, req)

			over := exact + "Z"
			req = validRequest(t)
			tt.apply(&req, over)
			assertStableZeroRejection(t, req, over)
		})
	}

	// Family is also capped at the predecessor's identifier bound, but valid
	// families are a closed, shorter carrier-review enumeration. The exact byte
	// maximum is therefore not semantically valid; the real family is accepted
	// and a one-over attacker value is rejected.
	assertAdmission(t, validRequest(t))
	req := validRequest(t)
	overFamily := strings.Repeat("f", maxStrategyIDBytes+1)
	req.Descriptors[0].Family = overFamily
	assertStableZeroRejection(t, req, overFamily)

	t.Run("endpoint token", func(t *testing.T) {
		exact := "relayref:" + strings.Repeat("r", maxIdentifierBytes)
		req := validRequest(t)
		req.Descriptors[0].EndpointReference = exact
		req.Policy.AuthorizedDescriptors[0].EndpointReference = exact
		assertAdmission(t, req)

		over := exact + "r"
		req = validRequest(t)
		req.Descriptors[0].EndpointReference = over
		assertStableZeroRejection(t, req, over)
	})
}

func TestAdmitExactMetadataBoundsAndOneOver(t *testing.T) {
	t.Run("metadata count", func(t *testing.T) {
		req := validRequest(t)
		metadata := makeMetadata(maxMetadataItems)
		req.Descriptors[0].Metadata = metadata
		req.Policy.AuthorizedDescriptors[0].Metadata = append([]Metadata(nil), metadata...)
		assertAdmission(t, req)

		req = validRequest(t)
		req.Descriptors[0].Metadata = makeMetadata(maxMetadataItems + 1)
		assertStableZeroRejection(t, req, "metadata-over")
	})

	for _, tt := range []struct {
		name  string
		exact int
		apply func(*Metadata, string)
	}{
		{"metadata name", maxIdentifierBytes, func(m *Metadata, v string) { m.Name = v }},
		{"metadata value", maxMetadataBytes, func(m *Metadata, v string) { m.Value = v }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			exact := strings.Repeat("m", tt.exact)
			req := validRequest(t)
			tt.apply(&req.Descriptors[0].Metadata[0], exact)
			tt.apply(&req.Policy.AuthorizedDescriptors[0].Metadata[0], exact)
			assertAdmission(t, req)

			over := exact + "X"
			req = validRequest(t)
			tt.apply(&req.Descriptors[0].Metadata[0], over)
			assertStableZeroRejection(t, req, over)
		})
	}
}

func TestAdmitExactDescriptorAndPolicyListBoundsAndOneOver(t *testing.T) {
	t.Run("requested descriptor count", func(t *testing.T) {
		req := validRequest(t)
		setDescriptorCount(&req, maxDescriptors)
		assertAdmission(t, req)

		req = validRequest(t)
		setRequestedDescriptorCount(&req, maxDescriptors+1)
		assertStableZeroRejection(t, req, "descriptor-over")
	})

	t.Run("authorized descriptor count", func(t *testing.T) {
		req := validRequest(t)
		setAuthorizedDescriptorCount(&req, maxDescriptors)
		assertAdmission(t, req)

		req = validRequest(t)
		setAuthorizedDescriptorCount(&req, maxDescriptors+1)
		assertStableZeroRejection(t, req, "authorized-over")
	})

	t.Run("authorized client list", func(t *testing.T) {
		req := validRequest(t)
		req.Policy.AuthorizedClientIDs = append([]string{req.Client.ID}, distinctIDs("client", maxListItems-1)...)
		assertAdmission(t, req)

		req = validRequest(t)
		req.Policy.AuthorizedClientIDs = append([]string{req.Client.ID}, distinctIDs("client", maxListItems)...)
		assertStableZeroRejection(t, req, "client-list-over")
	})

	t.Run("revocation list", func(t *testing.T) {
		req := validRequest(t)
		req.Revocation.RevokedDescriptorIDs = distinctIDs("revoked", maxListItems)
		assertAdmission(t, req)

		req = validRequest(t)
		req.Revocation.RevokedDescriptorIDs = distinctIDs("revoked", maxListItems+1)
		assertStableZeroRejection(t, req, "revocation-over")
	})
}

func TestAdmitExactCapabilityListBoundsAndOneOver(t *testing.T) {
	t.Run("strategy client and M5 policy capability lists", func(t *testing.T) {
		req := validRequest(t)
		setCapabilities(t, &req, maxListItems, false)
		assertAdmission(t, req)

		req = validRequest(t)
		setCapabilities(t, &req, maxListItems+1, false)
		assertStableZeroRejection(t, req, "capability-over")
	})

	t.Run("candidate required capability list", func(t *testing.T) {
		req := validRequest(t)
		setCapabilities(t, &req, maxListItems, true)
		assertAdmission(t, req)

		req = validRequest(t)
		setCapabilities(t, &req, maxListItems+1, true)
		assertStableZeroRejection(t, req, "required-capability-over")
	})

	t.Run("descriptor capability list", func(t *testing.T) {
		req := validRequest(t)
		setCapabilities(t, &req, maxListItems, false)
		assertAdmission(t, req)

		req = validRequest(t)
		over := distinctIDs("cap", maxListItems+1)
		req.Descriptors[0].ClientCapabilities = over
		assertStableZeroRejection(t, req, "descriptor-capability-over")
	})
}

func TestAdmitFallbackPermittedListBound(t *testing.T) {
	// The M5 structural bound accepts maxListItems at preflight. A full admission
	// cannot contain that many semantically valid entries because Phase 4 permits
	// only the much smaller closed carrier safety ceiling and rejects duplicates.
	req := validRequest(t)
	candidate := req.StrategyRequest.Policy.Permitted[0]
	req.Policy.FallbackPolicy.Permitted = make([]strategy.Candidate, maxListItems)
	for i := range req.Policy.FallbackPolicy.Permitted {
		req.Policy.FallbackPolicy.Permitted[i] = candidate
	}
	if !boundedRequestShape(req) {
		t.Fatal("exact fallback permitted structural bound was rejected")
	}

	req.Policy.FallbackPolicy.Permitted = append(req.Policy.FallbackPolicy.Permitted, candidate)
	if boundedRequestShape(req) {
		t.Fatal("one-over fallback permitted structural bound was accepted")
	}
	assertStableZeroRejection(t, req, "fallback-permitted-over")
}

func assertAdmission(t *testing.T, req Request) Admission {
	t.Helper()
	got, err := Admit(req)
	if err != nil || len(got.Descriptors) == 0 {
		t.Fatalf("expected admission, got=%+v err=%v", got, err)
	}
	return got
}

func assertStableZeroRejection(t *testing.T, req Request, controlled string) {
	t.Helper()
	first, firstErr := Admit(req)
	second, secondErr := Admit(req)
	if firstErr == nil || secondErr == nil || !reflect.DeepEqual(first, Admission{}) || !reflect.DeepEqual(second, Admission{}) {
		t.Fatalf("expected stable zero rejection, first=%+v err=%v second=%+v err=%v", first, firstErr, second, secondErr)
	}
	if firstErr.Error() != secondErr.Error() || (controlled != "" && strings.Contains(firstErr.Error(), controlled)) || !knownCategoricalError(firstErr) {
		t.Fatalf("unstable or echoing error: first=%v second=%v", firstErr, secondErr)
	}
}

func knownCategoricalError(err error) bool {
	for _, category := range []error{ErrInvalidRequest, ErrVersion, ErrStrategyProof, ErrBinding, ErrTime, ErrRevocation, ErrUnauthorized, ErrDescriptor} {
		if errors.Is(err, category) {
			return true
		}
	}
	return false
}

func distinctIDs(prefix string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = fmt.Sprintf("%s-%03d", prefix, i)
	}
	return values
}

func makeMetadata(count int) []Metadata {
	result := make([]Metadata, count)
	for i := range result {
		result[i] = Metadata{Name: fmt.Sprintf("field-%03d", i), Value: "value"}
	}
	return result
}

func descriptorCopies(req Request, count int) []Descriptor {
	result := make([]Descriptor, count)
	for i := range result {
		result[i] = req.Descriptors[0]
		if i > 0 {
			result[i].DescriptorID = fmt.Sprintf("relay-%03d", i)
			result[i].EndpointReference = fmt.Sprintf("relayref:node_%03d", i)
		}
	}
	return result
}

func setDescriptorCount(req *Request, count int) {
	descriptors := descriptorCopies(*req, count)
	req.Descriptors = append([]Descriptor(nil), descriptors...)
	req.Policy.AuthorizedDescriptors = append([]Descriptor(nil), descriptors...)
}

func setRequestedDescriptorCount(req *Request, count int) {
	req.Descriptors = descriptorCopies(*req, count)
}

func setAuthorizedDescriptorCount(req *Request, count int) {
	req.Policy.AuthorizedDescriptors = descriptorCopies(*req, count)
}

func setProfileID(req *Request, value string) {
	req.StrategyRequest.Lifecycle.ProfileID = value
	req.StrategyRequest.Policy.ProfileID = value
	req.Policy.ProfileID = value
	req.Revocation.ProfileID = value
	setDescriptorBinding(req, func(d *Descriptor) { d.ProfileID = value })
	refreshStrategy(req)
}

func setScope(req *Request, value string) {
	req.StrategyRequest.Lifecycle.Scope = value
	req.StrategyRequest.Policy.Scope = value
	req.Policy.Scope = value
	req.Revocation.Scope = value
	setDescriptorBinding(req, func(d *Descriptor) { d.Scope = value })
	refreshStrategy(req)
}

func setEvidenceReference(req *Request, value string) {
	req.StrategyRequest.Lifecycle.EvidenceReference = value
	req.StrategyRequest.Policy.EvidenceReference = value
	req.Policy.EvidenceReference = value
	req.Revocation.EvidenceReference = value
	setDescriptorBinding(req, func(d *Descriptor) { d.EvidenceReference = value })
	refreshStrategy(req)
}

func setClientID(req *Request, value string) {
	req.Client.ID = value
	req.Policy.AuthorizedClientIDs = []string{value}
	setDescriptorBinding(req, func(d *Descriptor) { d.ClientID = value })
}

func setCapabilities(t *testing.T, req *Request, count int, required bool) {
	t.Helper()
	capabilities := distinctIDs("cap", count)
	req.StrategyRequest.Client.Capabilities = capabilities
	if required {
		req.StrategyRequest.Policy.Permitted[0].RequiredCapabilities = append([]string(nil), capabilities...)
	} else {
		req.StrategyRequest.Policy.Permitted[0].RequiredCapabilities = nil
	}
	setDescriptorBinding(req, func(d *Descriptor) { d.ClientCapabilities = append([]string(nil), capabilities...) })
	refreshStrategy(req)
}

func setDescriptorBinding(req *Request, update func(*Descriptor)) {
	for i := range req.Descriptors {
		update(&req.Descriptors[i])
	}
	for i := range req.Policy.AuthorizedDescriptors {
		update(&req.Policy.AuthorizedDescriptors[i])
	}
}

func refreshStrategy(req *Request) {
	req.ClaimedResult, _ = strategy.Select(req.StrategyRequest)
	req.Policy.FallbackPolicy = req.StrategyRequest.Policy
	req.Policy.SelectedFamily = req.ClaimedResult.SelectedFamily
	req.Policy.ClientCapabilities = append([]string(nil), req.StrategyRequest.Client.Capabilities...)
}
