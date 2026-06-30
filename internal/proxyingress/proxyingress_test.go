// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import (
	"context"
	"encoding/json"
	"testing"
)

func TestContractValidationAndHash(t *testing.T) {
	contract := DefaultContract()
	if err := ValidateContract(contract); err != nil {
		t.Fatal(err)
	}
	if contract.ContractHash != ContractHash(contract) {
		t.Fatalf("contract hash unstable")
	}
	contract.Limits.MaxConcurrentRequests = 0
	if err := ValidateContract(contract); err == nil {
		t.Fatalf("unbounded contract accepted")
	}
}

func TestTargetDescriptorValidation(t *testing.T) {
	contract := DefaultContract()
	for _, target := range ValidTargetDescriptors() {
		if err := ValidateTargetDescriptor(target, contract.Limits); err != nil {
			t.Fatalf("valid target rejected: %v", err)
		}
	}
	for _, target := range InvalidTargetDescriptors() {
		if err := ValidateTargetDescriptor(target, contract.Limits); err == nil {
			t.Fatalf("invalid target accepted: %+v", target)
		}
	}
}

func TestTargetDescriptorEndpointPatternsRejected(t *testing.T) {
	contract := DefaultContract()
	cases := []string{"127.0.0.1", "2001:db8::1", "example.com", "https://example.com", "name@example.com"}
	for _, value := range cases {
		target := TargetDescriptor{TargetKind: TargetKindSyntheticName, DescriptorID: value, ServiceClass: "service_echo", AddressClass: "loopback_class"}
		if err := ValidateTargetDescriptor(target, contract.Limits); err == nil {
			t.Fatalf("unsafe target accepted: %s", value)
		}
	}
}

func TestCapabilityAndRuntimeMapping(t *testing.T) {
	contract := DefaultContract()
	mapping := MapCapabilities(contract, DefaultAvailableCapabilities())
	if mapping.Conclusion != "passed" {
		t.Fatalf("capability mapping failed: %+v", mapping)
	}
	missing := MapCapabilities(contract, []string{"stream_open"})
	if missing.Conclusion == "passed" || len(missing.MissingCapabilities) == 0 {
		t.Fatalf("missing capabilities not detected")
	}
	plan, err := BuildRuntimeStreamMappingPlan(ValidRequests()[0], contract)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.RequiresSecureContext || plan.OpenIntent == "" || plan.TargetDescriptorIntent == "" || plan.MappingHash == "" {
		t.Fatalf("incomplete plan: %+v", plan)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	request := ValidRequests()[0]
	var err error
	for i, state := range []IngressRequestState{RequestValidated, RequestMapped, RequestAccepted, RequestClosed} {
		request, _, err = TransitionRequest(request, state, "test", i)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := TransitionRequest(request, RequestAccepted, "bad", 9); err == nil {
		t.Fatalf("terminal transition accepted")
	}
	rejected := ValidRequests()[0]
	rejected, _, err = TransitionRequest(rejected, RequestRejected, "bad_target", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRuntimeStreamMappingPlan(rejected, DefaultContract()); err == nil {
		t.Fatalf("rejected request mapped")
	}
}

func TestFixtureSetValidationAndJSONRoundTrip(t *testing.T) {
	set, err := GoldenFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	raw, err := StableJSON(set)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ProxyIngressFixtureSet
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(decoded); err != nil {
		t.Fatal(err)
	}
}

func TestScanForLeak(t *testing.T) {
	if err := ScanForLeak(GoldenFixtureSetMust(t)); err != nil {
		t.Fatal(err)
	}
	unsafe := []map[string]string{
		{"endpoint": "x"},
		{"domain": "example.com"},
		{"url": "https://example.com"},
		{"secret": "x"},
	}
	for _, tc := range unsafe {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe value accepted: %v", tc)
		}
	}
}

func TestCompareContracts(t *testing.T) {
	report := CompareContractsOnly(DefaultContract(), DefaultContract())
	if report.Conclusion != "passed" {
		t.Fatalf("self compare failed: %+v", report)
	}
	_, err := VerifyContract(context.Background(), "missing")
	if err == nil {
		t.Fatalf("missing contract accepted")
	}
}

func GoldenFixtureSetMust(t *testing.T) ProxyIngressFixtureSet {
	t.Helper()
	set, err := GoldenFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	return set
}
