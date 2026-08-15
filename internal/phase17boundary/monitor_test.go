// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17boundary

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvaluateRequiresIndependentAndroidAndVPSBoundaryCoverage(t *testing.T) {
	request := validRequest()
	receipt, err := Evaluate(request, validObservation())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result != "PASS" || receipt.RouteLeak || receipt.DNSLeak || receipt.CoverageGap ||
		receipt.AttemptID != request.AttemptID || receipt.Name != MonitorName {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestEvaluateFailsClosedOnEveryBoundaryDefect(t *testing.T) {
	mutations := map[string]func(*Observation){
		"vpn inactive":        func(value *Observation) { value.AndroidVPNActive = false },
		"ipv4 route absent":   func(value *Observation) { value.AndroidIPv4Default = false },
		"ipv6 route absent":   func(value *Observation) { value.AndroidIPv6Default = false },
		"android dns leak":    func(value *Observation) { value.AndroidDNSPinned = false },
		"app bypass":          func(value *Observation) { value.AndroidBypassBlocked = false },
		"vps route absent":    func(value *Observation) { value.VPSRoutePolicy = false },
		"vps dns leak":        func(value *Observation) { value.VPSDNSPinned = false },
		"relay absent":        func(value *Observation) { value.VPSRelayBound = false },
		"source guard absent": func(value *Observation) { value.VPSSourceGuard = false },
		"vps ipv6 absent":     func(value *Observation) { value.VPSIPv6Policy = false },
		"coverage gap":        func(value *Observation) { value.CoverageGap = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			observation := validObservation()
			mutate(&observation)
			receipt, err := Evaluate(validRequest(), observation)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Result != "FAIL" {
				t.Fatalf("receipt=%+v", receipt)
			}
		})
	}
}

func TestEvaluateDoesNotRequireIPv6WhenEnvironmentDidNotAuthorizeIt(t *testing.T) {
	request := validRequest()
	request.VerifyIPv6 = false
	observation := validObservation()
	observation.AndroidIPv6Default = false
	observation.VPSIPv6Policy = false
	receipt, err := Evaluate(request, observation)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result != "PASS" || receipt.RouteLeak {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestValidateReceiptRejectsForgedOrInconsistentCategoricalResult(t *testing.T) {
	request := validRequest()
	receipt, err := Evaluate(request, validObservation())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceipt(request, receipt); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Receipt){
		"attempt": func(value *Receipt) { value.AttemptID = strings.Repeat("b", 32) },
		"result":  func(value *Receipt) { value.Result = "FAIL" },
		"route":   func(value *Receipt) { value.AndroidIPv4Default = false },
		"dns":     func(value *Receipt) { value.AndroidDNSPinned = false },
		"ipv6":    func(value *Receipt) { value.IPv6Required = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := receipt
			mutate(&candidate)
			if err := ValidateReceipt(request, candidate); err == nil {
				t.Fatal("forged receipt accepted")
			}
		})
	}
}

func TestRequestDecoderRejectsMalformedNoncanonicalAndPrivateFieldAbuse(t *testing.T) {
	raw := mustRequest(t, validRequest())
	for name, candidate := range map[string][]byte{
		"unknown field":   bytes.Replace(raw, []byte(`"verifyIpv6":true`), []byte(`"verifyIpv6":true,"extra":false`), 1),
		"duplicate field": bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		"trailing bytes":  append(append([]byte(nil), raw...), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(bytes.NewReader(candidate), int64(len(candidate))); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	bad := validRequest()
	bad.SSHAlias = "owner\nendpoint"
	if _, err := MarshalRequest(bad); err == nil {
		t.Fatal("control character accepted")
	}
	for _, invalid := range []string{
		"",
		"http://probe.invalid/check",
		"https://127.0.0.1/check",
		"https://[2001:db8::1]/check",
		"https://probe.invalid:/check",
		"https://probe.invalid:0/check",
		"https://probe.invalid:65536/check",
		"https://user@probe.invalid/check",
		"https://probe.invalid/check#fragment",
		"https://probe.invalid/" + strings.Repeat("a", 2049),
	} {
		bad = validRequest()
		bad.ProbeURL = invalid
		if _, err := MarshalRequest(bad); err == nil {
			t.Fatalf("invalid probe URL accepted: %q", invalid)
		}
	}
	if _, err := DecodeRequest(strings.NewReader("{}"), MaximumRequestBytes+1); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func validRequest() Request {
	return Request{
		Schema: RequestSchema, CampaignMode: "Functional", AttemptID: strings.Repeat("a", 32),
		ADBPath: "adb", DeviceSerial: "emulator-5554", SSHPath: "ssh", SSHAlias: "owner-node",
		ProbeURL: "https://probe.invalid/check", RelayPort: 8443, VerifyIPv6: true,
	}
}

func validObservation() Observation {
	return Observation{
		AndroidVPNActive: true, AndroidIPv4Default: true, AndroidIPv6Default: true,
		AndroidDNSPinned: true, AndroidBypassBlocked: true, VPSRoutePolicy: true,
		VPSDNSPinned: true, VPSRelayBound: true, VPSSourceGuard: true, VPSIPv6Policy: true,
	}
}

func mustRequest(t *testing.T, value Request) []byte {
	t.Helper()
	raw, err := MarshalRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
