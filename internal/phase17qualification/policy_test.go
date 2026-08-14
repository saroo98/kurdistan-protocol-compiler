// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryQualificationPolicyIsExactAndStrict(t *testing.T) {
	root := filepath.Join("..", "..")
	policy, err := LoadPolicy(filepath.Join(root, "config", "phase17", "qualification-policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if policy.Schema != PolicySchema {
		t.Fatalf("schema=%q", policy.Schema)
	}
	if got, want := policy.RequiredChecks, []string{
		"preflight", "packageVerification", "install", "serviceHealth", "enrollment",
		"sealedImport", "connect", "ipv4Tcp", "ipv4Udp", "dnsHealthy", "dnsFailClosed",
		"egressIdentity", "ipv6", "routeDnsLeak", "boundedFallback", "revocation",
		"restart", "drainResume", "emergencyDisable", "backupRestore", "upgradeRollback",
		"androidCrashFree", "privacy",
	}; !equalStrings(got, want) {
		t.Fatalf("checks=%v", got)
	}
	if got, want := policy.PrivacyPredicates, []string{
		"payloadRetained", "destinationRetained", "dnsNameRetained", "credentialRetained",
		"keyRetained", "profileRetained", "rawLogRetained",
	}; !equalStrings(got, want) {
		t.Fatalf("privacy predicates=%v", got)
	}
	if got, want := policy.Outcomes, []string{
		"PASS", "FAIL_PRODUCT", "FAIL_PRIVACY", "FAIL_HARNESS",
		"ABORT_ENVIRONMENT", "INVALID_IDENTITY", "INCONCLUSIVE",
	}; !equalStrings(got, want) {
		t.Fatalf("outcomes=%v", got)
	}
	if got, want := campaignModes(policy.Campaigns), []string{
		"Functional", "Stress", "Soak60m", "Soak90m", "Soak120m", "Soak12h",
	}; !equalStrings(got, want) {
		t.Fatalf("campaign modes=%v", got)
	}
	stress := policy.Campaigns[1]
	if stress.RestartReconnectCycles != 100 || stress.ProfileRotationCycles != 100 ||
		!equalStrings(stress.Impairments, []string{"bandwidth", "latency", "loss", "combined", "carrier-reset"}) ||
		stress.MinimumDurationMS != 0 || stress.CadenceMS != 0 {
		t.Fatalf("stress policy=%+v", stress)
	}
	finalSoak := policy.Campaigns[len(policy.Campaigns)-1]
	if finalSoak.MinimumDurationMS != 43_200_000 || finalSoak.CadenceMS != 300_000 || finalSoak.MinimumCycles != 144 ||
		finalSoak.RestartReconnectCycles != 0 || finalSoak.ProfileRotationCycles != 0 || len(finalSoak.Impairments) != 0 {
		t.Fatalf("final soak policy=%+v", finalSoak)
	}
	if policy.Resources.MaximumRSSBytes != 384<<20 || policy.Resources.MaximumFileDescriptors != 1024 ||
		policy.Resources.MaximumSwapBytes != 64<<20 {
		t.Fatalf("resource policy=%+v", policy.Resources)
	}
	if policy.Retry.InstrumentationLaunchAttempts != 2 || policy.Retry.QualifiedCampaignAutoRetries != 0 ||
		policy.Retry.EnvironmentAbortRequiresNewAuthorization != true {
		t.Fatalf("retry policy=%+v", policy.Retry)
	}
}

func TestQualificationPolicyRejectsEveryAuthorityWeakening(t *testing.T) {
	valid := validPolicyForTest()
	mutations := map[string]func(*Policy){
		"missing check": func(value *Policy) { value.RequiredChecks = value.RequiredChecks[:22] },
		"reordered check": func(value *Policy) {
			value.RequiredChecks[0], value.RequiredChecks[1] = value.RequiredChecks[1], value.RequiredChecks[0]
		},
		"missing privacy predicate":               func(value *Policy) { value.PrivacyPredicates = value.PrivacyPredicates[:6] },
		"missing outcome":                         func(value *Policy) { value.Outcomes = value.Outcomes[:6] },
		"stress restart reduction":                func(value *Policy) { value.Campaigns[1].RestartReconnectCycles = 99 },
		"stress rotation reduction":               func(value *Policy) { value.Campaigns[1].ProfileRotationCycles = 99 },
		"stress impairment removal":               func(value *Policy) { value.Campaigns[1].Impairments = value.Campaigns[1].Impairments[:4] },
		"soak shortened":                          func(value *Policy) { value.Campaigns[5].MinimumDurationMS-- },
		"soak cadence widened":                    func(value *Policy) { value.Campaigns[5].CadenceMS++ },
		"soak cycles reduced":                     func(value *Policy) { value.Campaigns[5].MinimumCycles-- },
		"rss widened":                             func(value *Policy) { value.Resources.MaximumRSSBytes++ },
		"fd widened":                              func(value *Policy) { value.Resources.MaximumFileDescriptors++ },
		"swap widened":                            func(value *Policy) { value.Resources.MaximumSwapBytes++ },
		"automatic qualified retry":               func(value *Policy) { value.Retry.QualifiedCampaignAutoRetries = 1 },
		"environment retry without authorization": func(value *Policy) { value.Retry.EnvironmentAbortRequiresNewAuthorization = false },
		"evidence allowlist widened":              func(value *Policy) { value.EvidenceOnlyPaths = append(value.EvidenceOnlyPaths, "cmd/**") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := clonePolicy(valid)
			mutate(&value)
			if err := ValidatePolicy(value); err == nil {
				t.Fatal("weakened qualification policy accepted")
			}
		})
	}
}

func TestDecodePolicyRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	valid := validPolicyForTest()
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate": bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		"unknown":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicy(bytes.NewReader(candidate)); err == nil {
				t.Fatal("non-strict policy accepted")
			}
		})
	}
}

func validPolicyForTest() Policy {
	return Policy{
		Schema: PolicySchema,
		RequiredChecks: []string{
			"preflight", "packageVerification", "install", "serviceHealth", "enrollment",
			"sealedImport", "connect", "ipv4Tcp", "ipv4Udp", "dnsHealthy", "dnsFailClosed",
			"egressIdentity", "ipv6", "routeDnsLeak", "boundedFallback", "revocation",
			"restart", "drainResume", "emergencyDisable", "backupRestore", "upgradeRollback",
			"androidCrashFree", "privacy",
		},
		PrivacyPredicates: []string{
			"payloadRetained", "destinationRetained", "dnsNameRetained", "credentialRetained",
			"keyRetained", "profileRetained", "rawLogRetained",
		},
		Outcomes: []string{
			"PASS", "FAIL_PRODUCT", "FAIL_PRIVACY", "FAIL_HARNESS",
			"ABORT_ENVIRONMENT", "INVALID_IDENTITY", "INCONCLUSIVE",
		},
		Campaigns: []CampaignPolicy{
			{Mode: "Functional", Impairments: []string{}},
			{Mode: "Stress", RestartReconnectCycles: 100, ProfileRotationCycles: 100, Impairments: []string{"bandwidth", "latency", "loss", "combined", "carrier-reset"}},
			{Mode: "Soak60m", Impairments: []string{}, MinimumDurationMS: 3_600_000, CadenceMS: 300_000, MinimumCycles: 12},
			{Mode: "Soak90m", Impairments: []string{}, MinimumDurationMS: 5_400_000, CadenceMS: 300_000, MinimumCycles: 18},
			{Mode: "Soak120m", Impairments: []string{}, MinimumDurationMS: 7_200_000, CadenceMS: 300_000, MinimumCycles: 24},
			{Mode: "Soak12h", Impairments: []string{}, MinimumDurationMS: 43_200_000, CadenceMS: 300_000, MinimumCycles: 144},
		},
		Resources: ResourcePolicy{MaximumRSSBytes: 384 << 20, MaximumFileDescriptors: 1024, MaximumSwapBytes: 64 << 20},
		Retry:     RetryPolicy{InstrumentationLaunchAttempts: 2, QualifiedCampaignAutoRetries: 0, EnvironmentAbortRequiresNewAuthorization: true},
		EvidenceOnlyPaths: []string{
			"testdata/evidence/phase17/acceptance-status.json",
			"testdata/evidence/phase17/live-data-plane-overlay.json",
		},
	}
}

func clonePolicy(value Policy) Policy {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result Policy
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return result
}

func campaignModes(values []CampaignPolicy) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Mode
	}
	return result
}

func equalStrings(left, right []string) bool {
	return strings.Join(left, "\x00") == strings.Join(right, "\x00")
}
