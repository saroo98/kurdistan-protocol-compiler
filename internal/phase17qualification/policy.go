// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"fmt"
	"io"
	"os"
	"reflect"

	"kurdistan/internal/assurance"
)

const PolicySchema = "kurdistan-phase17-qualification-policy-v1"

var exactRequiredChecks = []string{
	"preflight", "packageVerification", "install", "serviceHealth", "enrollment",
	"sealedImport", "connect", "ipv4Tcp", "ipv4Udp", "dnsHealthy", "dnsFailClosed",
	"egressIdentity", "ipv6", "routeDnsLeak", "boundedFallback", "revocation",
	"restart", "drainResume", "emergencyDisable", "backupRestore", "upgradeRollback",
	"androidCrashFree", "privacy",
}

var exactPrivacyPredicates = []string{
	"payloadRetained", "destinationRetained", "dnsNameRetained", "credentialRetained",
	"keyRetained", "profileRetained", "rawLogRetained",
}

var exactOutcomes = []string{
	"PASS", "FAIL_PRODUCT", "FAIL_PRIVACY", "FAIL_HARNESS",
	"ABORT_ENVIRONMENT", "INVALID_IDENTITY", "INCONCLUSIVE",
}

var exactCampaigns = []CampaignPolicy{
	{Mode: "Functional", Impairments: []string{}},
	{Mode: "Stress", RestartReconnectCycles: 100, ProfileRotationCycles: 100, Impairments: []string{"bandwidth", "latency", "loss", "combined", "carrier-reset"}},
	{Mode: "Soak60m", Impairments: []string{}, MinimumDurationMS: 3_600_000, CadenceMS: 300_000, MinimumCycles: 12},
	{Mode: "Soak90m", Impairments: []string{}, MinimumDurationMS: 5_400_000, CadenceMS: 300_000, MinimumCycles: 18},
	{Mode: "Soak120m", Impairments: []string{}, MinimumDurationMS: 7_200_000, CadenceMS: 300_000, MinimumCycles: 24},
	{Mode: "Soak12h", Impairments: []string{}, MinimumDurationMS: 43_200_000, CadenceMS: 300_000, MinimumCycles: 144},
}

var exactEvidenceOnlyPaths = []string{
	"testdata/evidence/phase17/acceptance-status.json",
	"testdata/evidence/phase17/live-data-plane-overlay.json",
}

type Policy struct {
	Schema            string           `json:"schema"`
	RequiredChecks    []string         `json:"requiredChecks"`
	PrivacyPredicates []string         `json:"privacyPredicates"`
	Outcomes          []string         `json:"outcomes"`
	Campaigns         []CampaignPolicy `json:"campaigns"`
	Resources         ResourcePolicy   `json:"resources"`
	Retry             RetryPolicy      `json:"retry"`
	EvidenceOnlyPaths []string         `json:"evidenceOnlyPaths"`
}

type CampaignPolicy struct {
	Mode                   string   `json:"mode"`
	RestartReconnectCycles uint64   `json:"restartReconnectCycles"`
	ProfileRotationCycles  uint64   `json:"profileRotationCycles"`
	Impairments            []string `json:"impairments"`
	MinimumDurationMS      uint64   `json:"minimumDurationMs"`
	CadenceMS              uint64   `json:"cadenceMs"`
	MinimumCycles          uint64   `json:"minimumCycles"`
}

type ResourcePolicy struct {
	MaximumRSSBytes        uint64 `json:"maximumRssBytes"`
	MaximumFileDescriptors uint64 `json:"maximumFileDescriptors"`
	MaximumSwapBytes       uint64 `json:"maximumSwapBytes"`
}

type RetryPolicy struct {
	InstrumentationLaunchAttempts            uint64 `json:"instrumentationLaunchAttempts"`
	QualifiedCampaignAutoRetries             uint64 `json:"qualifiedCampaignAutoRetries"`
	EnvironmentAbortRequiresNewAuthorization bool   `json:"environmentAbortRequiresNewAuthorization"`
}

func LoadPolicy(path string) (Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer file.Close()
	return DecodePolicy(file)
}

func DecodePolicy(reader io.Reader) (Policy, error) {
	var value Policy
	if err := assurance.DecodeStrict(reader, &value); err != nil {
		return Policy{}, err
	}
	if err := ValidatePolicy(value); err != nil {
		return Policy{}, err
	}
	return value, nil
}

func ValidatePolicy(value Policy) error {
	if value.Schema != PolicySchema {
		return fmt.Errorf("qualification policy schema rejected")
	}
	if !reflect.DeepEqual(value.RequiredChecks, exactRequiredChecks) {
		return fmt.Errorf("qualification check inventory rejected")
	}
	if !reflect.DeepEqual(value.PrivacyPredicates, exactPrivacyPredicates) {
		return fmt.Errorf("qualification privacy inventory rejected")
	}
	if !reflect.DeepEqual(value.Outcomes, exactOutcomes) {
		return fmt.Errorf("qualification outcome inventory rejected")
	}
	if !reflect.DeepEqual(value.Campaigns, exactCampaigns) {
		return fmt.Errorf("qualification campaign policy rejected")
	}
	if value.Resources != (ResourcePolicy{
		MaximumRSSBytes: 384 << 20, MaximumFileDescriptors: 1024, MaximumSwapBytes: 64 << 20,
	}) {
		return fmt.Errorf("qualification resource policy rejected")
	}
	if value.Retry != (RetryPolicy{
		InstrumentationLaunchAttempts:            2,
		QualifiedCampaignAutoRetries:             0,
		EnvironmentAbortRequiresNewAuthorization: true,
	}) {
		return fmt.Errorf("qualification retry policy rejected")
	}
	if !reflect.DeepEqual(value.EvidenceOnlyPaths, exactEvidenceOnlyPaths) {
		return fmt.Errorf("qualification evidence-only allowlist rejected")
	}
	return nil
}

func RequiredChecks() []string {
	return append([]string(nil), exactRequiredChecks...)
}

func PrivacyPredicates() []string {
	return append([]string(nil), exactPrivacyPredicates...)
}

func Outcomes() []string {
	return append([]string(nil), exactOutcomes...)
}

func CampaignPolicyForMode(mode string) (CampaignPolicy, bool) {
	for _, campaign := range exactCampaigns {
		if campaign.Mode == mode {
			campaign.Impairments = append([]string{}, campaign.Impairments...)
			return campaign, true
		}
	}
	return CampaignPolicy{}, false
}

func (policy Policy) Campaign(mode string) (CampaignPolicy, bool) {
	for _, campaign := range policy.Campaigns {
		if campaign.Mode == mode {
			campaign.Impairments = append([]string{}, campaign.Impairments...)
			return campaign, true
		}
	}
	return CampaignPolicy{}, false
}
