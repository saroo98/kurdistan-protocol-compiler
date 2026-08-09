// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17evidence

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

const OwnedVPSSchema = "kurdistan-phase17-owned-vps-evidence-v2"

const minimumSoakDurationMS = 12 * 60 * 60 * 1000

var requiredOwnedVPSChecks = []string{
	"preflight", "packageVerification", "install", "serviceHealth", "enrollment",
	"sealedImport", "connect", "ipv4Tcp", "ipv4Udp", "dnsHealthy", "dnsFailClosed",
	"egressIdentity", "ipv6", "routeDnsLeak", "boundedFallback", "revocation",
	"restart", "drainResume", "emergencyDisable", "backupRestore", "upgradeRollback",
	"androidCrashFree", "privacy",
}

type FieldSubject struct {
	CommitSHA  string `json:"commitSha"`
	TreeSHA    string `json:"treeSha"`
	PackageSHA string `json:"packageSha256"`
	AppAPKSHA  string `json:"appApkSha256"`
	TestAPKSHA string `json:"testApkSha256"`
}

type FieldEnvironment struct {
	HostClass    string `json:"hostClass"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AndroidClass string `json:"androidClass"`
	AndroidAPI   int    `json:"androidApi"`
	AndroidABI   string `json:"androidAbi"`
	IPv4         bool   `json:"ipv4"`
	IPv6         bool   `json:"ipv6"`
}

type FieldMetrics struct {
	DurationMS          uint64 `json:"durationMs"`
	PeakRSSBytes        uint64 `json:"peakRssBytes"`
	PeakFileDescriptors uint64 `json:"peakFileDescriptors"`
	Reconnects          uint64 `json:"reconnects"`
}

type FieldPrivacy struct {
	PayloadRetained     bool `json:"payloadRetained"`
	DestinationRetained bool `json:"destinationRetained"`
	DNSNameRetained     bool `json:"dnsNameRetained"`
	CredentialRetained  bool `json:"credentialRetained"`
	KeyRetained         bool `json:"keyRetained"`
	ProfileRetained     bool `json:"profileRetained"`
	RawLogRetained      bool `json:"rawLogRetained"`
}

type FieldCampaign struct {
	Mode                   string   `json:"mode"`
	RestartReconnectCycles uint64   `json:"restartReconnectCycles"`
	ProfileRotationCycles  uint64   `json:"profileRotationCycles"`
	Impairments            []string `json:"impairments"`
	SoakDurationMS         uint64   `json:"soakDurationMs"`
	SoakCycles             uint64   `json:"soakCycles"`
}

type OwnedVPSEvidence struct {
	Schema      string            `json:"schema"`
	Result      string            `json:"result"`
	Subject     FieldSubject      `json:"subject"`
	Environment FieldEnvironment  `json:"environment"`
	Checks      map[string]string `json:"checks"`
	Metrics     FieldMetrics      `json:"metrics"`
	Privacy     FieldPrivacy      `json:"privacy"`
	Limitations []string          `json:"limitations"`
	Campaign    FieldCampaign     `json:"campaign"`
}

func RequiredOwnedVPSChecks() []string {
	return append([]string(nil), requiredOwnedVPSChecks...)
}

func DecodeOwnedVPS(raw []byte) (OwnedVPSEvidence, error) {
	if containsSensitiveFieldEvidence(raw) {
		return OwnedVPSEvidence{}, errors.New("field evidence contains prohibited sensitive material")
	}
	var value OwnedVPSEvidence
	if err := DecodeStrict(raw, &value); err != nil {
		return OwnedVPSEvidence{}, err
	}
	if value.Schema != OwnedVPSSchema || value.Result != "PASS" {
		return OwnedVPSEvidence{}, errors.New("owned-VPS evidence is not a passing v2 record")
	}
	if !validLowerHex(value.Subject.CommitSHA, 40) || !validLowerHex(value.Subject.TreeSHA, 40) ||
		!validDigest(value.Subject.PackageSHA) || !validDigest(value.Subject.AppAPKSHA) || !validDigest(value.Subject.TestAPKSHA) {
		return OwnedVPSEvidence{}, errors.New("owned-VPS evidence subject digest rejected")
	}
	if value.Environment.HostClass != "OWNER_CONTROLLED_VPS" || value.Environment.OS != "linux" || value.Environment.Arch != "amd64" ||
		value.Environment.AndroidClass != "EMULATOR" || value.Environment.AndroidAPI != 26 && value.Environment.AndroidAPI != 34 && value.Environment.AndroidAPI != 36 ||
		value.Environment.AndroidABI != "x86_64" && value.Environment.AndroidABI != "arm64-v8a" || !value.Environment.IPv4 {
		return OwnedVPSEvidence{}, errors.New("owned-VPS evidence environment rejected")
	}
	if err := validateEvidenceMap("owned-VPS", value.Checks, requiredOwnedVPSChecks, map[string]bool{"PASS": true}); err != nil {
		return OwnedVPSEvidence{}, err
	}
	if value.Metrics.DurationMS == 0 || value.Metrics.DurationMS > 7*24*60*60*1000 || value.Metrics.PeakRSSBytes == 0 ||
		value.Metrics.PeakRSSBytes > 2<<30 || value.Metrics.PeakFileDescriptors == 0 || value.Metrics.PeakFileDescriptors > 4096 || value.Metrics.Reconnects > 1000 {
		return OwnedVPSEvidence{}, errors.New("owned-VPS evidence metrics rejected")
	}
	if value.Privacy != (FieldPrivacy{}) {
		return OwnedVPSEvidence{}, errors.New("owned-VPS evidence retained prohibited material")
	}
	if err := validateFieldCampaign(value.Campaign); err != nil {
		return OwnedVPSEvidence{}, err
	}
	if len(value.Limitations) == 0 || len(value.Limitations) > 8 {
		return OwnedVPSEvidence{}, errors.New("owned-VPS evidence limitations rejected")
	}
	for _, limitation := range value.Limitations {
		if strings.TrimSpace(limitation) == "" || len(limitation) > 256 {
			return OwnedVPSEvidence{}, errors.New("owned-VPS evidence limitation rejected")
		}
	}
	return value, nil
}

func validateFieldCampaign(value FieldCampaign) error {
	expectedImpairments := []string{"bandwidth", "latency", "loss", "combined", "carrier-reset"}
	switch value.Mode {
	case "Functional":
		if value.RestartReconnectCycles != 0 || value.ProfileRotationCycles != 0 || len(value.Impairments) != 0 || value.SoakDurationMS != 0 || value.SoakCycles != 0 {
			return errors.New("functional field campaign overstated")
		}
	case "Stress", "Soak12h":
		if value.RestartReconnectCycles != 100 || value.ProfileRotationCycles != 100 || len(value.Impairments) != len(expectedImpairments) {
			return errors.New("stress field campaign inventory rejected")
		}
		for index, expected := range expectedImpairments {
			if value.Impairments[index] != expected {
				return errors.New("stress field campaign impairment inventory rejected")
			}
		}
		if value.Mode == "Stress" && (value.SoakDurationMS != 0 || value.SoakCycles != 0) {
			return errors.New("stress field campaign overstated soak evidence")
		}
		if value.Mode == "Soak12h" && (value.SoakDurationMS < minimumSoakDurationMS || value.SoakDurationMS > 7*24*60*60*1000 || value.SoakCycles == 0) {
			return errors.New("soak field campaign duration rejected")
		}
	default:
		return errors.New("field campaign mode rejected")
	}
	return nil
}

func validLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func ConvertOwnedVPS(raw []byte, current Acceptance) (Acceptance, error) {
	field, err := DecodeOwnedVPS(raw)
	if err != nil {
		return Acceptance{}, err
	}
	if err := ValidateAcceptance(current); err != nil {
		return Acceptance{}, fmt.Errorf("current acceptance: %w", err)
	}
	result := current
	result.Local = cloneStatuses(current.Local)
	result.External = cloneStatuses(current.External)
	result.Local["ownedVps"] = "PASS"
	result.Local[fmt.Sprintf("api%dEmulator", field.Environment.AndroidAPI)] = "PASS"
	if field.Campaign.Mode == "Soak12h" {
		result.Local["loadRecoveryPrivacyCampaign"] = "PASS"
	}
	result.Complete = false
	result.Status = "IN_PROGRESS"
	result.Limitations = nil
	if hasIncompleteEvidence(result.Local) {
		result.Limitations = append(result.Limitations, "remaining local emulator, namespace, or load, recovery, privacy, and endurance evidence is not yet complete")
	}
	if hasIncompleteEvidence(result.External) {
		result.Limitations = append(result.Limitations, "physical Android devices and a second unrelated VPS provider remain external evidence")
	}
	if len(result.Limitations) == 0 {
		result.Limitations = append(result.Limitations, "final Phase 17 integration decision remains pending")
	}
	if err := ValidateAcceptance(result); err != nil {
		return Acceptance{}, err
	}
	return result, nil
}

func hasIncompleteEvidence(values map[string]string) bool {
	for _, value := range values {
		if value != "PASS" {
			return true
		}
	}
	return false
}

func containsSensitiveFieldEvidence(raw []byte) bool {
	lower := bytes.ToLower(raw)
	for _, marker := range [][]byte{
		[]byte("private key"), []byte("begin openssh"), []byte("ssh-rsa"), []byte("ssh-ed25519"),
		[]byte("password"), []byte("passphrase"), []byte("bearer token"),
		[]byte("c:\\users\\"), []byte("/home/"), []byte("kurd-node@"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	return containsIPAddressLiteral(raw)
}

// ContainsSensitiveFieldEvidence reports whether a proposed categorical field
// record contains endpoint, credential, key, profile, or owner-path material.
// Field runners use the same boundary before surfacing remote failure text.
func ContainsSensitiveFieldEvidence(raw []byte) bool {
	return containsSensitiveFieldEvidence(raw)
}

func containsIPAddressLiteral(raw []byte) bool {
	for _, field := range bytes.FieldsFunc(raw, func(r rune) bool {
		return !(r >= '0' && r <= '9' ||
			r >= 'a' && r <= 'f' ||
			r >= 'A' && r <= 'F' ||
			r == '.' || r == ':' || r == '%')
	}) {
		candidate := strings.Trim(string(field), "[]")
		if address, _, found := strings.Cut(candidate, "%"); found {
			candidate = address
		}
		if net.ParseIP(candidate) != nil {
			return true
		}
		if strings.Count(candidate, ":") == 1 {
			host, port, _ := strings.Cut(candidate, ":")
			if port != "" && net.ParseIP(host) != nil {
				return true
			}
		}
	}
	return false
}

func cloneStatuses(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
