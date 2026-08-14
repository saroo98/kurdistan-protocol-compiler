// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"kurdistan/internal/assurance"
)

const (
	PrivateEnvironmentSchema           = "kurdistan-phase17-private-environment-v1"
	privateEnvironmentCommitmentSchema = "kurdistan-phase17-private-environment-commitment-v1"
	privateEnvironmentCommitmentDomain = "KURDISTAN-PHASE17-PRIVATE-ENVIRONMENT-V1\x00"
	PrivateEnvironmentSaltSize         = 32
)

var privateEnvironmentSelectorPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// PrivateEnvironment is owner-local input. It must remain ignored and must
// never be copied into a candidate, receipt, evidence file, or command output.
type PrivateEnvironment struct {
	Schema               string `json:"schema"`
	SSHAlias             string `json:"sshAlias"`
	AVDName              string `json:"avdName"`
	DeviceSerial         string `json:"deviceSerial"`
	ProbeURLFile         string `json:"probeUrlFile"`
	ProbeDigestFile      string `json:"probeDigestFile"`
	IPv6ProbeAddress     string `json:"ipv6ProbeAddress"`
	RelayPort            int    `json:"relayPort"`
	PythonExecutable     string `json:"pythonExecutable"`
	ADBExecutable        string `json:"adbExecutable"`
	SSHExecutable        string `json:"sshExecutable"`
	SCPExecutable        string `json:"scpExecutable"`
	PowerShellExecutable string `json:"powershellExecutable"`
}

type privateEnvironmentCommitmentInput struct {
	Schema            string `json:"schema"`
	CandidateID       string `json:"candidateId"`
	SSHAlias          string `json:"sshAlias"`
	AndroidClass      string `json:"androidClass"`
	AndroidSelector   string `json:"androidSelector"`
	ProbeURLSHA256    string `json:"probeUrlSha256"`
	ProbeDigestSHA256 string `json:"probeDigestSha256"`
	HostBootSHA256    string `json:"hostBootSha256"`
	IPv6ProbeAddress  string `json:"ipv6ProbeAddress"`
	RelayPort         int    `json:"relayPort"`
}

func DecodePrivateEnvironment(reader io.Reader) (PrivateEnvironment, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 64<<10+1))
	if err != nil {
		return PrivateEnvironment{}, err
	}
	defer Clear(raw)
	if len(raw) == 0 || len(raw) > 64<<10 {
		return PrivateEnvironment{}, errors.New("qualification private environment exceeds limit")
	}
	var value PrivateEnvironment
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return PrivateEnvironment{}, err
	}
	if err := validatePrivateEnvironment(value); err != nil {
		return PrivateEnvironment{}, err
	}
	return value, nil
}

func ComputePrivateEnvironmentCommitment(
	candidateID, androidClass string,
	salt []byte,
	value PrivateEnvironment,
	probeURL, probeDigest, hostBootIdentity []byte,
) (string, error) {
	bootTime, bootErr := time.Parse(time.RFC3339Nano, string(hostBootIdentity))
	if !hex64Pattern.MatchString(candidateID) || len(salt) != PrivateEnvironmentSaltSize ||
		len(probeURL) == 0 || len(probeURL) > 2048 || bytes.ContainsAny(probeURL, "\r\n\x00") ||
		len(probeDigest) != 64 || !hex64Pattern.Match(probeDigest) || bootErr != nil ||
		bootTime.Location() != time.UTC || bootTime.Format(time.RFC3339Nano) != string(hostBootIdentity) {
		return "", errors.New("qualification private environment commitment input rejected")
	}
	if err := validatePrivateEnvironment(value); err != nil {
		return "", err
	}
	selector := ""
	switch androidClass {
	case "EMULATOR":
		if value.AVDName == "" || value.DeviceSerial != "" {
			return "", errors.New("qualification private environment Android class rejected")
		}
		selector = value.AVDName
	case "PHYSICAL":
		if value.AVDName != "" || value.DeviceSerial == "" {
			return "", errors.New("qualification private environment Android class rejected")
		}
		selector = value.DeviceSerial
	default:
		return "", errors.New("qualification private environment Android class rejected")
	}
	probeURLSum := sha256.Sum256(probeURL)
	probeDigestSum := sha256.Sum256(probeDigest)
	hostBootSum := sha256.Sum256(hostBootIdentity)
	payload := privateEnvironmentCommitmentInput{
		Schema: privateEnvironmentCommitmentSchema, CandidateID: candidateID,
		SSHAlias: value.SSHAlias, AndroidClass: androidClass, AndroidSelector: selector,
		ProbeURLSHA256: hex.EncodeToString(probeURLSum[:]), ProbeDigestSHA256: hex.EncodeToString(probeDigestSum[:]),
		HostBootSHA256:   hex.EncodeToString(hostBootSum[:]),
		IPv6ProbeAddress: value.IPv6ProbeAddress, RelayPort: value.RelayPort,
	}
	raw, err := MarshalCanonical(payload)
	if err != nil {
		return "", err
	}
	defer Clear(raw)
	key := bytes.Clone(salt)
	defer Clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(privateEnvironmentCommitmentDomain))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validatePrivateEnvironment(value PrivateEnvironment) error {
	if value.Schema != PrivateEnvironmentSchema || !privateEnvironmentSelectorPattern.MatchString(value.SSHAlias) ||
		(value.AVDName == "") == (value.DeviceSerial == "") ||
		(value.AVDName != "" && !privateEnvironmentSelectorPattern.MatchString(value.AVDName)) ||
		(value.DeviceSerial != "" && !privateEnvironmentSelectorPattern.MatchString(value.DeviceSerial)) ||
		value.RelayPort < 1 || value.RelayPort > 65535 {
		return errors.New("qualification private environment rejected")
	}
	address, err := netip.ParseAddr(value.IPv6ProbeAddress)
	if err != nil || !address.Is6() || address.Zone() != "" {
		return errors.New("qualification private environment rejected")
	}
	for _, path := range []string{
		value.ProbeURLFile, value.ProbeDigestFile, value.PythonExecutable,
		value.ADBExecutable, value.SSHExecutable, value.SCPExecutable, value.PowerShellExecutable,
	} {
		if len(path) == 0 || len(path) > 4096 || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return errors.New("qualification private environment rejected")
		}
	}
	return nil
}
