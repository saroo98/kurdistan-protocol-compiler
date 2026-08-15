// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package phase17boundary defines the private request and categorical receipt
// contract for the independently compiled Phase 17 route and DNS observer. It
// intentionally imports neither field-evidence verdicts nor qualification
// receipts.
package phase17boundary

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"kurdistan/internal/assurance"
)

const (
	RequestSchema       = "kurdistan-phase17-boundary-request-v2"
	AndroidSchema       = "kurdistan-phase17-boundary-android-v1"
	VPSSchema           = "kurdistan-phase17-boundary-vps-v1"
	ReceiptSchema       = "kurdistan-phase17-boundary-monitor-v2"
	MonitorName         = "BOUNDARY_MONITOR"
	MaximumRequestBytes = 16 << 10
	MaximumResultBytes  = 4 << 10
)

var attemptIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Request contains only ephemeral owner-local selectors. It is deleted after
// observation and is never copied into retained evidence.
type Request struct {
	Schema       string `json:"schema"`
	CampaignMode string `json:"campaignMode"`
	AttemptID    string `json:"attemptId"`
	ADBPath      string `json:"adbPath"`
	DeviceSerial string `json:"deviceSerial"`
	SSHPath      string `json:"sshPath"`
	SSHAlias     string `json:"sshAlias"`
	ProbeURL     string `json:"probeUrl"`
	RelayPort    uint16 `json:"relayPort"`
	VerifyIPv6   bool   `json:"verifyIpv6"`
}

// AndroidObservation is emitted by the test-only on-device observer. It is
// categorical by design and contains no endpoint, route, DNS-name, or payload.
type AndroidObservation struct {
	Schema        string `json:"schema"`
	AttemptID     string `json:"attemptId"`
	VPNActive     bool   `json:"vpnActive"`
	IPv4Default   bool   `json:"ipv4Default"`
	IPv6Default   bool   `json:"ipv6Default"`
	DNSPinned     bool   `json:"dnsPinned"`
	BypassBlocked bool   `json:"bypassBlocked"`
	CoverageGap   bool   `json:"coverageGap"`
}

// VPSObservation is emitted by a fixed observer script over strict SSH. It is
// likewise categorical and contains no host, interface, or endpoint value.
type VPSObservation struct {
	Schema      string `json:"schema"`
	AttemptID   string `json:"attemptId"`
	RoutePolicy bool   `json:"routePolicy"`
	DNSPinned   bool   `json:"dnsPinned"`
	RelayBound  bool   `json:"relayBound"`
	SourceGuard bool   `json:"sourceGuard"`
	IPv6Policy  bool   `json:"ipv6Policy"`
	CoverageGap bool   `json:"coverageGap"`
}

type Observation struct {
	AndroidVPNActive     bool
	AndroidIPv4Default   bool
	AndroidIPv6Default   bool
	AndroidDNSPinned     bool
	AndroidBypassBlocked bool
	VPSRoutePolicy       bool
	VPSDNSPinned         bool
	VPSRelayBound        bool
	VPSSourceGuard       bool
	VPSIPv6Policy        bool
	CoverageGap          bool
}

type Receipt struct {
	Schema               string `json:"schema"`
	Name                 string `json:"name"`
	AttemptID            string `json:"attemptId"`
	Result               string `json:"result"`
	AndroidVPNActive     bool   `json:"androidVpnActive"`
	AndroidIPv4Default   bool   `json:"androidIpv4Default"`
	AndroidIPv6Default   bool   `json:"androidIpv6Default"`
	AndroidDNSPinned     bool   `json:"androidDnsPinned"`
	AndroidBypassBlocked bool   `json:"androidBypassBlocked"`
	VPSRoutePolicy       bool   `json:"vpsRoutePolicy"`
	VPSDNSPinned         bool   `json:"vpsDnsPinned"`
	VPSRelayBound        bool   `json:"vpsRelayBound"`
	VPSSourceGuard       bool   `json:"vpsSourceGuard"`
	VPSIPv6Policy        bool   `json:"vpsIpv6Policy"`
	IPv6Required         bool   `json:"ipv6Required"`
	RouteLeak            bool   `json:"routeLeak"`
	DNSLeak              bool   `json:"dnsLeak"`
	CoverageGap          bool   `json:"coverageGap"`
}

func MarshalRequest(value Request) ([]byte, error) {
	if err := validateRequest(value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func DecodeRequest(reader io.Reader, declaredSize int64) (Request, error) {
	var value Request
	raw, err := readBounded(reader, declaredSize, MaximumRequestBytes)
	if err != nil {
		return value, errors.New("boundary request read rejected")
	}
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return Request{}, errors.New("boundary request decode rejected")
	}
	canonical, err := MarshalRequest(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Request{}, errors.New("boundary request is not canonical")
	}
	return value, nil
}

func DecodeAndroidObservation(raw []byte, attemptID string) (AndroidObservation, error) {
	var value AndroidObservation
	if err := decodeCategorical(raw, &value); err != nil || value.Schema != AndroidSchema || value.AttemptID != attemptID {
		return AndroidObservation{}, errors.New("Android boundary observation rejected")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return AndroidObservation{}, errors.New("Android boundary observation is not canonical")
	}
	return value, nil
}

func DecodeVPSObservation(raw []byte, attemptID string) (VPSObservation, error) {
	var value VPSObservation
	if err := decodeCategorical(raw, &value); err != nil || value.Schema != VPSSchema || value.AttemptID != attemptID {
		return VPSObservation{}, errors.New("VPS boundary observation rejected")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return VPSObservation{}, errors.New("VPS boundary observation is not canonical")
	}
	return value, nil
}

func Combine(android AndroidObservation, vps VPSObservation) Observation {
	return Observation{
		AndroidVPNActive: android.VPNActive, AndroidIPv4Default: android.IPv4Default,
		AndroidIPv6Default: android.IPv6Default, AndroidDNSPinned: android.DNSPinned,
		AndroidBypassBlocked: android.BypassBlocked, VPSRoutePolicy: vps.RoutePolicy,
		VPSDNSPinned: vps.DNSPinned, VPSRelayBound: vps.RelayBound,
		VPSSourceGuard: vps.SourceGuard, VPSIPv6Policy: vps.IPv6Policy,
		CoverageGap: android.CoverageGap || vps.CoverageGap,
	}
}

func Evaluate(request Request, value Observation) (Receipt, error) {
	if err := validateRequest(request); err != nil {
		return Receipt{}, err
	}
	routeLeak := !value.AndroidVPNActive || !value.AndroidIPv4Default || !value.AndroidBypassBlocked ||
		!value.VPSRoutePolicy || !value.VPSRelayBound || !value.VPSSourceGuard ||
		request.VerifyIPv6 && (!value.AndroidIPv6Default || !value.VPSIPv6Policy)
	dnsLeak := !value.AndroidDNSPinned || !value.VPSDNSPinned
	result := "PASS"
	if routeLeak || dnsLeak || value.CoverageGap {
		result = "FAIL"
	}
	return Receipt{
		Schema: ReceiptSchema, Name: MonitorName, AttemptID: request.AttemptID, Result: result,
		AndroidVPNActive: value.AndroidVPNActive, AndroidIPv4Default: value.AndroidIPv4Default,
		AndroidIPv6Default: value.AndroidIPv6Default, AndroidDNSPinned: value.AndroidDNSPinned,
		AndroidBypassBlocked: value.AndroidBypassBlocked, VPSRoutePolicy: value.VPSRoutePolicy,
		VPSDNSPinned: value.VPSDNSPinned, VPSRelayBound: value.VPSRelayBound,
		VPSSourceGuard: value.VPSSourceGuard, VPSIPv6Policy: value.VPSIPv6Policy,
		IPv6Required: request.VerifyIPv6, RouteLeak: routeLeak, DNSLeak: dnsLeak,
		CoverageGap: value.CoverageGap,
	}, nil
}

func ValidateReceipt(request Request, receipt Receipt) error {
	if receipt.Schema != ReceiptSchema || receipt.Name != MonitorName ||
		receipt.AttemptID != request.AttemptID || receipt.IPv6Required != request.VerifyIPv6 {
		return errors.New("boundary receipt identity rejected")
	}
	expected, err := Evaluate(request, Observation{
		AndroidVPNActive: receipt.AndroidVPNActive, AndroidIPv4Default: receipt.AndroidIPv4Default,
		AndroidIPv6Default: receipt.AndroidIPv6Default, AndroidDNSPinned: receipt.AndroidDNSPinned,
		AndroidBypassBlocked: receipt.AndroidBypassBlocked, VPSRoutePolicy: receipt.VPSRoutePolicy,
		VPSDNSPinned: receipt.VPSDNSPinned, VPSRelayBound: receipt.VPSRelayBound,
		VPSSourceGuard: receipt.VPSSourceGuard, VPSIPv6Policy: receipt.VPSIPv6Policy,
		CoverageGap: receipt.CoverageGap,
	})
	if err != nil || receipt != expected {
		return errors.New("boundary receipt categorical parity rejected")
	}
	return nil
}

func validateRequest(value Request) error {
	if value.Schema != RequestSchema || !validCampaignMode(value.CampaignMode) ||
		!attemptIDPattern.MatchString(value.AttemptID) || value.RelayPort == 0 {
		return errors.New("boundary request identity rejected")
	}
	for _, field := range []string{value.ADBPath, value.DeviceSerial, value.SSHPath, value.SSHAlias} {
		if !validPrivateSelector(field) {
			return errors.New("boundary request selector rejected")
		}
	}
	if !validProbeURL(value.ProbeURL) {
		return errors.New("boundary request probe rejected")
	}
	return nil
}

func validProbeURL(value string) bool {
	if len(value) > 2048 || !validPrivateSelector(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	if host == "" || net.ParseIP(host) != nil ||
		!strings.ContainsAny(strings.ToLower(host), "abcdefghijklmnopqrstuvwxyz") {
		return false
	}
	port := parsed.Port()
	if port == "" {
		return parsed.Host == host
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber >= 1 && portNumber <= 65535 && parsed.Host == net.JoinHostPort(host, port)
}

func validPrivateSelector(value string) bool {
	if value == "" || len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validCampaignMode(value string) bool {
	for _, mode := range []string{"Functional", "Stress", "Soak60m", "Soak90m", "Soak120m", "Soak12h"} {
		if value == mode {
			return true
		}
	}
	return false
}

func readBounded(reader io.Reader, declaredSize int64, maximum int64) ([]byte, error) {
	if reader == nil || declaredSize < 1 || declaredSize > maximum {
		return nil, errors.New("bounded input size rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, declaredSize+1))
	if err != nil || int64(len(raw)) != declaredSize {
		return nil, errors.New("bounded input read rejected")
	}
	return raw, nil
}

func decodeCategorical(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaximumResultBytes {
		return errors.New("categorical observation size rejected")
	}
	if err := assurance.DecodeStrict(bytes.NewReader(raw), target); err != nil {
		return errors.New("categorical observation decode rejected")
	}
	return nil
}
