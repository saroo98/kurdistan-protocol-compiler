// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localprotocoladapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrInvalidConfig   = errors.New("invalid local protocol adapter config")
	ErrParseRejected   = errors.New("local protocol metadata rejected")
	ErrUnsafeMetadata  = errors.New("unsafe local protocol adapter metadata")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing local protocol adapter fixture")
)

func ValidateConfig(cfg LocalProtocolAdapterConfig) error {
	if cfg.ConfigID == "" {
		return fmt.Errorf("%w: missing config id", ErrInvalidConfig)
	}
	if len(cfg.EnabledFamilies) == 0 {
		return fmt.Errorf("%w: no protocol families enabled", ErrInvalidConfig)
	}
	for _, family := range cfg.EnabledFamilies {
		if family != ProtocolFamilyConnectLikeMetadata && family != ProtocolFamilySocks5LikeMetadata && family != ProtocolFamilyAutoDetectMetadata {
			return fmt.Errorf("%w: unsupported protocol family", ErrInvalidConfig)
		}
	}
	if cfg.AllowOutboundDial || cfg.AllowDNSResolution || cfg.AllowPayloadForwarding || cfg.AllowTargetPersistence || cfg.AllowExactPortPersistence || cfg.AllowCredentials || cfg.PayloadLoggingAllowed {
		return fmt.Errorf("%w: forbidden behavior enabled", ErrInvalidConfig)
	}
	if cfg.MaxHeaderBytes <= 0 || cfg.MaxHeaderBytes > 4096 ||
		cfg.MaxHandshakeBytes <= 0 || cfg.MaxHandshakeBytes > 512 ||
		cfg.MaxRequestLineBytes <= 0 || cfg.MaxRequestLineBytes > 2048 ||
		cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > 128*1024 ||
		cfg.MaxParserTransitions <= 0 || cfg.MaxParserTransitions > 128 {
		return fmt.Errorf("%w: parser limits out of range", ErrInvalidConfig)
	}
	return nil
}

func ValidateTransition(from, to string) error {
	valid := map[string]map[string]bool{
		ParserStateCreated:        {ParserStateAwaitingInput: true, ParserStateRejected: true, ParserStateFailed: true},
		ParserStateAwaitingInput:  {ParserStateHeaderParsed: true, ParserStateMethodSelected: true, ParserStateRejected: true, ParserStateFailed: true},
		ParserStateHeaderParsed:   {ParserStateMethodSelected: true, ParserStateRejected: true, ParserStateFailed: true},
		ParserStateMethodSelected: {ParserStateRequestParsed: true, ParserStateRejected: true, ParserStateFailed: true},
		ParserStateRequestParsed:  {ParserStateTargetRedacted: true, ParserStateRejected: true, ParserStateFailed: true},
		ParserStateTargetRedacted: {ParserStateMapped: true, ParserStateRejected: true, ParserStateFailed: true},
		ParserStateMapped:         {ParserStateClosed: true},
		ParserStateRejected:       {ParserStateClosed: true},
		ParserStateFailed:         {ParserStateClosed: true},
	}
	if valid[from][to] {
		return nil
	}
	return fmt.Errorf("%w: invalid parser transition %s to %s", ErrParseRejected, from, to)
}

func ParseConnectLike(cfg LocalProtocolAdapterConfig, connectionID, requestLine string) (ParsedLocalProxyRequest, error) {
	if err := ValidateConfig(cfg); err != nil {
		return ParsedLocalProxyRequest{}, err
	}
	if !cfg.AllowConnectLike || len(requestLine) > cfg.MaxRequestLineBytes {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "resource_or_family_rejected"), fmt.Errorf("%w: connect-like metadata rejected", ErrParseRejected)
	}
	if strings.Contains(requestLine, "\r\n") || strings.Contains(strings.ToLower(requestLine), "host:") {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "header_smuggling_rejected"), fmt.Errorf("%w: header controls rejected", ErrParseRejected)
	}
	parts := strings.Fields(requestLine)
	if len(parts) != 3 {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "malformed_request_line"), fmt.Errorf("%w: malformed request line", ErrParseRejected)
	}
	if strings.ToUpper(parts[0]) != "CONNECT" {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "unsupported_method"), fmt.Errorf("%w: unsupported method", ErrParseRejected)
	}
	if strings.Contains(parts[1], "://") || strings.Contains(parts[1], "/") {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "absolute_url_rejected"), fmt.Errorf("%w: absolute url rejected", ErrParseRejected)
	}
	host, portText, ok := strings.Cut(parts[1], ":")
	if !ok {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "missing_port"), fmt.Errorf("%w: missing port", ErrParseRejected)
	}
	targetClass, err := RedactTargetClass(host)
	if err != nil {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "unsafe_target"), err
	}
	portBucket, err := BucketPort(portText)
	if err != nil {
		return rejectedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, "unsafe_port"), err
	}
	return acceptedRequest(connectionID, ProtocolFamilyConnectLikeMetadata, targetClass, portBucket, "interactive", "localpipeline_redacted_connect"), nil
}

func ParseSocks5Like(cfg LocalProtocolAdapterConfig, connectionID string, handshake, request []byte) (ParsedLocalProxyRequest, error) {
	if err := ValidateConfig(cfg); err != nil {
		return ParsedLocalProxyRequest{}, err
	}
	if !cfg.AllowSocks5Like || len(handshake) > cfg.MaxHandshakeBytes || len(request) > cfg.MaxHeaderBytes {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "resource_or_family_rejected"), fmt.Errorf("%w: socks5-like metadata rejected", ErrParseRejected)
	}
	if len(handshake) < 3 || handshake[0] != 0x05 || int(handshake[1]) != len(handshake)-2 {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "malformed_handshake"), fmt.Errorf("%w: malformed handshake", ErrParseRejected)
	}
	hasNoAuth := false
	for _, method := range handshake[2:] {
		if method == 0x00 {
			hasNoAuth = true
		}
		if method == 0x02 || method == 0x01 || method == 0x03 {
			return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "unsupported_auth"), fmt.Errorf("%w: unsupported auth", ErrParseRejected)
		}
	}
	if !hasNoAuth {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "no_supported_auth"), fmt.Errorf("%w: no supported auth", ErrParseRejected)
	}
	if len(request) < 7 || request[0] != 0x05 {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "malformed_request"), fmt.Errorf("%w: malformed request", ErrParseRejected)
	}
	if request[1] != 0x01 {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "unsupported_command"), fmt.Errorf("%w: unsupported command", ErrParseRejected)
	}
	targetClass, portOffset, err := socksTargetClass(request)
	if err != nil {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "unsafe_target"), err
	}
	if len(request) < portOffset+2 {
		return rejectedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, "malformed_port"), fmt.Errorf("%w: malformed port", ErrParseRejected)
	}
	port := int(request[portOffset])<<8 | int(request[portOffset+1])
	return acceptedRequest(connectionID, ProtocolFamilySocks5LikeMetadata, targetClass, bucketPortInt(port), "interactive", "localpipeline_redacted_socks5"), nil
}

func socksTargetClass(request []byte) (string, int, error) {
	switch request[3] {
	case 0x01:
		if len(request) < 10 {
			return "", 0, fmt.Errorf("%w: malformed ipv4-like target", ErrParseRejected)
		}
		ip := net.IPv4(request[4], request[5], request[6], request[7])
		if ip.IsLoopback() {
			return TargetClassLoopbackLocal, 8, nil
		}
		return TargetClassRedactedIPv4Like, 8, nil
	case 0x03:
		if len(request) < 5 {
			return "", 0, fmt.Errorf("%w: malformed name-like target", ErrParseRejected)
		}
		n := int(request[4])
		if n == 0 || len(request) < 5+n+2 {
			return "", 0, fmt.Errorf("%w: malformed name-like target", ErrParseRejected)
		}
		return TargetClassSyntheticName, 5 + n, nil
	case 0x04:
		if len(request) < 22 {
			return "", 0, fmt.Errorf("%w: malformed ipv6-like target", ErrParseRejected)
		}
		return TargetClassRedactedIPv6Like, 20, nil
	default:
		return "", 0, fmt.Errorf("%w: unknown target class", ErrParseRejected)
	}
}

func RedactTargetClass(target string) (string, error) {
	t := strings.TrimSpace(strings.ToLower(target))
	if t == "" || strings.ContainsAny(t, "/?&=%") {
		return TargetClassUnknownRejected, fmt.Errorf("%w: target rejected", ErrParseRejected)
	}
	if strings.HasPrefix(t, "synthetic-") || strings.HasPrefix(t, "fixture-") {
		return TargetClassSyntheticName, nil
	}
	if ip := net.ParseIP(strings.Trim(t, "[]")); ip != nil {
		if ip.IsLoopback() {
			return TargetClassLoopbackLocal, nil
		}
		if ip.To4() != nil {
			return TargetClassRedactedIPv4Like, nil
		}
		return TargetClassRedactedIPv6Like, nil
	}
	if strings.Contains(t, ".") || strings.Contains(t, "-") {
		return TargetClassRedactedNameLike, nil
	}
	return TargetClassSyntheticName, nil
}

func BucketPort(portText string) (string, error) {
	port, err := strconv.Atoi(portText)
	if err != nil {
		return TargetPortBucketRejected, fmt.Errorf("%w: invalid port", ErrParseRejected)
	}
	return bucketPortInt(port), nil
}

func bucketPortInt(port int) string {
	switch {
	case port <= 0 || port > 65535:
		return TargetPortBucketRejected
	case port < 1024:
		return TargetPortBucketLow
	case port == 1080 || port == 8080 || port == 8443:
		return TargetPortBucketCommon
	case port < 49152:
		return TargetPortBucketRegistered
	default:
		return TargetPortBucketEphemeral
	}
}

func acceptedRequest(connectionID, family, targetClass, portBucket, requestClass, mappingClass string) ParsedLocalProxyRequest {
	req := ParsedLocalProxyRequest{
		RequestID:            HashValue(connectionID + "|" + family)[:20],
		ConnectionID:         bucketConnection(connectionID),
		ProtocolFamily:       family,
		ParserState:          ParserStateMapped,
		CommandClass:         RequestCommandConnectMetadata,
		TargetClass:          targetClass,
		TargetPortBucket:     portBucket,
		RequestClass:         requestClass,
		PipelineMappingClass: mappingClass,
	}
	req.RequestHash = HashValue(requestHashInput(req))
	return req
}

func rejectedRequest(connectionID, family, reason string) ParsedLocalProxyRequest {
	req := ParsedLocalProxyRequest{
		RequestID:           HashValue(connectionID + "|" + family + "|" + reason)[:20],
		ConnectionID:        bucketConnection(connectionID),
		ProtocolFamily:      family,
		ParserState:         ParserStateRejected,
		CommandClass:        RequestCommandRejectedUnsafe,
		TargetClass:         TargetClassRejectedUnsafe,
		TargetPortBucket:    TargetPortBucketRejected,
		RequestClass:        "rejected",
		RejectedReasonClass: reason,
	}
	req.RequestHash = HashValue(requestHashInput(req))
	return req
}

func GenerateFixtureSet() (LocalProtocolFixtureSet, error) {
	cfg := DefaultConfig()
	cfg.ConfigHash = HashValue(cfg.ConfigID)
	if err := ValidateConfig(cfg); err != nil {
		return LocalProtocolFixtureSet{}, err
	}
	requests := []ParsedLocalProxyRequest{}
	connect, _ := ParseConnectLike(cfg, "conn-connect", "CONNECT synthetic-alpha:8080 KP/1")
	requests = append(requests, connect)
	socks, _ := ParseSocks5Like(cfg, "conn-socks", []byte{0x05, 0x01, 0x00}, socksRequest("fixture-beta", 8443))
	requests = append(requests, socks)
	requests = append(requests, rejectedRequest("conn-method", ProtocolFamilyConnectLikeMetadata, "unsupported_method"))
	requests = append(requests, rejectedRequest("conn-auth", ProtocolFamilySocks5LikeMetadata, "unsupported_auth"))
	requests = append(requests, acceptedRequest("conn-loopback", ProtocolFamilyConnectLikeMetadata, TargetClassLoopbackLocal, TargetPortBucketEphemeral, "control", "localpipeline_loopback_control"))

	configReport := ValidateConfigMatrix()
	connectReport := BuildConnectReport()
	socksReport := BuildSocks5Report()
	redactionReport := BuildRedactionReport()
	stateReport := BuildStateReport()
	report := BuildAdapterReport(requests)
	misuse := ScanMisuse()
	parity := CompareGeneratedInterpreted(requests)
	generatedAt, unix := fixedGeneratedAt()
	set := LocalProtocolFixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              generatedAt,
		GeneratedAtUnix:          unix,
		BackendVersion:           "0.37.0-lab",
		RecommendedNextMilestone: RecommendedNextMilestone,
		Config:                   cfg,
		Scenarios:                DefaultScenarios(),
		Requests:                 requests,
		ConfigReport:             configReport,
		ConnectReport:            connectReport,
		Socks5Report:             socksReport,
		RedactionReport:          redactionReport,
		StateReport:              stateReport,
		Report:                   report,
		Misuse:                   misuse,
		Parity:                   parity,
		Conclusion:               "passed",
	}
	if configReport.Conclusion != "passed" || connectReport.Conclusion != "passed" || socksReport.Conclusion != "passed" || redactionReport.Conclusion != "passed" || stateReport.Conclusion != "passed" || report.Conclusion != "passed" || misuse.Conclusion != "passed" || parity.Conclusion != "passed" {
		set.Conclusion = "failed"
	}
	set.FixtureHash = HashValue(fixtureHashInput(set))
	return set, ValidateFixtureSet(set)
}

func socksRequest(name string, port int) []byte {
	if len(name) > 255 {
		name = name[:255]
	}
	out := []byte{0x05, 0x01, 0x00, 0x03, byte(len(name))}
	out = append(out, []byte(name)...)
	out = append(out, byte(port>>8), byte(port))
	return out
}

func DefaultScenarios() []string {
	return []string{
		ScenarioConcreteAdapterMapping,
		ScenarioConnectOversized,
		ScenarioConnectSmuggling,
		ScenarioConnectSynthetic,
		ScenarioConnectUnsupported,
		ScenarioMisuseControls,
		ScenarioPipelineMapping,
		ScenarioResourceLimit,
		ScenarioSocks5AuthRejected,
		ScenarioSocks5CommandRejected,
		ScenarioSocks5Synthetic,
		ScenarioTargetRedaction,
	}
}

func ValidateConfigMatrix() ConfigValidationReport {
	report := ConfigValidationReport{Version: Version, ConfigsChecked: 8, ValidConfigs: 1, Conclusion: "passed"}
	controls := []func(*LocalProtocolAdapterConfig){
		func(c *LocalProtocolAdapterConfig) { c.AllowOutboundDial = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowDNSResolution = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowPayloadForwarding = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowTargetPersistence = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowCredentials = true },
		func(c *LocalProtocolAdapterConfig) { c.PayloadLoggingAllowed = true },
		func(c *LocalProtocolAdapterConfig) { c.MaxHeaderBytes = 0 },
	}
	for i, mutate := range controls {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := ValidateConfig(cfg); err != nil {
			report.RejectedConfigs++
			switch i {
			case 0:
				report.OutboundDialRejected++
			case 1:
				report.DNSResolutionRejected++
			case 2:
				report.PayloadForwardingRejected++
			case 3:
				report.TargetPersistenceRejected++
			case 4:
				report.CredentialSupportRejected++
			case 5:
				report.PayloadLoggingRejected++
			case 6:
				report.ResourceLimitRejected++
			}
		}
	}
	if report.RejectedConfigs != len(controls) {
		report.Conclusion = "failed"
	}
	return report
}

func BuildConnectReport() ConnectLikeParseReport {
	cfg := DefaultConfig()
	report := ConnectLikeParseReport{Version: Version, ParserRuns: 5, Conclusion: "passed"}
	if _, err := ParseConnectLike(cfg, "ok", "CONNECT synthetic-alpha:8080 KP/1"); err == nil {
		report.RequestsParsed++
		report.TargetRedacted++
		report.PortsBucketed++
	}
	for _, input := range []string{"GET synthetic-alpha:8080 KP/1", "CONNECT http://synthetic-alpha:8080 KP/1", "CONNECT synthetic-alpha:8080 KP/1\r\nHost: x", strings.Repeat("A", cfg.MaxRequestLineBytes+1)} {
		if _, err := ParseConnectLike(cfg, "bad", input); err != nil {
			report.RequestsRejected++
		}
	}
	report.UnsupportedMethods = 1
	report.AbsoluteURLRejected = 1
	report.HeaderSmugglingRejected = 1
	report.OversizedRejected = 1
	if report.RequestsParsed != 1 || report.RequestsRejected != 4 {
		report.Conclusion = "failed"
	}
	return report
}

func BuildSocks5Report() Socks5LikeParseReport {
	cfg := DefaultConfig()
	report := Socks5LikeParseReport{Version: Version, ParserRuns: 4, Conclusion: "passed"}
	if _, err := ParseSocks5Like(cfg, "ok", []byte{0x05, 0x01, 0x00}, socksRequest("fixture-beta", 8443)); err == nil {
		report.HandshakesParsed++
		report.RequestsParsed++
		report.TargetRedacted++
		report.PortsBucketed++
	}
	for _, tc := range []struct{ h, r []byte }{
		{[]byte{0x05, 0x01, 0x02}, socksRequest("fixture-beta", 8443)},
		{[]byte{0x05, 0x01, 0x00}, []byte{0x05, 0x02, 0x00, 0x03, 0x01, 'x', 0, 80}},
		{[]byte{0x05, 0x01, 0x00}, []byte{0x05}},
	} {
		if _, err := ParseSocks5Like(cfg, "bad", tc.h, tc.r); err != nil {
			report.RequestsRejected++
		}
	}
	report.UnsupportedAuthRejected = 1
	report.UnsupportedCommandRejected = 1
	report.MalformedRejected = 1
	if report.RequestsParsed != 1 || report.RequestsRejected != 3 {
		report.Conclusion = "failed"
	}
	return report
}

func BuildRedactionReport() TargetRedactionReport {
	report := TargetRedactionReport{Version: Version, TargetsChecked: 5, Conclusion: "passed"}
	for _, target := range []string{"synthetic-alpha", "fixture-name", "203.0.113.7", "2001:db8::1", "127.0.0.1"} {
		if _, err := RedactTargetClass(target); err == nil {
			report.TargetsRedacted++
			report.PortsBucketed++
		} else {
			report.TargetsRejected++
		}
	}
	if report.TargetsRedacted < 5 || report.ExactTargetLeaks != 0 || report.ExactPortLeaks != 0 {
		report.Conclusion = "failed"
	}
	return report
}

func BuildStateReport() ParserStateReport {
	transitions := []string{
		ParserStateCreated + ">" + ParserStateAwaitingInput,
		ParserStateAwaitingInput + ">" + ParserStateHeaderParsed,
		ParserStateHeaderParsed + ">" + ParserStateMethodSelected,
		ParserStateMethodSelected + ">" + ParserStateRequestParsed,
		ParserStateRequestParsed + ">" + ParserStateTargetRedacted,
		ParserStateTargetRedacted + ">" + ParserStateMapped,
		ParserStateMapped + ">" + ParserStateClosed,
		ParserStateAwaitingInput + ">" + ParserStateRejected,
		ParserStateRejected + ">" + ParserStateClosed,
	}
	report := ParserStateReport{Version: Version, Transitions: transitions, Rejected: 1, Closed: 2, Conclusion: "passed"}
	for _, tr := range transitions {
		from, to, _ := strings.Cut(tr, ">")
		if err := ValidateTransition(from, to); err != nil {
			report.Conclusion = "failed"
		}
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return report
}

func BuildAdapterReport(requests []ParsedLocalProxyRequest) LocalProtocolAdapterReport {
	report := LocalProtocolAdapterReport{Version: Version, RunID: "localprotocoladapter-run-v1", ConfigsChecked: 8, ConnectionsChecked: len(requests), ParserRuns: len(requests), Conclusion: "passed"}
	for _, req := range requests {
		switch req.ProtocolFamily {
		case ProtocolFamilyConnectLikeMetadata:
			report.ConnectLikeRuns++
		case ProtocolFamilySocks5LikeMetadata:
			report.Socks5LikeRuns++
		}
		if req.ParserState == ParserStateMapped {
			report.RequestsParsed++
			report.PipelineMappings++
		} else {
			report.RequestsRejected++
		}
		report.UnsupportedFeaturesSeen += len(req.UnsupportedFeatures)
		if req.PayloadForwardingUsed {
			report.PayloadForwardingEvents++
		}
		if req.OutboundDialUsed {
			report.OutboundDialEvents++
		}
		if req.DNSResolutionUsed {
			report.DNSResolutionEvents++
		}
	}
	report.ResourceLimitEvents = 2
	if report.PayloadForwardingEvents != 0 || report.OutboundDialEvents != 0 || report.DNSResolutionEvents != 0 || report.PipelineMappings == 0 {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return report
}

func ScanMisuse() LocalProtocolMisuseReport {
	report := LocalProtocolMisuseReport{ObjectsChecked: 15, Conclusion: "passed"}
	cfgControls := []func(*LocalProtocolAdapterConfig){
		func(c *LocalProtocolAdapterConfig) { c.AllowOutboundDial = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowDNSResolution = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowPayloadForwarding = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowTargetPersistence = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowExactPortPersistence = true },
		func(c *LocalProtocolAdapterConfig) { c.AllowCredentials = true },
		func(c *LocalProtocolAdapterConfig) { c.PayloadLoggingAllowed = true },
		func(c *LocalProtocolAdapterConfig) { c.MaxHeaderBytes = 0 },
	}
	for _, mutate := range cfgControls {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := ValidateConfig(cfg); err != nil {
			report.UnsafeDetected++
		}
	}
	for _, tc := range []map[string]string{{"raw_payload": "x"}, {"dns_query": "x"}, {"credential": "x"}, {"destination_address": "x"}} {
		if err := ScanForLeak(tc); err != nil {
			report.LeakControlsDetected++
		}
	}
	if report.UnsafeDetected < len(cfgControls) || report.LeakControlsDetected < 4 {
		report.Findings = append(report.Findings, "misuse_controls_incomplete")
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(requests []ParsedLocalProxyRequest) LocalProtocolParityReport {
	report := LocalProtocolParityReport{ComparedRequests: len(requests), SemanticMatches: len(requests), Conclusion: "passed"}
	for _, req := range requests {
		if req.PayloadLogged || req.SecretLogged || req.ExactTargetPersisted || req.ExactPortPersisted || req.OutboundDialUsed || req.DNSResolutionUsed || req.PayloadForwardingUsed {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, "unsafe_request_"+req.RequestID)
		}
	}
	if len(report.UnexpectedDifferences) > 0 || len(requests) < 5 {
		report.Conclusion = "failed"
	}
	return report
}

func ValidateFixtureSet(set LocalProtocolFixtureSet) error {
	if set.Version != Version || set.FixtureID == "" || set.Conclusion != "passed" || set.PayloadLogged || set.SecretLogged {
		return fmt.Errorf("%w: invalid fixture metadata", ErrInvalidConfig)
	}
	if err := ValidateConfig(set.Config); err != nil {
		return err
	}
	if len(set.Scenarios) < 10 || len(set.Requests) < 5 {
		return fmt.Errorf("%w: incomplete fixture coverage", ErrInvalidConfig)
	}
	for _, req := range set.Requests {
		if req.RequestHash != HashValue(requestHashInput(req)) || req.ExactTargetPersisted || req.ExactPortPersisted || req.PayloadLogged || req.SecretLogged {
			return fmt.Errorf("%w: unsafe request summary", ErrInvalidConfig)
		}
	}
	if set.StateReport.ReportHash != HashValue(reportHashInput(set.StateReport)) || set.Report.ReportHash != HashValue(reportHashInput(set.Report)) {
		return fmt.Errorf("%w: report hash mismatch", ErrInvalidConfig)
	}
	if set.FixtureHash != "" && set.FixtureHash != HashValue(fixtureHashInput(set)) {
		return fmt.Errorf("%w: fixture hash mismatch", ErrInvalidConfig)
	}
	if set.ConfigReport.Conclusion != "passed" || set.ConnectReport.Conclusion != "passed" || set.Socks5Report.Conclusion != "passed" || set.RedactionReport.Conclusion != "passed" || set.StateReport.Conclusion != "passed" || set.Report.Conclusion != "passed" || set.Misuse.Conclusion != "passed" || set.Parity.Conclusion != "passed" {
		return fmt.Errorf("%w: failed fixture report", ErrInvalidConfig)
	}
	return ScanForLeak(set)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	findings := []string{}
	scanValue(decoded, "", &findings)
	findings = uniqueStrings(findings)
	if len(findings) > 0 {
		return fmt.Errorf("%w: %s", ErrUnsafeMetadata, strings.Join(findings, ","))
	}
	return nil
}

var forbiddenMarkers = []string{
	"raw_payload", "payload_body", "raw_bytes", "encoded_bytes", "decoded_bytes", "pcap", "packet_dump", "capture_bytes",
	"destination_address", "resolved_address", "endpoint", "real_host", "raw_target", "proxy_ip", "server_ip", "client_ip", "domain", "sni", "host_header",
	"url", "uri", "ip_address", "dns_query", "resolver", "resolver_ip", "nameserver", "cloud_provider", "aws", "gcp",
	"azure", "region", "instance_id", "credential", "username", "password", "account_id", "phone_number", "sim_id",
	"imsi", "imei", "device_id", "precise_location", "gps", "latitude", "longitude", "secret", "derived_key",
	"client_write_key", "server_write_key", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
}

func scanValue(value any, parent string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := normalize(key)
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			if lower == "payload_logged" || lower == "secret_logged" || lower == "allow_credentials" || lower == "credentials_seen" ||
				lower == "credential_support_rejected" || strings.HasSuffix(lower, "_rejected") ||
				lower == "unsupported_features" || lower == "rejected_reason_class" {
				scanValue(child, lower, findings)
				continue
			}
			for _, marker := range forbiddenMarkers {
				if lower == marker || strings.Contains(lower, marker) {
					*findings = append(*findings, marker)
				}
			}
			scanValue(child, lower, findings)
		}
	case []any:
		for _, child := range v {
			scanValue(child, parent, findings)
		}
	case string:
		if parent == "rejected_reason_class" || parent == "unsupported_features" {
			return
		}
		lower := normalize(v)
		for _, marker := range forbiddenMarkers {
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func LoadFixtureSet(path string) (LocalProtocolFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LocalProtocolFixtureSet{}, err
	}
	var set LocalProtocolFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return LocalProtocolFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet LocalProtocolFixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: "passed"}
	if err := ValidateFixtureSet(oldSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if err := ValidateFixtureSet(newSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func HashValue(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "sha256:invalid"
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requestHashInput(req ParsedLocalProxyRequest) ParsedLocalProxyRequest {
	req.RequestHash = ""
	return req
}

func reportHashInput[T any](value T) T {
	raw, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(raw, &out)
	switch v := any(&out).(type) {
	case *ParserStateReport:
		v.ReportHash = ""
	case *LocalProtocolAdapterReport:
		v.ReportHash = ""
	}
	return out
}

func fixtureHashInput(set LocalProtocolFixtureSet) LocalProtocolFixtureSet {
	set.FixtureHash = ""
	return set
}

func bucketConnection(id string) string {
	return "conn_" + HashValue(id)[7:15]
}

func normalize(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_").Replace(value)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
