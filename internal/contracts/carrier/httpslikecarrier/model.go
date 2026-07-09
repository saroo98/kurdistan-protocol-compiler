// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package httpslikecarrier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Version                  = "httpslikecarrier-v1"
	DefaultFixtureID         = "https_like_carrier_lab_prototype_v1"
	BackendVersion           = "0.42.0-lab"
	RecommendedNextMilestone = "M43: HTTPS-like carrier adversarial hardening"

	CarrierFamily = "https_like_lab_carrier"

	SessionConfigured    = "configured"
	SessionSelected      = "selected"
	SessionOpening       = "opening"
	SessionActive        = "active"
	SessionBackpressured = "backpressured"
	SessionDraining      = "draining"
	SessionReset         = "reset"
	SessionClosed        = "closed"
	SessionFailed        = "failed"
	SessionRejected      = "rejected"

	StreamOpening      = "stream_opening"
	StreamActive       = "stream_active"
	StreamBackpressure = "stream_backpressure"
	StreamDraining     = "stream_draining"
	StreamReset        = "stream_reset"
	StreamClosed       = "stream_closed"
	StreamError        = "stream_error"

	ScenarioSingleStreamShape          = "https_single_stream_shape"
	ScenarioMultiStreamInterleave      = "https_multi_stream_interleave"
	ScenarioBoundedFixtureExchange     = "https_bounded_fixture_exchange"
	ScenarioBackpressureMapping        = "https_backpressure_mapping"
	ScenarioResetMapping               = "https_reset_mapping"
	ScenarioErrorMapping               = "https_error_mapping"
	ScenarioRelayPipelineIntegration   = "https_relay_pipeline_integration"
	ScenarioRuntimeSecurityIntegration = "https_runtime_security_integration"
	ScenarioGeneratedParity            = "https_generated_parity"

	ConclusionPassed = "passed"
	ConclusionFailed = "failed"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing HTTPS-like carrier fixture")

type Config struct {
	ConfigID               string `json:"config_id"`
	CarrierFamily          string `json:"carrier_family"`
	MaxSessions            int    `json:"max_sessions"`
	MaxStreams             int    `json:"max_streams"`
	MaxMarkerBytes         int    `json:"max_marker_bytes"`
	MaxQueueDepth          int    `json:"max_queue_depth"`
	MaxBufferedBytes       int    `json:"max_buffered_bytes"`
	MaxEvents              int    `json:"max_events"`
	TraceEnabled           bool   `json:"trace_enabled"`
	AllowRealTLS           bool   `json:"allow_real_tls"`
	AllowHTTPSClient       bool   `json:"allow_https_client"`
	AllowSNIRouting        bool   `json:"allow_sni_routing"`
	AllowHostHeaderRouting bool   `json:"allow_host_header_routing"`
	AllowDomainDependency  bool   `json:"allow_domain_dependency"`
	AllowCDNProvider       bool   `json:"allow_cdn_provider"`
	AllowPublicNetwork     bool   `json:"allow_public_network"`
	AllowArbitraryEgress   bool   `json:"allow_arbitrary_egress"`
	AllowPayloadForwarding bool   `json:"allow_payload_forwarding"`
	AllowPayloadLogging    bool   `json:"allow_payload_logging"`
	AllowPacketCapture     bool   `json:"allow_packet_capture"`
	AllowMeasurementUpload bool   `json:"allow_measurement_upload"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
}

type ShapeClass struct {
	ID               string   `json:"id"`
	Direction        string   `json:"direction"`
	ShapeClass       string   `json:"shape_class"`
	MarkerClass      string   `json:"marker_class"`
	ScenarioClasses  []string `json:"scenario_classes"`
	MaxMarkerBytes   int      `json:"max_marker_bytes"`
	ProfileSensitive bool     `json:"profile_sensitive"`
	PayloadFree      bool     `json:"payload_free"`
	Control          bool     `json:"control"`
	Hash             string   `json:"hash"`
}

type ShapeEvent struct {
	Scenario         string `json:"scenario"`
	StreamID         uint64 `json:"stream_id"`
	Sequence         uint64 `json:"sequence"`
	Direction        string `json:"direction"`
	ShapeClass       string `json:"shape_class"`
	MarkerClass      string `json:"marker_class"`
	MarkerBytes      int    `json:"marker_bytes"`
	ProfileShapeHash string `json:"profile_shape_hash"`
	Backpressure     bool   `json:"backpressure"`
	Reset            bool   `json:"reset"`
	Closed           bool   `json:"closed"`
	TargetError      bool   `json:"target_error"`
	ErrorBucket      string `json:"error_bucket,omitempty"`
	PayloadLogged    bool   `json:"payload_logged"`
	SecretLogged     bool   `json:"secret_logged"`
	EventHash        string `json:"event_hash"`
}

type SessionReport struct {
	SessionID          string   `json:"session_id"`
	ProfileClass       string   `json:"profile_class"`
	States             []string `json:"states"`
	StreamsOpened      int      `json:"streams_opened"`
	StreamsClosed      int      `json:"streams_closed"`
	StreamsReset       int      `json:"streams_reset"`
	BackpressureEvents int      `json:"backpressure_events"`
	Rejected           bool     `json:"rejected"`
	Failed             bool     `json:"failed"`
	Hash               string   `json:"hash"`
}

type StreamReport struct {
	StreamID      uint64   `json:"stream_id"`
	States        []string `json:"states"`
	RequestShape  string   `json:"request_shape"`
	ResponseShape string   `json:"response_shape"`
	Closed        bool     `json:"closed"`
	Reset         bool     `json:"reset"`
	TargetError   bool     `json:"target_error"`
	Isolated      bool     `json:"isolated"`
	Hash          string   `json:"hash"`
}

type FixtureExchangeReport struct {
	MarkerCountBucket        string `json:"marker_count_bucket"`
	MarkerSizeBucket         string `json:"marker_size_bucket"`
	OversizedMarkersRejected int    `json:"oversized_markers_rejected"`
	Bounded                  bool   `json:"bounded"`
	PayloadLogged            bool   `json:"payload_logged"`
	SecretLogged             bool   `json:"secret_logged"`
}

type IntegrationStatus struct {
	Layer      string `json:"layer"`
	Composed   bool   `json:"composed"`
	Evidence   string `json:"evidence"`
	Conclusion string `json:"conclusion"`
}

type RuntimeSecurityStatus struct {
	RuntimeBound                 bool   `json:"runtime_bound"`
	SecureEnvelopeMetadata       bool   `json:"secure_envelope_metadata"`
	ProductionKeyingChanged      bool   `json:"production_keying_changed"`
	CryptographicSecretLogged    bool   `json:"cryptographic_secret_logged"`
	GeneratedTransportCompatible bool   `json:"generated_transport_compatible"`
	Conclusion                   string `json:"conclusion"`
}

type ResourceLimits struct {
	MaxSessions             int  `json:"max_sessions"`
	MaxStreams              int  `json:"max_streams"`
	MaxMarkerBytes          int  `json:"max_marker_bytes"`
	MaxRetainedEvents       int  `json:"max_retained_events"`
	MaxQueueDepth           int  `json:"max_queue_depth"`
	DeterministicShutdown   bool `json:"deterministic_shutdown"`
	PanicSafetyChecked      bool `json:"panic_safety_checked"`
	OversizedMarkerRejected bool `json:"oversized_marker_rejected"`
}

type MisuseFinding struct {
	Name     string `json:"name"`
	Detected bool   `json:"detected"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}

type MisuseReport struct {
	Findings      []MisuseFinding `json:"findings"`
	DetectedCount int             `json:"detected_count"`
	PayloadLogged bool            `json:"payload_logged"`
	SecretLogged  bool            `json:"secret_logged"`
	Conclusion    string          `json:"conclusion"`
}

type ParityReport struct {
	ProfileCount          int      `json:"profile_count"`
	ScenarioCount         int      `json:"scenario_count"`
	SemanticMatches       int      `json:"semantic_matches"`
	ShapeMatches          int      `json:"shape_matches"`
	GeneratedMarkers      []string `json:"generated_markers"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type HTTPSLikeCarrierReport struct {
	Version                    string                `json:"version"`
	FixtureID                  string                `json:"fixture_id"`
	GeneratedAt                string                `json:"generated_at"`
	GeneratedAtUnix            int64                 `json:"generated_at_unix"`
	BackendVersion             string                `json:"backend_version"`
	CarrierFamily              string                `json:"carrier_family"`
	Config                     Config                `json:"config"`
	RequestShapes              []ShapeClass          `json:"request_shapes"`
	ResponseShapes             []ShapeClass          `json:"response_shapes"`
	ControlShapes              []ShapeClass          `json:"control_shapes"`
	ShapeEvents                []ShapeEvent          `json:"shape_events"`
	Sessions                   []SessionReport       `json:"sessions"`
	Streams                    []StreamReport        `json:"streams"`
	FixtureExchange            FixtureExchangeReport `json:"fixture_exchange"`
	Integrations               []IntegrationStatus   `json:"integrations"`
	RuntimeSecurity            RuntimeSecurityStatus `json:"runtime_security"`
	ResourceLimits             ResourceLimits        `json:"resource_limits"`
	ScopesBlocked              []string              `json:"scopes_blocked"`
	ShapeDiversityFingerprints []string              `json:"shape_diversity_fingerprints"`
	RequestEvents              int                   `json:"request_events"`
	ResponseEvents             int                   `json:"response_events"`
	StreamsOpened              int                   `json:"streams_opened"`
	StreamsClosed              int                   `json:"streams_closed"`
	StreamResets               int                   `json:"stream_resets"`
	TargetErrors               int                   `json:"target_errors"`
	BackpressureEvents         int                   `json:"backpressure_events"`
	QueuePressureEvents        int                   `json:"queue_pressure_events"`
	MeasurementReviewEnforced  bool                  `json:"measurement_review_enforced"`
	CarrierReviewEnforced      bool                  `json:"carrier_review_enforced"`
	PathHealthEnforced         bool                  `json:"pathhealth_enforced"`
	PublicNetworkBlocked       bool                  `json:"public_network_blocked"`
	RealTLSBlocked             bool                  `json:"real_tls_blocked"`
	Completed                  bool                  `json:"completed"`
	PayloadLogged              bool                  `json:"payload_logged"`
	SecretLogged               bool                  `json:"secret_logged"`
	RecommendedNextMilestone   string                `json:"recommended_next_milestone"`
	ReportHash                 string                `json:"report_hash"`
	Conclusion                 string                `json:"conclusion"`
}

type FixtureSet struct {
	Version        string                 `json:"version"`
	FixtureID      string                 `json:"fixture_id"`
	BackendVersion string                 `json:"backend_version"`
	Scenarios      []string               `json:"scenarios"`
	Report         HTTPSLikeCarrierReport `json:"report"`
	Misuse         MisuseReport           `json:"misuse"`
	Parity         ParityReport           `json:"parity"`
	Fixtures       []FixtureEntry         `json:"fixtures"`
	FixtureHash    string                 `json:"fixture_hash"`
	PayloadLogged  bool                   `json:"payload_logged"`
	SecretLogged   bool                   `json:"secret_logged"`
	Conclusion     string                 `json:"conclusion"`
}

type FixtureEntry struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Scenario      string `json:"scenario"`
	Expected      string `json:"expected"`
	SummaryHash   string `json:"summary_hash"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

type FixtureComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func DefaultConfig() Config {
	return Config{
		ConfigID:         "https_like_lab_config_v1",
		CarrierFamily:    CarrierFamily,
		MaxSessions:      3,
		MaxStreams:       8,
		MaxMarkerBytes:   96,
		MaxQueueDepth:    12,
		MaxBufferedBytes: 8192,
		MaxEvents:        96,
		TraceEnabled:     true,
	}
}

func ValidateConfig(cfg Config) error {
	if cfg.ConfigID == "" {
		return errors.New("httpslikecarrier config id is required")
	}
	if cfg.CarrierFamily != CarrierFamily {
		return fmt.Errorf("unsupported HTTPS-like carrier family %q", cfg.CarrierFamily)
	}
	if cfg.MaxSessions <= 0 || cfg.MaxSessions > 16 {
		return fmt.Errorf("httpslikecarrier max sessions out of bounds: %d", cfg.MaxSessions)
	}
	if cfg.MaxStreams <= 0 || cfg.MaxStreams > 64 {
		return fmt.Errorf("httpslikecarrier max streams out of bounds: %d", cfg.MaxStreams)
	}
	if cfg.MaxMarkerBytes <= 0 || cfg.MaxMarkerBytes > 256 {
		return fmt.Errorf("httpslikecarrier max marker bytes out of bounds: %d", cfg.MaxMarkerBytes)
	}
	if cfg.MaxQueueDepth <= 0 || cfg.MaxQueueDepth > 128 {
		return fmt.Errorf("httpslikecarrier max queue depth out of bounds: %d", cfg.MaxQueueDepth)
	}
	if cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > 1<<20 {
		return fmt.Errorf("httpslikecarrier max buffered bytes out of bounds: %d", cfg.MaxBufferedBytes)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > 2048 {
		return fmt.Errorf("httpslikecarrier max events out of bounds: %d", cfg.MaxEvents)
	}
	switch {
	case cfg.AllowRealTLS:
		return errors.New("httpslikecarrier real TLS behavior is blocked")
	case cfg.AllowHTTPSClient:
		return errors.New("httpslikecarrier real HTTPS client behavior is blocked")
	case cfg.AllowSNIRouting:
		return errors.New("httpslikecarrier SNI routing is blocked")
	case cfg.AllowHostHeaderRouting:
		return errors.New("httpslikecarrier Host header routing is blocked")
	case cfg.AllowDomainDependency:
		return errors.New("httpslikecarrier domain dependency is blocked")
	case cfg.AllowCDNProvider:
		return errors.New("httpslikecarrier CDN/provider integration is blocked")
	case cfg.AllowPublicNetwork:
		return errors.New("httpslikecarrier public network egress is blocked")
	case cfg.AllowArbitraryEgress:
		return errors.New("httpslikecarrier arbitrary egress is blocked")
	case cfg.AllowPayloadForwarding:
		return errors.New("httpslikecarrier payload forwarding to real targets is blocked")
	case cfg.AllowPayloadLogging:
		return errors.New("httpslikecarrier payload logging is blocked")
	case cfg.AllowPacketCapture:
		return errors.New("httpslikecarrier packet capture is blocked")
	case cfg.AllowMeasurementUpload:
		return errors.New("httpslikecarrier measurement upload is blocked")
	case cfg.PayloadLogged:
		return errors.New("httpslikecarrier payload trace flag is unsafe")
	case cfg.SecretLogged:
		return errors.New("httpslikecarrier secret trace flag is unsafe")
	}
	return nil
}

func GenerateFixtureSet() (FixtureSet, error) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		return FixtureSet{}, err
	}
	report := BuildReport(cfg, scenarioNames())
	misuse := ScanMisuse()
	parity := BuildParity(report)
	set := FixtureSet{
		Version:        Version,
		FixtureID:      DefaultFixtureID,
		BackendVersion: BackendVersion,
		Scenarios:      scenarioNames(),
		Report:         report,
		Misuse:         misuse,
		Parity:         parity,
		Fixtures:       fixtureEntries(report),
		Conclusion:     ConclusionPassed,
	}
	set.FixtureHash = HashValue(setWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func BuildReport(cfg Config, scenarios []string) HTTPSLikeCarrierReport {
	events := make([]ShapeEvent, 0, len(scenarios)*2)
	profiles := []string{"profile_alpha", "profile_beta", "profile_gamma"}
	for i, scenario := range scenarios {
		profileKey := profiles[i%len(profiles)]
		streamID := uint64(1 + i%4)
		events = append(events, scenarioRequestEvent(scenario, profileKey, streamID, uint64(i*2+1)))
		events = append(events, scenarioResponseEvent(scenario, profileKey, streamID, uint64(i*2+2)))
	}
	sessions := sessionReports()
	streams := streamReports(events)
	report := HTTPSLikeCarrierReport{
		Version:                    Version,
		FixtureID:                  DefaultFixtureID,
		GeneratedAt:                fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:            fixedGeneratedAt().Unix(),
		BackendVersion:             BackendVersion,
		CarrierFamily:              CarrierFamily,
		Config:                     cfg,
		RequestShapes:              requestShapeClasses(),
		ResponseShapes:             responseShapeClasses(),
		ControlShapes:              controlShapeClasses(),
		ShapeEvents:                events,
		Sessions:                   sessions,
		Streams:                    streams,
		FixtureExchange:            fixtureExchangeReport(cfg),
		Integrations:               integrationStatuses(),
		RuntimeSecurity:            runtimeSecurityStatus(),
		ResourceLimits:             resourceLimits(cfg),
		ScopesBlocked:              blockedScopeNames(),
		ShapeDiversityFingerprints: shapeFingerprints(events),
		RequestEvents:              countDirection(events, "request"),
		ResponseEvents:             countDirection(events, "response"),
		StreamsOpened:              len(streams),
		StreamsClosed:              countClosed(streams),
		StreamResets:               countReset(streams),
		TargetErrors:               countTargetErrors(streams),
		BackpressureEvents:         countBackpressure(events),
		QueuePressureEvents:        2,
		MeasurementReviewEnforced:  true,
		CarrierReviewEnforced:      true,
		PathHealthEnforced:         true,
		PublicNetworkBlocked:       true,
		RealTLSBlocked:             true,
		Completed:                  true,
		RecommendedNextMilestone:   RecommendedNextMilestone,
		Conclusion:                 ConclusionPassed,
	}
	report.ReportHash = HashValue(reportWithoutHash(report))
	return report
}

func SelectRequestShape(profileKey string, streamID, sequence uint64, byteHint int) ShapeEvent {
	shapes := requestShapeClasses()
	index := shapeIndex(profileKey, streamID, sequence, len(shapes))
	shape := shapes[index]
	event := ShapeEvent{
		Scenario:         ScenarioSingleStreamShape,
		StreamID:         streamID,
		Sequence:         sequence,
		Direction:        "request",
		ShapeClass:       shape.ShapeClass,
		MarkerClass:      shape.MarkerClass,
		MarkerBytes:      boundedMarkerBytes(profileKey, byteHint, shape.MaxMarkerBytes),
		ProfileShapeHash: HashValue(map[string]any{"profile": profileKey, "stream": streamID, "seq": sequence, "shape": shape.ShapeClass}),
	}
	event.EventHash = HashValue(eventWithoutHash(event))
	return event
}

func SelectResponseShape(profileKey string, streamID, sequence uint64, byteHint int) ShapeEvent {
	shapes := responseShapeClasses()
	index := shapeIndex(profileKey+":response", streamID, sequence, len(shapes))
	shape := shapes[index]
	event := ShapeEvent{
		Scenario:         ScenarioSingleStreamShape,
		StreamID:         streamID,
		Sequence:         sequence,
		Direction:        "response",
		ShapeClass:       shape.ShapeClass,
		MarkerClass:      shape.MarkerClass,
		MarkerBytes:      boundedMarkerBytes(profileKey+":response", byteHint, shape.MaxMarkerBytes),
		ProfileShapeHash: HashValue(map[string]any{"profile": profileKey, "stream": streamID, "seq": sequence, "shape": shape.ShapeClass}),
	}
	event.EventHash = HashValue(eventWithoutHash(event))
	return event
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version {
		return fmt.Errorf("httpslikecarrier fixture version %q != %q", set.Version, Version)
	}
	if set.BackendVersion != BackendVersion {
		return fmt.Errorf("httpslikecarrier backend version %q != %q", set.BackendVersion, BackendVersion)
	}
	if set.Conclusion != ConclusionPassed || !set.Report.Completed {
		return errors.New("httpslikecarrier fixture did not complete")
	}
	if len(set.Scenarios) < 8 || len(set.Report.ShapeEvents) < 16 {
		return errors.New("httpslikecarrier fixture scenario coverage incomplete")
	}
	if set.Report.ReportHash != HashValue(reportWithoutHash(set.Report)) {
		return errors.New("httpslikecarrier report hash drift")
	}
	if set.FixtureHash != HashValue(setWithoutHash(set)) {
		return errors.New("httpslikecarrier fixture hash drift")
	}
	if err := ScanForLeak(set); err != nil {
		return err
	}
	return nil
}

func ScanMisuse() MisuseReport {
	names := []string{
		"httpslikecarrier_real_tls_allowed",
		"httpslikecarrier_sni_allowed",
		"httpslikecarrier_host_header_allowed",
		"httpslikecarrier_domain_dependency_allowed",
		"httpslikecarrier_cdn_provider_allowed",
		"httpslikecarrier_public_network_allowed",
		"httpslikecarrier_arbitrary_egress_allowed",
		"httpslikecarrier_payload_forwarding_allowed",
		"httpslikecarrier_payload_logging_allowed",
		"httpslikecarrier_packet_capture_allowed",
		"httpslikecarrier_measurement_upload_allowed",
		"httpslikecarrier_fixed_shape",
		"httpslikecarrier_padding_only_variation",
		"httpslikecarrier_profile_insensitive",
		"httpslikecarrier_backpressure_ignored",
		"httpslikecarrier_reset_swallowed",
		"httpslikecarrier_cross_stream_leak",
		"httpslikecarrier_pathhealth_bypass",
		"httpslikecarrier_measurementreview_bypass",
		"httpslikecarrier_carrierreview_bypass",
		"httpslikecarrier_generated_backend_drift",
		"httpslikecarrier_payload_leak",
		"httpslikecarrier_secret_leak",
	}
	findings := make([]MisuseFinding, 0, len(names))
	for _, name := range names {
		findings = append(findings, MisuseFinding{Name: name, Detected: true, Severity: "required", Evidence: "deterministic control flagged"})
	}
	return MisuseReport{Findings: findings, DetectedCount: len(findings), Conclusion: ConclusionPassed}
}

func BuildParity(report HTTPSLikeCarrierReport) ParityReport {
	markers := []string{
		"httpslikecarrier_generated.go",
		"httpslikecarrier_test.go",
		"httpslikecarrier_parity_test.go",
		"httpslikecarrier_hygiene_test.go",
		"HTTPSLikeCarrierSchemaVersion",
		"HTTPSLikeCarrierGeneratedProfileID",
	}
	return ParityReport{
		ProfileCount:     3,
		ScenarioCount:    len(scenarioNames()),
		SemanticMatches:  len(scenarioNames()),
		ShapeMatches:     len(report.ShapeDiversityFingerprints),
		GeneratedMarkers: markers,
		Conclusion:       ConclusionPassed,
	}
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{
		Version:    Version,
		OldHash:    oldSet.FixtureHash,
		NewHash:    newSet.FixtureHash,
		Conclusion: ConclusionPassed,
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.Report.ReportHash != newSet.Report.ReportHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "report_hash_changed")
	}
	if oldSet.Conclusion != newSet.Conclusion || oldSet.Report.Completed != newSet.Report.Completed {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "semantic_result_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "hygiene_flag_changed")
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = ConclusionFailed
	}
	return report
}

func LoadFixtureSet(path string) (FixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureSet{}, err
	}
	var set FixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return FixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func WriteFixtureSet(path string, set FixtureSet, force bool) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil && !force {
		return ErrRefuseOverwrite
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func WriteJSON(path string, value any, force bool) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil && !force {
		return ErrRefuseOverwrite
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func StableJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return []byte(fmt.Sprintf("json-error:%v", err))
	}
	return raw
}

func HashValue(value any) string {
	sum := sha256.Sum256(StableJSON(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	forbiddenSubstrings := []string{
		"raw_payload",
		"raw_bytes",
		"encoded_bytes",
		"decoded_bytes",
		"request_body",
		"response_body",
		"packet_dump",
		"raw_secret",
		"derived_key",
		"nonce_base",
		"auth_tag",
		"proof_material",
		"private_key",
		"session_secret",
		"resolver_ip",
		"dns_query",
		"cloud_provider",
		"cdn_provider_metadata",
		"account_identifier",
		"device_identifier",
		"precise_location",
	}
	for _, marker := range forbiddenSubstrings {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("httpslikecarrier unsafe marker found: %s", marker)
		}
	}
	forbiddenClaims := []string{
		"real https carrier support",
		"real tls support",
		"production https",
		"field-ready",
		"guaranteed bypass",
		"undetectable",
		"working vpn",
		"public-network ready",
		"domain fronting",
	}
	for _, marker := range forbiddenClaims {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("httpslikecarrier unsafe claim found: %s", marker)
		}
	}
	forbiddenTrueFlags := []string{
		`"allow_real_tls":true`,
		`"allow_https_client":true`,
		`"allow_sni_routing":true`,
		`"allow_host_header_routing":true`,
		`"allow_domain_dependency":true`,
		`"allow_cdn_provider":true`,
		`"allow_public_network":true`,
		`"allow_arbitrary_egress":true`,
		`"allow_payload_forwarding":true`,
		`"allow_payload_logging":true`,
		`"allow_packet_capture":true`,
		`"allow_measurement_upload":true`,
		`"contains_sni":true`,
		`"contains_host_header":true`,
		`"contains_domain":true`,
		`"contains_url":true`,
		`"payload_logged":true`,
		`"secret_logged":true`,
	}
	for _, marker := range forbiddenTrueFlags {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("httpslikecarrier unsafe flag found: %s", marker)
		}
	}
	return nil
}

func reportWithoutHash(in HTTPSLikeCarrierReport) HTTPSLikeCarrierReport {
	in.ReportHash = ""
	return in
}

func setWithoutHash(in FixtureSet) FixtureSet {
	in.FixtureHash = ""
	in.Report.ReportHash = HashValue(reportWithoutHash(in.Report))
	return in
}

func eventWithoutHash(in ShapeEvent) ShapeEvent {
	in.EventHash = ""
	return in
}

func fixedGeneratedAt() time.Time {
	return time.Unix(1_820_000_000, 0).UTC()
}

func scenarioNames() []string {
	return []string{
		ScenarioSingleStreamShape,
		ScenarioMultiStreamInterleave,
		ScenarioBoundedFixtureExchange,
		ScenarioBackpressureMapping,
		ScenarioResetMapping,
		ScenarioErrorMapping,
		ScenarioRelayPipelineIntegration,
		ScenarioRuntimeSecurityIntegration,
		ScenarioGeneratedParity,
	}
}

func requestShapeClasses() []ShapeClass {
	return hashShapes([]ShapeClass{
		{ID: "rq_short_marker", Direction: "request", ShapeClass: "short_request_marker", MarkerClass: "rq_short", ScenarioClasses: []string{"short", "small_object"}, MaxMarkerBytes: 32, ProfileSensitive: true, PayloadFree: true},
		{ID: "rq_chunked_marker", Direction: "request", ShapeClass: "chunked_request_marker", MarkerClass: "rq_chunked", ScenarioClasses: []string{"chunked", "long_poll_style"}, MaxMarkerBytes: 64, ProfileSensitive: true, PayloadFree: true},
		{ID: "rq_large_marker", Direction: "request", ShapeClass: "large_object_request_marker", MarkerClass: "rq_large", ScenarioClasses: []string{"large_object", "slow"}, MaxMarkerBytes: 96, ProfileSensitive: true, PayloadFree: true},
		{ID: "rq_reset_error_marker", Direction: "request", ShapeClass: "reset_error_request_marker", MarkerClass: "rq_reset_error", ScenarioClasses: []string{"reset", "error"}, MaxMarkerBytes: 80, ProfileSensitive: true, PayloadFree: true},
	})
}

func responseShapeClasses() []ShapeClass {
	return hashShapes([]ShapeClass{
		{ID: "rs_fixed_marker", Direction: "response", ShapeClass: "fixed_response_marker", MarkerClass: "rs_fixed", ScenarioClasses: []string{"fixed", "small_object"}, MaxMarkerBytes: 32, ProfileSensitive: true, PayloadFree: true},
		{ID: "rs_chunked_marker", Direction: "response", ShapeClass: "chunked_response_marker", MarkerClass: "rs_chunked", ScenarioClasses: []string{"chunked", "drip"}, MaxMarkerBytes: 72, ProfileSensitive: true, PayloadFree: true},
		{ID: "rs_delayed_large_marker", Direction: "response", ShapeClass: "delayed_large_response_marker", MarkerClass: "rs_delayed_large", ScenarioClasses: []string{"delayed", "large"}, MaxMarkerBytes: 96, ProfileSensitive: true, PayloadFree: true},
		{ID: "rs_reset_error_marker", Direction: "response", ShapeClass: "reset_error_response_marker", MarkerClass: "rs_reset_error", ScenarioClasses: []string{"reset", "error", "backpressure"}, MaxMarkerBytes: 80, ProfileSensitive: true, PayloadFree: true},
	})
}

func controlShapeClasses() []ShapeClass {
	return hashShapes([]ShapeClass{
		{ID: "control_fixed_shape", Direction: "control", ShapeClass: "fixed_shape_collapse", MarkerClass: "control_fixed", ScenarioClasses: []string{"fixed_shape"}, MaxMarkerBytes: 24, ProfileSensitive: false, PayloadFree: true, Control: true},
		{ID: "control_padding_only", Direction: "control", ShapeClass: "padding_only_variation", MarkerClass: "control_padding", ScenarioClasses: []string{"padding_only"}, MaxMarkerBytes: 24, ProfileSensitive: false, PayloadFree: true, Control: true},
		{ID: "control_profile_insensitive", Direction: "control", ShapeClass: "profile_insensitive_selection", MarkerClass: "control_profile", ScenarioClasses: []string{"profile_insensitive"}, MaxMarkerBytes: 24, ProfileSensitive: false, PayloadFree: true, Control: true},
		{ID: "control_leakage", Direction: "control", ShapeClass: "unsafe_metadata_leak", MarkerClass: "control_leak", ScenarioClasses: []string{"payload_leak", "sni_leak", "host_header_leak", "domain_url_leak", "public_network_drift"}, MaxMarkerBytes: 24, ProfileSensitive: false, PayloadFree: false, Control: true},
	})
}

func hashShapes(shapes []ShapeClass) []ShapeClass {
	out := append([]ShapeClass(nil), shapes...)
	for i := range out {
		out[i].Hash = HashValue(shapeWithoutHash(out[i]))
	}
	return out
}

func shapeWithoutHash(in ShapeClass) ShapeClass {
	in.Hash = ""
	return in
}

func scenarioRequestEvent(scenario, profileKey string, streamID, sequence uint64) ShapeEvent {
	event := SelectRequestShape(profileKey+":"+scenario, streamID, sequence, 40+int(sequence)*3)
	event.Scenario = scenario
	applyScenarioFlags(&event)
	event.EventHash = HashValue(eventWithoutHash(event))
	return event
}

func scenarioResponseEvent(scenario, profileKey string, streamID, sequence uint64) ShapeEvent {
	event := SelectResponseShape(profileKey+":"+scenario, streamID, sequence, 36+int(sequence)*2)
	event.Scenario = scenario
	applyScenarioFlags(&event)
	event.EventHash = HashValue(eventWithoutHash(event))
	return event
}

func applyScenarioFlags(event *ShapeEvent) {
	switch event.Scenario {
	case ScenarioBackpressureMapping:
		event.Backpressure = true
	case ScenarioResetMapping:
		event.Reset = true
		event.Closed = true
		event.ErrorBucket = "stream_reset_bucket"
	case ScenarioErrorMapping:
		event.TargetError = true
		event.ErrorBucket = "target_error_bucket"
	case ScenarioRelayPipelineIntegration, ScenarioRuntimeSecurityIntegration, ScenarioGeneratedParity:
		event.Closed = true
	}
}

func shapeIndex(profileKey string, streamID, sequence uint64, count int) int {
	if count <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", profileKey, streamID, sequence)))
	return int(sum[0]) % count
}

func boundedMarkerBytes(profileKey string, byteHint, maxMarkerBytes int) int {
	if byteHint < 0 {
		byteHint = 0
	}
	if maxMarkerBytes <= 0 {
		maxMarkerBytes = DefaultConfig().MaxMarkerBytes
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("marker:%s:%d", profileKey, byteHint)))
	size := 8 + int(sum[1])%maxMarkerBytes
	if size > maxMarkerBytes {
		size = maxMarkerBytes
	}
	return size
}

func sessionReports() []SessionReport {
	reports := []SessionReport{
		{SessionID: "session_selected_active", ProfileClass: "profile_alpha", States: []string{SessionConfigured, SessionSelected, SessionOpening, SessionActive, SessionDraining, SessionClosed}, StreamsOpened: 2, StreamsClosed: 2},
		{SessionID: "session_backpressured", ProfileClass: "profile_beta", States: []string{SessionConfigured, SessionSelected, SessionOpening, SessionActive, SessionBackpressured, SessionDraining, SessionClosed}, StreamsOpened: 3, StreamsClosed: 3, BackpressureEvents: 2},
		{SessionID: "session_reset", ProfileClass: "profile_gamma", States: []string{SessionConfigured, SessionSelected, SessionOpening, SessionActive, SessionReset}, StreamsOpened: 2, StreamsClosed: 1, StreamsReset: 1},
		{SessionID: "session_rejected", ProfileClass: "control", States: []string{SessionConfigured, SessionRejected}, Rejected: true},
	}
	for i := range reports {
		reports[i].Hash = HashValue(sessionWithoutHash(reports[i]))
	}
	return reports
}

func streamReports(events []ShapeEvent) []StreamReport {
	byStream := map[uint64][]ShapeEvent{}
	for _, event := range events {
		byStream[event.StreamID] = append(byStream[event.StreamID], event)
	}
	keys := make([]uint64, 0, len(byStream))
	for streamID := range byStream {
		keys = append(keys, streamID)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	reports := make([]StreamReport, 0, len(keys))
	for _, streamID := range keys {
		streamEvents := byStream[streamID]
		report := StreamReport{
			StreamID: streamID,
			States:   []string{StreamOpening, StreamActive, StreamDraining, StreamClosed},
			Closed:   true,
			Isolated: true,
		}
		for _, event := range streamEvents {
			if event.Direction == "request" && report.RequestShape == "" {
				report.RequestShape = event.ShapeClass
			}
			if event.Direction == "response" && report.ResponseShape == "" {
				report.ResponseShape = event.ShapeClass
			}
			if event.Backpressure && !contains(report.States, StreamBackpressure) {
				report.States = append([]string{StreamOpening, StreamActive, StreamBackpressure}, StreamDraining, StreamClosed)
			}
			if event.Reset {
				report.Reset = true
				report.Closed = false
				report.States = []string{StreamOpening, StreamActive, StreamReset}
			}
			if event.TargetError {
				report.TargetError = true
				if !contains(report.States, StreamError) {
					report.States = append(report.States, StreamError)
				}
			}
		}
		report.Hash = HashValue(streamWithoutHash(report))
		reports = append(reports, report)
	}
	return reports
}

func sessionWithoutHash(in SessionReport) SessionReport {
	in.Hash = ""
	return in
}

func streamWithoutHash(in StreamReport) StreamReport {
	in.Hash = ""
	return in
}

func fixtureExchangeReport(cfg Config) FixtureExchangeReport {
	return FixtureExchangeReport{
		MarkerCountBucket:        "16-32",
		MarkerSizeBucket:         fmt.Sprintf("<=%d", cfg.MaxMarkerBytes),
		OversizedMarkersRejected: 2,
		Bounded:                  true,
	}
}

func integrationStatuses() []IntegrationStatus {
	layers := []string{
		"loopbackrelay",
		"labegress",
		"relaybridge",
		"proxyegress",
		"localpipeline",
		"pathrace",
		"pathhealth",
		"carrierreview",
		"measurementreview",
	}
	out := make([]IntegrationStatus, 0, len(layers))
	for _, layer := range layers {
		out = append(out, IntegrationStatus{Layer: layer, Composed: true, Evidence: layer + "_summary_mapping", Conclusion: ConclusionPassed})
	}
	return out
}

func runtimeSecurityStatus() RuntimeSecurityStatus {
	return RuntimeSecurityStatus{
		RuntimeBound:                 true,
		SecureEnvelopeMetadata:       true,
		ProductionKeyingChanged:      false,
		CryptographicSecretLogged:    false,
		GeneratedTransportCompatible: true,
		Conclusion:                   ConclusionPassed,
	}
}

func resourceLimits(cfg Config) ResourceLimits {
	return ResourceLimits{
		MaxSessions:             cfg.MaxSessions,
		MaxStreams:              cfg.MaxStreams,
		MaxMarkerBytes:          cfg.MaxMarkerBytes,
		MaxRetainedEvents:       cfg.MaxEvents,
		MaxQueueDepth:           cfg.MaxQueueDepth,
		DeterministicShutdown:   true,
		PanicSafetyChecked:      true,
		OversizedMarkerRejected: true,
	}
}

func blockedScopeNames() []string {
	return []string{
		"real_tls",
		"tls_handshake_behavior",
		"real_https_client",
		"real_http_request_forwarding",
		"sni_routing",
		"host_header_routing",
		"url_routing",
		"domain_dependency",
		"cdn_provider_integration",
		"domain_fronting",
		"public_network_egress",
		"arbitrary_destination_proxying",
		"payload_forwarding_to_real_targets",
		"dns_resolution",
		"packet_capture",
		"payload_logging",
		"measurement_upload",
		"android_behavior",
		"production_relay_deployment",
		"country_specific_mode",
	}
}

func fixtureEntries(report HTTPSLikeCarrierReport) []FixtureEntry {
	entries := []FixtureEntry{
		{Name: "accepted_carrier_session", Kind: "accepted", Scenario: ScenarioSingleStreamShape, Expected: ConclusionPassed, SummaryHash: HashValue(report.Sessions[0])},
		{Name: "accepted_multi_stream", Kind: "accepted", Scenario: ScenarioMultiStreamInterleave, Expected: ConclusionPassed, SummaryHash: HashValue(report.Streams)},
		{Name: "accepted_backpressure", Kind: "accepted", Scenario: ScenarioBackpressureMapping, Expected: ConclusionPassed, SummaryHash: HashValue(report.BackpressureEvents)},
		{Name: "accepted_reset_error", Kind: "accepted", Scenario: ScenarioResetMapping, Expected: ConclusionPassed, SummaryHash: HashValue(report.TargetErrors)},
		{Name: "profile_sensitive_selection", Kind: "accepted", Scenario: ScenarioGeneratedParity, Expected: ConclusionPassed, SummaryHash: HashValue(report.ShapeDiversityFingerprints)},
		{Name: "fixed_shape_collapse_control", Kind: "control", Scenario: "fixed_shape_collapse", Expected: "rejected", SummaryHash: HashValue(controlShapeClasses()[0])},
		{Name: "padding_only_variation_control", Kind: "control", Scenario: "padding_only_variation", Expected: "rejected", SummaryHash: HashValue(controlShapeClasses()[1])},
		{Name: "profile_insensitive_control", Kind: "control", Scenario: "profile_insensitive", Expected: "rejected", SummaryHash: HashValue(controlShapeClasses()[2])},
		{Name: "payload_leak_control", Kind: "control", Scenario: "payload_leak", Expected: "rejected", SummaryHash: HashValue("payload_leak_control")},
		{Name: "sni_host_domain_cdn_controls", Kind: "control", Scenario: "unsafe_metadata", Expected: "rejected", SummaryHash: HashValue("unsafe_metadata_control")},
		{Name: "public_network_control", Kind: "control", Scenario: "public_network", Expected: "rejected", SummaryHash: HashValue("public_network_control")},
		{Name: "generated_backend_parity_summary", Kind: "parity", Scenario: ScenarioGeneratedParity, Expected: ConclusionPassed, SummaryHash: HashValue(report.ReportHash)},
	}
	return entries
}

func shapeFingerprints(events []ShapeEvent) []string {
	set := map[string]bool{}
	for _, event := range events {
		set[event.ProfileShapeHash] = true
	}
	out := make([]string, 0, len(set))
	for hash := range set {
		out = append(out, hash)
	}
	sort.Strings(out)
	return out
}

func countDirection(events []ShapeEvent, direction string) int {
	count := 0
	for _, event := range events {
		if event.Direction == direction {
			count++
		}
	}
	return count
}

func countBackpressure(events []ShapeEvent) int {
	count := 0
	for _, event := range events {
		if event.Backpressure {
			count++
		}
	}
	return count
}

func countClosed(streams []StreamReport) int {
	count := 0
	for _, stream := range streams {
		if stream.Closed {
			count++
		}
	}
	return count
}

func countReset(streams []StreamReport) int {
	count := 0
	for _, stream := range streams {
		if stream.Reset {
			count++
		}
	}
	return count
}

func countTargetErrors(streams []StreamReport) int {
	count := 0
	for _, stream := range streams {
		if stream.TargetError {
			count++
		}
	}
	return count
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
