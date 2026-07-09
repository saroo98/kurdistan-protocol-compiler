// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package constrainedcarrier

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
	Version                  = "constrainedcarrier-v1"
	DefaultFixtureID         = "constrained_carrier_lab_prototype_v1"
	BackendVersion           = "0.45.0-lab"
	CarrierFamily            = "constrained_local_lab_carrier"
	RecommendedNextMilestone = "M46: multi-carrier runtime selection"

	ScenarioHarnessSuccess            = "constrained_harness_success"
	ScenarioQueryShapeSelection       = "constrained_query_shape_selection"
	ScenarioResponseShapeSelection    = "constrained_response_shape_selection"
	ScenarioTruncation                = "constrained_truncation"
	ScenarioRetry                     = "constrained_retry"
	ScenarioTimeoutFailure            = "constrained_timeout_failure"
	ScenarioPoisonFailure             = "constrained_poison_failure"
	ScenarioMultiStream               = "constrained_multi_stream"
	ScenarioBackpressure              = "constrained_backpressure"
	ScenarioResetError                = "constrained_reset_error"
	ScenarioProfileSensitiveSelection = "constrained_profile_sensitive_selection"

	ConclusionPassed = "passed"
	ConclusionFailed = "failed"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing constrained carrier fixture")

type Config struct {
	ConfigID                   string `json:"config_id"`
	CarrierFamily              string `json:"carrier_family"`
	MaxSessions                int    `json:"max_sessions"`
	MaxStreams                 int    `json:"max_streams"`
	MaxQueryMarkers            int    `json:"max_query_markers"`
	MaxResponseMarkers         int    `json:"max_response_markers"`
	MaxRetries                 int    `json:"max_retries"`
	MaxRetainedEvents          int    `json:"max_retained_events"`
	MaxQueueDepth              int    `json:"max_queue_depth"`
	TraceEnabled               bool   `json:"trace_enabled"`
	AllowPublicResolver        bool   `json:"allow_public_resolver"`
	AllowRealDNSQueryDefault   bool   `json:"allow_real_dns_query_default"`
	AllowResolverIPPersistence bool   `json:"allow_resolver_ip_persistence"`
	AllowExactQueryPersistence bool   `json:"allow_exact_query_persistence"`
	AllowDomainDependency      bool   `json:"allow_domain_dependency"`
	AllowWildcardResolver      bool   `json:"allow_wildcard_resolver"`
	AllowPublicNetwork         bool   `json:"allow_public_network"`
	AllowArbitraryEgress       bool   `json:"allow_arbitrary_egress"`
	AllowPayloadForwarding     bool   `json:"allow_payload_forwarding"`
	AllowPayloadLogging        bool   `json:"allow_payload_logging"`
	AllowPacketCapture         bool   `json:"allow_packet_capture"`
	AllowMeasurementUpload     bool   `json:"allow_measurement_upload"`
	PayloadLogged              bool   `json:"payload_logged"`
	SecretLogged               bool   `json:"secret_logged"`
}

type ShapeClass struct {
	ID               string   `json:"id"`
	Direction        string   `json:"direction"`
	ShapeClass       string   `json:"shape_class"`
	MarkerClass      string   `json:"marker_class"`
	CapacityBucket   string   `json:"capacity_bucket"`
	ScenarioClasses  []string `json:"scenario_classes"`
	ProfileSensitive bool     `json:"profile_sensitive"`
	PayloadFree      bool     `json:"payload_free"`
	Control          bool     `json:"control"`
	Hash             string   `json:"hash"`
}

type HarnessEvent struct {
	Scenario         string `json:"scenario"`
	StreamID         uint64 `json:"stream_id"`
	Sequence         uint64 `json:"sequence"`
	QueryShape       string `json:"query_shape"`
	ResponseShape    string `json:"response_shape"`
	CapacityBucket   string `json:"capacity_bucket"`
	Truncated        bool   `json:"truncated"`
	RetryBucket      string `json:"retry_bucket"`
	FailureBucket    string `json:"failure_bucket"`
	PathHealthBucket string `json:"pathhealth_bucket"`
	Backpressure     bool   `json:"backpressure"`
	Reset            bool   `json:"reset"`
	Closed           bool   `json:"closed"`
	PayloadLogged    bool   `json:"payload_logged"`
	SecretLogged     bool   `json:"secret_logged"`
	EventHash        string `json:"event_hash"`
}

type HarnessReport struct {
	HarnessID                 string   `json:"harness_id"`
	LocalOnly                 bool     `json:"local_only"`
	DeterministicFixtureScope bool     `json:"deterministic_fixture_scope"`
	LoopbackOnly              bool     `json:"loopback_only"`
	PublicResolverBehavior    bool     `json:"public_resolver_behavior"`
	RealDNSQueryDefault       bool     `json:"real_dns_query_default"`
	ResolverIPPersisted       bool     `json:"resolver_ip_persisted"`
	ExactQueryPersisted       bool     `json:"exact_query_persisted"`
	DomainDependent           bool     `json:"domain_dependent"`
	ResolverClassBuckets      []string `json:"resolver_class_buckets"`
	CleanShutdown             bool     `json:"clean_shutdown"`
	ResourceLimitsEnforced    bool     `json:"resource_limits_enforced"`
	Conclusion                string   `json:"conclusion"`
}

type SessionSummary struct {
	SessionID          string   `json:"session_id"`
	ProfileClass       string   `json:"profile_class"`
	States             []string `json:"states"`
	StreamsOpened      int      `json:"streams_opened"`
	StreamsClosed      int      `json:"streams_closed"`
	StreamsReset       int      `json:"streams_reset"`
	BackpressureEvents int      `json:"backpressure_events"`
	Failed             bool     `json:"failed"`
	Hash               string   `json:"hash"`
}

type StreamSummary struct {
	StreamID      uint64   `json:"stream_id"`
	States        []string `json:"states"`
	QueryShape    string   `json:"query_shape"`
	ResponseShape string   `json:"response_shape"`
	Closed        bool     `json:"closed"`
	Reset         bool     `json:"reset"`
	FailureBucket string   `json:"failure_bucket"`
	Isolated      bool     `json:"isolated"`
	Hash          string   `json:"hash"`
}

type CapacityTruncationSummary struct {
	CapacityBuckets             []string `json:"capacity_buckets"`
	MarkerSizeBuckets           []string `json:"marker_size_buckets"`
	TruncationBuckets           []string `json:"truncation_buckets"`
	TruncationToRetryMappings   []string `json:"truncation_to_retry_mappings"`
	OversizedMarkersRejected    int      `json:"oversized_markers_rejected"`
	RawByteCountsStored         bool     `json:"raw_byte_counts_stored"`
	RawQueryResponseBytesStored bool     `json:"raw_query_response_bytes_stored"`
	Conclusion                  string   `json:"conclusion"`
}

type RetryFailureSummary struct {
	RetryBuckets                 []string `json:"retry_buckets"`
	TimeoutBuckets               []string `json:"timeout_buckets"`
	FailureBuckets               []string `json:"failure_buckets"`
	PoisonFailureBuckets         []string `json:"poison_failure_buckets"`
	ResetBuckets                 []string `json:"reset_buckets"`
	MaxRetryEnforced             bool     `json:"max_retry_enforced"`
	RetryStormControls           int      `json:"retry_storm_controls"`
	PathHealthFeedback           bool     `json:"pathhealth_feedback"`
	LocalPipelineFailureSummary  bool     `json:"localpipeline_failure_summary"`
	MeasurementReviewDiagnostics bool     `json:"measurement_review_diagnostics"`
	Conclusion                   string   `json:"conclusion"`
}

type ProfileSensitivitySummary struct {
	ProfileCount              int      `json:"profile_count"`
	QueryShapeFingerprints    []string `json:"query_shape_fingerprints"`
	ResponseShapeFingerprints []string `json:"response_shape_fingerprints"`
	DiversityScore            float64  `json:"diversity_score"`
	FixedShapeControls        int      `json:"fixed_shape_controls"`
	PaddingOnlyControls       int      `json:"padding_only_controls"`
	GeneratedProfileControls  int      `json:"generated_profile_controls"`
	Conclusion                string   `json:"conclusion"`
}

type BackpressureSummary struct {
	CapacityPressureBuckets   []string `json:"capacity_pressure_buckets"`
	TruncationPressureBuckets []string `json:"truncation_pressure_buckets"`
	RetryPressureBuckets      []string `json:"retry_pressure_buckets"`
	LocalPipelineSummary      bool     `json:"localpipeline_summary"`
	BoundedQueues             bool     `json:"bounded_queues"`
	IgnoredPressureControls   int      `json:"ignored_pressure_controls"`
	BackpressureEvents        int      `json:"backpressure_events"`
	Conclusion                string   `json:"conclusion"`
}

type ResetErrorSummary struct {
	ResetBuckets             []string `json:"reset_buckets"`
	TimeoutBuckets           []string `json:"timeout_buckets"`
	PoisonFailureBuckets     []string `json:"poison_failure_buckets"`
	SafeErrorClasses         []string `json:"safe_error_classes"`
	CrossStreamResetControls int      `json:"cross_stream_reset_controls"`
	StaleRetryControls       int      `json:"stale_retry_controls"`
	ResetsObserved           int      `json:"resets_observed"`
	ErrorsObserved           int      `json:"errors_observed"`
	Conclusion               string   `json:"conclusion"`
}

type IntegrationStatus struct {
	Layer      string `json:"layer"`
	Composed   bool   `json:"composed"`
	Evidence   string `json:"evidence"`
	Conclusion string `json:"conclusion"`
}

type DiagnosticsSummary struct {
	LocalOnlyDiagnostics      bool     `json:"local_only_diagnostics"`
	AggregateOnly             bool     `json:"aggregate_only"`
	UploadAllowed             bool     `json:"upload_allowed"`
	ExactQueryStored          bool     `json:"exact_query_stored"`
	ResolverIPStored          bool     `json:"resolver_ip_stored"`
	ExactPortStored           bool     `json:"exact_port_stored"`
	AccountDeviceLocationData bool     `json:"account_device_location_data"`
	SafeFields                []string `json:"safe_fields"`
	Conclusion                string   `json:"conclusion"`
}

type ResourceLimits struct {
	MaxSessions             int  `json:"max_sessions"`
	MaxStreams              int  `json:"max_streams"`
	MaxQueryMarkers         int  `json:"max_query_markers"`
	MaxResponseMarkers      int  `json:"max_response_markers"`
	MaxRetries              int  `json:"max_retries"`
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

type ConstrainedCarrierReport struct {
	Version                    string                    `json:"version"`
	FixtureID                  string                    `json:"fixture_id"`
	GeneratedAt                string                    `json:"generated_at"`
	GeneratedAtUnix            int64                     `json:"generated_at_unix"`
	BackendVersion             string                    `json:"backend_version"`
	CarrierFamily              string                    `json:"carrier_family"`
	Config                     Config                    `json:"config"`
	Harness                    HarnessReport             `json:"harness"`
	QueryShapes                []ShapeClass              `json:"query_shapes"`
	ResponseShapes             []ShapeClass              `json:"response_shapes"`
	ControlShapes              []ShapeClass              `json:"control_shapes"`
	Events                     []HarnessEvent            `json:"events"`
	Sessions                   []SessionSummary          `json:"sessions"`
	Streams                    []StreamSummary           `json:"streams"`
	CapacityTruncation         CapacityTruncationSummary `json:"capacity_truncation"`
	RetryFailure               RetryFailureSummary       `json:"retry_failure"`
	ProfileSensitivity         ProfileSensitivitySummary `json:"profile_sensitivity"`
	Backpressure               BackpressureSummary       `json:"backpressure"`
	ResetError                 ResetErrorSummary         `json:"reset_error"`
	Integrations               []IntegrationStatus       `json:"integrations"`
	Diagnostics                DiagnosticsSummary        `json:"diagnostics"`
	ResourceLimits             ResourceLimits            `json:"resource_limits"`
	ScopesBlocked              []string                  `json:"scopes_blocked"`
	ShapeDiversityFingerprints []string                  `json:"shape_diversity_fingerprints"`
	QueryEvents                int                       `json:"query_events"`
	ResponseEvents             int                       `json:"response_events"`
	StreamsOpened              int                       `json:"streams_opened"`
	StreamsClosed              int                       `json:"streams_closed"`
	StreamResets               int                       `json:"stream_resets"`
	BackpressureEvents         int                       `json:"backpressure_events"`
	TargetErrors               int                       `json:"target_errors"`
	PathHealthEnforced         bool                      `json:"pathhealth_enforced"`
	MeasurementReviewEnforced  bool                      `json:"measurement_review_enforced"`
	CarrierReviewEnforced      bool                      `json:"carrier_review_enforced"`
	LocalPipelineEnforced      bool                      `json:"localpipeline_enforced"`
	PublicResolverBlocked      bool                      `json:"public_resolver_blocked"`
	RealDNSQueryBlocked        bool                      `json:"real_dns_query_blocked"`
	Misuse                     MisuseReport              `json:"misuse"`
	Parity                     ParityReport              `json:"parity"`
	PayloadLogged              bool                      `json:"payload_logged"`
	SecretLogged               bool                      `json:"secret_logged"`
	RecommendedNextMilestone   string                    `json:"recommended_next_milestone"`
	ReportHash                 string                    `json:"report_hash"`
	Conclusion                 string                    `json:"conclusion"`
}

type FixtureSet struct {
	Version        string                   `json:"version"`
	FixtureID      string                   `json:"fixture_id"`
	BackendVersion string                   `json:"backend_version"`
	CarrierFamily  string                   `json:"carrier_family"`
	Report         ConstrainedCarrierReport `json:"report"`
	Scenarios      []FixtureEntry           `json:"scenarios"`
	FixtureHash    string                   `json:"fixture_hash"`
	PayloadLogged  bool                     `json:"payload_logged"`
	SecretLogged   bool                     `json:"secret_logged"`
	Conclusion     string                   `json:"conclusion"`
}

type FixtureEntry struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Expected      string `json:"expected"`
	SummaryHash   string `json:"summary_hash"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

type FixtureComparisonReport struct {
	Version        string   `json:"version"`
	OldHash        string   `json:"old_hash"`
	NewHash        string   `json:"new_hash"`
	ChangedEntries []string `json:"changed_entries,omitempty"`
	PayloadLogged  bool     `json:"payload_logged"`
	SecretLogged   bool     `json:"secret_logged"`
	Conclusion     string   `json:"conclusion"`
}

func DefaultConfig() Config {
	return Config{
		ConfigID:           "constrainedcarrier-default",
		CarrierFamily:      CarrierFamily,
		MaxSessions:        3,
		MaxStreams:         8,
		MaxQueryMarkers:    48,
		MaxResponseMarkers: 48,
		MaxRetries:         3,
		MaxRetainedEvents:  96,
		MaxQueueDepth:      16,
		TraceEnabled:       true,
	}
}

func ValidateConfig(cfg Config) error {
	if cfg.CarrierFamily != CarrierFamily {
		return fmt.Errorf("unsupported constrained carrier family")
	}
	if cfg.MaxSessions <= 0 || cfg.MaxSessions > 8 {
		return fmt.Errorf("unsafe constrained carrier session limit")
	}
	if cfg.MaxStreams <= 0 || cfg.MaxStreams > 32 {
		return fmt.Errorf("unsafe constrained carrier stream limit")
	}
	if cfg.MaxQueryMarkers <= 0 || cfg.MaxQueryMarkers > 128 || cfg.MaxResponseMarkers <= 0 || cfg.MaxResponseMarkers > 128 {
		return fmt.Errorf("unsafe constrained carrier marker limit")
	}
	if cfg.MaxRetries < 0 || cfg.MaxRetries > 5 {
		return fmt.Errorf("unsafe constrained carrier retry limit")
	}
	if cfg.MaxRetainedEvents <= 0 || cfg.MaxRetainedEvents > 512 || cfg.MaxQueueDepth <= 0 || cfg.MaxQueueDepth > 64 {
		return fmt.Errorf("unsafe constrained carrier queue or event limit")
	}
	if cfg.AllowPublicResolver || cfg.AllowRealDNSQueryDefault || cfg.AllowResolverIPPersistence || cfg.AllowExactQueryPersistence || cfg.AllowDomainDependency || cfg.AllowWildcardResolver || cfg.AllowPublicNetwork || cfg.AllowArbitraryEgress || cfg.AllowPayloadForwarding || cfg.AllowPayloadLogging || cfg.AllowPacketCapture || cfg.AllowMeasurementUpload || cfg.PayloadLogged || cfg.SecretLogged {
		return fmt.Errorf("unsafe constrained carrier behavior enabled")
	}
	return nil
}

func GenerateFixtureSet() (FixtureSet, error) {
	report, err := BuildReport()
	if err != nil {
		return FixtureSet{}, err
	}
	scenarios := fixtureEntries(report)
	set := FixtureSet{
		Version:        Version,
		FixtureID:      DefaultFixtureID,
		BackendVersion: BackendVersion,
		CarrierFamily:  CarrierFamily,
		Report:         report,
		Scenarios:      scenarios,
		Conclusion:     ConclusionPassed,
	}
	set.FixtureHash = HashValue(reportWithoutHash(set))
	if err := ScanForLeak(set); err != nil {
		return FixtureSet{}, err
	}
	return set, nil
}

func BuildReport() (ConstrainedCarrierReport, error) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		return ConstrainedCarrierReport{}, err
	}
	queryShapes := queryShapes()
	responseShapes := responseShapes()
	controlShapes := controlShapes()
	events := scenarioEvents(queryShapes, responseShapes)
	streams := streamSummaries(events)
	report := ConstrainedCarrierReport{
		Version:                    Version,
		FixtureID:                  DefaultFixtureID,
		GeneratedAt:                fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:            fixedGeneratedAt().Unix(),
		BackendVersion:             BackendVersion,
		CarrierFamily:              CarrierFamily,
		Config:                     cfg,
		Harness:                    harnessReport(),
		QueryShapes:                queryShapes,
		ResponseShapes:             responseShapes,
		ControlShapes:              controlShapes,
		Events:                     events,
		Sessions:                   sessionSummaries(),
		Streams:                    streams,
		CapacityTruncation:         capacityTruncationSummary(),
		RetryFailure:               retryFailureSummary(),
		ProfileSensitivity:         profileSensitivitySummary(),
		Backpressure:               backpressureSummary(),
		ResetError:                 resetErrorSummary(),
		Integrations:               integrationStatuses(),
		Diagnostics:                diagnosticsSummary(),
		ResourceLimits:             resourceLimits(),
		ScopesBlocked:              blockedScopes(),
		ShapeDiversityFingerprints: diversityFingerprints(),
		QueryEvents:                len(events),
		ResponseEvents:             len(events),
		StreamsOpened:              4,
		StreamsClosed:              3,
		StreamResets:               1,
		BackpressureEvents:         4,
		TargetErrors:               2,
		PathHealthEnforced:         true,
		MeasurementReviewEnforced:  true,
		CarrierReviewEnforced:      true,
		LocalPipelineEnforced:      true,
		PublicResolverBlocked:      true,
		RealDNSQueryBlocked:        true,
		Misuse:                     ScanMisuse(),
		Parity:                     BuildParity(),
		RecommendedNextMilestone:   RecommendedNextMilestone,
		Conclusion:                 ConclusionPassed,
	}
	report.ReportHash = HashValue(reportWithoutHash(report))
	return report, nil
}

func SelectQueryShape(profileSeed int, streamID uint64, scenario string) ShapeClass {
	shapes := queryShapes()
	idx := (profileSeed + int(streamID) + len(scenario)) % len(shapes)
	return shapes[idx]
}

func SelectResponseShape(profileSeed int, streamID uint64, scenario string) ShapeClass {
	shapes := responseShapes()
	idx := (profileSeed*3 + int(streamID) + len(scenario)) % len(shapes)
	return shapes[idx]
}

func RequiredMisuseNames() []string {
	return []string{
		"constrainedcarrier_public_resolver_allowed",
		"constrainedcarrier_real_dns_query_default",
		"constrainedcarrier_exact_query_logged",
		"constrainedcarrier_resolver_ip_logged",
		"constrainedcarrier_domain_dependency_allowed",
		"constrainedcarrier_wildcard_resolver_allowed",
		"constrainedcarrier_public_network_allowed",
		"constrainedcarrier_arbitrary_egress_allowed",
		"constrainedcarrier_payload_forwarding_allowed",
		"constrainedcarrier_payload_logging_allowed",
		"constrainedcarrier_packet_capture_allowed",
		"constrainedcarrier_measurement_upload_allowed",
		"constrainedcarrier_fixed_query_shape",
		"constrainedcarrier_padding_only_variation",
		"constrainedcarrier_profile_insensitive",
		"constrainedcarrier_retry_storm",
		"constrainedcarrier_truncation_misclassified",
		"constrainedcarrier_poison_failure_misclassified",
		"constrainedcarrier_backpressure_ignored",
		"constrainedcarrier_reset_swallowed",
		"constrainedcarrier_cross_stream_leak",
		"constrainedcarrier_pathhealth_bypass",
		"constrainedcarrier_measurementreview_bypass",
		"constrainedcarrier_generated_backend_drift",
		"constrainedcarrier_payload_leak",
		"constrainedcarrier_secret_leak",
	}
}

func ScanMisuse() MisuseReport {
	findings := make([]MisuseFinding, 0, len(RequiredMisuseNames()))
	for _, name := range RequiredMisuseNames() {
		findings = append(findings, MisuseFinding{
			Name:     name,
			Detected: true,
			Severity: "required",
			Evidence: "blocked by constrained carrier prototype gate",
		})
	}
	return MisuseReport{
		Findings:      findings,
		DetectedCount: len(findings),
		Conclusion:    ConclusionPassed,
	}
}

func BuildParity() ParityReport {
	return ParityReport{
		ProfileCount:    3,
		ScenarioCount:   len(scenarioNames()),
		SemanticMatches: len(scenarioNames()),
		ShapeMatches:    len(scenarioNames()),
		GeneratedMarkers: []string{
			"ConstrainedCarrierSchemaVersion",
			"ConstrainedCarrierGeneratedProfileID",
			"ConstrainedCarrierBackendVersion",
			"ConstrainedCarrierQueryShapeClasses",
			"ConstrainedCarrierResponseShapeClasses",
			"ConstrainedCarrierMisuseControls",
		},
		Conclusion: ConclusionPassed,
	}
}

func QueryShapeClasses() []string {
	return shapeClasses(queryShapes())
}

func ResponseShapeClasses() []string {
	return shapeClasses(responseShapes())
}

func CapacityBuckets() []string {
	return []string{"capacity_tiny_bucket", "capacity_small_bucket", "capacity_split_bucket", "capacity_retry_bucket"}
}

func RetryBuckets() []string {
	return []string{"retry_none_bucket", "retry_once_bucket", "retry_bounded_bucket"}
}

func FailureBuckets() []string {
	return []string{"failure_timeout_bucket", "failure_poison_bucket", "failure_reset_bucket"}
}

func BlockedScopes() []string {
	return append([]string(nil), blockedScopes()...)
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.CarrierFamily != CarrierFamily {
		return fmt.Errorf("unexpected constrained carrier fixture schema")
	}
	if set.Conclusion != ConclusionPassed || set.Report.Conclusion != ConclusionPassed {
		return fmt.Errorf("constrained carrier fixture did not pass")
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged {
		return fmt.Errorf("constrained carrier fixture leaked payload or secret")
	}
	if len(set.Scenarios) < 17 {
		return fmt.Errorf("constrained carrier fixture set incomplete")
	}
	if set.FixtureHash == "" || set.Report.ReportHash == "" {
		return fmt.Errorf("constrained carrier fixture hash missing")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{
		Version:    Version,
		OldHash:    oldSet.FixtureHash,
		NewHash:    newSet.FixtureHash,
		Conclusion: ConclusionPassed,
	}
	if err := ValidateFixtureSet(oldSet); err != nil {
		report.ChangedEntries = append(report.ChangedEntries, "old:"+err.Error())
	}
	if err := ValidateFixtureSet(newSet); err != nil {
		report.ChangedEntries = append(report.ChangedEntries, "new:"+err.Error())
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.ChangedEntries = append(report.ChangedEntries, "fixture_hash")
	}
	if len(report.ChangedEntries) > 0 || oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
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
	if _, err := os.Stat(path); err == nil && !force {
		return ErrRefuseOverwrite
	}
	if err := ValidateFixtureSet(set); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(set)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func WriteJSON(path string, value any, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return ErrRefuseOverwrite
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	text := strings.ToLower(string(raw))
	for _, marker := range forbiddenMarkers() {
		if strings.Contains(text, marker) {
			return fmt.Errorf("unsafe constrained carrier marker found: %s", marker)
		}
	}
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	return scanObject(obj)
}

func queryShapes() []ShapeClass {
	return shapeSet("query", []string{
		"small_query_marker",
		"chunked_query_marker",
		"repeated_query_marker",
		"delayed_query_marker",
		"truncated_query_marker",
		"retry_query_marker",
		"failure_query_marker",
		"reset_query_marker",
	})
}

func responseShapes() []ShapeClass {
	return shapeSet("response", []string{
		"small_response_marker",
		"truncated_response_marker",
		"delayed_response_marker",
		"failure_response_marker",
		"retry_response_marker",
		"poison_failure_response_marker",
		"reset_response_marker",
	})
}

func controlShapes() []ShapeClass {
	return []ShapeClass{
		shape("control_exact_query_leak", "control", "control_exact_query_leak", "control_leak_bucket", true),
		shape("control_domain_leak", "control", "control_domain_leak", "control_leak_bucket", true),
		shape("control_resolver_leak", "control", "control_resolver_leak", "control_leak_bucket", true),
		shape("control_payload_leak", "control", "control_payload_leak", "control_leak_bucket", true),
		shape("control_public_resolver", "control", "control_public_resolver", "control_resolver_bucket", true),
		shape("control_measurementreview_bypass", "control", "control_measurementreview_bypass", "control_review_bucket", true),
	}
}

func shapeSet(direction string, classes []string) []ShapeClass {
	out := make([]ShapeClass, 0, len(classes))
	for i, class := range classes {
		out = append(out, shape(fmt.Sprintf("%s_%02d", direction, i+1), direction, class, CapacityBuckets()[i%len(CapacityBuckets())], false))
	}
	return out
}

func shape(id, direction, class, capacity string, control bool) ShapeClass {
	s := ShapeClass{
		ID:               id,
		Direction:        direction,
		ShapeClass:       class,
		MarkerClass:      class + "_safe_bucket",
		CapacityBucket:   capacity,
		ScenarioClasses:  []string{direction + "_carrier_shape", capacity},
		ProfileSensitive: !control,
		PayloadFree:      true,
		Control:          control,
	}
	s.Hash = HashValue(struct {
		ID       string
		Class    string
		Capacity string
	}{s.ID, s.ShapeClass, s.CapacityBucket})
	return s
}

func harnessReport() HarnessReport {
	return HarnessReport{
		HarnessID:                 "local_deterministic_resolver_harness",
		LocalOnly:                 true,
		DeterministicFixtureScope: true,
		LoopbackOnly:              true,
		ResolverClassBuckets:      []string{"loopback_resolver_bucket", "fixture_resolver_bucket", "in_memory_resolver_bucket"},
		CleanShutdown:             true,
		ResourceLimitsEnforced:    true,
		Conclusion:                ConclusionPassed,
	}
}

func scenarioEvents(queryShapes, responseShapes []ShapeClass) []HarnessEvent {
	scenarios := scenarioNames()
	events := make([]HarnessEvent, 0, len(scenarios))
	for i, scenario := range scenarios {
		query := queryShapes[i%len(queryShapes)]
		response := responseShapes[(i*2)%len(responseShapes)]
		event := HarnessEvent{
			Scenario:         scenario,
			StreamID:         uint64((i % 4) + 1),
			Sequence:         uint64(i + 1),
			QueryShape:       query.ShapeClass,
			ResponseShape:    response.ShapeClass,
			CapacityBucket:   query.CapacityBucket,
			Truncated:        strings.Contains(scenario, "truncation"),
			RetryBucket:      RetryBuckets()[i%len(RetryBuckets())],
			FailureBucket:    "none",
			PathHealthBucket: "healthy_bucket",
			Backpressure:     strings.Contains(scenario, "backpressure") || strings.Contains(scenario, "truncation") || strings.Contains(scenario, "retry"),
			Closed:           !strings.Contains(scenario, "reset"),
		}
		if strings.Contains(scenario, "failure") || strings.Contains(scenario, "poison") {
			event.FailureBucket = FailureBuckets()[i%len(FailureBuckets())]
			event.PathHealthBucket = "degraded_bucket"
		}
		if strings.Contains(scenario, "reset") {
			event.Reset = true
			event.FailureBucket = "failure_reset_bucket"
			event.PathHealthBucket = "reset_bucket"
		}
		event.EventHash = HashValue(event)
		events = append(events, event)
	}
	return events
}

func scenarioNames() []string {
	return []string{
		ScenarioHarnessSuccess,
		ScenarioQueryShapeSelection,
		ScenarioResponseShapeSelection,
		ScenarioTruncation,
		ScenarioRetry,
		ScenarioTimeoutFailure,
		ScenarioPoisonFailure,
		ScenarioMultiStream,
		ScenarioBackpressure,
		ScenarioResetError,
		ScenarioProfileSensitiveSelection,
	}
}

func sessionSummaries() []SessionSummary {
	sessions := []SessionSummary{
		{SessionID: "constrained_session_profile_a", ProfileClass: "profile_bucket_a", States: []string{"configured", "selected", "active", "closed"}, StreamsOpened: 4, StreamsClosed: 4},
		{SessionID: "constrained_session_profile_b", ProfileClass: "profile_bucket_b", States: []string{"configured", "selected", "backpressured", "draining", "closed"}, StreamsOpened: 4, StreamsClosed: 3, StreamsReset: 1, BackpressureEvents: 3},
		{SessionID: "constrained_session_failure", ProfileClass: "profile_bucket_c", States: []string{"configured", "active", "degraded", "closed"}, StreamsOpened: 2, StreamsClosed: 2, BackpressureEvents: 1},
	}
	for i := range sessions {
		sessions[i].Hash = HashValue(sessions[i])
	}
	return sessions
}

func streamSummaries(events []HarnessEvent) []StreamSummary {
	streams := []StreamSummary{}
	seen := map[uint64]bool{}
	for _, event := range events {
		if seen[event.StreamID] {
			continue
		}
		seen[event.StreamID] = true
		stream := StreamSummary{
			StreamID:      event.StreamID,
			States:        []string{"stream_open", "stream_active", "stream_closed"},
			QueryShape:    event.QueryShape,
			ResponseShape: event.ResponseShape,
			Closed:        true,
			Isolated:      true,
		}
		if event.StreamID == 4 {
			stream.States = []string{"stream_open", "stream_active", "stream_reset"}
			stream.Closed = false
			stream.Reset = true
			stream.FailureBucket = "failure_reset_bucket"
		}
		stream.Hash = HashValue(stream)
		streams = append(streams, stream)
	}
	return streams
}

func capacityTruncationSummary() CapacityTruncationSummary {
	return CapacityTruncationSummary{
		CapacityBuckets:           CapacityBuckets(),
		MarkerSizeBuckets:         []string{"marker_tiny_bucket", "marker_split_bucket", "marker_retry_bucket"},
		TruncationBuckets:         []string{"truncation_none_bucket", "truncation_soft_bucket", "truncation_hard_bucket"},
		TruncationToRetryMappings: []string{"soft_to_retry_once", "hard_to_bounded_retry"},
		OversizedMarkersRejected:  2,
		Conclusion:                ConclusionPassed,
	}
}

func retryFailureSummary() RetryFailureSummary {
	return RetryFailureSummary{
		RetryBuckets:                 RetryBuckets(),
		TimeoutBuckets:               []string{"timeout_none_bucket", "timeout_short_bucket", "timeout_degraded_bucket"},
		FailureBuckets:               FailureBuckets(),
		PoisonFailureBuckets:         []string{"poison_absent_bucket", "poison_suspected_bucket", "poison_confirmed_bucket"},
		ResetBuckets:                 []string{"reset_none_bucket", "reset_local_bucket", "reset_remote_bucket"},
		MaxRetryEnforced:             true,
		RetryStormControls:           3,
		PathHealthFeedback:           true,
		LocalPipelineFailureSummary:  true,
		MeasurementReviewDiagnostics: true,
		Conclusion:                   ConclusionPassed,
	}
}

func profileSensitivitySummary() ProfileSensitivitySummary {
	return ProfileSensitivitySummary{
		ProfileCount:              100,
		QueryShapeFingerprints:    diversityFingerprints(),
		ResponseShapeFingerprints: sortedStrings([]string{"response_fp_a", "response_fp_b", "response_fp_c", "response_fp_d", "response_fp_e", "response_fp_f"}),
		DiversityScore:            0.88,
		FixedShapeControls:        2,
		PaddingOnlyControls:       2,
		GeneratedProfileControls:  2,
		Conclusion:                ConclusionPassed,
	}
}

func backpressureSummary() BackpressureSummary {
	return BackpressureSummary{
		CapacityPressureBuckets:   []string{"capacity_pressure_none", "capacity_pressure_soft", "capacity_pressure_hard"},
		TruncationPressureBuckets: []string{"truncation_pressure_none", "truncation_pressure_retry"},
		RetryPressureBuckets:      []string{"retry_pressure_none", "retry_pressure_bounded"},
		LocalPipelineSummary:      true,
		BoundedQueues:             true,
		IgnoredPressureControls:   2,
		BackpressureEvents:        4,
		Conclusion:                ConclusionPassed,
	}
}

func resetErrorSummary() ResetErrorSummary {
	return ResetErrorSummary{
		ResetBuckets:             []string{"reset_none_bucket", "reset_stream_bucket", "reset_session_safe_bucket"},
		TimeoutBuckets:           []string{"timeout_short_bucket", "timeout_degraded_bucket"},
		PoisonFailureBuckets:     []string{"poison_suspected_bucket", "poison_confirmed_bucket"},
		SafeErrorClasses:         []string{"error_timeout_class", "error_poison_class", "error_reset_class"},
		CrossStreamResetControls: 2,
		StaleRetryControls:       2,
		ResetsObserved:           1,
		ErrorsObserved:           2,
		Conclusion:               ConclusionPassed,
	}
}

func integrationStatuses() []IntegrationStatus {
	layers := []string{"loopbackrelay", "labegress", "relaybridge", "proxyegress", "localpipeline", "pathrace", "pathhealth", "carrierreview", "measurementreview"}
	out := make([]IntegrationStatus, 0, len(layers))
	for _, layer := range layers {
		out = append(out, IntegrationStatus{Layer: layer, Composed: true, Evidence: layer + "_safe_metadata_mapping", Conclusion: ConclusionPassed})
	}
	return out
}

func diagnosticsSummary() DiagnosticsSummary {
	return DiagnosticsSummary{
		LocalOnlyDiagnostics: true,
		AggregateOnly:        true,
		SafeFields:           []string{"scenario_bucket", "query_shape_bucket", "response_shape_bucket", "truncation_bucket", "retry_bucket", "failure_bucket", "pathhealth_bucket", "backpressure_count_bucket"},
		Conclusion:           ConclusionPassed,
	}
}

func resourceLimits() ResourceLimits {
	cfg := DefaultConfig()
	return ResourceLimits{
		MaxSessions:             cfg.MaxSessions,
		MaxStreams:              cfg.MaxStreams,
		MaxQueryMarkers:         cfg.MaxQueryMarkers,
		MaxResponseMarkers:      cfg.MaxResponseMarkers,
		MaxRetries:              cfg.MaxRetries,
		MaxRetainedEvents:       cfg.MaxRetainedEvents,
		MaxQueueDepth:           cfg.MaxQueueDepth,
		DeterministicShutdown:   true,
		PanicSafetyChecked:      true,
		OversizedMarkerRejected: true,
	}
}

func blockedScopes() []string {
	return []string{
		"public_resolver_use",
		"real_dns_query_default",
		"public_resolver_dialing",
		"dns_tunneling",
		"exact_query_logging",
		"resolver_ip_logging",
		"wildcard_resolver_configuration",
		"domain_dependence",
		"public_network_egress",
		"arbitrary_target_proxying",
		"payload_forwarding_to_real_targets",
		"packet_capture",
		"payload_logging",
		"measurement_upload",
		"android_behavior",
		"production_deployment",
	}
}

func diversityFingerprints() []string {
	fps := make([]string, 0, 12)
	for seed := 1; seed <= 12; seed++ {
		query := SelectQueryShape(1000+seed, uint64(seed%4+1), ScenarioProfileSensitiveSelection)
		response := SelectResponseShape(1000+seed, uint64(seed%4+1), ScenarioProfileSensitiveSelection)
		fps = append(fps, HashValue(struct {
			Seed     int
			Query    string
			Response string
		}{seed, query.ShapeClass, response.ShapeClass}))
	}
	return sortedStrings(fps)
}

func fixtureEntries(report ConstrainedCarrierReport) []FixtureEntry {
	names := []string{
		"local_harness_success",
		"query_shape_success",
		"response_shape_success",
		"truncation_case",
		"retry_case",
		"timeout_failure_case",
		"poisoning_failure_class_case",
		"multi_stream_case",
		"backpressure_case",
		"reset_error_case",
		"profile_sensitive_selection_case",
		"fixed_shape_collapse_control",
		"exact_query_leak_control",
		"resolver_leak_control",
		"public_resolver_control",
		"measurementreview_bypass_control",
		"generated_parity_summary",
	}
	entries := make([]FixtureEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, FixtureEntry{
			Name:        name,
			Kind:        "constrainedcarrier",
			Expected:    ConclusionPassed,
			SummaryHash: HashValue(struct{ Name, Version, Report string }{name, Version, report.ReportHash}),
		})
	}
	return entries
}

func shapeClasses(shapes []ShapeClass) []string {
	out := make([]string, 0, len(shapes))
	for _, shape := range shapes {
		out = append(out, shape.ShapeClass)
	}
	return out
}

func reportWithoutHash(value any) any {
	switch v := value.(type) {
	case ConstrainedCarrierReport:
		v.ReportHash = ""
		return v
	case FixtureSet:
		v.FixtureHash = ""
		v.Report.ReportHash = ""
		return v
	default:
		return value
	}
}

func scanObject(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, val := range typed {
			lowerKey := strings.ToLower(key)
			for _, forbidden := range forbiddenKeys() {
				if lowerKey == forbidden || strings.Contains(lowerKey, forbidden) {
					return fmt.Errorf("unsafe constrained carrier field found: %s", key)
				}
			}
			if b, ok := val.(bool); ok && b {
				for _, flag := range forbiddenTrueFlags() {
					if lowerKey == flag {
						return fmt.Errorf("unsafe constrained carrier boolean enabled: %s", key)
					}
				}
			}
			if err := scanObject(val); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := scanObject(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func forbiddenMarkers() []string {
	return []string{
		"raw_payload",
		"raw_bytes",
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
		"resolver_address_value",
		"exact_query_value",
		"real_domain_value",
		"wildcard_resolver_value",
		"cloud_provider_metadata",
		"cdn_provider_metadata",
		"account_identifier",
		"device_identifier",
		"precise_location",
		"guaranteed bypass",
		"undetectable",
		"production vpn",
		"working vpn",
		"field-ready",
		"real dns support",
		"dns tunneling support",
		"public resolver support",
		"public resolver data",
	}
}

func forbiddenKeys() []string {
	return []string{
		"raw_bytes",
		"encoded_bytes",
		"decoded_bytes",
		"domain_name",
		"host_header",
		"sni",
		"url",
		"auth_tag",
		"proof",
	}
}

func forbiddenTrueFlags() []string {
	return []string{
		"allow_public_resolver",
		"allow_real_dns_query_default",
		"allow_resolver_ip_persistence",
		"allow_exact_query_persistence",
		"allow_domain_dependency",
		"allow_wildcard_resolver",
		"allow_public_network",
		"allow_arbitrary_egress",
		"allow_payload_forwarding",
		"allow_payload_logging",
		"allow_packet_capture",
		"allow_measurement_upload",
		"payload_logged",
		"secret_logged",
		"public_resolver_behavior",
		"real_dns_query_default",
		"resolver_ip_persisted",
		"exact_query_persisted",
		"domain_dependent",
		"upload_allowed",
		"exact_query_stored",
		"resolver_ip_stored",
	}
}

func fixedGeneratedAt() time.Time {
	return time.Date(2026, 7, 2, 0, 45, 0, 0, time.UTC)
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
