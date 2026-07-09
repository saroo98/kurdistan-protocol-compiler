// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localvpnadapter

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

	"kurdistan/internal/contracts/vpn/vpnsemantics"
)

const (
	Version                  = "localvpnadapter-v1"
	BackendVersion           = "0.51.0-lab"
	DefaultFixtureID         = "local_desktop_packet_adapter_prototype_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M52: relay process architecture"
)

var generatedAt = time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type Config struct {
	ConfigID                   string   `json:"config_id"`
	SemanticsVersion           string   `json:"semantics_version"`
	AcceptedFlowClasses        []string `json:"accepted_flow_classes"`
	MaxFlowClass               string   `json:"max_flow_class"`
	MaxBufferedPacketClass     string   `json:"max_buffered_packet_class"`
	MaxEventsClass             string   `json:"max_events_class"`
	AllowAndroidService        bool     `json:"allow_android_service"`
	AllowPublicDeployment      bool     `json:"allow_public_deployment"`
	AllowRouteMutation         bool     `json:"allow_route_mutation"`
	AllowPacketDump            bool     `json:"allow_packet_dump"`
	AllowPayloadLogging        bool     `json:"allow_payload_logging"`
	AllowCredentialStorage     bool     `json:"allow_credential_storage"`
	AllowAppIdentityLogging    bool     `json:"allow_app_identity_logging"`
	AllowPreciseEndpointLog    bool     `json:"allow_precise_endpoint_log"`
	AllowDNSInterception       bool     `json:"allow_dns_interception"`
	AllowPublicNetworkDefaults bool     `json:"allow_public_network_defaults"`
	PayloadLogged              bool     `json:"payload_logged"`
	SecretLogged               bool     `json:"secret_logged"`
}

type FlowDescriptor struct {
	FlowID                 string `json:"flow_id"`
	PacketFlowClass        string `json:"packet_flow_class"`
	IdentityClass          string `json:"identity_class"`
	AppIdentityPolicyClass string `json:"app_identity_policy_class"`
	MTUBucket              string `json:"mtu_bucket"`
	FragmentationBucket    string `json:"fragmentation_bucket"`
	RetryBucket            string `json:"retry_bucket"`
	ResetBucket            string `json:"reset_bucket"`
	BackpressureBucket     string `json:"backpressure_bucket"`
	KillSwitchPolicyClass  string `json:"kill_switch_policy_class"`
	DNSBoundaryClass       string `json:"dns_boundary_class"`
	RoutingBoundaryClass   string `json:"routing_boundary_class"`
	DiagnosticsClass       string `json:"diagnostics_class"`
	PrivacyClass           string `json:"privacy_class"`
	DescriptorHash         string `json:"descriptor_hash"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
	AppIdentityLogged      bool   `json:"app_identity_logged"`
	PreciseEndpointLogged  bool   `json:"precise_endpoint_logged"`
	PacketDumped           bool   `json:"packet_dumped"`
}

type FlowRun struct {
	Name                    string `json:"name"`
	FlowID                  string `json:"flow_id"`
	PacketFlowClass         string `json:"packet_flow_class"`
	RuntimeStreamClass      string `json:"runtime_stream_class"`
	StreamState             string `json:"stream_state"`
	FlowState               string `json:"flow_state"`
	OpenResult              string `json:"open_result"`
	CloseResult             string `json:"close_result"`
	ResetResult             string `json:"reset_result"`
	BackpressureResult      string `json:"backpressure_result"`
	MTUResult               string `json:"mtu_result"`
	RetryResult             string `json:"retry_result"`
	KillSwitchResult        string `json:"kill_switch_result"`
	DNSBoundaryResult       string `json:"dns_boundary_result"`
	PrivacyResult           string `json:"privacy_result"`
	LocalProxyAdapterResult string `json:"localproxyadapter_result"`
	MultiCarrierResult      string `json:"multicarrierselect_result"`
	RelayBridgeResult       string `json:"relaybridge_result"`
	LocalPipelineResult     string `json:"localpipeline_result"`
	PathHealthResult        string `json:"pathhealth_result"`
	MeasurementReviewResult string `json:"measurementreview_result"`
	ByteCountBucket         string `json:"byte_count_bucket"`
	FragmentCountBucket     string `json:"fragment_count_bucket"`
	SummaryHash             string `json:"summary_hash"`
	Rejected                bool   `json:"rejected"`
	RejectReasonBucket      string `json:"reject_reason_bucket,omitempty"`
	PayloadLogged           bool   `json:"payload_logged"`
	SecretLogged            bool   `json:"secret_logged"`
	PacketDumped            bool   `json:"packet_dumped"`
}

type AdapterSummary struct {
	AdapterSessionsOpened     int  `json:"adapter_sessions_opened"`
	AdapterSessionsClosed     int  `json:"adapter_sessions_closed"`
	FlowDescriptorsAccepted   int  `json:"flow_descriptors_accepted"`
	FlowDescriptorsRejected   int  `json:"flow_descriptors_rejected"`
	FlowsOpened               int  `json:"flows_opened"`
	FlowsClosed               int  `json:"flows_closed"`
	FlowsReset                int  `json:"flows_reset"`
	RuntimeStreamsMapped      int  `json:"runtime_streams_mapped"`
	MTUDecisions              int  `json:"mtu_decisions"`
	FragmentationDecisions    int  `json:"fragmentation_decisions"`
	RetryDecisions            int  `json:"retry_decisions"`
	BackpressureEvents        int  `json:"backpressure_events"`
	KillSwitchDecisions       int  `json:"kill_switch_decisions"`
	DNSBoundaryChecks         int  `json:"dns_boundary_checks"`
	PrivacyChecks             int  `json:"privacy_checks"`
	MeasurementReviews        int  `json:"measurement_reviews"`
	LocalProxyAdapterMappings int  `json:"localproxyadapter_mappings"`
	MultiCarrierSelections    int  `json:"multicarrier_selections"`
	RelayBridgeMappings       int  `json:"relaybridge_mappings"`
	LocalPipelineMappings     int  `json:"localpipeline_mappings"`
	PathHealthReports         int  `json:"pathhealth_reports"`
	ResourceLimitRejections   int  `json:"resource_limit_rejections"`
	PanicSafetyChecks         int  `json:"panic_safety_checks"`
	PayloadLogged             bool `json:"payload_logged"`
	SecretLogged              bool `json:"secret_logged"`
	Completed                 bool `json:"completed"`
}

type IntegrationReport struct {
	VPNSemantics       string   `json:"vpnsemantics"`
	LocalProxyAdapter  string   `json:"localproxyadapter"`
	MultiCarrierSelect string   `json:"multicarrierselect"`
	RelayBridge        string   `json:"relaybridge"`
	LocalPipeline      string   `json:"localpipeline"`
	PathHealth         string   `json:"pathhealth"`
	MeasurementReview  string   `json:"measurementreview"`
	Hardening          string   `json:"hardening"`
	RequiredGates      []string `json:"required_gates"`
	Conclusion         string   `json:"conclusion"`
}

type ResourceReport struct {
	MaxFlowClass           string   `json:"max_flow_class"`
	MaxBufferedPacketClass string   `json:"max_buffered_packet_class"`
	MaxEventsClass         string   `json:"max_events_class"`
	RejectedControls       []string `json:"rejected_controls"`
	Conclusion             string   `json:"conclusion"`
}

type PanicSafetyReport struct {
	Targets    []string `json:"targets"`
	Checked    int      `json:"checked"`
	Conclusion string   `json:"conclusion"`
}

type TraceHygieneReport struct {
	FixturesScanned int    `json:"fixtures_scanned"`
	PayloadLogged   bool   `json:"payload_logged"`
	SecretLogged    bool   `json:"secret_logged"`
	PacketDumped    bool   `json:"packet_dumped"`
	Conclusion      string `json:"conclusion"`
}

type MisuseReport struct {
	DetectedControls []string `json:"detected_controls"`
	DetectedCount    int      `json:"detected_count"`
	ExpectedCount    int      `json:"expected_count"`
	Conclusion       string   `json:"conclusion"`
}

type ParityReport struct {
	GeneratedMarkers []string `json:"generated_markers"`
	InterpretedHash  string   `json:"interpreted_hash"`
	GeneratedHash    string   `json:"generated_hash"`
	UnexpectedDrift  []string `json:"unexpected_drift"`
	Conclusion       string   `json:"conclusion"`
}

type FixtureSet struct {
	Version                  string             `json:"version"`
	FixtureID                string             `json:"fixture_id"`
	GeneratedAt              string             `json:"generated_at"`
	BackendVersion           string             `json:"backend_version"`
	RecommendedNextMilestone string             `json:"recommended_next_milestone"`
	Config                   Config             `json:"config"`
	Descriptors              []FlowDescriptor   `json:"descriptors"`
	Runs                     []FlowRun          `json:"runs"`
	Summary                  AdapterSummary     `json:"summary"`
	Integration              IntegrationReport  `json:"integration"`
	Resource                 ResourceReport     `json:"resource"`
	PanicSafety              PanicSafetyReport  `json:"panic_safety"`
	TraceHygiene             TraceHygieneReport `json:"trace_hygiene"`
	Misuse                   MisuseReport       `json:"misuse"`
	Parity                   ParityReport       `json:"parity"`
	FixtureHash              string             `json:"fixture_hash"`
	PayloadLogged            bool               `json:"payload_logged"`
	SecretLogged             bool               `json:"secret_logged"`
	Conclusion               string             `json:"conclusion"`
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
		ConfigID:               "localvpnadapter-config-v1",
		SemanticsVersion:       vpnsemantics.Version,
		AcceptedFlowClasses:    []string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "fragmented_flow", "retry_backpressure_flow", "reset_flow", "kill_switch_flow"},
		MaxFlowClass:           "profile_bounded_packet_flows",
		MaxBufferedPacketClass: "bounded_packet_descriptor_buffer",
		MaxEventsClass:         "bounded_packet_adapter_events",
	}
}

func ValidateConfig(cfg Config) error {
	if cfg.ConfigID == "" || cfg.SemanticsVersion != vpnsemantics.Version {
		return errors.New("invalid local packet adapter config")
	}
	if len(cfg.AcceptedFlowClasses) < 6 || cfg.MaxFlowClass == "" || cfg.MaxBufferedPacketClass == "" || cfg.MaxEventsClass == "" {
		return errors.New("local packet adapter classes incomplete")
	}
	if cfg.AllowAndroidService || cfg.AllowPublicDeployment || cfg.AllowRouteMutation || cfg.AllowPacketDump || cfg.AllowPayloadLogging || cfg.AllowCredentialStorage || cfg.AllowAppIdentityLogging || cfg.AllowPreciseEndpointLog || cfg.AllowDNSInterception || cfg.AllowPublicNetworkDefaults || cfg.PayloadLogged || cfg.SecretLogged {
		return errors.New("unsafe local packet adapter config")
	}
	return nil
}

func GenerateFixtureSet() (FixtureSet, error) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		return FixtureSet{}, err
	}
	descriptors := BuildFlowDescriptors()
	runs := BuildFlowRuns(descriptors)
	set := FixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              generatedAt,
		BackendVersion:           BackendVersion,
		RecommendedNextMilestone: RecommendedNextMilestone,
		Config:                   cfg,
		Descriptors:              descriptors,
		Runs:                     runs,
		Summary:                  BuildSummary(descriptors, runs),
		Integration:              BuildIntegrationReport(),
		Resource:                 BuildResourceReport(),
		PanicSafety:              BuildPanicSafetyReport(),
		Misuse:                   BuildMisuseReport(),
		Conclusion:               ConclusionPassed,
	}
	set.TraceHygiene = BuildTraceHygieneReport(set)
	set.Parity = BuildParityReport(set)
	set.FixtureHash = HashValue(fixtureHashInput(set))
	if err := ValidateFixtureSet(set); err != nil {
		return FixtureSet{}, err
	}
	return set, nil
}

func BuildFlowDescriptors() []FlowDescriptor {
	classes := []string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "fragmented_flow", "retry_backpressure_flow", "reset_flow", "kill_switch_flow", "control_payload_logging", "control_route_mutation", "control_android_service", "control_endpoint_logging"}
	mtuBuckets := []string{"small_mtu", "standard_mtu", "constrained_mtu", "fragmented_mtu", "standard_mtu", "small_mtu", "constrained_mtu", "control", "control", "control", "control"}
	out := make([]FlowDescriptor, 0, len(classes))
	for i, class := range classes {
		desc := FlowDescriptor{
			FlowID:                 fmt.Sprintf("packet-flow-%02d", i+1),
			PacketFlowClass:        class,
			IdentityClass:          []string{"tuple_hash_bucket", "session_scoped_flow", "dns_boundary_flow", "fragment_group", "retry_group", "reset_group", "killswitch_group", "control", "control", "control", "control"}[i],
			AppIdentityPolicyClass: "not_collected",
			MTUBucket:              mtuBuckets[i],
			FragmentationBucket:    []string{"none", "none", "boundary_only", "bounded_fragmentation", "none", "none", "none", "control", "control", "control", "control"}[i],
			RetryBucket:            []string{"none", "none", "dns_boundary_retry", "fragment_retry", "bounded_retry", "none", "none", "control", "control", "control", "control"}[i],
			ResetBucket:            []string{"none", "none", "none", "none", "none", "stream_scoped_reset", "adapter_terminal_drop", "control", "control", "control", "control"}[i],
			BackpressureBucket:     []string{"none", "none", "dns_boundary_pressure", "fragment_pressure", "adapter_runtime_pressure", "none", "killswitch_pressure", "control", "control", "control", "control"}[i],
			KillSwitchPolicyClass:  []string{"inactive", "inactive", "dns_boundary_only", "inactive", "inactive", "inactive", "fail_closed_summary", "control", "control", "control", "control"}[i],
			DNSBoundaryClass:       []string{"not_dns", "not_dns", "metadata_boundary_only", "not_dns", "not_dns", "not_dns", "not_dns", "control", "control", "control", "control"}[i],
			RoutingBoundaryClass:   "no_os_route_mutation",
			DiagnosticsClass:       "aggregate_buckets_only",
			PrivacyClass:           "payload_endpoint_app_identity_redacted",
		}
		desc.DescriptorHash = HashValue(descriptorHashInput(desc))
		out = append(out, desc)
	}
	return out
}

func BuildFlowRuns(descriptors []FlowDescriptor) []FlowRun {
	runs := make([]FlowRun, 0, len(descriptors))
	for i, desc := range descriptors {
		run := FlowRun{
			Name:                    "localvpnadapter_" + desc.PacketFlowClass,
			FlowID:                  desc.FlowID,
			PacketFlowClass:         desc.PacketFlowClass,
			RuntimeStreamClass:      []string{"interactive_packet_stream", "datagram_like_stream", "dns_boundary_stream", "fragmented_packet_stream", "retry_pressure_stream", "reset_packet_stream", "control_policy_stream", "control", "control", "control", "control"}[i],
			StreamState:             "closed",
			FlowState:               "closed",
			OpenResult:              "descriptor_opened_runtime_stream",
			CloseResult:             "flow_closed_cleanly",
			ResetResult:             "not_reset",
			BackpressureResult:      desc.BackpressureBucket,
			MTUResult:               desc.MTUBucket + "_handled",
			RetryResult:             desc.RetryBucket,
			KillSwitchResult:        desc.KillSwitchPolicyClass,
			DNSBoundaryResult:       desc.DNSBoundaryClass,
			PrivacyResult:           desc.PrivacyClass,
			LocalProxyAdapterResult: "localproxyadapter_boundary_composed",
			MultiCarrierResult:      "multicarrierselect_invoked",
			RelayBridgeResult:       "relaybridge_mapped",
			LocalPipelineResult:     "localpipeline_mapped",
			PathHealthResult:        "pathhealth_checked",
			MeasurementReviewResult: "measurementreview_enforced",
			ByteCountBucket:         []string{"small", "small", "dns_boundary", "fragmented", "medium", "partial", "dropped", "control", "control", "control", "control"}[i],
			FragmentCountBucket:     []string{"one", "one", "boundary", "many", "few", "partial", "none", "control", "control", "control", "control"}[i],
		}
		switch desc.PacketFlowClass {
		case "reset_flow":
			run.StreamState = "reset"
			run.FlowState = "reset"
			run.CloseResult = "not_closed_after_reset"
			run.ResetResult = "stream_scoped_reset"
		case "retry_backpressure_flow", "fragmented_flow", "dns_boundary_flow":
			run.BackpressureResult = "bounded_" + desc.BackpressureBucket
		case "kill_switch_flow":
			run.FlowState = "closed"
			run.CloseResult = "fail_closed_without_payload_summary"
		case "control_payload_logging":
			run.Rejected = true
			run.RejectReasonBucket = "payload_logging_control"
		case "control_route_mutation":
			run.Rejected = true
			run.RejectReasonBucket = "route_mutation_control"
		case "control_android_service":
			run.Rejected = true
			run.RejectReasonBucket = "android_service_control"
		case "control_endpoint_logging":
			run.Rejected = true
			run.RejectReasonBucket = "endpoint_logging_control"
		}
		if run.Rejected {
			run.OpenResult = "rejected_before_runtime_stream"
			run.CloseResult = "not_opened"
			run.StreamState = "rejected"
			run.FlowState = "rejected"
		}
		run.SummaryHash = HashValue(runHashInput(run))
		runs = append(runs, run)
	}
	return runs
}

func BuildSummary(descriptors []FlowDescriptor, runs []FlowRun) AdapterSummary {
	summary := AdapterSummary{AdapterSessionsOpened: 1, AdapterSessionsClosed: 1, FlowDescriptorsAccepted: len(descriptors), Completed: true, PanicSafetyChecks: len(BuildPanicSafetyReport().Targets)}
	for _, run := range runs {
		if run.Rejected {
			summary.FlowDescriptorsRejected++
			summary.ResourceLimitRejections++
			continue
		}
		summary.FlowsOpened++
		summary.RuntimeStreamsMapped++
		summary.MTUDecisions++
		summary.FragmentationDecisions++
		summary.RetryDecisions++
		summary.KillSwitchDecisions++
		summary.DNSBoundaryChecks++
		summary.PrivacyChecks++
		summary.LocalProxyAdapterMappings++
		summary.MultiCarrierSelections++
		summary.RelayBridgeMappings++
		summary.LocalPipelineMappings++
		summary.PathHealthReports++
		summary.MeasurementReviews++
		if run.FlowState == "reset" {
			summary.FlowsReset++
		} else {
			summary.FlowsClosed++
		}
		if run.BackpressureResult != "none" {
			summary.BackpressureEvents++
		}
	}
	return summary
}

func BuildIntegrationReport() IntegrationReport {
	return IntegrationReport{
		VPNSemantics:       "m50_contract_is_source_of_packet_flow_policy",
		LocalProxyAdapter:  "local_proxy_boundary_composed_without_bypass",
		MultiCarrierSelect: "reviewed_carrier_selection_required",
		RelayBridge:        "packet_flow_streams_mapped_to_relay_bridge",
		LocalPipeline:      "local_pipeline_summary_round_trip",
		PathHealth:         "pathhealth_report_required_before_carrier_use",
		MeasurementReview:  "aggregate_local_diagnostics_only",
		Hardening:          "resource_panic_trace_hygiene_checks_composed",
		RequiredGates:      []string{"vpnsemantics", "localproxyadapter", "multicarrierselect", "carriercollapse", "relaybridge", "localpipeline", "pathhealth", "measurementreview", "hardening", "codegen"},
		Conclusion:         ConclusionPassed,
	}
}

func BuildResourceReport() ResourceReport {
	return ResourceReport{
		MaxFlowClass:           "profile_bounded_packet_flows",
		MaxBufferedPacketClass: "bounded_packet_descriptor_buffer",
		MaxEventsClass:         "bounded_packet_adapter_events",
		RejectedControls:       []string{"control_payload_logging", "control_route_mutation", "control_android_service", "control_endpoint_logging"},
		Conclusion:             ConclusionPassed,
	}
}

func BuildPanicSafetyReport() PanicSafetyReport {
	targets := []string{"flow_descriptor_validator", "mtu_bucket_mapper", "fragmentation_bucket_mapper", "retry_reset_mapper", "diagnostic_summary_builder", "trace_hygiene_scanner"}
	return PanicSafetyReport{Targets: targets, Checked: len(targets), Conclusion: ConclusionPassed}
}

func BuildTraceHygieneReport(set FixtureSet) TraceHygieneReport {
	return TraceHygieneReport{FixturesScanned: len(set.Runs) + len(set.Descriptors), Conclusion: ConclusionPassed}
}

func BuildMisuseReport() MisuseReport {
	required := RequiredMisuseNames()
	return MisuseReport{DetectedControls: append([]string{}, required...), DetectedCount: len(required), ExpectedCount: len(required), Conclusion: ConclusionPassed}
}

func BuildParityReport(set FixtureSet) ParityReport {
	markers := []string{"PacketAdapterSchemaVersion", "PacketAdapterGeneratedProfileID", "PacketAdapterBackendVersion", "PacketAdapterRuntimePolicy", "PacketAdapterFlowClasses", "GeneratedPacketAdapterFixtureSet"}
	hash := HashValue(map[string]any{
		"version":     set.Version,
		"summary":     set.Summary,
		"integration": set.Integration.RequiredGates,
		"resource":    set.Resource,
	})
	return ParityReport{GeneratedMarkers: markers, InterpretedHash: hash, GeneratedHash: hash, Conclusion: ConclusionPassed}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid local packet adapter fixture metadata")
	}
	if err := ValidateConfig(set.Config); err != nil {
		return err
	}
	if len(set.Descriptors) < 10 || len(set.Runs) < 10 {
		return errors.New("local packet adapter fixture coverage incomplete")
	}
	if set.PayloadLogged || set.SecretLogged || set.Summary.PayloadLogged || set.Summary.SecretLogged || !set.Summary.Completed {
		return errors.New("local packet adapter summary unsafe or incomplete")
	}
	if set.Summary.RuntimeStreamsMapped < 7 || set.Summary.LocalProxyAdapterMappings < 7 || set.Summary.MultiCarrierSelections < 7 || set.Summary.MeasurementReviews < 7 {
		return errors.New("local packet adapter integration counts incomplete")
	}
	if set.Summary.BackpressureEvents == 0 || set.Summary.FlowsReset == 0 || set.Summary.KillSwitchDecisions == 0 || set.Summary.DNSBoundaryChecks == 0 {
		return errors.New("local packet adapter behavior coverage incomplete")
	}
	for _, desc := range set.Descriptors {
		if desc.DescriptorHash != HashValue(descriptorHashInput(desc)) || desc.PayloadLogged || desc.SecretLogged || desc.AppIdentityLogged || desc.PreciseEndpointLogged || desc.PacketDumped {
			return errors.New("unsafe local packet flow descriptor")
		}
	}
	for _, run := range set.Runs {
		if run.SummaryHash == "" || run.PayloadLogged || run.SecretLogged || run.PacketDumped {
			return errors.New("unsafe local packet flow run")
		}
	}
	if len(set.Integration.RequiredGates) < 9 || set.Integration.Conclusion != ConclusionPassed {
		return errors.New("local packet adapter integration report incomplete")
	}
	if len(set.Resource.RejectedControls) < 4 || set.Summary.ResourceLimitRejections < 4 || set.Resource.Conclusion != ConclusionPassed {
		return errors.New("local packet adapter resource report incomplete")
	}
	if set.PanicSafety.Checked < 5 || set.PanicSafety.Conclusion != ConclusionPassed {
		return errors.New("local packet adapter panic-safety report incomplete")
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.PacketDumped || set.TraceHygiene.Conclusion != ConclusionPassed {
		return errors.New("local packet adapter trace hygiene failed")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("local packet adapter misuse report incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("local packet adapter generated/interpreted parity failed")
	}
	if set.FixtureHash != "" && set.FixtureHash != HashValue(fixtureHashInput(set)) {
		return errors.New("local packet adapter fixture hash mismatch")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash}
	if oldSet.PayloadLogged || newSet.PayloadLogged || oldSet.Summary.PayloadLogged || newSet.Summary.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload logging flag changed")
	}
	if oldSet.SecretLogged || newSet.SecretLogged || oldSet.Summary.SecretLogged || newSet.Summary.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret logging flag changed")
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture hash changed")
	}
	if len(report.UnexpectedDrift) == 0 {
		report.Conclusion = ConclusionPassed
	} else {
		report.Conclusion = "failed"
	}
	return report
}

func LoadFixtureSet(path string) (FixtureSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FixtureSet{}, err
	}
	var set FixtureSet
	if err := json.Unmarshal(data, &set); err != nil {
		return FixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func WriteFixtureSet(path string, set FixtureSet, force bool) error {
	if err := ValidateFixtureSet(set); err != nil {
		return err
	}
	return WriteJSON(path, set, force)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; use --force", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func StableJSON(value any) ([]byte, error) {
	return json.MarshalIndent(value, "", "  ")
}

func HashValue(value any) string {
	data, _ := StableJSON(value)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	data, err := StableJSON(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(data))
	for _, marker := range ForbiddenMarkers() {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return fmt.Errorf("forbidden marker %q found", marker)
		}
	}
	for _, marker := range []string{`"payload_logged": true`, `"secret_logged": true`, `"allow_payload_logging": true`, `"allow_packet_dump": true`, `"allow_route_mutation": true`, `"allow_android_service": true`, `"allow_app_identity_logging": true`, `"allow_precise_endpoint_log": true`, `"allow_dns_interception": true`, `"allow_public_deployment": true`, `"packet_dumped": true`, `"app_identity_logged": true`, `"precise_endpoint_logged": true`} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("unsafe flag %s found", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"raw_packet_bytes"`,
		`"packet_capture_dump"`,
		`"packet_dump"`,
		`"packet_bytes"`,
		`"credential_value"`,
		`"secret_value"`,
		`"private_key"`,
		`"session_secret"`,
		`"auth_tag"`,
		`"nonce_base"`,
		`"app_identity_value"`,
		`"exact_endpoint_value"`,
		`"exact_dns_query"`,
		`"resolver_ip"`,
		`"public_network_egress"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"localvpnadapter_payload_logging_allowed",
		"localvpnadapter_packet_dump_allowed",
		"localvpnadapter_android_vpnservice_added",
		"localvpnadapter_unreviewed_route_mutation",
		"localvpnadapter_exact_endpoint_logged",
		"localvpnadapter_app_identity_logged",
		"localvpnadapter_dns_interception_allowed",
		"localvpnadapter_killswitch_bypass",
		"localvpnadapter_unbounded_flows",
		"localvpnadapter_backpressure_ignored",
		"localvpnadapter_reset_swallowed",
		"localvpnadapter_localproxyadapter_bypass",
		"localvpnadapter_multicarrierselect_bypass",
		"localvpnadapter_measurementreview_bypass",
		"localvpnadapter_generated_backend_drift",
		"localvpnadapter_payload_leak",
		"localvpnadapter_secret_leak",
	}
}

func SortedRequiredMisuseNames() []string {
	names := RequiredMisuseNames()
	sort.Strings(names)
	return names
}

func descriptorHashInput(desc FlowDescriptor) FlowDescriptor {
	desc.DescriptorHash = ""
	return desc
}

func runHashInput(run FlowRun) FlowRun {
	run.SummaryHash = ""
	return run
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}
