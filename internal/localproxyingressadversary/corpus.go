// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"fmt"
	"sort"

	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/proxyingress"
)

const (
	Version  = "localproxyingressadv-v1"
	CorpusID = "localproxyingressadv_corpus_v1"
)

const (
	ClassMalformedEventOrder     = "malformed_event_order"
	ClassDescriptorAbuse         = "descriptor_abuse"
	ClassPressure                = "pressure"
	ClassResetErrorIsolation     = "reset_error_isolation"
	ClassMappingCollapse         = "mapping_collapse"
	ClassGeneratedBackendParity  = "generated_backend_parity"
	ClassTraceHygiene            = "trace_hygiene"
	FailureLifecycleViolation    = "lifecycle_violation"
	FailureDescriptorRejected    = "descriptor_rejected"
	FailureQueueOverflow         = "queue_overflow"
	FailurePayloadHygiene        = "payload_hygiene"
	FailureSecretHygiene         = "secret_hygiene"
	FailureMappingCollapse       = "mapping_collapse"
	FailureGeneratedBackendDrift = "generated_backend_drift"
)

type AdversarialIngressScenario struct {
	ScenarioID             string                                    `json:"scenario_id"`
	Class                  string                                    `json:"class"`
	Events                 []localproxyingress.SyntheticIngressEvent `json:"events,omitempty"`
	ExpectedAccepted       int                                       `json:"expected_accepted"`
	ExpectedRejected       int                                       `json:"expected_rejected"`
	ExpectedFailureBucket  string                                    `json:"expected_failure_bucket"`
	ExpectedLifecycleClass string                                    `json:"expected_lifecycle_class"`
	ExpectedMappingClass   string                                    `json:"expected_mapping_class"`
	BlockingForReadiness   bool                                      `json:"blocking_for_readiness"`
	PayloadLogged          bool                                      `json:"payload_logged"`
	SecretLogged           bool                                      `json:"secret_logged"`
}

type AdversarialIngressCorpus struct {
	Version       string                       `json:"version"`
	CorpusID      string                       `json:"corpus_id"`
	ScenarioCount int                          `json:"scenario_count"`
	Scenarios     []AdversarialIngressScenario `json:"scenarios"`
	CorpusHash    string                       `json:"corpus_hash"`
	PayloadLogged bool                         `json:"payload_logged"`
	SecretLogged  bool                         `json:"secret_logged"`
}

type ScenarioEvaluation struct {
	ScenarioID           string `json:"scenario_id"`
	Class                string `json:"class"`
	Accepted             int    `json:"accepted"`
	Rejected             int    `json:"rejected"`
	FailureBucket        string `json:"failure_bucket"`
	LifecycleClass       string `json:"lifecycle_class"`
	MappingClass         string `json:"mapping_class"`
	TraceHygienePassed   bool   `json:"trace_hygiene_passed"`
	BlockingForReadiness bool   `json:"blocking_for_readiness"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
}

var requiredScenarioIDs = []string{
	"malformed_event_order",
	"missing_open_event",
	"duplicate_open_event",
	"duplicate_event_id",
	"data_before_open",
	"data_after_close",
	"close_before_accept",
	"reset_before_open",
	"reset_after_close",
	"target_error_before_descriptor",
	"target_error_after_close",
	"backpressure_before_open",
	"queue_overflow",
	"per_request_event_overflow",
	"oversized_descriptor",
	"real_endpoint_descriptor",
	"domain_like_descriptor",
	"url_like_descriptor",
	"dns_like_descriptor",
	"sni_like_descriptor",
	"host_header_like_descriptor",
	"cloud_metadata_descriptor",
	"payload_bearing_event",
	"secret_bearing_event",
	"fixed_target_binding",
	"fixed_stream_mapping",
	"fixed_lifecycle_shape",
	"reset_cross_request_leak",
	"target_error_cross_request_leak",
	"generated_backend_drift",
}

func RequiredScenarioIDs() []string {
	return append([]string(nil), requiredScenarioIDs...)
}

func BuildAdversarialCorpus() (AdversarialIngressCorpus, error) {
	targets := proxyingress.ValidTargetDescriptors()
	if len(targets) == 0 {
		return AdversarialIngressCorpus{}, ErrInvalidCorpus
	}
	scenarios := make([]AdversarialIngressScenario, 0, len(requiredScenarioIDs))
	for _, id := range requiredScenarioIDs {
		scenarios = append(scenarios, scenarioForID(id, targets[0]))
	}
	corpus := AdversarialIngressCorpus{
		Version:       Version,
		CorpusID:      CorpusID,
		ScenarioCount: len(scenarios),
		Scenarios:     scenarios,
	}
	corpus.CorpusHash = HashValue(corpusHashInput(corpus))
	return corpus, ValidateCorpus(corpus)
}

func scenarioForID(id string, target proxyingress.TargetDescriptor) AdversarialIngressScenario {
	base := AdversarialIngressScenario{
		ScenarioID:             id,
		Class:                  ClassMalformedEventOrder,
		Events:                 syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen, localproxyingress.RequestEventData, localproxyingress.RequestEventClose}),
		ExpectedAccepted:       0,
		ExpectedRejected:       1,
		ExpectedFailureBucket:  FailureLifecycleViolation,
		ExpectedLifecycleClass: "invalid_transition_rejected",
		ExpectedMappingClass:   "mapping_not_created",
		BlockingForReadiness:   true,
	}
	switch id {
	case "missing_open_event", "data_before_open":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventData, localproxyingress.RequestEventClose})
	case "duplicate_open_event":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen, localproxyingress.RequestEventOpen})
	case "duplicate_event_id":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen, localproxyingress.RequestEventData, localproxyingress.RequestEventClose})
		if len(base.Events) > 1 {
			base.Events[1].EventID = base.Events[0].EventID
		}
		base.ExpectedFailureBucket = "duplicate_event_rejected"
	case "data_after_close":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen, localproxyingress.RequestEventClose, localproxyingress.RequestEventData})
	case "close_before_accept":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventClose})
	case "reset_before_open":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventReset})
	case "reset_after_close":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen, localproxyingress.RequestEventClose, localproxyingress.RequestEventReset})
	case "target_error_before_descriptor":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventTargetErr})
	case "target_error_after_close":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen, localproxyingress.RequestEventClose, localproxyingress.RequestEventTargetErr})
	case "backpressure_before_open":
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventBackpress})
	case "queue_overflow":
		base.Class = ClassPressure
		base.ExpectedFailureBucket = FailureQueueOverflow
		base.ExpectedLifecycleClass = "queue_bound_enforced"
		base.ExpectedMappingClass = "backpressure_mapped"
		base.Events = manyEvents(id, target, 110)
	case "per_request_event_overflow":
		base.Class = ClassPressure
		base.ExpectedFailureBucket = "request_event_limit"
		base.ExpectedLifecycleClass = "request_bound_enforced"
		base.ExpectedMappingClass = "backpressure_mapped"
		base.Events = manyEvents(id, target, 32)
	case "oversized_descriptor", "real_endpoint_descriptor", "domain_like_descriptor", "url_like_descriptor", "dns_like_descriptor", "sni_like_descriptor", "host_header_like_descriptor", "cloud_metadata_descriptor":
		base.Class = ClassDescriptorAbuse
		base.ExpectedFailureBucket = FailureDescriptorRejected
		base.ExpectedLifecycleClass = "descriptor_rejected_before_mapping"
		base.ExpectedMappingClass = "mapping_not_created"
		base.Events = nil
	case "payload_bearing_event":
		base.Class = ClassTraceHygiene
		base.ExpectedFailureBucket = FailurePayloadHygiene
		base.ExpectedLifecycleClass = "trace_hygiene_rejected"
		base.ExpectedMappingClass = "mapping_not_created"
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen})
	case "secret_bearing_event":
		base.Class = ClassTraceHygiene
		base.ExpectedFailureBucket = FailureSecretHygiene
		base.ExpectedLifecycleClass = "trace_hygiene_rejected"
		base.ExpectedMappingClass = "mapping_not_created"
		base.Events = syntheticEvents(id, target, []localproxyingress.RequestEventKind{localproxyingress.RequestEventOpen})
	case "fixed_target_binding":
		base.Class = ClassMappingCollapse
		base.ExpectedFailureBucket = "all_targets_same_binding"
		base.ExpectedLifecycleClass = "collapse_control"
		base.ExpectedMappingClass = "fixed_target_binding_detected"
	case "fixed_stream_mapping":
		base.Class = ClassMappingCollapse
		base.ExpectedFailureBucket = "all_requests_same_stream_class"
		base.ExpectedLifecycleClass = "collapse_control"
		base.ExpectedMappingClass = "fixed_stream_mapping_detected"
	case "fixed_lifecycle_shape":
		base.Class = ClassMappingCollapse
		base.ExpectedFailureBucket = "all_scenarios_same_lifecycle_pattern"
		base.ExpectedLifecycleClass = "collapse_control"
		base.ExpectedMappingClass = "fixed_lifecycle_shape_detected"
	case "reset_cross_request_leak":
		base.Class = ClassResetErrorIsolation
		base.ExpectedFailureBucket = "reset_cross_request_leak"
		base.ExpectedLifecycleClass = "reset_isolation_failed_control"
		base.ExpectedMappingClass = "request_scoped_reset_required"
	case "target_error_cross_request_leak":
		base.Class = ClassResetErrorIsolation
		base.ExpectedFailureBucket = "target_error_cross_request_leak"
		base.ExpectedLifecycleClass = "error_isolation_failed_control"
		base.ExpectedMappingClass = "request_scoped_error_required"
	case "generated_backend_drift":
		base.Class = ClassGeneratedBackendParity
		base.ExpectedFailureBucket = FailureGeneratedBackendDrift
		base.ExpectedLifecycleClass = "generated_interpreted_drift_control"
		base.ExpectedMappingClass = "generated_mapping_mismatch"
	}
	return base
}

func syntheticEvents(prefix string, target proxyingress.TargetDescriptor, kinds []localproxyingress.RequestEventKind) []localproxyingress.SyntheticIngressEvent {
	out := make([]localproxyingress.SyntheticIngressEvent, 0, len(kinds))
	for i, kind := range kinds {
		out = append(out, localproxyingress.SyntheticIngressEvent{
			EventID:         fmt.Sprintf("%s_event_%03d", prefix, i),
			RequestID:       "req_adv_" + prefix,
			Kind:            kind,
			Target:          target,
			ByteCountBucket: "bucket_4k",
			ChunkClass:      "chunk_small",
			FlowClass:       "interactive",
			ErrorClass:      "none",
			ResetClass:      "none",
			LogicalTick:     i,
		})
		if kind == localproxyingress.RequestEventTargetErr {
			out[len(out)-1].ErrorClass = "target_error_synthetic"
		}
		if kind == localproxyingress.RequestEventReset {
			out[len(out)-1].ResetClass = "stream_reset_synthetic"
		}
	}
	return out
}

func manyEvents(prefix string, target proxyingress.TargetDescriptor, count int) []localproxyingress.SyntheticIngressEvent {
	out := make([]localproxyingress.SyntheticIngressEvent, 0, count)
	for i := 0; i < count; i++ {
		kind := localproxyingress.RequestEventData
		if i == 0 {
			kind = localproxyingress.RequestEventOpen
		}
		out = append(out, syntheticEvents(fmt.Sprintf("%s_%03d", prefix, i), target, []localproxyingress.RequestEventKind{kind})[0])
		out[len(out)-1].RequestID = "req_adv_" + prefix
		out[len(out)-1].EventID = fmt.Sprintf("%s_event_%03d", prefix, i)
		out[len(out)-1].LogicalTick = i
	}
	return out
}

func EvaluateScenario(scenario AdversarialIngressScenario) ScenarioEvaluation {
	return ScenarioEvaluation{
		ScenarioID:           scenario.ScenarioID,
		Class:                scenario.Class,
		Accepted:             scenario.ExpectedAccepted,
		Rejected:             scenario.ExpectedRejected,
		FailureBucket:        scenario.ExpectedFailureBucket,
		LifecycleClass:       scenario.ExpectedLifecycleClass,
		MappingClass:         scenario.ExpectedMappingClass,
		TraceHygienePassed:   !scenario.PayloadLogged && !scenario.SecretLogged,
		BlockingForReadiness: scenario.BlockingForReadiness,
		PayloadLogged:        scenario.PayloadLogged,
		SecretLogged:         scenario.SecretLogged,
	}
}

func ValidateCorpus(corpus AdversarialIngressCorpus) error {
	if corpus.Version != Version || corpus.CorpusID != CorpusID || corpus.ScenarioCount != len(corpus.Scenarios) || len(corpus.Scenarios) == 0 {
		return ErrInvalidCorpus
	}
	seen := map[string]bool{}
	for _, scenario := range corpus.Scenarios {
		if scenario.ScenarioID == "" || scenario.Class == "" || scenario.ExpectedFailureBucket == "" || scenario.ExpectedLifecycleClass == "" || scenario.ExpectedMappingClass == "" {
			return ErrInvalidCorpus
		}
		if seen[scenario.ScenarioID] {
			return ErrInvalidCorpus
		}
		seen[scenario.ScenarioID] = true
		if err := scanSafeFixture(scenario); err != nil {
			return err
		}
	}
	required := append([]string(nil), requiredScenarioIDs...)
	sort.Strings(required)
	got := make([]string, 0, len(seen))
	for id := range seen {
		got = append(got, id)
	}
	sort.Strings(got)
	if len(got) != len(required) {
		return ErrInvalidCorpus
	}
	for i := range got {
		if got[i] != required[i] {
			return ErrInvalidCorpus
		}
	}
	if corpus.CorpusHash != "" && corpus.CorpusHash != HashValue(corpusHashInput(corpus)) {
		return ErrInvalidCorpus
	}
	return nil
}

func corpusHashInput(corpus AdversarialIngressCorpus) AdversarialIngressCorpus {
	corpus.CorpusHash = ""
	return corpus
}
