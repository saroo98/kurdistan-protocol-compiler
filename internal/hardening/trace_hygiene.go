// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"kurdistan/internal/adapter"
	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/bytetransport"
	"kurdistan/internal/classifierdata"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/hostdetect"
	"kurdistan/internal/ir"
	"kurdistan/internal/localadapter"
	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/pathrace"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
	"kurdistan/internal/relayfleet"
	kruntime "kurdistan/internal/runtime"
	ktrace "kurdistan/internal/trace"
	"kurdistan/internal/transportbundle"
	"kurdistan/internal/wireeval"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregencompare"
)

type TraceHygieneReport struct {
	Passed   bool     `json:"passed"`
	Findings []string `json:"findings,omitempty"`
}

var forbiddenTraceKeys = []string{
	"raw_secret",
	"derived_key",
	"nonce_base",
	"plaintext_payload",
	"ciphertext_payload",
	"auth_tag",
	"proof_material",
	"private_key",
	"session_secret",
	"client_write_key",
	"server_write_key",
	"exporter_secret",
	"payload",
	"raw_payload",
	"raw_bytes",
	"encoded_bytes",
	"decoded_bytes",
	"pcap",
	"packet_dump",
	"capture_bytes",
	"destination_address",
	"endpoint",
	"real_host",
	"proxy_ip",
	"server_ip",
	"domain",
	"sni",
	"host_header",
	"url",
	"dns_query",
	"resolver",
	"resolver_ip",
	"nameserver",
	"ip_address",
	"cloud_provider",
	"aws",
	"gcp",
	"azure",
	"region",
	"instance_id",
	"credential",
	"plaintext",
	"ciphertext",
	"secret",
}

func ScanJSON(raw []byte) TraceHygieneReport {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return TraceHygieneReport{Passed: false, Findings: []string{"invalid_json"}}
	}
	findings := []string{}
	scanValue(value, "", &findings)
	return TraceHygieneReport{Passed: len(findings) == 0, Findings: findings}
}

func ScanValue(value any) TraceHygieneReport {
	raw, err := json.Marshal(value)
	if err != nil {
		return TraceHygieneReport{Passed: false, Findings: []string{"marshal_failed"}}
	}
	return ScanJSON(raw)
}

func ScanEvents(events []ktrace.Event) TraceHygieneReport {
	return ScanValue(events)
}

func ScanErrorString(value string) TraceHygieneReport {
	lower := strings.ToLower(value)
	findings := []string{}
	for _, marker := range forbiddenTraceKeys {
		if strings.Contains(lower, marker) {
			findings = append(findings, marker)
		}
	}
	return TraceHygieneReport{Passed: len(findings) == 0, Findings: findings}
}

func RunTraceHygieneChecks(ctx context.Context, profiles []*ir.Profile) []CheckResult {
	p := firstProfile(profiles)
	results := []CheckResult{}
	results = append(results, check("clean_trace_hygiene_passes", CategoryTraceHygiene, func() error {
		evs := []ktrace.Event{{ProfileID: p.ID, EventType: "runtime", PayloadHygiene: true, SecretHygiene: true}}
		report := ScanEvents(evs)
		if !report.Passed {
			return fmt.Errorf("clean trace rejected: %v", report.Findings)
		}
		return nil
	}))
	results = append(results, check("secret_marker_rejected", CategoryTraceHygiene, func() error {
		if ScanJSON([]byte(`{"client_write_key":"abc"}`)).Passed {
			return fmt.Errorf("client_write_key accepted")
		}
		if ScanJSON([]byte(`{"raw_secret":"abc"}`)).Passed {
			return fmt.Errorf("raw_secret accepted")
		}
		return nil
	}))
	results = append(results, check("payload_marker_rejected", CategoryTraceHygiene, func() error {
		if ScanJSON([]byte(`{"payload":"hello"}`)).Passed {
			return fmt.Errorf("payload field accepted")
		}
		return nil
	}))
	results = append(results, check("runtime_summary_leak_flags_rejected", CategoryTraceHygiene, func() error {
		if ScanValue(kruntime.HarnessSummary{PayloadLogged: true}).Passed {
			return fmt.Errorf("PayloadLogged=true accepted")
		}
		if ScanValue(kruntime.HarnessSummary{SecretLogged: true}).Passed {
			return fmt.Errorf("SecretLogged=true accepted")
		}
		return nil
	}))
	results = append(results, check("generated_runtime_trace_hygiene", CategorySecurityHygiene, func() error {
		summary, events, err := kruntime.RunLocalHarness(ctx, p, kruntime.HarnessOptions{ClientSecret: []byte("hardening-secret"), ServerSecret: []byte("hardening-secret")})
		if err != nil {
			return err
		}
		if summary.PayloadLogged || summary.SecretLogged {
			return fmt.Errorf("runtime reported leak")
		}
		raw, _ := json.Marshal(events)
		if bytes.Contains(raw, []byte("hardening-secret")) || bytes.Contains(raw, []byte("runtime-local-bytes")) {
			return fmt.Errorf("trace contained sensitive bytes")
		}
		report := ScanEvents(events)
		if !report.Passed {
			return fmt.Errorf("trace hygiene failed: %v", report.Findings)
		}
		return nil
	}))
	results = append(results, check("adapter_trace_hygiene", CategoryTraceHygiene, func() error {
		evs := []ktrace.Event{{EventType: "adapter", AdapterKind: "ingress", FlowState: "open", FlowEvent: "flow_progress", PayloadHygiene: true, SecretHygiene: true}}
		report := ScanEvents(evs)
		if !report.Passed {
			return fmt.Errorf("adapter trace rejected: %v", report.Findings)
		}
		if ScanValue(adapter.AdapterHarnessSummary{PayloadLogged: true}).Passed {
			return fmt.Errorf("adapter payload leak flag accepted")
		}
		if ScanValue(adapter.AdapterHarnessSummary{SecretLogged: true}).Passed {
			return fmt.Errorf("adapter secret leak flag accepted")
		}
		return nil
	}))
	results = append(results, check("local_adapter_trace_hygiene", CategoryTraceHygiene, func() error {
		evs := []ktrace.Event{{
			EventType:                    "local_adapter",
			LocalAdapterSourceModel:      localadapter.SourceSmallBurst,
			LocalAdapterSinkModel:        "memory_sink",
			LocalFlowState:               "open",
			LocalSequenceIntegrityResult: "passed",
			LocalAdapterScenario:         localadapter.ScenarioSingleFlowEcho,
			PayloadHygiene:               true,
			SecretHygiene:                true,
			LocalSourceChunkCountBucket:  "1",
			LocalSinkChunkCountBucket:    "1",
			LocalSourceByteBucket:        "small",
			LocalSinkByteBucket:          "small",
			LocalPostCloseRejections:     0,
			LocalBackpressureCount:       0,
			LocalQueuePressureCount:      0,
		}}
		report := ScanEvents(evs)
		if !report.Passed {
			return fmt.Errorf("local adapter trace rejected: %v", report.Findings)
		}
		if ScanValue(localadapter.LocalAdapterSummary{PayloadLogged: true}).Passed {
			return fmt.Errorf("local adapter payload leak flag accepted")
		}
		if ScanValue(localadapter.LocalAdapterSummary{SecretLogged: true}).Passed {
			return fmt.Errorf("local adapter secret leak flag accepted")
		}
		return nil
	}))
	results = append(results, check("byte_transport_trace_hygiene", CategoryTraceHygiene, func() error {
		evs := []ktrace.Event{{
			EventType:                   "byte_transport",
			ByteTransportScenario:       bytetransport.ScenarioSingleFlow,
			ByteFrameKindBucket:         "data",
			ByteFrameCountBucket:        "small",
			ByteFragmentCountBucket:     "small",
			ByteCountBucket:             "small",
			BytePipeQueuePressureBucket: "zero",
			ByteReassemblyResult:        "passed",
			PayloadHygiene:              true,
			SecretHygiene:               true,
		}}
		report := ScanEvents(evs)
		if !report.Passed {
			return fmt.Errorf("byte transport trace rejected: %v", report.Findings)
		}
		if ScanValue(bytetransport.ByteTransportSummary{PayloadLogged: true}).Passed {
			return fmt.Errorf("byte transport payload leak flag accepted")
		}
		if ScanValue(bytetransport.ByteTransportSummary{SecretLogged: true}).Passed {
			return fmt.Errorf("byte transport secret leak flag accepted")
		}
		return nil
	}))
	results = append(results, check("bytepath_fixture_trace_hygiene", CategoryTraceHygiene, func() error {
		manifest := fixtures.NewManifest(fixtures.ManifestOptions{BackendVersion: Version})
		summary := fixtures.BytePathFixtureSummary{
			ProfileID:            p.ID,
			ProfileSeed:          int(p.Seed),
			Scenario:             "byte_single_flow_echo",
			Backend:              fixtures.BackendLab,
			FramesEncoded:        1,
			FramesDecoded:        1,
			FragmentsCreated:     1,
			FragmentsReassembled: 1,
			BytesWrittenBucket:   "tiny",
			BytesReadBucket:      "tiny",
			RuntimeStreamsMapped: 1,
			SinkCompleted:        true,
		}
		entry, err := fixtures.EntryForSummary(summary)
		if err != nil {
			return err
		}
		manifest.ProfileSeeds = []int{int(p.Seed)}
		manifest.ScenarioNames = []string{summary.Scenario}
		manifest.Summaries = []fixtures.BytePathFixtureSummary{summary}
		manifest.Entries = []fixtures.FixtureEntry{entry}
		manifest.Normalize()
		if err := fixtures.ValidateManifest(manifest); err != nil {
			return err
		}
		if ScanValue(manifest).Passed == false {
			return fmt.Errorf("clean fixture rejected")
		}
		if ScanJSON([]byte(`{"encoded_bytes":"abcd"}`)).Passed {
			return fmt.Errorf("encoded_bytes fixture field accepted")
		}
		if fixtures.ValidateRedaction(map[string]string{"raw_payload": "x"}).Passed {
			return fmt.Errorf("fixture redaction accepted raw_payload")
		}
		if ScanValue(fixtures.BytePathFixtureSummary{PayloadLogged: true}).Passed {
			return fmt.Errorf("fixture payload leak flag accepted")
		}
		if ScanValue(fixtures.BytePathFixtureSummary{SecretLogged: true}).Passed {
			return fmt.Errorf("fixture secret leak flag accepted")
		}
		return nil
	}))
	results = append(results, check("protocol_corpus_wirefeatures_trace_hygiene", CategoryTraceHygiene, func() error {
		corpus := protocorpus.DefaultCorpus()
		if err := protocorpus.ValidateManifest(corpus); err != nil {
			return err
		}
		if report := ScanValue(corpus); !report.Passed {
			return fmt.Errorf("protocol corpus rejected: %v", report.Findings)
		}
		manifest, err := fixtures.GenerateBytePathManifest(ctx, fixtures.ManifestOptions{
			ProfileSeeds:   []int{int(p.Seed)},
			ScenarioNames:  []string{bytetransport.ScenarioSingleFlow},
			BackendVersion: Version,
		})
		if err != nil {
			return err
		}
		_, extraction := wirefeatures.ExtractFromFixtureManifest(manifest)
		if extraction.Conclusion != "passed" {
			return fmt.Errorf("wire feature extraction failed")
		}
		baseline, err := wirefeatures.GenerateBaseline(ctx, manifest, corpus)
		if err != nil {
			return err
		}
		if report := ScanValue(baseline); !report.Passed {
			return fmt.Errorf("wire feature baseline rejected: %v", report.Findings)
		}
		if ScanJSON([]byte(`{"encoded_bytes":"abc"}`)).Passed {
			return fmt.Errorf("encoded byte marker accepted")
		}
		if ScanJSON([]byte(`{"destination_address":"127.0.0.1"}`)).Passed {
			return fmt.Errorf("destination address marker accepted")
		}
		if ScanJSON([]byte(`{"proxy_ip":"127.0.0.1"}`)).Passed {
			return fmt.Errorf("proxy IP marker accepted")
		}
		return nil
	}))
	results = append(results, check("wiregen_fixture_trace_hygiene", CategoryTraceHygiene, func() error {
		baseline, err := wiregencompare.GenerateBaseline(ctx, protocorpus.DefaultCorpus(), []int{int(p.Seed)}, []string{bytetransport.ScenarioSingleFlow})
		if err != nil {
			return err
		}
		if report := ScanValue(baseline); !report.Passed {
			return fmt.Errorf("wiregen baseline rejected: %v", report.Findings)
		}
		if ScanJSON([]byte(`{"raw_bytes":"abc"}`)).Passed {
			return fmt.Errorf("raw byte marker accepted")
		}
		return nil
	}))
	results = append(results, check("wireeval_dataset_trace_hygiene", CategoryTraceHygiene, func() error {
		dataset, err := wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{
			Seeds:    wireeval.DefaultSeeds(),
			Controls: true,
		})
		if err != nil {
			return err
		}
		if report := wireeval.ScanDatasetForLeakage(dataset); !report.Passed {
			return fmt.Errorf("wireeval dataset rejected: %v", report.Findings)
		}
		csvRaw, err := classifierdata.ExportCSV(dataset.Records)
		if err != nil {
			return err
		}
		if err := classifierdata.ValidateCSV(csvRaw); err != nil {
			return err
		}
		jsonlRaw, err := classifierdata.ExportJSONL(dataset.Records)
		if err != nil {
			return err
		}
		if err := classifierdata.ValidateJSONL(jsonlRaw); err != nil {
			return err
		}
		if ScanJSON([]byte(`{"raw_payload":"abc"}`)).Passed {
			return fmt.Errorf("raw payload wireeval field accepted")
		}
		if ScanJSON([]byte(`{"encoded_bytes":"abc"}`)).Passed {
			return fmt.Errorf("encoded bytes wireeval field accepted")
		}
		if ScanJSON([]byte(`{"destination_address":"127.0.0.1"}`)).Passed {
			return fmt.Errorf("endpoint wireeval field accepted")
		}
		return nil
	}))
	results = append(results, check("hostdetect_trace_hygiene", CategoryTraceHygiene, func() error {
		summary, err := hostdetect.GenerateGoldenSummary(ctx)
		if err != nil {
			return err
		}
		if err := hostdetect.ScanForLeak(summary); err != nil {
			return fmt.Errorf("hostdetect summary rejected: %w", err)
		}
		if report := ScanValue(summary); !report.Passed {
			return fmt.Errorf("hostdetect summary failed generic hygiene: %v", report.Findings)
		}
		unsafeCases := []map[string]string{
			{"raw_payload": "x"},
			{"encoded_bytes": "x"},
			{"destination_address": "127.0.0.1"},
			{"secret": "x"},
		}
		for _, tc := range unsafeCases {
			if err := hostdetect.ScanForLeak(tc); err == nil {
				return fmt.Errorf("unsafe hostdetect metadata accepted: %v", tc)
			}
		}
		return nil
	}))
	results = append(results, check("relayfleet_trace_hygiene", CategoryTraceHygiene, func() error {
		summary, err := relayfleet.GenerateGoldenSummary(ctx)
		if err != nil {
			return err
		}
		if err := relayfleet.ScanForLeak(summary); err != nil {
			return fmt.Errorf("relayfleet summary rejected: %w", err)
		}
		if report := ScanValue(summary); !report.Passed {
			return fmt.Errorf("relayfleet summary failed generic hygiene: %v", report.Findings)
		}
		unsafeCases := []map[string]string{
			{"endpoint": "x"},
			{"cloud_provider": "x"},
			{"real_host": "x"},
			{"raw_payload": "x"},
			{"secret": "x"},
		}
		for _, tc := range unsafeCases {
			if err := relayfleet.ScanForLeak(tc); err == nil {
				return fmt.Errorf("unsafe relayfleet metadata accepted: %v", tc)
			}
		}
		return nil
	}))
	results = append(results, check("proxyingress_trace_hygiene", CategoryTraceHygiene, func() error {
		set, err := proxyingress.GoldenFixtureSet()
		if err != nil {
			return err
		}
		if err := proxyingress.ValidateFixtureSet(set); err != nil {
			return err
		}
		review, _, _, err := proxyingressreview.GenerateGoldenReview()
		if err != nil {
			return err
		}
		if review.PayloadLogged || review.SecretLogged || review.GoNoGoDecision != proxyingressreview.DecisionGo {
			return fmt.Errorf("proxyingress review hygiene failed")
		}
		for _, tc := range []map[string]string{{"endpoint": "x"}, {"domain": "x"}, {"url": "x"}, {"secret": "x"}} {
			if err := proxyingress.ScanForLeak(tc); err == nil {
				return fmt.Errorf("unsafe proxyingress metadata accepted")
			}
		}
		return nil
	}))
	results = append(results, check("localproxyingress_trace_hygiene", CategoryTraceHygiene, func() error {
		set, err := localproxyingress.GenerateFixtureSet(ctx, localproxyingress.QuickScenarios())
		if err != nil {
			return err
		}
		if err := localproxyingress.ValidateFixtureSet(set); err != nil {
			return err
		}
		for _, summary := range set.Summaries {
			if summary.PayloadLogged || summary.SecretLogged {
				return fmt.Errorf("localproxyingress summary hygiene failed")
			}
			events := localproxyingress.TraceEvents(summary)
			if report := ScanEvents(events); !report.Passed {
				return fmt.Errorf("localproxyingress trace rejected: %v", report.Findings)
			}
		}
		if ScanJSON([]byte(`{"endpoint":"x"}`)).Passed {
			return fmt.Errorf("unsafe localproxyingress field accepted")
		}
		return nil
	}))
	results = append(results, check("localproxyingressadv_trace_hygiene", CategoryTraceHygiene, func() error {
		set, err := localproxyingressadversary.GenerateAdversarialFixtureSet(ctx)
		if err != nil {
			return err
		}
		if err := localproxyingressadversary.ValidateAdversarialFixtureSet(set); err != nil {
			return err
		}
		if err := localproxyingressadversary.ScanFixtureHygiene(set); err != nil {
			return err
		}
		for _, tc := range []map[string]string{{"endpoint": "x"}, {"payload": "x"}, {"raw_bytes": "x"}, {"secret": "x"}} {
			if err := localproxyingressadversary.ScanFixtureHygiene(tc); err == nil {
				return fmt.Errorf("unsafe localproxyingressadv metadata accepted")
			}
		}
		return nil
	}))
	results = append(results, check("adaptivepath_trace_hygiene", CategoryTraceHygiene, func() error {
		set, err := adaptivepath.GenerateFixtureSet(ctx)
		if err != nil {
			return err
		}
		if err := adaptivepath.ValidateFixtureSet(set); err != nil {
			return err
		}
		if err := adaptivepath.ScanForLeak(set); err != nil {
			return err
		}
		if report := ScanValue(set); !report.Passed {
			return fmt.Errorf("adaptivepath fixture failed generic hygiene: %v", report.Findings)
		}
		for _, tc := range []map[string]string{
			{"endpoint": "x"},
			{"dns_query": "x"},
			{"resolver_ip": "x"},
			{"payload": "x"},
			{"secret": "x"},
		} {
			if err := adaptivepath.ScanForLeak(tc); err == nil {
				return fmt.Errorf("unsafe adaptivepath metadata accepted")
			}
		}
		return nil
	}))
	results = append(results, check("transportbundle_trace_hygiene", CategoryTraceHygiene, func() error {
		set, err := transportbundle.GenerateFixtureSet(ctx)
		if err != nil {
			return err
		}
		if err := transportbundle.ValidateFixtureSet(set); err != nil {
			return err
		}
		if err := transportbundle.ScanForLeak(set); err != nil {
			return err
		}
		if report := ScanValue(set); !report.Passed {
			return fmt.Errorf("transportbundle fixture failed generic hygiene: %v", report.Findings)
		}
		for _, tc := range []map[string]string{
			{"endpoint": "x"},
			{"dns_query": "x"},
			{"resolver_ip": "x"},
			{"payload": "x"},
			{"secret": "x"},
		} {
			if err := transportbundle.ScanForLeak(tc); err == nil {
				return fmt.Errorf("unsafe transportbundle metadata accepted")
			}
		}
		return nil
	}))
	results = append(results, check("pathrace_trace_hygiene", CategoryTraceHygiene, func() error {
		set, err := pathrace.GenerateFixtureSet(ctx)
		if err != nil {
			return err
		}
		if err := pathrace.ValidateFixtureSet(set); err != nil {
			return err
		}
		if err := pathrace.ScanForLeak(set); err != nil {
			return err
		}
		if report := ScanValue(set); !report.Passed {
			return fmt.Errorf("pathrace fixture failed generic hygiene: %v", report.Findings)
		}
		for _, tc := range []map[string]string{
			{"endpoint": "x"},
			{"dns_query": "x"},
			{"resolver_ip": "x"},
			{"cloud_provider": "x"},
			{"payload": "x"},
			{"secret": "x"},
		} {
			if err := pathrace.ScanForLeak(tc); err == nil {
				return fmt.Errorf("unsafe pathrace metadata accepted")
			}
		}
		return nil
	}))
	return results
}

func scanValue(value any, path string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if forbiddenKey(lower) {
				*findings = append(*findings, key)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, key+"_true")
			}
			scanValue(child, key, findings)
		}
	case []any:
		for _, child := range v {
			scanValue(child, path, findings)
		}
	case string:
		lower := strings.ToLower(v)
		for _, marker := range forbiddenTraceKeys {
			if marker == "payload" || marker == "secret" {
				continue
			}
			if marker == "auth_tag" && lower == "auth_tag_like" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func forbiddenKey(key string) bool {
	for _, marker := range forbiddenTraceKeys {
		if key == marker || strings.Contains(key, marker) {
			switch key {
			case "payload_bytes", "payload_hygiene", "payload_logged", "payload_visibility", "secret_logged", "secret_hygiene", "secret_hygiene_result", "ciphertext_bytes", "auth_tag_bytes", "name_service_class":
				return false
			}
			return true
		}
	}
	return false
}
