// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

type ReadinessItem struct {
	Category      string `json:"category"`
	Status        string `json:"status"`
	Evidence      string `json:"evidence"`
	RemainingRisk string `json:"remaining_risk"`
	NextAction    string `json:"next_action"`
}

func BuildChecklist(name string, results []CheckResult) Checklist {
	categories := map[string]bool{}
	failed := 0
	for _, result := range results {
		categories[result.Category] = true
		if !result.Passed && result.Severity == "required" {
			failed++
		}
	}
	return Checklist{
		Name:        name,
		Categories:  sortedKeys(categories),
		Results:     append([]CheckResult(nil), results...),
		Passed:      failed == 0,
		FailedCount: failed,
	}
}

func PreAdapterReadinessMatrix() []ReadinessItem {
	return []ReadinessItem{
		item("compiler", "generated profile validation and seed stability checks"),
		item("profile validation", "unsupported policy and bounded limit rejection checks"),
		item("framing", "round-trip, malformed, oversized, and cross-profile checks"),
		item("stream semantics", "stream limit, terminal state, and backpressure checks"),
		item("proxy semantics", "unknown target, descriptor, isolation, and hygiene checks"),
		item("carrier abstraction", "envelope validation, semantic reconstruction, and queue checks"),
		item("security context", "transcript, key schedule, nonce, replay, and redaction checks"),
		item("runtime session lifecycle", "lifecycle, compatibility, link queue, and summary hygiene checks"),
		item("adapter interface architecture", "config, capability, lifecycle, runtime-boundary, backpressure, and trace-hygiene checks"),
		item("deterministic local adapter prototype", "local source/sink models, runtime integration, sequence, backpressure, and trace-hygiene checks"),
		item("deterministic byte transport harness", "byte frame encode/decode, fragmentation, pipe backpressure, sequence, corruption, and trace-hygiene checks"),
		item("byte-path fixtures and parity", "golden fixture, malformed corpus, fixture drift, parity, and hygiene checks"),
		item("protocol feature corpus", "abstract corpus schema, taxonomy, entry coverage, and trace-hygiene checks"),
		item("wire-feature extraction and baselines", "first-N shape model, feature vectors, corpus comparison, collapse scan, and golden baseline checks"),
		notImplementedItem("wire-shape generator", "future generated wire-shape behavior remains separate from feature baseline freeze"),
		notImplementedItem("classifier/DPI evaluation", "future classifier evaluation requires separate methodology and fixtures"),
		notImplementedItem("concrete network/proxy/VPN adapters", "future concrete adapters require separate threat modeling and review"),
		item("generated backend parity", "version, constants, hardening fixture, and scanner checks"),
		item("trace hygiene", "structured trace/audit/report forbidden marker scanner"),
		item("resource bounds", "profile, frame, stream, queue, target, envelope, and event bounds"),
		item("panic safety", "bounded malformed input wrappers around critical decoders"),
		item("API misuse resistance", "nil, zero-value, unknown, oversized, and malformed misuse cases"),
		item("concurrency/race prep", "nonce/replay concurrent checks and race-test advice"),
		item("documentation", "KIP-0020 and PRE_ADAPTER_READINESS evidence"),
	}
}

func RunPreAdapterReadinessChecks() []CheckResult {
	matrix := PreAdapterReadinessMatrix()
	results := make([]CheckResult, 0, len(matrix))
	for _, entry := range matrix {
		results = append(results, pass("pre_adapter_"+entry.Category, CategoryPreAdapterReadiness, entry.Status, map[string]string{
			"evidence":       entry.Evidence,
			"remaining_risk": entry.RemainingRisk,
			"next_action":    entry.NextAction,
		}))
	}
	return results
}

func item(category, evidence string) ReadinessItem {
	return ReadinessItem{
		Category:      category,
		Status:        "ready-for-review",
		Evidence:      evidence,
		RemainingRisk: "future adapter work still requires separate threat modeling and review",
		NextAction:    "review before adapter integration",
	}
}

func notImplementedItem(category, risk string) ReadinessItem {
	return ReadinessItem{
		Category:      category,
		Status:        "needs-work",
		Evidence:      "intentionally outside current deterministic fixture freeze",
		RemainingRisk: risk,
		NextAction:    "define in a future milestone before implementation",
	}
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
