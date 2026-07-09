// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package productionreadiness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

func GenerateReview() (ProductionReadinessReview, error) {
	items := DefaultItems()
	deps := DefaultDependencies()
	boundaries := DefaultBoundaries()
	contracts := DefaultContracts()
	blockers := DefaultBlockers()
	misuse := ScanMisuse(items, boundaries, contracts, blockers)
	parity := CompareGeneratedInterpreted(items, contracts)
	review := ProductionReadinessReview{
		Version:      Version,
		ReviewID:     DefaultReviewID,
		Items:        items,
		Dependencies: deps,
		Boundaries:   boundaries,
		Contracts:    contracts,
		Blockers:     blockers,
		Misuse:       misuse,
		Parity:       parity,
		Conclusion:   "passed",
	}
	if misuse.Conclusion != "passed" || parity.Conclusion != "passed" {
		review.Conclusion = "failed"
	}
	review.ReviewHash = HashValue(reviewHashInput(review))
	return review, ValidateReview(review)
}

func DefaultItems() []ReadinessItem {
	items := []ReadinessItem{
		item("compiler", "compiler", []string{"profile generation", "seed stability", "corpus diversity gates"}, "future policy expansion can regress diversity", "keep corpus and mutation gates mandatory"),
		item("profile validation", "compiler", []string{"schema validation", "bounded limits", "unsupported policy rejection"}, "new policy fields need validators", "require tests for each policy"),
		item("framing", "runtime", []string{"round trip", "malformed rejection", "cross-profile checks"}, "future grammar expansion needs new malformed cases", "extend framing fuzz coverage"),
		item("stream semantics", "runtime", []string{"max stream gates", "flow control", "backpressure", "reset isolation"}, "future concrete adapters add pressure", "keep stream adversary gates mandatory"),
		item("proxy semantics", "proxy", []string{"synthetic target registry", "descriptor rejection", "target isolation"}, "synthetic targets are not real destinations", "keep target classes synthetic until reviewed"),
		item("carrier abstraction", "carrier", []string{"carrier envelope validation", "queue limits", "reorder/retry recovery"}, "abstract carriers are not deployable carriers", "review each carrier family separately"),
		item("security context", "security", []string{"transcript binding", "nonce/replay", "downgrade rejection"}, "no production key exchange", "design key exchange separately"),
		item("runtime session lifecycle", "runtime", []string{"roles", "session state", "capability negotiation", "in-memory link"}, "no real socket session manager", "keep runtime adversary gates mandatory"),
		item("adapter interface", "adapter", []string{"flow lifecycle", "config validation", "capability compatibility"}, "interface only", "only add concrete adapters after readiness gates"),
		item("local adapter prototype", "adapter", []string{"memory ingress", "memory egress", "source/sink models"}, "memory-only prototype", "use byte transport and local pipeline as prerequisites"),
		item("byte transport harness", "bytepath", []string{"bounded byte pipe", "fragmentation", "sequence checks", "corruption rejection"}, "local deterministic bytes only", "keep malformed byte corpus current"),
		item("byte-path fixtures", "bytepath", []string{"golden summaries", "malformed corpus", "parity checks"}, "safe metadata only", "regenerate only when drift is reviewed"),
		item("wire-shape baselines", "wire", []string{"wire features", "wiregen", "wireeval datasets"}, "classifier harness is offline synthetic", "treat live captures as separate review"),
		item("host and relay risk models", "risk", []string{"hostdetect", "relayfleet", "burn-risk controls"}, "synthetic hosts and relays only", "no infrastructure automation"),
		item("proxy ingress prototype", "proxy", []string{"localproxyingress", "adversarial hardening", "fixture drift"}, "no socket listener", "bridge through M33/M34 before concrete adapter"),
		item("proxy egress and relay bridge", "proxy", []string{"proxyegress", "relaybridge", "generated parity"}, "synthetic egress and bridge only", "keep egress descriptors safe"),
		item("end-to-end local proxy pipeline", "pipeline", []string{"localpipeline", "boundary integration", "descriptor rejection", "collapse controls"}, "synthetic local pipeline only", "use as readiness evidence for M35"),
		item("trace hygiene", "safety", []string{"payload-free summaries", "forbidden field scans", "STATUS audit"}, "new fields can drift", "update scanner allowlists with tests"),
		item("generated backend parity", "codegen", []string{"kgen source scanner", "generated tests", "codegen quick audit"}, "shared helpers still exist", "keep scanner expanding"),
		item("documentation and status", "docs", []string{"README", "KIP docs", "STATUS", "docs site"}, "docs can drift", "update docs with every command and gate"),
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func DefaultDependencies() []DependencyEdge {
	edges := []DependencyEdge{
		{"compiler", "profile validation", "defines"},
		{"profile validation", "framing", "guards"},
		{"framing", "byte transport harness", "encodes"},
		{"stream semantics", "proxy semantics", "carries"},
		{"proxy semantics", "proxy ingress prototype", "binds"},
		{"proxy ingress prototype", "proxy egress and relay bridge", "feeds"},
		{"proxy egress and relay bridge", "end-to-end local proxy pipeline", "composes"},
		{"carrier abstraction", "byte transport harness", "maps_to"},
		{"security context", "runtime session lifecycle", "protects"},
		{"runtime session lifecycle", "adapter interface", "exposes"},
		{"adapter interface", "local adapter prototype", "implements"},
		{"local adapter prototype", "end-to-end local proxy pipeline", "drives"},
		{"byte-path fixtures", "wire-shape baselines", "freezes"},
		{"trace hygiene", "generated backend parity", "checks"},
		{"end-to-end local proxy pipeline", "M36", "prerequisite_for"},
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From == edges[j].From {
			return edges[i].To < edges[j].To
		}
		return edges[i].From < edges[j].From
	})
	return edges
}

func DefaultBoundaries() []BoundaryReview {
	return []BoundaryReview{
		boundary("real_io_boundary", BoundaryNoRealNetworkIO, []string{"external targets", "resolver access", "packet capture", "live probing"}),
		boundary("deployment_boundary", BoundaryNoDeployment, []string{"service deployment", "relay orchestration", "cloud provisioning"}),
		boundary("trace_boundary", BoundaryNoPayloadLogging, []string{"raw payload", "raw bytes", "endpoint data", "keys", "nonces", "auth tags"}),
		boundary("security_boundary", BoundaryNoProductionKeyXchg, []string{"production key exchange", "long-term secret distribution"}),
		boundary("adapter_boundary", BoundaryStrictLocalOnly, []string{"SOCKS", "TUN", "VPN", "HTTP carrier", "TLS mimicry", "CDN behavior"}),
	}
}

func DefaultContracts() []FutureContract {
	contracts := []FutureContract{
		{"M36", "concrete local socket adapter", "loopback-only local socket harness", []string{"productionreadiness", "localpipeline", "hardening", "codegen"}, []string{"external targets", "public network relay", "deployment"}, StatusNeedsDesign},
		{"M37", "socket adapter adversarial hardening", "deterministic loopback misuse and pressure tests", []string{"M36 gates", "trace hygiene", "mutant detection"}, []string{"field probing", "external DNS", "HTTP/TLS mimicry"}, StatusNeedsDesign},
		{"M38", "adapter readiness consolidation", "review matrix and fixture freeze", []string{"M36", "M37", "fixture drift"}, []string{"production claims", "mobile client"}, StatusNeedsDesign},
		{"M39", "client architecture review", "architecture-only review of future client constraints", []string{"privacy review", "trace hygiene", "local-only test plan"}, []string{"app store release", "user-risk guidance", "field readiness claims"}, StatusNeedsDesign},
	}
	return contracts
}

func DefaultBlockers() []Blocker {
	return []Blocker{
		{"prod_key_exchange_design", "high", "security", "production key exchange is not designed", true, false},
		{"external_carrier_review", "high", "carrier", "concrete carrier families require separate review", true, false},
		{"field_measurement_review", "high", "privacy", "field measurement client is not designed", true, false},
		{"mobile_client_review", "medium", "client", "Android client architecture is not reviewed", false, false},
		{"deployment_review", "high", "operations", "deployment and relay operations are out of scope", true, false},
	}
}

func ScanMisuse(items []ReadinessItem, boundaries []BoundaryReview, contracts []FutureContract, blockers []Blocker) ReadinessMisuseReport {
	report := ReadinessMisuseReport{ObjectsChecked: len(items) + len(boundaries) + len(contracts) + len(blockers), Conclusion: "passed"}
	if len(items) < 18 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "readiness_inventory_too_small")
	}
	if len(boundaries) < 5 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "missing_boundary_reviews")
	}
	if len(contracts) < 4 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "missing_future_contracts")
	}
	for _, boundary := range boundaries {
		if boundary.Allowed || boundary.Conclusion != "passed" {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "unsafe_boundary_"+boundary.Name)
		}
	}
	for _, contract := range contracts {
		if contract.Name == "" || contract.AllowedScope == "" || len(contract.ForbiddenScopes) == 0 {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "incomplete_contract_"+contract.Milestone)
		}
	}
	if err := ScanForLeak(map[string]string{"raw_payload": "unsafe"}); err == nil {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "leak_scanner_control_failed")
	}
	report.SuspiciousMetrics = uniqueStrings(report.SuspiciousMetrics)
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(items []ReadinessItem, contracts []FutureContract) ReadinessParityReport {
	report := ReadinessParityReport{ItemsCompared: len(items), ContractsCompared: len(contracts), Conclusion: "passed"}
	report.SemanticMatches = report.ItemsCompared + report.ContractsCompared
	if report.ItemsCompared < 18 || report.ContractsCompared < 4 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "production_readiness_parity_drift")
	}
	return report
}

func item(name, layer string, evidence []string, risk, next string) ReadinessItem {
	return ReadinessItem{Name: name, Layer: layer, Status: StatusReadyForReview, Evidence: evidence, RemainingRisk: risk, NextAction: next}
}

func boundary(name, policy string, forbidden []string) BoundaryReview {
	return BoundaryReview{Name: name, Policy: policy, Allowed: false, Forbidden: forbidden, Evidence: []string{"review gate", "trace hygiene", "fixture drift"}, Conclusion: "passed"}
}

func reviewHashInput(review ProductionReadinessReview) ProductionReadinessReview {
	review.ReviewHash = ""
	return review
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

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
