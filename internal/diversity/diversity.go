// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package diversity

import (
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/ir"
)

const (
	ClassIdentical             = "identical"
	ClassCosmeticDifference    = "cosmetic difference only"
	ClassStructurallyDifferent = "structurally different"
)

type ProfileDiversityReport struct {
	NumberOfProfiles                     int            `json:"number_of_profiles"`
	ProfileCount                         int            `json:"profile_count"`
	PairCount                            int            `json:"pair_count"`
	IdenticalPairs                       int            `json:"identical_pairs"`
	CosmeticDifferencePairs              int            `json:"cosmetic_difference_pairs"`
	StructurallyDifferentPairs           int            `json:"structurally_different_pairs"`
	UniqueFirstContactPatterns           int            `json:"unique_first_contact_patterns"`
	UniqueFirstContactShapes             int            `json:"unique_first_contact_shapes"`
	UniqueFrameGrammarCombinations       int            `json:"unique_frame_grammar_combinations"`
	UniqueSchedulerCombinations          int            `json:"unique_scheduler_combinations"`
	UniqueStreamPolicyCombinations       int            `json:"unique_stream_policy_combinations"`
	UniqueProxyPolicyCombinations        int            `json:"unique_proxy_policy_combinations"`
	UniqueCarrierPolicyCombinations      int            `json:"unique_carrier_policy_combinations"`
	UniquePaddingCombinations            int            `json:"unique_padding_combinations"`
	UniqueInvalidInputPolicyCombinations int            `json:"unique_invalid_input_policy_combinations"`
	StateCountDistribution               map[int]int    `json:"state_count_distribution"`
	TransitionCountDistribution          map[int]int    `json:"transition_count_distribution"`
	MessageSymbolCountDistribution       map[int]int    `json:"message_symbol_count_distribution"`
	Warnings                             []string       `json:"warnings,omitempty"`
	Classifications                      map[string]int `json:"classifications"`
}

type StructuralDifferenceReport struct {
	ProfileA              string   `json:"profile_a"`
	ProfileB              string   `json:"profile_b"`
	Classification        string   `json:"classification"`
	StructuralDifferences []string `json:"structural_differences,omitempty"`
	CosmeticDifferences   []string `json:"cosmetic_differences,omitempty"`
}

func AnalyzeProfiles(profiles []*ir.Profile) ProfileDiversityReport {
	report := ProfileDiversityReport{
		NumberOfProfiles:               len(profiles),
		ProfileCount:                   len(profiles),
		StateCountDistribution:         map[int]int{},
		TransitionCountDistribution:    map[int]int{},
		MessageSymbolCountDistribution: map[int]int{},
		Classifications:                map[string]int{},
	}
	firstContactPatterns := map[string]bool{}
	firstContactShapes := map[string]bool{}
	frameGrammarCombinations := map[string]bool{}
	schedulerCombinations := map[string]bool{}
	streamPolicyCombinations := map[string]bool{}
	proxyPolicyCombinations := map[string]bool{}
	carrierPolicyCombinations := map[string]bool{}
	paddingCombinations := map[string]bool{}
	invalidInputCombinations := map[string]bool{}

	for _, p := range profiles {
		if p == nil {
			report.Warnings = append(report.Warnings, "nil profile skipped")
			continue
		}
		firstContactPatterns[p.FirstContact.PatternID] = true
		firstContactShapes[firstContactShape(p)] = true
		frameGrammarCombinations[frameGrammarShape(p)] = true
		schedulerCombinations[schedulerShape(p)] = true
		streamPolicyCombinations[streamPolicyShape(p)] = true
		proxyPolicyCombinations[proxyPolicyShape(p)] = true
		carrierPolicyCombinations[carrierPolicyShape(p)] = true
		paddingCombinations[paddingShape(p)] = true
		invalidInputCombinations[invalidInputShape(p)] = true
		report.StateCountDistribution[len(p.States)]++
		report.TransitionCountDistribution[len(p.Transitions)]++
		report.MessageSymbolCountDistribution[len(p.Messages)]++
	}

	for i := 0; i < len(profiles); i++ {
		for j := i + 1; j < len(profiles); j++ {
			pair := CompareProfileStructure(profiles[i], profiles[j])
			report.PairCount++
			report.Classifications[pair.Classification]++
			switch pair.Classification {
			case ClassIdentical:
				report.IdenticalPairs++
			case ClassCosmeticDifference:
				report.CosmeticDifferencePairs++
			case ClassStructurallyDifferent:
				report.StructurallyDifferentPairs++
			}
		}
	}

	report.UniqueFirstContactPatterns = len(firstContactPatterns)
	report.UniqueFirstContactShapes = len(firstContactShapes)
	report.UniqueFrameGrammarCombinations = len(frameGrammarCombinations)
	report.UniqueSchedulerCombinations = len(schedulerCombinations)
	report.UniqueStreamPolicyCombinations = len(streamPolicyCombinations)
	report.UniqueProxyPolicyCombinations = len(proxyPolicyCombinations)
	report.UniqueCarrierPolicyCombinations = len(carrierPolicyCombinations)
	report.UniquePaddingCombinations = len(paddingCombinations)
	report.UniqueInvalidInputPolicyCombinations = len(invalidInputCombinations)
	return report
}

func CompareProfileStructure(a, b *ir.Profile) StructuralDifferenceReport {
	report := StructuralDifferenceReport{Classification: ClassIdentical}
	if a == nil || b == nil {
		report.Classification = ClassStructurallyDifferent
		report.StructuralDifferences = append(report.StructuralDifferences, "nil profile")
		return report
	}
	report.ProfileA = a.ID
	report.ProfileB = b.ID

	addStructural := func(name, av, bv string) {
		if av != bv {
			report.StructuralDifferences = append(report.StructuralDifferences, name)
		}
	}
	addCosmetic := func(name, av, bv string) {
		if av != bv {
			report.CosmeticDifferences = append(report.CosmeticDifferences, name)
		}
	}

	addStructural("first-contact sequence shape", firstContactShape(a), firstContactShape(b))
	addStructural("state graph edge set", stateGraphShape(a), stateGraphShape(b))
	addStructural("transition count", fmt.Sprint(len(a.Transitions)), fmt.Sprint(len(b.Transitions)))
	addStructural("role-specific state paths", rolePathShape(a), rolePathShape(b))
	addStructural("frame grammar strategy", frameGrammarShape(a), frameGrammarShape(b))
	addStructural("scheduler strategy", schedulerShape(a), schedulerShape(b))
	addStructural("multi-stream strategy", streamPolicyShape(a), streamPolicyShape(b))
	addStructural("proxy-semantics strategy", proxyPolicyShape(a), proxyPolicyShape(b))
	addStructural("carrier strategy", carrierPolicyShape(a), carrierPolicyShape(b))
	addStructural("padding strategy", paddingShape(a), paddingShape(b))
	addStructural("invalid-input policy", invalidInputShape(a), invalidInputShape(b))
	addStructural("semantic-to-wire mapping shape", semanticMappingShape(a), semanticMappingShape(b))

	addCosmetic("profile id", a.ID, b.ID)
	addCosmetic("seed", fmt.Sprint(a.Seed), fmt.Sprint(b.Seed))
	addCosmetic("generation hash", a.GenerationHash, b.GenerationHash)
	addCosmetic("state names", stateNames(a), stateNames(b))
	addCosmetic("transition message names", transitionMessageNames(a), transitionMessageNames(b))
	addCosmetic("wire symbols", wireSymbols(a), wireSymbols(b))
	addCosmetic("test-only auth material", a.Auth.KeyID+"|"+a.Auth.TestKeyHex, b.Auth.KeyID+"|"+b.Auth.TestKeyHex)

	switch {
	case len(report.StructuralDifferences) > 0:
		report.Classification = ClassStructurallyDifferent
	case len(report.CosmeticDifferences) > 0:
		report.Classification = ClassCosmeticDifference
	default:
		report.Classification = ClassIdentical
	}
	return report
}

func firstContactShape(p *ir.Profile) string {
	parts := make([]string, 0, len(p.FirstContact.Steps))
	for _, step := range p.FirstContact.Steps {
		parts = append(parts, fmt.Sprintf("%s:%t:%t:%d", step.Role, step.Proof, step.Decoy, step.PayloadSize))
	}
	return strings.Join(parts, ">")
}

func stateGraphShape(p *ir.Profile) string {
	indexes := canonicalStateIndexes(p)
	messageOrdinals := firstContactMessageOrdinals(p)
	edges := make([]string, 0, len(p.Transitions))
	for _, tr := range p.Transitions {
		msg := messageOrdinals[tr.OnMessage]
		if msg == "" {
			msg = semanticTransitionLabel(tr.OnMessage)
		}
		edges = append(edges, fmt.Sprintf("%03d>%03d:%s:%t:%s", indexes[tr.From], indexes[tr.To], tr.Role, tr.RequiresAuth, msg))
	}
	sort.Strings(edges)
	return strings.Join(edges, "|")
}

func rolePathShape(p *ir.Profile) string {
	parts := make([]string, 0, len(p.FirstContact.Steps))
	for _, step := range p.FirstContact.Steps {
		parts = append(parts, step.Role)
	}
	return strings.Join(parts, ">")
}

func frameGrammarShape(p *ir.Profile) string {
	return strings.Join([]string{
		p.FrameGrammar.LengthMode,
		p.FrameGrammar.TypeMode,
		strings.Join(p.FrameGrammar.HeaderOrder, ","),
		p.FrameGrammar.FragmentationMode,
		p.FrameGrammar.ChecksumMode,
		p.FrameGrammar.PaddingPlacement,
	}, "|")
}

func schedulerShape(p *ir.Profile) string {
	return fmt.Sprintf("%s|%d|%d|%d|%s", p.Scheduler.Mode, p.Scheduler.MaxBatchBytes, p.Scheduler.FlushIntervalMs, p.Scheduler.MaxInFlightFrames, p.Scheduler.PriorityMode)
}

func streamPolicyShape(p *ir.Profile) string {
	return fmt.Sprintf("%s|%s|%d|%d|%d|%s|%s|%s|%s|%d",
		p.Stream.IDStrategy,
		p.Stream.IDEncodingMode,
		p.Stream.MaxConcurrentStreams,
		p.Stream.InitialStreamWindowBytes,
		p.Stream.InitialSessionWindowBytes,
		p.Stream.WindowUpdatePolicy,
		p.Stream.PriorityPolicy,
		p.Stream.ClosePolicy,
		p.Stream.ResetPolicy,
		p.Stream.MaxStreamID,
	)
}

func proxyPolicyShape(p *ir.Profile) string {
	return strings.Join([]string{
		p.ProxySemantics.RelayIntentEncoding,
		p.ProxySemantics.TargetDescriptorEncoding,
		p.ProxySemantics.RequestClassEncoding,
		p.ProxySemantics.ResponseModeEncoding,
		p.ProxySemantics.TargetErrorPolicy,
		p.ProxySemantics.TargetClosePolicy,
		p.ProxySemantics.TargetResetPolicy,
		p.ProxySemantics.TargetMetadataPolicy,
		p.ProxySemantics.RelayOpenOrderingPolicy,
		p.ProxySemantics.RelayIntentPaddingPolicy,
		p.ProxySemantics.TargetClassMapping,
		fmt.Sprint(p.ProxySemantics.MaxRequestBytes),
		fmt.Sprint(p.ProxySemantics.MaxResponseBytes),
		strings.Join(p.ProxySemantics.TargetClasses, ","),
	}, "|")
}

func carrierPolicyShape(p *ir.Profile) string {
	return strings.Join([]string{
		p.CarrierPolicy.CarrierFamily,
		p.CarrierPolicy.EnvelopeEncoding,
		p.CarrierPolicy.FlushPolicy,
		p.CarrierPolicy.BatchPolicy,
		p.CarrierPolicy.ChunkingPolicy,
		p.CarrierPolicy.ReliabilityPolicy,
		p.CarrierPolicy.ReorderPolicy,
		p.CarrierPolicy.BackpressurePolicy,
		p.CarrierPolicy.PriorityMappingPolicy,
		p.CarrierPolicy.EnvelopePaddingPolicy,
		p.CarrierPolicy.TimingBucketPolicy,
		fmt.Sprint(p.CarrierPolicy.MaxEnvelopeBytes),
		fmt.Sprint(p.CarrierPolicy.MaxMessagesPerEnvelope),
		fmt.Sprint(p.CarrierPolicy.MaxCarrierQueueDepth),
		fmt.Sprint(p.CarrierPolicy.MaxRetryCount),
	}, "|")
}

func paddingShape(p *ir.Profile) string {
	return fmt.Sprintf("%s|%d|%d|%.3f", p.Padding.Mode, p.Padding.MinPaddingBytes, p.Padding.MaxPaddingBytes, p.Padding.Probability)
}

func invalidInputShape(p *ir.Profile) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d", p.InvalidInput.UnknownFirstMessage, p.InvalidInput.MalformedFrame, p.InvalidInput.FailedAuth, p.InvalidInput.Replay, p.InvalidInput.DelayMsMin, p.InvalidInput.DelayMsMax)
}

func semanticMappingShape(p *ir.Profile) string {
	entries := make([]string, 0, len(p.Messages))
	for _, msg := range p.Messages {
		entries = append(entries, fmt.Sprintf("%s:%s:%d:%d", msg.Semantic, msg.Direction, msg.MinPayloadSize, msg.MaxPayloadSize))
	}
	sort.Strings(entries)
	return strings.Join(entries, "|")
}

func canonicalStateIndexes(p *ir.Profile) map[string]int {
	indexes := map[string]int{}
	next := 0
	assign := func(id string) {
		if _, ok := indexes[id]; ok {
			return
		}
		indexes[id] = next
		next++
	}
	assign(p.FirstContact.StartState)
	for _, step := range p.FirstContact.Steps {
		assign(step.FromState)
		assign(step.ToState)
	}
	remaining := make([]string, 0, len(p.States))
	for _, st := range p.States {
		if _, ok := indexes[st.ID]; !ok {
			remaining = append(remaining, st.ID)
		}
	}
	sort.Strings(remaining)
	for _, id := range remaining {
		assign(id)
	}
	return indexes
}

func firstContactMessageOrdinals(p *ir.Profile) map[string]string {
	out := map[string]string{}
	for i, step := range p.FirstContact.Steps {
		out[step.Message] = fmt.Sprintf("fc%d", i)
	}
	return out
}

func semanticTransitionLabel(message string) string {
	if message == "session_close" {
		return "session_close"
	}
	if strings.HasPrefix(message, "fc_") {
		return "fc"
	}
	return "other"
}

func stateNames(p *ir.Profile) string {
	names := make([]string, 0, len(p.States))
	for _, st := range p.States {
		names = append(names, st.ID)
	}
	sort.Strings(names)
	return strings.Join(names, "|")
}

func transitionMessageNames(p *ir.Profile) string {
	names := make([]string, 0, len(p.Transitions))
	for _, tr := range p.Transitions {
		names = append(names, tr.OnMessage+"|"+tr.EmitsMessage)
	}
	sort.Strings(names)
	return strings.Join(names, "|")
}

func wireSymbols(p *ir.Profile) string {
	symbols := make([]string, 0, len(p.Messages)+len(p.FirstContact.Steps))
	for _, msg := range p.Messages {
		symbols = append(symbols, msg.WireSymbol)
	}
	for _, step := range p.FirstContact.Steps {
		symbols = append(symbols, step.WireSymbol)
	}
	sort.Strings(symbols)
	return strings.Join(symbols, "|")
}
