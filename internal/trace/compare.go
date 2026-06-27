package trace

import (
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/ir"
)

type TraceReport struct {
	ProfileA              string
	ProfileB              string
	FirstContactCountA    int
	FirstContactCountB    int
	FirstContactSizesA    []int
	FirstContactSizesB    []int
	StatePathSimilarity   float64
	SemanticSimilarity    float64
	FrameHistogramA       map[int]int
	FrameHistogramB       map[int]int
	PaddingHistogramA     map[int]int
	PaddingHistogramB     map[int]int
	SchedulerModesA       []string
	SchedulerModesB       []string
	DifferenceScore       int
	Conclusion            string
	MeaningfullyDifferent bool
	Valid                 bool
}

func CompareEvents(a, b []Event) TraceReport {
	report := TraceReport{Valid: len(a) > 0 && len(b) > 0}
	if !report.Valid {
		report.Conclusion = "invalid trace"
		return report
	}
	report.ProfileA = firstProfile(a)
	report.ProfileB = firstProfile(b)
	report.FirstContactCountA, report.FirstContactSizesA = firstContact(a)
	report.FirstContactCountB, report.FirstContactSizesB = firstContact(b)
	report.StatePathSimilarity = sequenceSimilarity(states(a), states(b))
	report.SemanticSimilarity = sequenceSimilarity(semantics(a), semantics(b))
	report.FrameHistogramA = histogram(frameSizes(a))
	report.FrameHistogramB = histogram(frameSizes(b))
	report.PaddingHistogramA = histogram(paddingSizes(a))
	report.PaddingHistogramB = histogram(paddingSizes(b))
	report.SchedulerModesA = uniqueSchedulers(a)
	report.SchedulerModesB = uniqueSchedulers(b)

	if report.ProfileA != report.ProfileB {
		report.DifferenceScore++
	}
	if report.FirstContactCountA != report.FirstContactCountB || fmt.Sprint(report.FirstContactSizesA) != fmt.Sprint(report.FirstContactSizesB) {
		report.DifferenceScore++
	}
	if report.StatePathSimilarity < 0.8 {
		report.DifferenceScore++
	}
	if report.SemanticSimilarity < 1 {
		report.DifferenceScore++
	}
	if fmt.Sprint(report.FrameHistogramA) != fmt.Sprint(report.FrameHistogramB) {
		report.DifferenceScore++
	}
	if fmt.Sprint(report.PaddingHistogramA) != fmt.Sprint(report.PaddingHistogramB) {
		report.DifferenceScore++
	}
	if fmt.Sprint(report.SchedulerModesA) != fmt.Sprint(report.SchedulerModesB) {
		report.DifferenceScore++
	}
	report.MeaningfullyDifferent = report.DifferenceScore >= 3
	if report.MeaningfullyDifferent {
		report.Conclusion = "meaningfully different"
	} else {
		report.Conclusion = "suspiciously similar"
	}
	return report
}

func CompareFiles(aPath, bPath string) (TraceReport, error) {
	a, err := ReadJSONL(aPath)
	if err != nil {
		return TraceReport{}, err
	}
	b, err := ReadJSONL(bPath)
	if err != nil {
		return TraceReport{}, err
	}
	return CompareEvents(a, b), nil
}

func (r TraceReport) String() string {
	return fmt.Sprintf(`profile_a: %s
profile_b: %s
first_contact_count_a: %d
first_contact_count_b: %d
first_contact_sizes_a: %v
first_contact_sizes_b: %v
state_path_similarity: %.2f
semantic_similarity: %.2f
frame_histogram_a: %v
frame_histogram_b: %v
padding_histogram_a: %v
padding_histogram_b: %v
scheduler_modes_a: %v
scheduler_modes_b: %v
conclusion: %s
`, r.ProfileA, r.ProfileB, r.FirstContactCountA, r.FirstContactCountB, r.FirstContactSizesA, r.FirstContactSizesB, r.StatePathSimilarity, r.SemanticSimilarity, r.FrameHistogramA, r.FrameHistogramB, r.PaddingHistogramA, r.PaddingHistogramB, r.SchedulerModesA, r.SchedulerModesB, r.Conclusion)
}

type ProfileDifferenceReport struct {
	ProfileA    string
	ProfileB    string
	Level       string
	Differences []string
}

func CompareProfiles(a, b *ir.Profile) ProfileDifferenceReport {
	report := ProfileDifferenceReport{ProfileA: a.ID, ProfileB: b.ID, Level: "identical"}
	add := func(name string, av, bv any) {
		if fmt.Sprint(av) != fmt.Sprint(bv) {
			report.Differences = append(report.Differences, name)
		}
	}
	add("first-contact pattern", a.FirstContact.PatternID, b.FirstContact.PatternID)
	add("state count", len(a.States), len(b.States))
	add("transition count", len(a.Transitions), len(b.Transitions))
	add("state graph edges", edgeSet(a), edgeSet(b))
	add("frame grammar", a.FrameGrammar, b.FrameGrammar)
	add("message symbol mapping", wireMap(a), wireMap(b))
	add("scheduler policy", a.Scheduler, b.Scheduler)
	add("padding policy", a.Padding, b.Padding)
	add("invalid-input policy", a.InvalidInput, b.InvalidInput)
	switch {
	case len(report.Differences) >= 4:
		report.Level = "structurally different"
	case len(report.Differences) > 0:
		report.Level = "trivially different"
	}
	return report
}

func firstProfile(events []Event) string {
	for _, ev := range events {
		if ev.ProfileID != "" {
			return ev.ProfileID
		}
	}
	return ""
}

func firstContact(events []Event) (int, []int) {
	var sizes []int
	count := 0
	for _, ev := range events {
		if ev.EventType == "first_contact" {
			count++
			sizes = append(sizes, ev.FrameBytes)
		}
	}
	return count, sizes
}

func states(events []Event) []string {
	var out []string
	for _, ev := range events {
		if ev.State != "" {
			out = append(out, ev.State)
		}
	}
	return out
}

func semantics(events []Event) []string {
	var out []string
	for _, ev := range events {
		if ev.Semantic != "" {
			out = append(out, ev.Semantic)
		}
	}
	return out
}

func frameSizes(events []Event) []int {
	var out []int
	for _, ev := range events {
		if ev.FrameBytes > 0 {
			out = append(out, ev.FrameBytes)
		}
	}
	return out
}

func paddingSizes(events []Event) []int {
	var out []int
	for _, ev := range events {
		out = append(out, ev.PaddingBytes)
	}
	return out
}

func histogram(values []int) map[int]int {
	out := map[int]int{}
	for _, v := range values {
		out[v]++
	}
	return out
}

func uniqueSchedulers(events []Event) []string {
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.SchedulerMode != "" {
			seen[ev.SchedulerMode] = true
		}
	}
	var out []string
	for mode := range seen {
		out = append(out, mode)
	}
	sort.Strings(out)
	return out
}

func sequenceSimilarity(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	maxLen := max(len(a), len(b))
	same := 0
	for i := 0; i < min(len(a), len(b)); i++ {
		if a[i] == b[i] {
			same++
		}
	}
	return float64(same) / float64(maxLen)
}

func edgeSet(p *ir.Profile) string {
	var edges []string
	for _, tr := range p.Transitions {
		edges = append(edges, tr.From+"->"+tr.To+":"+tr.OnMessage)
	}
	sort.Strings(edges)
	return strings.Join(edges, "|")
}

func wireMap(p *ir.Profile) string {
	var entries []string
	for _, msg := range p.Messages {
		entries = append(entries, msg.Semantic+"="+msg.WireSymbol)
	}
	sort.Strings(entries)
	return strings.Join(entries, "|")
}
