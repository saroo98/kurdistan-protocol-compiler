package trace

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const DefaultStabilityThreshold = 0.80

type StabilityMetric struct {
	Name          string  `json:"name"`
	Total         int     `json:"total"`
	UniqueValues  int     `json:"unique_values"`
	Dominant      string  `json:"dominant"`
	DominantCount int     `json:"dominant_count"`
	Stability     float64 `json:"stability"`
	Flagged       bool    `json:"flagged"`
}

type TraceScanReport struct {
	TraceCount int               `json:"trace_count"`
	FileCount  int               `json:"file_count"`
	Metrics    []StabilityMetric `json:"metrics"`
	Flagged    []StabilityMetric `json:"flagged"`
	Conclusion string            `json:"conclusion"`
}

func ScanDirectory(dir string, threshold float64) (TraceScanReport, error) {
	if threshold <= 0 || threshold > 1 {
		threshold = DefaultStabilityThreshold
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return TraceScanReport{}, err
	}
	var traces [][]Event
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		events, err := ReadJSONL(filepath.Join(dir, entry.Name()))
		if err != nil {
			return TraceScanReport{}, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		traces = append(traces, events)
	}
	if len(traces) == 0 {
		return TraceScanReport{}, fmt.Errorf("no trace jsonl files found in %s", dir)
	}
	report := ScanTraces(traces, threshold)
	report.FileCount = len(traces)
	return report, nil
}

func ScanTraces(traces [][]Event, threshold float64) TraceScanReport {
	if threshold <= 0 || threshold > 1 {
		threshold = DefaultStabilityThreshold
	}
	report := TraceScanReport{TraceCount: len(traces), FileCount: len(traces)}
	add := func(name string, values []string) {
		metric := summarizeMetric(name, values, threshold)
		if metric.Total == 0 {
			return
		}
		report.Metrics = append(report.Metrics, metric)
		if metric.Flagged {
			report.Flagged = append(report.Flagged, metric)
		}
	}
	add("first_frame_size", perTraceValue(traces, firstFrameSizeSignature))
	add("first_contact_message_count", perTraceValue(traces, firstContactCountSignature))
	add("state_path_shape", perTraceValue(traces, statePathShapeSignature))
	add("frame_size_histogram", perTraceValue(traces, frameHistogramSignature))
	add("padding_histogram", perTraceValue(traces, paddingHistogramSignature))
	add("invalid_input_result", presentTraceValue(traces, invalidInputSignature))
	add("close_behavior", presentTraceValue(traces, closeBehaviorSignature))
	if len(report.Flagged) > 0 {
		report.Conclusion = "suspicious stability detected"
	} else {
		report.Conclusion = "no suspicious stability detected"
	}
	return report
}

func (r TraceScanReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "trace_count: %d\n", r.TraceCount)
	for _, metric := range r.Metrics {
		fmt.Fprintf(&b, "%s: unique=%d dominant=%q dominant_count=%d stability=%.2f flagged=%t\n", metric.Name, metric.UniqueValues, metric.Dominant, metric.DominantCount, metric.Stability, metric.Flagged)
	}
	fmt.Fprintf(&b, "conclusion: %s\n", r.Conclusion)
	return b.String()
}

func summarizeMetric(name string, values []string, threshold float64) StabilityMetric {
	counts := map[string]int{}
	for _, value := range values {
		if value == "" {
			continue
		}
		counts[value]++
	}
	metric := StabilityMetric{Name: name, Total: len(values), UniqueValues: len(counts)}
	for value, count := range counts {
		if count > metric.DominantCount || (count == metric.DominantCount && value < metric.Dominant) {
			metric.Dominant = value
			metric.DominantCount = count
		}
	}
	if metric.Total > 0 {
		metric.Stability = float64(metric.DominantCount) / float64(metric.Total)
	}
	metric.Flagged = metric.Total >= 3 && metric.UniqueValues > 0 && metric.Stability >= threshold
	return metric
}

func perTraceValue(traces [][]Event, fn func([]Event) string) []string {
	values := make([]string, 0, len(traces))
	for _, events := range traces {
		values = append(values, fn(events))
	}
	return values
}

func presentTraceValue(traces [][]Event, fn func([]Event) string) []string {
	values := make([]string, 0, len(traces))
	for _, events := range traces {
		value := fn(events)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func firstFrameSizeSignature(events []Event) string {
	for _, ev := range events {
		if ev.FrameBytes > 0 {
			return fmt.Sprint(ev.FrameBytes)
		}
	}
	return ""
}

func firstContactCountSignature(events []Event) string {
	count := 0
	for _, ev := range events {
		if ev.EventType == "first_contact" {
			count++
		}
	}
	return fmt.Sprint(count)
}

func statePathShapeSignature(events []Event) string {
	indexes := map[string]int{}
	next := 0
	parts := []string{}
	for _, ev := range events {
		if ev.State == "" {
			continue
		}
		if _, ok := indexes[ev.State]; !ok {
			indexes[ev.State] = next
			next++
		}
		parts = append(parts, fmt.Sprintf("s%d", indexes[ev.State]))
	}
	return strings.Join(parts, ">")
}

func frameHistogramSignature(events []Event) string {
	return intHistogramSignature(frameSizes(events))
}

func paddingHistogramSignature(events []Event) string {
	return intHistogramSignature(paddingSizes(events))
}

func invalidInputSignature(events []Event) string {
	for _, ev := range events {
		if ev.EventType == "invalid_input" {
			if ev.Note != "" {
				return ev.Note
			}
			if ev.Semantic != "" {
				return ev.Semantic
			}
			return "invalid_input"
		}
	}
	return ""
}

func closeBehaviorSignature(events []Event) string {
	for _, ev := range events {
		if ev.EventType == "close" {
			if ev.Note != "" {
				return ev.Note
			}
			return "close"
		}
	}
	return ""
}

func intHistogramSignature(values []int) string {
	counts := map[int]int{}
	for _, value := range values {
		counts[value]++
	}
	keys := make([]int, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%d:%d", key, counts[key]))
	}
	return strings.Join(parts, ",")
}
