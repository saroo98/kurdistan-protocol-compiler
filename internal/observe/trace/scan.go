// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package trace

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// ContainsSensitiveValue recursively inspects structured diagnostic values.
// It recognizes raw, hexadecimal, and JSON-string representations so nesting
// cannot bypass the same value check used for top-level event fields.
func ContainsSensitiveValue(value any, sensitive ...[]byte) bool {
	needles := make([][]byte, 0, len(sensitive)*2)
	for _, item := range sensitive {
		if len(item) == 0 {
			continue
		}
		hexValue := hex.EncodeToString(item)
		jsonValue, _ := json.Marshal(string(item))
		needles = append(needles,
			append([]byte(nil), item...),
			[]byte(hexValue), []byte(strings.ToUpper(hexValue)),
			[]byte(base64.StdEncoding.EncodeToString(item)),
			[]byte(base64.RawStdEncoding.EncodeToString(item)),
			[]byte(base64.URLEncoding.EncodeToString(item)),
			[]byte(base64.RawURLEncoding.EncodeToString(item)),
			jsonValue,
		)
	}
	type visitV1 struct {
		typeName string
		pointer  uintptr
		kind     reflect.Kind
	}
	visited := make(map[visitV1]bool)
	var scan func(reflect.Value) bool
	scan = func(current reflect.Value) bool {
		if !current.IsValid() {
			return false
		}
		if current.Kind() == reflect.Interface {
			if current.IsNil() {
				return false
			}
			return scan(current.Elem())
		}
		if current.Kind() == reflect.Pointer {
			if current.IsNil() {
				return false
			}
			identity := visitV1{typeName: current.Type().String(), pointer: current.Pointer(), kind: current.Kind()}
			if visited[identity] {
				return false
			}
			visited[identity] = true
			return scan(current.Elem())
		}
		switch current.Kind() {
		case reflect.String:
			text := []byte(current.String())
			for _, needle := range needles {
				if bytes.Contains(text, needle) {
					return true
				}
			}
		case reflect.Slice:
			if current.IsNil() {
				return false
			}
			identity := visitV1{typeName: current.Type().String(), pointer: current.Pointer(), kind: current.Kind()}
			if identity.pointer != 0 {
				if visited[identity] {
					return false
				}
				visited[identity] = true
			}
			if current.Type().Elem().Kind() == reflect.Uint8 {
				text := current.Bytes()
				for _, needle := range needles {
					if bytes.Contains(text, needle) {
						return true
					}
				}
			}
			for i := 0; i < current.Len(); i++ {
				if scan(current.Index(i)) {
					return true
				}
			}
		case reflect.Array:
			for i := 0; i < current.Len(); i++ {
				if scan(current.Index(i)) {
					return true
				}
			}
		case reflect.Map:
			if current.IsNil() {
				return false
			}
			identity := visitV1{typeName: current.Type().String(), pointer: current.Pointer(), kind: current.Kind()}
			if visited[identity] {
				return false
			}
			visited[identity] = true
			iter := current.MapRange()
			for iter.Next() {
				if scan(iter.Key()) || scan(iter.Value()) {
					return true
				}
			}
		case reflect.Struct:
			for i := 0; i < current.NumField(); i++ {
				if scan(current.Field(i)) {
					return true
				}
			}
		}
		return false
	}
	return scan(reflect.ValueOf(value))
}

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
	add("stream_count", perTraceValue(traces, streamCountSignature))
	add("stream_interleaving_pattern", perTraceValue(traces, streamInterleavingSignature))
	add("stream_priority_pattern", perTraceValue(traces, streamPrioritySignature))
	add("window_update_pattern", perTraceValue(traces, windowUpdateSignature))
	add("stream_close_reset_pattern", perTraceValue(traces, streamCloseResetSignature))
	add("backpressure_pattern", perTraceValue(traces, backpressureSignature))
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

func streamCountSignature(events []Event) string {
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.StreamLabel != "" {
			seen[ev.StreamLabel] = true
		}
	}
	return fmt.Sprint(len(seen))
}

func streamInterleavingSignature(events []Event) string {
	parts := []string{}
	for _, ev := range events {
		if ev.StreamLabel == "" || ev.StreamEvent == "" {
			continue
		}
		parts = append(parts, ev.StreamLabel+":"+ev.StreamEvent)
	}
	return strings.Join(limitTraceParts(parts, 24), ">")
}

func streamPrioritySignature(events []Event) string {
	parts := []string{}
	for _, ev := range events {
		if ev.PriorityClass != "" {
			parts = append(parts, ev.PriorityClass)
		}
	}
	return strings.Join(collapseTraceRepeats(limitTraceParts(parts, 24)), ">")
}

func windowUpdateSignature(events []Event) string {
	parts := []string{}
	for _, ev := range events {
		if ev.Semantic == "window_update" || ev.StreamEvent == "window_update" {
			parts = append(parts, ev.StreamWindowBucket+"/"+ev.SessionWindowBucket)
		}
	}
	return strings.Join(parts, ">")
}

func streamCloseResetSignature(events []Event) string {
	parts := []string{}
	for _, ev := range events {
		if ev.CloseResetEvent != "" {
			parts = append(parts, ev.CloseResetEvent)
		}
	}
	return strings.Join(parts, ">")
}

func backpressureSignature(events []Event) string {
	count := 0
	for _, ev := range events {
		if ev.Backpressure {
			count++
		}
	}
	return fmt.Sprint(count)
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

func limitTraceParts(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func collapseTraceRepeats(values []string) []string {
	out := make([]string, 0, len(values))
	prev := ""
	for _, value := range values {
		if value == "" || value == prev {
			continue
		}
		out = append(out, value)
		prev = value
	}
	return out
}
