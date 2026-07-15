// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package trace

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestDiagnosticEventV1ExhaustiveSchemaAndValues(t *testing.T) {
	wantFields := []string{"SchemaVersion", "EventClass", "RoleBucket", "StateBucket", "OutcomeBucket", "DirectionBucket", "SizeBucket", "CountBucket", "ReasonBucket", "HygieneResult"}
	typeOf := reflect.TypeOf(DiagnosticEventV1{})
	if typeOf.NumField() != len(wantFields) {
		t.Fatalf("diagnostic fields=%d want=%d", typeOf.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if typeOf.Field(index).Name != want {
			t.Fatalf("field %d=%s want=%s", index, typeOf.Field(index).Name, want)
		}
	}
	for class := range diagnosticAllowedV1["event_class"] {
		for field, values := range diagnosticAllowedV1 {
			if field == "event_class" {
				continue
			}
			for value := range values {
				event := DiagnosticEventV1{SchemaVersion: DiagnosticSchemaV1, EventClass: class}
				reflect.ValueOf(&event).Elem().FieldByName(map[string]string{"role_bucket": "RoleBucket", "state_bucket": "StateBucket", "outcome_bucket": "OutcomeBucket", "direction_bucket": "DirectionBucket", "size_bucket": "SizeBucket", "count_bucket": "CountBucket", "reason_bucket": "ReasonBucket", "hygiene_result": "HygieneResult"}[field]).SetString(value)
				if err := ValidateDiagnosticEventV1(event); err != nil {
					t.Fatalf("class=%s field=%s value=%s: %v", class, field, value, err)
				}
			}
		}
	}
	fieldNames := []string{"RoleBucket", "StateBucket", "OutcomeBucket", "DirectionBucket", "SizeBucket", "CountBucket", "ReasonBucket", "HygieneResult"}
	jsonNames := []string{"role_bucket", "state_bucket", "outcome_bucket", "direction_bucket", "size_bucket", "count_bucket", "reason_bucket", "hygiene_result"}
	for left := range fieldNames {
		for right := left + 1; right < len(fieldNames); right++ {
			event := DiagnosticEventV1{SchemaVersion: DiagnosticSchemaV1, EventClass: "runtime"}
			for index, field := range []int{left, right} {
				for value := range diagnosticAllowedV1[jsonNames[field]] {
					reflect.ValueOf(&event).Elem().FieldByName(fieldNames[field]).SetString(value)
					break
				}
				_ = index
			}
			if err := ValidateDiagnosticEventV1(event); err != nil {
				t.Fatalf("pair %s/%s: %v", fieldNames[left], fieldNames[right], err)
			}
		}
	}
	for _, invalid := range []DiagnosticEventV1{{}, {SchemaVersion: "unknown", EventClass: "runtime"}, {SchemaVersion: DiagnosticSchemaV1, EventClass: "unknown"}, {SchemaVersion: DiagnosticSchemaV1, EventClass: "runtime", ReasonBucket: "raw-error"}} {
		if err := ValidateDiagnosticEventV1(invalid); err != ErrDiagnosticEventInvalidV1 {
			t.Fatalf("malformed diagnostic accepted: %+v err=%v", invalid, err)
		}
	}
}

func TestSchemaSequenceAllOptionalFieldMasksV1(t *testing.T) {
	type optionalField struct {
		goName, jsonName, value string
	}
	fields := []optionalField{
		{"RoleBucket", "role_bucket", "client"},
		{"StateBucket", "state_bucket", "active"},
		{"OutcomeBucket", "outcome_bucket", "accepted"},
		{"DirectionBucket", "direction_bucket", "client_to_relay"},
		{"SizeBucket", "size_bucket", "small"},
		{"CountBucket", "count_bucket", "one"},
		{"ReasonBucket", "reason_bucket", "policy"},
		{"HygieneResult", "hygiene_result", "redacted"},
	}
	canary := []byte("mask-sensitive-canary-057")
	for mask := 0; mask < 1<<len(fields); mask++ {
		event := DiagnosticEventV1{SchemaVersion: DiagnosticSchemaV1, EventClass: "runtime"}
		value := reflect.ValueOf(&event).Elem()
		for index, field := range fields {
			if mask&(1<<index) != 0 {
				value.FieldByName(field.goName).SetString(field.value)
			}
		}
		if err := ValidateDiagnosticEventV1(event); err != nil {
			t.Fatalf("mask %08b validation: %v", mask, err)
		}
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("mask %08b marshal: %v", mask, err)
		}
		var emitted map[string]any
		if err := json.Unmarshal(raw, &emitted); err != nil {
			t.Fatalf("mask %08b decode: %v", mask, err)
		}
		if emitted["schema_version"] != DiagnosticSchemaV1 || emitted["event_class"] != "runtime" || len(emitted) != 2+bitsSetV1(mask) {
			t.Fatalf("mask %08b required/cardinality fields=%v", mask, emitted)
		}
		for index, field := range fields {
			_, present := emitted[field.jsonName]
			wantPresent := mask&(1<<index) != 0
			if present != wantPresent {
				t.Fatalf("mask %08b field %s present=%t want=%t", mask, field.jsonName, present, wantPresent)
			}
		}
		if ContainsSensitiveValue([]any{event, emitted, raw}, canary) {
			t.Fatalf("mask %08b recursive scanner false positive", mask)
		}
	}
}

func bitsSetV1(value int) int {
	count := 0
	for value != 0 {
		count += value & 1
		value >>= 1
	}
	return count
}

func TestSchemaSequenceCrossSessionProfileCorrelationV1(t *testing.T) {
	sequence := func() []DiagnosticEventV1 {
		return []DiagnosticEventV1{
			{SchemaVersion: DiagnosticSchemaV1, EventClass: "runtime", RoleBucket: "client", StateBucket: "active", OutcomeBucket: "accepted", HygieneResult: "redacted"},
			{SchemaVersion: DiagnosticSchemaV1, EventClass: "channel", DirectionBucket: "client_to_relay", SizeBucket: "small", CountBucket: "one", HygieneResult: "redacted"},
			{SchemaVersion: DiagnosticSchemaV1, EventClass: "replay", OutcomeBucket: "rejected", CountBucket: "one", ReasonBucket: "replay", HygieneResult: "redacted"},
			{SchemaVersion: DiagnosticSchemaV1, EventClass: "rekey", OutcomeBucket: "completed", CountBucket: "one", HygieneResult: "redacted"},
			{SchemaVersion: DiagnosticSchemaV1, EventClass: "failure", OutcomeBucket: "rejected", ReasonBucket: "policy", HygieneResult: "redacted"},
			{SchemaVersion: DiagnosticSchemaV1, EventClass: "close", StateBucket: "terminal", OutcomeBucket: "completed", ReasonBucket: "closed", HygieneResult: "redacted"},
		}
	}
	left, right := sequence(), sequence()
	if err := ValidateDiagnosticSequenceV1(left); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("identical coarse behavior varied across sessions/profiles")
	}
	identifiers := [][]byte{[]byte("session-a"), []byte("session-b"), []byte("profile-a"), []byte("profile-b"), []byte("retry-91"), []byte("rekey-44")}
	if ContainsSensitiveValue([][]DiagnosticEventV1{left, right}, identifiers...) {
		t.Fatal("cross-session sequence retained identifier")
	}
}

func TestDiagnosticRecorderV1RejectsSchemaExpansionV1(t *testing.T) {
	recorder, err := NewDiagnosticRecorderV1(1, 1024)
	if err != nil {
		t.Fatal(err)
	}
	event := DiagnosticEventV1{SchemaVersion: DiagnosticSchemaV1, EventClass: "runtime", RoleBucket: "client", StateBucket: "active", OutcomeBucket: "accepted", HygieneResult: "redacted"}
	if err := recorder.Record(event); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(recorder.Snapshot()[0])
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	want := map[string]bool{"schema_version": true, "event_class": true, "role_bucket": true, "state_bucket": true, "outcome_bucket": true, "hygiene_result": true}
	if len(fields) != len(want) {
		t.Fatalf("recorded fields=%v", fields)
	}
	for field := range fields {
		if !want[field] {
			t.Fatalf("non-allowlisted recorded field %q", field)
		}
	}
	invalid := event
	invalid.RoleBucket = "session-identifier"
	if err := recorder.Record(invalid); err != ErrDiagnosticEventInvalidV1 {
		t.Fatalf("invalid diagnostic error=%v", err)
	}
	if err := recorder.Record(event); err != ErrDiagnosticRecorderLimitV1 {
		t.Fatalf("event bound error=%v", err)
	}
	if _, err := NewDiagnosticRecorderV1(0, 1); err != ErrDiagnosticRecorderLimitV1 {
		t.Fatalf("malformed bounds error=%v", err)
	}
	small, err := NewDiagnosticRecorderV1(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := small.Record(event); err != ErrDiagnosticRecorderLimitV1 {
		t.Fatalf("encoded size bound error=%v", err)
	}
	snapshot := recorder.Snapshot()
	snapshot[0].EventClass = "corrupted"
	if recorder.Snapshot()[0].EventClass != "runtime" {
		t.Fatal("snapshot mutation corrupted recorder state")
	}
}

func TestDiagnosticCorrelationSequenceAllowlistV1(t *testing.T) {
	sequence := []Event{
		{TimeUnixNano: 1720428123456789000, ProfileID: "profile-stable", StreamLabel: "stream-9281", EventType: "runtime", RuntimeRole: "client", RuntimeState: "active", LifecycleTransition: "state_change", RelayFleetID: "fleet-stable", RelayIDBucket: "relay-7", Note: "operator note"},
		{TimeUnixNano: 1720428124456789000, ProfileID: "profile-stable", EventType: "channel", RuntimeFrameBucket: "small", FrameDirectionBucket: "client_to_server"},
		{TimeUnixNano: 1720428125456789000, ProfileID: "profile-stable", EventType: "replay", RuntimeReplayRejections: 1, FailureReasonBucket: "replay"},
		{TimeUnixNano: 1720428126456789000, ProfileID: "profile-stable", EventType: "rekey", LifecycleTransition: "state_change"},
		{TimeUnixNano: 1720428127456789000, ProfileID: "profile-stable", EventType: "failure", FailureReasonBucket: "policy"},
		{TimeUnixNano: 1720428128456789000, ProfileID: "profile-stable", EventType: "close", CloseReasonBucket: "close"},
	}
	allowed := map[string]bool{
		"time_unix_nano": true, "role": true, "event_type": true, "runtime_role": true, "runtime_state": true,
		"lifecycle_transition": true, "runtime_frame_bucket": true, "frame_direction_bucket": true,
		"runtime_replay_rejections": true, "failure_reason_bucket": true, "close_reason_bucket": true,
	}
	for i, original := range sequence {
		minimized := MinimizeDiagnosticEvent(original)
		if minimized.ProfileID != "" || minimized.StreamLabel != "" || minimized.RelayFleetID != "" || minimized.RelayIDBucket != "" || minimized.Note != "" {
			t.Fatalf("event %d retained stable correlation data: %+v", i, minimized)
		}
		if minimized.TimeUnixNano%int64(time.Minute) != 0 {
			t.Fatalf("event %d retained sub-minute time precision: %d", i, minimized.TimeUnixNano)
		}
		raw, err := json.Marshal(minimized)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		for field := range fields {
			if !allowed[field] {
				t.Fatalf("event %d emitted non-allowlisted diagnostic field %q", i, field)
			}
		}
	}
}

func TestSensitiveScannerEncodingsCyclesAndPrivateFieldsV1(t *testing.T) {
	values := [][]byte{[]byte("secret-9241"), []byte("payload-9241"), []byte("ciphertext-9241"), []byte("nonce-9241"), []byte("key-9241"), []byte("identity-9241"), []byte("hashprefix-9241"), []byte("destination-9241"), []byte("json-\"line\n9241")}
	for _, sensitive := range values {
		encodings := []string{string(sensitive), bytesToHexV1(sensitive), string(bytes.ToUpper([]byte(bytesToHexV1(sensitive)))), base64.StdEncoding.EncodeToString(sensitive), base64.RawStdEncoding.EncodeToString(sensitive), base64.URLEncoding.EncodeToString(sensitive), base64.RawURLEncoding.EncodeToString(sensitive)}
		jsonString, _ := json.Marshal(string(sensitive))
		encodings = append(encodings, string(jsonString))
		for _, encoded := range encodings {
			nested := map[string]any{"outer": []any{map[string]any{"value": "prefix-" + encoded}}}
			if !ContainsSensitiveValue(nested, sensitive) {
				t.Fatalf("encoding %q escaped recursive scanner", encoded)
			}
		}
		copyValue := append([]byte(nil), sensitive...)
		if !ContainsSensitiveValue(struct{ Nested [][]byte }{Nested: [][]byte{copyValue}}, sensitive) {
			t.Fatal("nested sensitive bytes escaped scanner")
		}
	}
	if ContainsSensitiveValue(map[string]any{"outer": []string{"coarse", "operational"}}, values...) {
		t.Fatal("scanner reported unrelated coarse values")
	}
	type privateNode struct {
		next   *privateNode
		secret string
	}
	node := &privateNode{secret: string(values[0])}
	node.next = node
	if !ContainsSensitiveValue(node, values[0]) {
		t.Fatal("cycle-safe scanner missed unexported sensitive field")
	}
	mapCycle := map[string]any{}
	mapCycle["self"] = mapCycle
	mapCycle["value"] = string(values[1])
	if !ContainsSensitiveValue(mapCycle, values[1]) {
		t.Fatal("cycle-safe scanner missed map value")
	}
}

func TestRecorderAppliesCorrelationMinimizationV1(t *testing.T) {
	var output bytes.Buffer
	recorder := NewRecorder(&output)
	input := Event{TimeUnixNano: 1720428123456789000, ProfileID: "profile-stable", StreamLabel: "stream-2", RelayFleetID: "fleet", RelayIDBucket: "relay", EventType: "runtime", Note: "diagnostic detail"}
	if err := recorder.Record(input); err != nil {
		t.Fatal(err)
	}
	events, err := DecodeJSONL(&output)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d", len(events))
	}
	want := MinimizeDiagnosticEvent(input)
	if !reflect.DeepEqual(events[0], want) {
		t.Fatalf("recorded=%+v want=%+v", events[0], want)
	}
}

func bytesToHexV1(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, item := range value {
		out[i*2], out[i*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(out)
}
