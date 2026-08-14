// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const draft202012 = "https://json-schema.org/draft/2020-12/schema"

type qualificationSchemaObject struct {
	Schema               string                               `json:"$schema"`
	Type                 string                               `json:"type"`
	Required             []string                             `json:"required"`
	Properties           map[string]json.RawMessage           `json:"properties"`
	Defs                 map[string]qualificationSchemaObject `json:"$defs"`
	AdditionalProperties *bool                                `json:"additionalProperties"`
}

func TestPhase17QualificationSchemasMatchGoTypes(t *testing.T) {
	tests := []struct {
		file string
		root reflect.Type
		defs map[string]reflect.Type
	}{
		{
			file: "phase17-qualification-envelope-v1.schema.json",
			root: reflect.TypeOf(Envelope{}),
			defs: map[string]reflect.Type{
				"roots":         reflect.TypeOf(SubjectRoots{}),
				"candidate":     reflect.TypeOf(CandidateIdentity{}),
				"rcLocked":      reflect.TypeOf(RCLockedPayload{}),
				"attempt":       reflect.TypeOf(AttemptPayload{}),
				"soakReady":     reflect.TypeOf(SoakReadyPayload{}),
				"soakConsumed":  reflect.TypeOf(SoakConsumedPayload{}),
				"supersede":     reflect.TypeOf(SupersedePayload{}),
				"evidenceFinal": reflect.TypeOf(EvidenceFinalPayload{}),
			},
		},
		{
			file: "phase17-candidate-manifest-v1.schema.json",
			root: reflect.TypeOf(CandidateManifest{}),
			defs: map[string]reflect.Type{
				"source":  reflect.TypeOf(SourceProvenance{}),
				"roots":   reflect.TypeOf(SubjectRoots{}),
				"subject": reflect.TypeOf(SubjectManifest{}),
				"entry":   reflect.TypeOf(ManifestEntry{}),
			},
		},
		{
			file: "phase17-candidate-comparison-v1.schema.json",
			root: reflect.TypeOf(CandidateComparison{}),
			defs: map[string]reflect.Type{
				"entry": reflect.TypeOf(ManifestEntry{}),
			},
		},
		{
			file: "phase17-environment-context-v1.schema.json",
			root: reflect.TypeOf(EnvironmentContext{}),
		},
		{
			file: "phase17-owned-vps-preflight-v1.schema.json",
			root: reflect.TypeOf(OwnerVPSPreflight{}),
		},
		{
			file: "phase17-readiness-evidence-index-v1.schema.json",
			root: reflect.TypeOf(ReadinessEvidenceIndex{}),
			defs: map[string]reflect.Type{
				"roots": reflect.TypeOf(SubjectRoots{}),
				"entry": reflect.TypeOf(ReadinessEvidenceEntry{}),
			},
		},
		{
			file: "phase17-readiness-proof-v1.schema.json",
			root: reflect.TypeOf(ReadinessProof{}),
			defs: map[string]reflect.Type{
				"roots": reflect.TypeOf(SubjectRoots{}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			document := loadQualificationSchema(t, test.file)
			if document.Schema != draft202012 {
				t.Fatalf("$schema=%q", document.Schema)
			}
			assertQualificationSchemaObjectMatches(t, "root", document, test.root)
			for name, goType := range test.defs {
				definition, ok := document.Defs[name]
				if !ok {
					t.Fatalf("missing $defs.%s", name)
				}
				assertQualificationSchemaObjectMatches(t, "$defs."+name, definition, goType)
			}
		})
	}
}

func loadQualificationSchema(t *testing.T, name string) qualificationSchemaObject {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/schemas/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var document qualificationSchemaObject
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func assertQualificationSchemaObjectMatches(t *testing.T, location string, schema qualificationSchemaObject, goType reflect.Type) {
	t.Helper()
	if schema.Type != "object" {
		t.Fatalf("%s type=%q", location, schema.Type)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatalf("%s must set additionalProperties=false", location)
	}
	want := qualificationJSONFields(t, goType)
	if !reflect.DeepEqual(schema.Required, want) {
		t.Fatalf("%s required=%v want=%v", location, schema.Required, want)
	}
	gotProperties := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		gotProperties = append(gotProperties, name)
	}
	sort.Strings(gotProperties)
	wantProperties := append([]string(nil), want...)
	sort.Strings(wantProperties)
	if !reflect.DeepEqual(gotProperties, wantProperties) {
		t.Fatalf("%s properties=%v want=%v", location, gotProperties, wantProperties)
	}
}

func qualificationJSONFields(t *testing.T, goType reflect.Type) []string {
	t.Helper()
	if goType.Kind() != reflect.Struct {
		t.Fatalf("schema parity type %s is not a struct", goType)
	}
	fields := make([]string, 0, goType.NumField())
	for index := 0; index < goType.NumField(); index++ {
		field := goType.Field(index)
		if field.PkgPath != "" {
			t.Fatalf("schema parity type %s has unexported field %s", goType, field.Name)
		}
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("schema parity type %s field %s lacks a JSON name", goType, field.Name)
		}
		fields = append(fields, tag)
	}
	return fields
}
