// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17evidence

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type fieldV3SchemaObject struct {
	Schema               string                         `json:"$schema"`
	Type                 string                         `json:"type"`
	Required             []string                       `json:"required"`
	Properties           map[string]json.RawMessage     `json:"properties"`
	AllOf                []json.RawMessage              `json:"allOf"`
	Defs                 map[string]fieldV3SchemaObject `json:"$defs"`
	AdditionalProperties *bool                          `json:"additionalProperties"`
}

func TestOwnedVPSEvidenceV3SchemaMatchesGoTypes(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/schemas/phase17-owned-vps-evidence-v3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document fieldV3SchemaObject
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema=%q", document.Schema)
	}
	assertFieldV3SchemaObjectMatches(t, "root", document, reflect.TypeOf(OwnedVPSEvidenceV3{}))
	definitions := map[string]reflect.Type{
		"subject":     reflect.TypeOf(FieldSubjectV3{}),
		"attempt":     reflect.TypeOf(FieldAttemptV3{}),
		"environment": reflect.TypeOf(FieldEnvironmentV3{}),
		"check":       reflect.TypeOf(FieldCheckV3{}),
		"metrics":     reflect.TypeOf(FieldMetricsV3{}),
		"privacy":     reflect.TypeOf(FieldPrivacyV3{}),
		"scanner":     reflect.TypeOf(FieldScannerV3{}),
		"boundary":    reflect.TypeOf(FieldBoundaryV3{}),
		"campaign":    reflect.TypeOf(FieldCampaignV3{}),
	}
	for name, goType := range definitions {
		definition, ok := document.Defs[name]
		if !ok {
			t.Fatalf("missing $defs.%s", name)
		}
		assertFieldV3SchemaObjectMatches(t, "$defs."+name, definition, goType)
	}
}

func TestOwnedVPSEvidenceV3SchemaAcceptsCurrentPhysicalAPIWithoutWideningEmulatorMatrix(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/schemas/phase17-owned-vps-evidence-v3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document fieldV3SchemaObject
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	environment, ok := document.Defs["environment"]
	if !ok {
		t.Fatal("missing $defs.environment")
	}
	assertFieldV3AndroidAPISchemaPolicy(t, environment.Properties, environment.AllOf)
}

func assertFieldV3SchemaObjectMatches(t *testing.T, location string, schema fieldV3SchemaObject, goType reflect.Type) {
	t.Helper()
	if schema.Type != "object" {
		t.Fatalf("%s type=%q", location, schema.Type)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatalf("%s must set additionalProperties=false", location)
	}
	want := fieldV3JSONFields(t, goType)
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

func fieldV3JSONFields(t *testing.T, goType reflect.Type) []string {
	t.Helper()
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

func assertFieldV3AndroidAPISchemaPolicy(t *testing.T, properties map[string]json.RawMessage, allOf []json.RawMessage) {
	t.Helper()
	var api struct {
		Type    string `json:"type"`
		Minimum *int   `json:"minimum"`
		Enum    []int  `json:"enum"`
	}
	if err := json.Unmarshal(properties["androidApi"], &api); err != nil {
		t.Fatal(err)
	}
	if api.Type != "integer" || api.Minimum == nil || *api.Minimum != 26 || len(api.Enum) != 0 {
		t.Fatalf("androidApi base policy=%+v", api)
	}
	if len(allOf) != 1 {
		t.Fatalf("android API class rules=%d want=1", len(allOf))
	}
	var rule struct {
		If struct {
			Properties map[string]struct {
				Const string `json:"const"`
			} `json:"properties"`
			Required []string `json:"required"`
		} `json:"if"`
		Then struct {
			Properties map[string]struct {
				Enum []int `json:"enum"`
			} `json:"properties"`
		} `json:"then"`
	}
	if err := json.Unmarshal(allOf[0], &rule); err != nil {
		t.Fatal(err)
	}
	if rule.If.Properties["androidClass"].Const != "EMULATOR" ||
		!reflect.DeepEqual(rule.If.Required, []string{"androidClass"}) ||
		!reflect.DeepEqual(rule.Then.Properties["androidApi"].Enum, []int{26, 34, 36}) {
		t.Fatalf("android API class rule=%+v", rule)
	}
}
