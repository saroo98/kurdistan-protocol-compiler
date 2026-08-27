// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAcceptanceRegistryRetainsAllApprovedDefinitions(t *testing.T) {
	raw, err := os.ReadFile("../../config/phase17-acceptance-registry-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Entries []struct {
			ID string `json:"id"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Entries) != 189 {
		t.Fatalf("definitions=%d, require exactly 189", len(document.Entries))
	}
	ids := make(map[string]bool)
	for _, entry := range document.Entries {
		if ids[entry.ID] {
			t.Fatalf("duplicate acceptance ID %s", entry.ID)
		}
		ids[entry.ID] = true
	}
	for _, id := range []string{"S1-01", "RV-01", "PS-M-01", "MG-I-03", "RST-M-01", "BVM-M-01", "C01", "D08", "G04", "JL-12", "BV-03"} {
		if !ids[id] {
			t.Fatalf("approved definition absent: %s", id)
		}
	}
	registry, err := DecodeAcceptanceRegistry(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if registry.DefinitionSetSHA256() != "467f055345c12a225764937dd36a51f851958bdcfeb9f38afabf30aab6fba054" {
		t.Fatal("independent approved definition root not reproduced")
	}
	for _, entry := range registry.Entries() {
		if entry.Implementation.SourceStatus != "FULL" || entry.Implementation.TestStatus != "FULL" {
			t.Fatalf("%s does not retain the completed source and mapped-test implementation", entry.ID)
		}
		if entry.Implementation.Execution != "UNEXECUTED" {
			t.Fatal("registry falsely claims complete acceptance execution")
		}
	}
}

func acceptanceRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"go.mod", "config/phase17-acceptance-registry-v2.json", "internal/phase17qualification/acceptance_registry_test.go"} {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("acceptance repository root is not bound to the checked-out test source: %s", relative)
		}
	}
	return root
}

func acceptanceTestSource(path string) bool {
	return strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".Tests.ps1") ||
		strings.HasSuffix(path, ".kt") && (strings.Contains(path, "/src/test/") || strings.Contains(path, "/src/androidTest/"))
}

// This checkout-local audit is deliberately not part of the evidence verifier.
// A file's existence establishes a mapping target, never acceptance execution.
func checkAcceptanceMappingFiles(root string, entry AcceptanceEntry) error {
	if err := validateAcceptanceMapping(entry.Implementation); err != nil {
		return err
	}
	seen := map[string]bool{}
	for kind, paths := range [][]string{entry.Implementation.SourcePaths, entry.Implementation.TestPaths} {
		for _, relative := range paths {
			if acceptanceTestSource(relative) != (kind == 1) || seen[strings.ToLower(relative)] {
				return fmt.Errorf("%s maps the wrong source role or duplicate path: %s", entry.ID, relative)
			}
			seen[strings.ToLower(relative)] = true
			parts := strings.Split(relative, "/")
			path := root
			for index, part := range parts {
				path = filepath.Join(path, part)
				info, err := os.Lstat(path)
				if err != nil {
					return fmt.Errorf("%s mapped path is absent: %s", entry.ID, relative)
				}
				if info.Mode()&os.ModeSymlink != 0 || index < len(parts)-1 && !info.IsDir() ||
					index == len(parts)-1 && !info.Mode().IsRegular() {
					return fmt.Errorf("%s mapped path is not a regular confined source: %s", entry.ID, relative)
				}
			}
		}
	}
	return nil
}

func TestAcceptanceRegistryMappingTargetsExistInTheCurrentSourceTree(t *testing.T) {
	root := acceptanceRepositoryRoot(t)
	registry, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceRaw(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range registry.Entries() {
		if err := checkAcceptanceMappingFiles(root, entry); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAcceptanceRegistryRetainsCompleteMappingsWithoutExecutionClaims(t *testing.T) {
	d := acceptanceDocument(t)
	expected := map[string]bool{
		"A05": true, "BV-01": true, "C03": true, "EV-01": true, "FS-03": true,
		"HR-04": true, "JL-03": true, "MB-03": true, "PS-U-03": true, "PV-I-01": true,
		"RST-I-02": true, "S1-02": true,
	}
	for _, entry := range d.Entries {
		if entry.Implementation.Execution != "UNEXECUTED" {
			t.Fatalf("%s source mapping became an execution receipt", entry.ID)
		}
		if expected[entry.ID] {
			if entry.Implementation.SourceStatus != "FULL" || entry.Implementation.TestStatus != "FULL" || len(entry.Implementation.SourcePaths) == 0 || len(entry.Implementation.TestPaths) == 0 {
				t.Errorf("%s complete source and regression mapping absent", entry.ID)
			}
			delete(expected, entry.ID)
		}
	}
	if len(expected) != 0 {
		t.Fatal("required mapping IDs absent")
	}
}

func TestAcceptanceRegistryCheckoutAuditRejectsAbsentAndMisclassifiedMappings(t *testing.T) {
	root := acceptanceRepositoryRoot(t)
	for name, mapping := range map[string]AcceptanceImplementation{
		"absent source":  {SourceStatus: "FULL", TestStatus: "ABSENT", SourcePaths: []string{"android/no-such-acceptance-source.kt"}, TestPaths: []string{}, Execution: "UNEXECUTED"},
		"source is test": {SourceStatus: "FULL", TestStatus: "ABSENT", SourcePaths: []string{"internal/phase17qualification/acceptance_registry_test.go"}, TestPaths: []string{}, Execution: "UNEXECUTED"},
		"test is source": {SourceStatus: "FULL", TestStatus: "FULL", SourcePaths: []string{"internal/phase17qualification/acceptance_registry.go"}, TestPaths: []string{"internal/phase17qualification/device_verifier.go"}, Execution: "UNEXECUTED"},
		"directory":      {SourceStatus: "FULL", TestStatus: "ABSENT", SourcePaths: []string{"internal/phase17qualification"}, TestPaths: []string{}, Execution: "UNEXECUTED"},
		"escaping":       {SourceStatus: "FULL", TestStatus: "ABSENT", SourcePaths: []string{"../outside.go"}, TestPaths: []string{}, Execution: "UNEXECUTED"},
		"absent test":    {SourceStatus: "FULL", TestStatus: "FULL", SourcePaths: []string{"internal/phase17qualification/acceptance_registry.go"}, TestPaths: []string{"internal/phase17qualification/no_such_acceptance_test.go"}, Execution: "UNEXECUTED"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkAcceptanceMappingFiles(root, AcceptanceEntry{ID: "synthetic", Implementation: mapping}); err == nil {
				t.Fatal("unbound mapping target admitted")
			}
		})
	}
}

func TestAcceptanceRegistryIndependentDefinitionGoldenVectors(t *testing.T) {
	// These fixed values were calculated with .NET SHA256 over the documented
	// binary framing, independently of the Go encoder and verifier.
	want := map[string]string{
		"S1-01":    "3b147ee9d69b6bebc282b3a6fa307579f64ebb67094e8f9c09475a525a4238d8",
		"PS-M-01":  "07e22e9229fef487069177300b9ce7ebcfc501ae2160199004f5c1e4bf60cd9d",
		"RST-M-01": "15437511231b7adfb8ddcf2d0e1c5f315678b03968fc1cbde3da0b2bc1e5dd02",
		"D01":      "1497058e541b04d9b7ff99fcd1075edc131755651b7137526b8a0b8d8b429bfe",
		"JL-01":    "82d5e4a4235dd65a54fc098631fbc2bbb983547ec907c6db918ba831063dd0c1",
	}
	for _, entry := range acceptanceDocument(t).Entries {
		if digest, ok := want[entry.ID]; ok {
			if acceptanceDefinitionDigest(entry) != digest {
				t.Fatalf("independent vector failed: %s", entry.ID)
			}
			delete(want, entry.ID)
		}
	}
	if len(want) != 0 {
		t.Fatal("independent vector entries missing")
	}
}

func acceptanceRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../config/phase17-acceptance-registry-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func acceptanceDocument(t *testing.T) acceptanceRegistryDocument {
	t.Helper()
	var document acceptanceRegistryDocument
	if err := json.Unmarshal(acceptanceRaw(t), &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func acceptanceBytes(t *testing.T, value acceptanceRegistryDocument) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAcceptanceRegistryRejectsMissingDuplicateUnknownAndRepurposedIDs(t *testing.T) {
	for name, mutate := range map[string]func(*acceptanceRegistryDocument){
		"missing":                  func(d *acceptanceRegistryDocument) { d.Entries = d.Entries[:188] },
		"duplicate":                func(d *acceptanceRegistryDocument) { d.Entries[1] = d.Entries[0] },
		"unknown":                  func(d *acceptanceRegistryDocument) { d.Entries[0].ID = "A11" },
		"renamed":                  func(d *acceptanceRegistryDocument) { d.Entries[0].ID = "A-01" },
		"wrong source":             func(d *acceptanceRegistryDocument) { d.Entries[0].Source = "P1J" },
		"wrong count":              func(d *acceptanceRegistryDocument) { d.EntryCount = 188 },
		"wrong group count":        func(d *acceptanceRegistryDocument) { d.Groups[0].Count = 71 },
		"wrong version":            func(d *acceptanceRegistryDocument) { d.RegistryVersion = 1 },
		"wrong schema":             func(d *acceptanceRegistryDocument) { d.Schema = "approval" },
		"wrong definition version": func(d *acceptanceRegistryDocument) { d.Entries[0].DefinitionVersion++ },
		"reordered":                func(d *acceptanceRegistryDocument) { d.Entries[0], d.Entries[1] = d.Entries[1], d.Entries[0] },
	} {
		t.Run(name, func(t *testing.T) {
			d := acceptanceDocument(t)
			mutate(&d)
			if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
				t.Fatal("changed acceptance accounting admitted")
			}
		})
	}
}

func TestAcceptanceRegistryRejectsCallerAuthoredExecutionAndQualification(t *testing.T) {
	for _, status := range []string{"PASS", "HOST_PASS", "COMPILED_ONLY", "INSTALLED_VERIFIED", "OPERATIONALLY_VERIFIED"} {
		t.Run(status, func(t *testing.T) {
			d := acceptanceDocument(t)
			for i := range d.Entries {
				if d.Entries[i].ID == "D01" {
					d.Entries[i].Implementation.Execution = status
				}
			}
			if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
				t.Fatal("definition registry accepted an execution assertion")
			}
		})
	}
	d := acceptanceDocument(t)
	d.Entries[0].Implementation.SourceStatus = "IMPLEMENTED"
	if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
		t.Fatal("source treated as implemented acceptance")
	}
}

func TestAcceptanceRegistryRejectsDefinitionWeakening(t *testing.T) {
	for name, mutate := range map[string]func(*AcceptanceEntry){
		"criterion":        func(e *AcceptanceEntry) { e.Criterion += " unless inconvenient" },
		"controlled input": func(e *AcceptanceEntry) { e.ControlledInput = "happy path only" },
		"oracle":           func(e *AcceptanceEntry) { e.RequiredOracle = "application status" },
		"assertion":        func(e *AcceptanceEntry) { e.RequiredAssertion = "caller-provided PASS" },
		"evidence level":   func(e *AcceptanceEntry) { e.EvidenceRequirement = "host-only" },
		"digest":           func(e *AcceptanceEntry) { e.DefinitionSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			d := acceptanceDocument(t)
			mutate(&d.Entries[0])
			if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
				t.Fatal("weakened definition admitted")
			}
		})
	}
}

func TestAcceptanceRegistryRejectsAmbiguousAndUnboundedJSON(t *testing.T) {
	raw := acceptanceBytes(t, acceptanceDocument(t))
	for name, candidate := range map[string][]byte{
		"root duplicate":   bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1),
		"nested duplicate": bytes.Replace(raw, []byte(`"id":`), []byte(`"id":"x","id":`), 1),
		"unknown proof":    bytes.Replace(raw, []byte(`"implementation":{`), []byte(`"implementation":{"passed":true,`), 1),
		"case alias":       bytes.Replace(raw, []byte(`"id":`), []byte(`"ID":`), 1),
		"trailing value":   append(append([]byte{}, raw...), []byte(`{}`)...),
		"oversized":        bytes.Repeat([]byte{' '}, MaxAcceptanceRegistryBytes+1),
		"null":             []byte(`null`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAcceptanceRegistry(bytes.NewReader(candidate)); err == nil {
				t.Fatal("ambiguous registry admitted")
			}
		})
	}
}

func TestAcceptanceRegistryDefensiveCopiesDoNotChangeValidatedEntries(t *testing.T) {
	r, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceRaw(t)))
	if err != nil {
		t.Fatal(err)
	}
	copy := r.Entries()
	copy[0].Criterion = "changed"
	if r.Entries()[0].Criterion == "changed" {
		t.Fatal("validated registry exposed mutable backing entries")
	}
}

type acceptanceFailingReader struct{}

func (acceptanceFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}

func TestAcceptanceRegistryPropagatesBoundedReadFailure(t *testing.T) {
	if _, err := DecodeAcceptanceRegistry(acceptanceFailingReader{}); err == nil {
		t.Fatal("read failure accepted")
	}
	if _, err := DecodeAcceptanceRegistry(io.LimitReader(bytes.NewReader(acceptanceRaw(t)), 10)); err == nil {
		t.Fatal("truncated registry accepted")
	}
}

func TestAcceptanceRegistryAttackerRehashCannotRedefineApprovedContract(t *testing.T) {
	d := acceptanceDocument(t)
	d.Entries[0].Criterion = "Host-only success is enough."
	d.Entries[0].DefinitionSHA256 = acceptanceDefinitionDigest(d.Entries[0])
	d.DefinitionSetSHA256 = acceptanceSetDigest(d.Entries)
	if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
		t.Fatal("self-consistent but unapproved definitions admitted")
	}
	d.DefinitionSetSHA256 = AcceptanceDefinitionSetSHA256
	if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
		t.Fatal("claimed approved root hid recomputed definition drift")
	}
}

func TestAcceptanceRegistrySourceMappingIsNotExecutionEvidenceAndIsDeepCopied(t *testing.T) {
	d := acceptanceDocument(t)
	d.Entries[0].Implementation = AcceptanceImplementation{
		SourceStatus: "FULL", TestStatus: "FULL", SourcePaths: []string{"android/data/protected-state/src/main/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateAuthorityFactory.kt"},
		TestPaths: []string{"android/data/protected-state/src/test/kotlin/org/kurdistanvpn/data/protectedstate/ProtectedStateAuthorityFactoryTest.kt"}, Execution: "UNEXECUTED",
	}
	r, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d)))
	if err != nil {
		t.Fatal(err)
	}
	entries := r.Entries()
	entries[0].Implementation.SourcePaths[0] = "changed"
	entries[0].Implementation.TestPaths[0] = "changed"
	groups := r.Groups()
	groups[0].Count = 0
	if !reflect.DeepEqual(r.Entries()[0], d.Entries[0]) || !reflect.DeepEqual(r.Groups(), d.Groups) {
		t.Fatal("source mapping escaped defensive ownership")
	}
	if r.DefinitionSetSHA256() != AcceptanceDefinitionSetSHA256 {
		t.Fatal("advisory mapping changed definition authority")
	}
	for _, path := range []string{"../outside.kt", "C:/outside.kt", "android/../outside.kt", "android/.private/record", "android/a\\b.kt", "android/a//b.kt", "android/a.kt\n"} {
		d.Entries[0].Implementation.SourcePaths = []string{path}
		if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
			t.Fatal("escaping or private-looking mapping admitted")
		}
	}
	d.Entries[0].Implementation.SourcePaths = []string{"android/A.kt", "android/a.kt"}
	if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
		t.Fatal("case-alias duplicate mapping admitted")
	}
	d.Entries[0].Implementation.SourcePaths = []string{}
	if _, err := DecodeAcceptanceRegistry(bytes.NewReader(acceptanceBytes(t, d))); err == nil {
		t.Fatal("partial source claim without a source admitted")
	}
}

func TestAcceptanceRegistrySchemaPinsEveryDefinitionAndClosedFieldShape(t *testing.T) {
	document := loadQualificationSchema(t, "phase17-acceptance-registry-v2.schema.json")
	if document.Schema != draft202012 {
		t.Fatal("schema draft missing")
	}
	assertQualificationSchemaObjectMatches(t, "registry", document, reflect.TypeOf(acceptanceRegistryDocument{}))
	assertQualificationSchemaObjectMatches(t, "entry", document.Defs["entry"], reflect.TypeOf(AcceptanceEntry{}))
	assertQualificationSchemaObjectMatches(t, "implementation", document.Defs["implementation"], reflect.TypeOf(AcceptanceImplementation{}))
	assertQualificationSchemaObjectMatches(t, "group", document.Defs["group"], reflect.TypeOf(AcceptanceGroup{}))
	var entryArray struct {
		MinItems    int  `json:"minItems"`
		MaxItems    int  `json:"maxItems"`
		Items       bool `json:"items"`
		PrefixItems []struct {
			AllOf []struct {
				Ref        string `json:"$ref"`
				Properties map[string]struct {
					Const json.RawMessage `json:"const"`
				} `json:"properties"`
			} `json:"allOf"`
		} `json:"prefixItems"`
	}
	if err := json.Unmarshal(document.Properties["entries"], &entryArray); err != nil {
		t.Fatal(err)
	}
	if entryArray.MinItems != 189 || entryArray.MaxItems != 189 || entryArray.Items || len(entryArray.PrefixItems) != 189 {
		t.Fatal("schema does not bind the complete ID sequence")
	}
	d := acceptanceDocument(t)
	for i, prefix := range entryArray.PrefixItems {
		if len(prefix.AllOf) != 2 || prefix.AllOf[0].Ref != "#/$defs/entry" {
			t.Fatal("entry shape not enforced")
		}
		raw, _ := json.Marshal(d.Entries[i])
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		delete(fields, "implementation")
		if len(prefix.AllOf[1].Properties) != len(fields) {
			t.Fatal("schema omits a definition field")
		}
		for field, want := range fields {
			if !bytes.Equal(prefix.AllOf[1].Properties[field].Const, want) {
				t.Fatalf("schema changed definition field %s for %s", field, d.Entries[i].ID)
			}
		}
	}
}
