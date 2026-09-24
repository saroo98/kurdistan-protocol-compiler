// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package committedevidence

import (
	"encoding/json"
	"strings"
	"testing"

	"kurdistan/internal/testkit/evidenceoverlay"
)

// The provenance subtests retain each original owner's mutation/assertion union.
func TestHistoricalOverlayProvenance(t *testing.T) {
	t.Run("audit/TestPhase8ProfileCryptographyOverlayMutationsV1", auditTestPhase8ProfileCryptographyOverlayMutationsV1)
	t.Run("audit/TestPhase8WO801ThreatModelOverlayMutationsV1", auditTestPhase8WO801ThreatModelOverlayMutationsV1)
	t.Run("audit/TestM2HelperOwnerOverlayCompositionMutationsV2", auditTestM2HelperOwnerOverlayCompositionMutationsV2)
	t.Run("audit/TestPhase8WO801AdoptionOverlayMutationsV1", auditTestPhase8WO801AdoptionOverlayMutationsV1)
	t.Run("audit/TestEvidenceStateLoadsSuccessorOnceForManyHashes", auditTestEvidenceStateLoadsSuccessorOnceForManyHashes)
	t.Run("codegen/TestPhase8ProfileCryptographyOverlayMutationsV1", codegenTestPhase8ProfileCryptographyOverlayMutationsV1)
	t.Run("codegen/TestPhase8WO801ThreatModelOverlayMutationsV1", codegenTestPhase8WO801ThreatModelOverlayMutationsV1)
	t.Run("codegen/TestM2HelperOwnerOverlayCompositionMutationsV2", codegenTestM2HelperOwnerOverlayCompositionMutationsV2)
	t.Run("codegen/TestPhase8WO801AdoptionOverlayMutationsV1", codegenTestPhase8WO801AdoptionOverlayMutationsV1)
	t.Run("kgen/TestPhase8ProfileCryptographyOverlayMutationsV1", kgenTestPhase8ProfileCryptographyOverlayMutationsV1)
	t.Run("kgen/TestPhase8WO801ThreatModelOverlayMutationsV1", kgenTestPhase8WO801ThreatModelOverlayMutationsV1)
	t.Run("kgen/TestM2HelperOwnerOverlayCompositionMutationsV2", kgenTestM2HelperOwnerOverlayCompositionMutationsV2)
	t.Run("kgen/TestPhase8WO801AdoptionOverlayMutationsV1", kgenTestPhase8WO801AdoptionOverlayMutationsV1)
	t.Run("importer/TestPhase8ProfileCryptographyOverlayMutationsV1", importerTestPhase8ProfileCryptographyOverlayMutationsV1)
	t.Run("importer/TestPhase8WO801ThreatModelOverlayMutationsV1", importerTestPhase8WO801ThreatModelOverlayMutationsV1)
	t.Run("importer/TestPhase8WO801AdoptionOverlayMutationsV1", importerTestPhase8WO801AdoptionOverlayMutationsV1)
	t.Run("importer/TestM2MaintenanceOverlayExactContentAndMutationsV1", importerTestM2MaintenanceOverlayExactContentAndMutationsV1)
	t.Run("importer/TestPhase12OperatorControlPlaneOverlayMutationsV1", importerTestPhase12OperatorControlPlaneOverlayMutationsV1)
	t.Run("importer/TestPhase8GuardMaintenanceOverlayMutationsV1", importerTestPhase8GuardMaintenanceOverlayMutationsV1)
}

// Origin: audit/TestPhase8ProfileCryptographyOverlayMutationsV1.
func auditTestPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 profile cryptography") {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

// Origin: audit/TestPhase8WO801ThreatModelOverlayMutationsV1.
func auditTestPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 WO-801") {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
}

// Origin: audit/TestM2HelperOwnerOverlayCompositionMutationsV2.
func auditTestM2HelperOwnerOverlayCompositionMutationsV2(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.HelperOwnerOverlays[helperOwnerOverlayNameV2]
	v1Raw, err := json.Marshal(manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*helperOwnerOverlayV1){
		func(v *helperOwnerOverlayV1) { v.Version = "wrong" },
		func(v *helperOwnerOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) },
		func(v *helperOwnerOverlayV1) { v.Entries = v.Entries[:2] },
		func(v *helperOwnerOverlayV1) { v.Entries = append(v.Entries, helperOwnerOverlayEntryV1{}) },
		func(v *helperOwnerOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] },
		func(v *helperOwnerOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) },
		func(v *helperOwnerOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) },
	}
	for i, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Entries = append([]helperOwnerOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest := manifest
		copyManifest.HelperOwnerOverlays = map[string]helperOwnerOverlayV1{
			helperOwnerOverlayNameV1: manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1],
			helperOwnerOverlayNameV2: copyOverlay,
		}
		if _, err := validateEvidenceOverlaysV1(root, copyManifest); err == nil {
			t.Fatalf("helper-owner mutation %d accepted", i)
		}
		gotV1, _ := json.Marshal(copyManifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
		if string(gotV1) != string(v1Raw) {
			t.Fatalf("helper-owner v1 changed by mutation %d", i)
		}
	}
}

// Origin: audit/TestPhase8WO801AdoptionOverlayMutationsV1.
func auditTestPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(map[string]phase2CompleteOverlayV1){
		"missing-map": func(v map[string]phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") },
		"extra-map":   func(v map[string]phase2CompleteOverlayV1) { v["extra"] = base },
		"wrong-version": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Version = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-predecessor": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = x.Paths[:8]
			v["phase8-wo801-adoption-v1"] = x
		},
		"extra-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = append(x.Paths, "extra")
			v["phase8-wo801-adoption-v1"] = x
		},
		"reordered": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-not-last": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = x.Entries[:7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = append(x.Entries, phase2CompleteOverlayEntryV1{})
			v["phase8-wo801-adoption-v1"] = x
		},
		"entry-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].Path = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"malformed-hash": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PostSHA256 = "bad"
			v["phase8-wo801-adoption-v1"] = x
		},
		"evidence-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PreEvidence = strings.Repeat("2", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"consumer-absent": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = "ABSENT"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = strings.Repeat("3", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"current-drift": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mutate(v)
			if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, v); err == nil || !strings.Contains(err.Error(), "phase8 WO-801 adoption") {
				t.Fatalf("accepted %s mutation", name)
			}
		})
	}
}

// Origin: audit/TestEvidenceStateLoadsSuccessorOnceForManyHashes.
func auditTestEvidenceStateLoadsSuccessorOnceForManyHashes(t *testing.T) {
	root := repositoryRoot(t)
	loads := 0
	state, err := loadEvidenceStateV1(root, func(root, expectedVersion string) (map[string]string, error) {
		loads++
		return evidenceoverlay.LoadSuccessor(root, expectedVersion)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"cmd/phase17field/main.go",
		"internal/audit/security.go",
		"go.mod",
	} {
		if _, err := state.resolve(path); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 1 {
		t.Fatalf("successor loads=%d, want 1", loads)
	}
}

// Origin: codegen/TestPhase8ProfileCryptographyOverlayMutationsV1.
func codegenTestPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 profile cryptography") {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

// Origin: codegen/TestPhase8WO801ThreatModelOverlayMutationsV1.
func codegenTestPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 WO-801") {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
}

// Origin: codegen/TestM2HelperOwnerOverlayCompositionMutationsV2.
func codegenTestM2HelperOwnerOverlayCompositionMutationsV2(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.HelperOwnerOverlays[helperOwnerOverlayNameV2]
	v1Raw, err := json.Marshal(manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*helperOwnerOverlayV1){func(v *helperOwnerOverlayV1) { v.Version = "wrong" }, func(v *helperOwnerOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) }, func(v *helperOwnerOverlayV1) { v.Entries = v.Entries[:2] }, func(v *helperOwnerOverlayV1) { v.Entries = append(v.Entries, helperOwnerOverlayEntryV1{}) }, func(v *helperOwnerOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] }, func(v *helperOwnerOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) }, func(v *helperOwnerOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) }}
	for i, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Entries = append([]helperOwnerOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest := manifest
		copyManifest.HelperOwnerOverlays = map[string]helperOwnerOverlayV1{helperOwnerOverlayNameV1: manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1], helperOwnerOverlayNameV2: copyOverlay}
		if _, err := validateEvidenceOverlaysV1(root, copyManifest); err == nil {
			t.Fatalf("helper-owner mutation %d accepted", i)
		}
		gotV1, _ := json.Marshal(copyManifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
		if string(gotV1) != string(v1Raw) {
			t.Fatalf("helper-owner v1 changed by mutation %d", i)
		}
	}
}

// Origin: codegen/TestPhase8WO801AdoptionOverlayMutationsV1.
func codegenTestPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(map[string]phase2CompleteOverlayV1){
		"missing-map": func(v map[string]phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") },
		"extra-map":   func(v map[string]phase2CompleteOverlayV1) { v["extra"] = base },
		"wrong-version": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Version = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-predecessor": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = x.Paths[:8]
			v["phase8-wo801-adoption-v1"] = x
		},
		"extra-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = append(x.Paths, "extra")
			v["phase8-wo801-adoption-v1"] = x
		},
		"reordered": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-not-last": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = x.Entries[:7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = append(x.Entries, phase2CompleteOverlayEntryV1{})
			v["phase8-wo801-adoption-v1"] = x
		},
		"entry-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].Path = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"malformed-hash": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PostSHA256 = "bad"
			v["phase8-wo801-adoption-v1"] = x
		},
		"evidence-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PreEvidence = strings.Repeat("2", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"consumer-absent": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = "ABSENT"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = strings.Repeat("3", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"current-drift": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mutate(v)
			if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, v); err == nil || !strings.Contains(err.Error(), "phase8 WO-801 adoption") {
				t.Fatalf("accepted %s mutation", name)
			}
		})
	}
}

// Origin: kgen/TestPhase8ProfileCryptographyOverlayMutationsV1.
func kgenTestPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 profile cryptography") {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

// Origin: kgen/TestPhase8WO801ThreatModelOverlayMutationsV1.
func kgenTestPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 WO-801") {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
}

// Origin: kgen/TestM2HelperOwnerOverlayCompositionMutationsV2.
func kgenTestM2HelperOwnerOverlayCompositionMutationsV2(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.HelperOwnerOverlays[helperOwnerOverlayNameV2]
	v1Raw, err := json.Marshal(manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*helperOwnerOverlayV1){func(v *helperOwnerOverlayV1) { v.Version = "wrong" }, func(v *helperOwnerOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) }, func(v *helperOwnerOverlayV1) { v.Entries = v.Entries[:2] }, func(v *helperOwnerOverlayV1) { v.Entries = append(v.Entries, helperOwnerOverlayEntryV1{}) }, func(v *helperOwnerOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] }, func(v *helperOwnerOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) }, func(v *helperOwnerOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) }}
	for i, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Entries = append([]helperOwnerOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest := manifest
		copyManifest.HelperOwnerOverlays = map[string]helperOwnerOverlayV1{helperOwnerOverlayNameV1: manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1], helperOwnerOverlayNameV2: copyOverlay}
		if _, err := validateEvidenceOverlaysV1(root, copyManifest); err == nil {
			t.Fatalf("helper-owner mutation %d accepted", i)
		}
		gotV1, _ := json.Marshal(copyManifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
		if string(gotV1) != string(v1Raw) {
			t.Fatalf("helper-owner v1 changed by mutation %d", i)
		}
	}
}

// Origin: kgen/TestPhase8WO801AdoptionOverlayMutationsV1.
func kgenTestPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(map[string]phase2CompleteOverlayV1){
		"missing-map": func(v map[string]phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") },
		"extra-map":   func(v map[string]phase2CompleteOverlayV1) { v["extra"] = base },
		"wrong-version": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Version = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-predecessor": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = x.Paths[:len(x.Paths)-1]
			v["phase8-wo801-adoption-v1"] = x
		},
		"extra-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = append(x.Paths, "extra")
			v["phase8-wo801-adoption-v1"] = x
		},
		"reordered-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-not-last": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = x.Entries[:len(x.Entries)-1]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = append(x.Entries, phase2CompleteOverlayEntryV1{Path: committedEvidenceManifestPathV1, PreEvidence: strings.Repeat("2", 64), PostSHA256: strings.Repeat("3", 64)})
			v["phase8-wo801-adoption-v1"] = x
		},
		"entry-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].Path = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"malformed-hash": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PostSHA256 = "bad"
			v["phase8-wo801-adoption-v1"] = x
		},
		"evidence-not-absent": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PreEvidence = strings.Repeat("4", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"consumer-absent": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = "ABSENT"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-consumer-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = strings.Repeat("5", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"current-drift": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PostSHA256 = strings.Repeat("6", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copyOverlay := base
			copyOverlay.Paths = append([]string(nil), base.Paths...)
			copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
			overlays := map[string]phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": copyOverlay}
			mutate(overlays)
			if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, overlays); err == nil || !strings.Contains(err.Error(), "phase8 WO-801 adoption") {
				t.Fatalf("accepted phase8 WO-801 adoption %s mutation", name)
			}
		})
	}
}

// Origin: importer/TestPhase8ProfileCryptographyOverlayMutationsV1.
func importerTestPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 profile cryptography") {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

// Origin: importer/TestPhase8WO801ThreatModelOverlayMutationsV1.
func importerTestPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	post := validatedPhase8Post(t, root, manifest, base)
	if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil || !strings.Contains(err.Error(), "phase8 WO-801") {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
}

// Origin: importer/TestPhase8WO801AdoptionOverlayMutationsV1.
func importerTestPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var m committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	base := m.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	post := validatedPhase8Post(t, root, m, base)
	if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, map[string]phase2CompleteOverlayV1{base.Version: base}); err != nil {
		t.Fatalf("stage positive control: %v", err)
	}
	muts := map[string]func(map[string]phase2CompleteOverlayV1){"missing-map": func(v map[string]phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") }, "extra-map": func(v map[string]phase2CompleteOverlayV1) { v["extra"] = base }, "wrong-version": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Version = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-predecessor": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-path": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = x.Paths[:8]
		v["phase8-wo801-adoption-v1"] = x
	}, "extra-path": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = append(x.Paths, "x")
		v["phase8-wo801-adoption-v1"] = x
	}, "reordered": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-not-last": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-entry": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = x.Entries[:7]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-entry": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = append(x.Entries, phase2CompleteOverlayEntryV1{})
		v["phase8-wo801-adoption-v1"] = x
	}, "entry-path": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].Path = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "malformed": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PostSHA256 = "bad"
		v["phase8-wo801-adoption-v1"] = x
	}, "evidence-pre": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PreEvidence = strings.Repeat("2", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "consumer-absent": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = "ABSENT"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-pre": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = strings.Repeat("3", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "current-drift": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
		v["phase8-wo801-adoption-v1"] = x
	}}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mut(v)
			if _, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, post, v); err == nil || !strings.Contains(err.Error(), "phase8 WO-801 adoption") {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// Origin: importer/TestM2MaintenanceOverlayExactContentAndMutationsV1.
func importerTestM2MaintenanceOverlayExactContentAndMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	overlay := manifest.MaintenanceOverlays[maintenanceOverlayNameV1]
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}

	missing := overlay
	missing.Paths = append([]string(nil), overlay.Paths[:len(overlay.Paths)-1]...)
	missingManifest := manifest
	missingManifest.MaintenanceOverlays = map[string]committedMaintenanceOverlayV1{maintenanceOverlayNameV1: missing}
	if _, err := validateEvidenceOverlaysV1(root, missingManifest); err == nil {
		t.Fatal("missing M2 path accepted")
	}
	extra := overlay
	extra.Paths = append(append([]string(nil), overlay.Paths...), "extra.md")
	extraManifest := manifest
	extraManifest.MaintenanceOverlays = map[string]committedMaintenanceOverlayV1{maintenanceOverlayNameV1: extra}
	if _, err := validateEvidenceOverlaysV1(root, extraManifest); err == nil {
		t.Fatal("extra M2 path accepted")
	}
	drift := overlay
	drift.Entries = append([]helperOwnerOverlayEntryV1(nil), overlay.Entries...)
	drift.Entries[0].PostSHA256 = strings.Repeat("1", 64)
	driftManifest := manifest
	driftManifest.MaintenanceOverlays = map[string]committedMaintenanceOverlayV1{maintenanceOverlayNameV1: drift}
	if _, err := validateEvidenceOverlaysV1(root, driftManifest); err == nil || !strings.Contains(err.Error(), "hash drift") {
		t.Fatalf("changed M2 content error=%v", err)
	}
	historical := manifest.Sets["WO-044"][4]
	if historical.PostSHA256 != "68ebebb5c733c2c8aa31d9d67bed24489635c82e38a0451a9ca6e9e6e0adcb8b" {
		t.Fatalf("historical README binding changed: %+v", historical)
	}
}

// Origin: importer/TestPhase12OperatorControlPlaneOverlayMutationsV1.
func importerTestPhase12OperatorControlPlaneOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]committedMaintenanceOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase12OperatorControlPlaneOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var overlays map[string]committedMaintenanceOverlayV1
		if err := json.Unmarshal(encoded, &overlays); err != nil {
			t.Fatal(err)
		}
		return overlays
	}
	phase14Pre, err := validatePhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase13Pre, err := validatePhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePhase12OperatorControlPlaneOverlayV1(root, phase13Pre, clone()); err != nil {
		t.Fatal(err)
	}
	const name = "phase12-operator-control-plane-v1"
	mutations := map[string]func(map[string]committedMaintenanceOverlayV1){
		"missing-overlay": func(overlays map[string]committedMaintenanceOverlayV1) {
			delete(overlays, name)
		},
		"extra-overlay": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlays["extra"] = overlays[name]
		},
		"missing-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries = overlay.Entries[:len(overlay.Entries)-1]
			overlays[name] = overlay
		},
		"extra-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Paths = append(overlay.Paths, "zz-phase12-extra")
			overlay.Entries = append(overlay.Entries, helperOwnerOverlayEntryV1{
				Path: "zz-phase12-extra", PreEvidence: "ABSENT",
				PostSHA256: strings.Repeat("1", 64),
			})
			overlays[name] = overlay
		},
		"reordered-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0], overlay.Entries[1] = overlay.Entries[1], overlay.Entries[0]
			overlays[name] = overlay
		},
		"substituted-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0].Path = "README.md"
			overlays[name] = overlay
		},
		"substituted-scope-with-self-authorized-absence": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			index := 4
			overlay.Paths[index] = "zz-phase12-self-authorized"
			overlay.Entries[index] = helperOwnerOverlayEntryV1{
				Path:        "zz-phase12-self-authorized",
				PreEvidence: "ABSENT",
				PostSHA256:  strings.Repeat("3", 64),
			}
			overlays[name] = overlay
		},
		"existing-path-self-authorized-as-absent": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0].PreSHA256 = ""
			overlay.Entries[0].PreEvidence = "ABSENT"
			overlays[name] = overlay
		},
		"delete-authority-state-path": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			index := 15
			overlay.Paths = append(overlay.Paths[:index], overlay.Paths[index+1:]...)
			overlay.Entries = append(overlay.Entries[:index], overlay.Entries[index+1:]...)
			overlays[name] = overlay
		},
		"substitute-authority-state-path": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			index := 15
			overlay.Paths[index] = "internal/operator/controlplane/authority_substitute.go"
			overlay.Entries[index] = helperOwnerOverlayEntryV1{
				Path:        "internal/operator/controlplane/authority_substitute.go",
				PreEvidence: "ABSENT",
				PostSHA256:  strings.Repeat("4", 64),
			}
			overlays[name] = overlay
		},
		"add-authority-state-sibling": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Paths = append(overlay.Paths, "zz-authority-state-sibling.go")
			overlay.Entries = append(overlay.Entries, helperOwnerOverlayEntryV1{
				Path:        "zz-authority-state-sibling.go",
				PreEvidence: "ABSENT",
				PostSHA256:  strings.Repeat("5", 64),
			})
			overlays[name] = overlay
		},
		"post-hash-drift": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0].PostSHA256 = strings.Repeat("2", 64)
			overlays[name] = overlay
		},
	}
	for mutation, mutate := range mutations {
		t.Run(mutation, func(t *testing.T) {
			overlays := clone()
			mutate(overlays)
			if _, err := validatePhase12OperatorControlPlaneOverlayV1(root, phase13Pre, overlays); err == nil {
				t.Fatal("Phase 12 operator control-plane overlay mutation accepted")
			}
		})
	}
}

// Origin: importer/TestPhase8GuardMaintenanceOverlayMutationsV1.
func importerTestPhase8GuardMaintenanceOverlayMutationsV1(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]committedMaintenanceOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase8GuardMaintenanceOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]committedMaintenanceOverlayV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase14Pre, err := validatePhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase13Pre, err := validatePhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase12Pre, err := validatePhase12OperatorControlPlaneOverlayV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase11Pre, err := validatePhase11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase10Pre, err := validatePhase10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase9Pre, err := validatePhase9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, manifest.Phase9GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	finalGuardPre, err := validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, clone()); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]committedMaintenanceOverlayV1){
		"missing-overlay": func(v map[string]committedMaintenanceOverlayV1) { delete(v, "phase8-wo806-guard-convergence-v1") },
		"extra-overlay":   func(v map[string]committedMaintenanceOverlayV1) { v["extra"] = v["phase8-wo806-guard-convergence-v1"] },
		"missing-path": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = o.Paths[:len(o.Paths)-1]
			v[o.Version] = o
		},
		"extra-path": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = append(o.Paths, "README.md")
			v[o.Version] = o
		},
		"reordered-path": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Paths[1] = o.Paths[1], o.Paths[0]
			v[o.Version] = o
		},
		"self-pre": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.SelfPreSHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"pre-hash": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PreSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
		"post-hash": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("3", 64)
			v[o.Version] = o
		},
		"path-substitution": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Entries[0].Path = "README.md", "README.md"
			v[o.Version] = o
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := clone()
			mutate(v)
			if _, err := validatePhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, v); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

// Each entry's post value has already been checked against the immutable
// successor rewind by the complete chain. Reuse that validated stage subject,
// never the mutated overlay, to exercise the individual validator.
func validatedPhase8Post(t *testing.T, root string, manifest committedEvidenceManifestV1, base phase2CompleteOverlayV1) map[string]string {
	t.Helper()
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatalf("immutable chain control: %v", err)
	}
	post := make(map[string]string, len(base.Entries))
	for _, entry := range base.Entries {
		post[entry.Path] = entry.PostSHA256
	}
	return post
}
