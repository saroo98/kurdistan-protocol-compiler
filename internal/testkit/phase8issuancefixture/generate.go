// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase8issuancefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/evidenceoverlay"
	"kurdistan/internal/testkit/phase8issuance"
)

var classes = []envelope.ArtifactClass{envelope.ArtifactSignedPublic, envelope.ArtifactProviderGroup, envelope.ArtifactDeviceRecipient, envelope.ArtifactEncryptedBackup}

type evidenceCaseOwner struct {
	Case string `json:"case"`
	Test string `json:"test"`
}

func Generate(out, repoRoot string) error {
	if out == "" || repoRoot == "" {
		return errors.New("fixture generator: paths required")
	}
	if err := os.Mkdir(out, 0o755); err != nil {
		return err
	}
	issuer, sealer := phase8issuance.NewIssuer(), phase8issuance.NewRecipientSealer()
	manifest := map[string]string{}
	artifacts := map[envelope.ArtifactClass][]byte{}
	roundtripObservations := make([]string, 0, len(classes))
	inspectObservations := make([]string, 0, len(classes))
	for _, class := range classes {
		spec := phase8issuance.ValidSpec(class)
		artifact, err := profile.IssueOffline(spec, issuer, sealer)
		if err != nil {
			return err
		}
		name := string(class) + ".bin"
		if err := writeNew(filepath.Join(out, name), artifact); err != nil {
			return err
		}
		manifest[name] = hashBytes(artifact)
		artifacts[class] = artifact
		verified, err := profile.VerifyOffline(verifyRequest(spec, artifact), phase8issuance.NewIndependentVerifier(), phase8issuance.NewResolver(class), phase8issuance.NewIndependentRecipientOpener())
		if err != nil {
			return err
		}
		roundtripObservations = append(roundtripObservations, string(class)+":artifact="+hashBytes(artifact)+":content="+verified.Profile.ContentID)
		inspection, err := json.Marshal(profile.InspectRedacted(verified))
		if err != nil {
			return err
		}
		inspectObservations = append(inspectObservations, string(class)+":inspection="+hashBytes(inspection))
	}
	invalidObservations, err := writeInvalidFixtures(out, manifest, artifacts[envelope.ArtifactDeviceRecipient])
	if err != nil {
		return err
	}
	sourceHash, err := evidenceoverlay.ResolveCurrentSHA256(repoRoot, "internal/product/profile/phase8_tooling.go")
	if err != nil {
		return err
	}
	testHash, err := evidenceoverlay.ResolveCurrentSHA256(repoRoot, "internal/product/profile/phase8_tooling_external_test.go")
	if err != nil {
		return err
	}
	testHashByReport := map[string]string{}
	for name, path := range map[string]string{"fixture-reproduction-report.json": "internal/product/profile/phase8_tooling_evidence_test.go", "issuance-roundtrip-report.json": "internal/product/profile/phase8_tooling_external_test.go", "production-wiring-negative-report.json": "internal/testkit/phase8issuancefixture/isolation_test.go", "offline-boundary-report.json": "cmd/kprofile/main_test.go", "issuance-negative-report.json": "internal/product/profile/phase8_tooling_external_test.go", "redacted-inspect-report.json": "cmd/kprofile/main_test.go"} {
		digest, hashErr := evidenceoverlay.ResolveCurrentSHA256(repoRoot, path)
		if hashErr != nil {
			return hashErr
		}
		testHashByReport[name] = digest
	}
	if err := writeJSON(out, "fixture-manifest.json", map[string]any{"schema": "phase8-issuance-fixture-manifest-v1", "source_sha256": sourceHash, "test_source_sha256": testHash, "fixtures": manifest}); err != nil {
		return err
	}
	negativeCases := []string{"wrong-role", "unsupported-suite", "missing-audience", "stale-generation", "expired", "scope", "recipient", "truncation", "ciphertext-tamper", "wrong-header-class", "wrong-recipient"}
	negativeCaseOwners := []evidenceCaseOwner{
		{Case: "wrong-role", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "unsupported-suite", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "missing-audience", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "stale-generation", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "expired", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "scope", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "recipient", Test: "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse"},
		{Case: "truncation", Test: "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation"},
		{Case: "ciphertext-tamper", Test: "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation"},
		{Case: "wrong-header-class", Test: "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation"},
		{Case: "wrong-recipient", Test: "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation"},
	}
	reports := map[string]any{
		"fixture-reproduction-report.json":       evidence("TestWO806FixtureReproduction", sourceHash, testHash, sortedKeys(manifest), manifestObservations(manifest)),
		"issuance-roundtrip-report.json":         evidence("TestOfflineIssuanceRoundTripsAllArtifactClasses", sourceHash, testHash, []string{"signed-public", "provider-group", "device-recipient", "encrypted-backup"}, roundtripObservations),
		"production-wiring-negative-report.json": evidence("TestWO806ProductionWiringIsolation", sourceHash, testHash, []string{"no-testkit-import", "no-deterministic-selector", "no-private-key-material", "no-environment-key-selector"}, []string{"production-deps=go-list-checked", "production-imports=ast-checked", "production-selectors=ast-checked", "production-environment=ast-checked"}),
		"offline-boundary-report.json":           evidence("TestCompileInspectAreSecretSafeAndNeverOverwrite", sourceHash, testHash, []string{"offline-only", "no-service", "no-network", "no-overwrite", "no-real-endpoint"}, []string{"commands=compile,inspect", "service-listeners=0", "network-clients=0", "outputs=o_excl", "fixture-endpoints=0"}),
		"issuance-negative-report.json":          evidence("TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse", sourceHash, testHash, negativeCases, invalidObservations),
		"redacted-inspect-report.json":           evidence("TestCompileInspectAreSecretSafeAndNeverOverwrite", sourceHash, testHash, []string{"signed-public", "provider-group", "device-recipient", "encrypted-backup"}, inspectObservations),
	}
	for name, report := range reports {
		row := report.(map[string]any)
		row["test_source_sha256"] = testHashByReport[name]
		cases, observed := row["cases"].([]string), row["observations"].([]string)
		caseHash, observationHash := hashStrings(cases), hashStrings(observed)
		row["case_set_sha256"], row["observation_sha256"], row["execution_sha256"] = caseHash, observationHash, observationHash
		resultInputs := []string{row["test"].(string), row["source_sha256"].(string), row["test_source_sha256"].(string), caseHash, observationHash}
		if name == "issuance-negative-report.json" {
			ownerHash := hashCaseOwners(negativeCaseOwners)
			row["case_owners"], row["case_owner_sha256"] = negativeCaseOwners, ownerHash
			resultInputs = append(resultInputs, ownerHash)
		}
		row["result_sha256"] = hashStrings(resultInputs)
		if err := writeJSON(out, name, row); err != nil {
			return err
		}
	}
	return nil
}

func evidence(test, sourceHash, testHash string, cases, observations []string) map[string]any {
	return map[string]any{"schema": "phase8-issuance-evidence-v1", "test": test, "source_sha256": sourceHash, "test_source_sha256": testHash, "cases": cases, "observations": observations}
}

func manifestObservations(manifest map[string]string) []string {
	keys := sortedKeys(manifest)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+":"+manifest[key])
	}
	return result
}

func writeInvalidFixtures(out string, manifest map[string]string, sealed []byte) ([]string, error) {
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	truncated := append([]byte(nil), sealed[:len(sealed)-1]...)
	for name, raw := range map[string][]byte{"invalid-tamper.bin": tampered, "invalid-truncation.bin": truncated} {
		if err := writeNew(filepath.Join(out, name), raw); err != nil {
			return nil, err
		}
		manifest[name] = hashBytes(raw)
	}
	spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
	requests := map[string]any{
		"invalid-wrong-header.json": mutateVerify(verifyRequest(spec, sealed), func(r *profile.OfflineVerifyRequest) {
			r.Class, r.Audience = envelope.ArtifactProviderGroup, envelope.AudienceProvisionedGroup
		}),
		"invalid-wrong-recipient.json": map[string]any{"request": verifyRequest(spec, sealed), "resolver": "wrong-recipient"},
		"invalid-wrong-role.json":      mutateSpec(spec, func(s *profile.OfflineIssuanceSpec) { s.IssuerRole = profile.RoleProvider }),
		"invalid-generation.json":      mutateSpec(spec, func(s *profile.OfflineIssuanceSpec) { s.MinimumGeneration = s.Profile.Generation + 1 }),
	}
	for name, value := range requests {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, err
		}
		raw = append(raw, '\n')
		if err := writeNew(filepath.Join(out, name), raw); err != nil {
			return nil, err
		}
		manifest[name] = hashBytes(raw)
	}
	return []string{"wrong-role:error=" + profile.ErrOfflineIssuance.Error(), "unsupported-suite:error=" + profile.ErrOfflineIssuance.Error(), "missing-audience:error=" + profile.ErrOfflineIssuance.Error(), "stale-generation:error=" + profile.ErrOfflineIssuance.Error(), "expired:error=" + profile.ErrOfflineIssuance.Error(), "scope:error=" + profile.ErrOfflineIssuance.Error(), "recipient:error=" + profile.ErrOfflineIssuance.Error(), "truncation:artifact=" + hashBytes(truncated), "ciphertext-tamper:artifact=" + hashBytes(tampered), "wrong-header-class:error=" + profile.ErrOfflineVerify.Error(), "wrong-recipient:error=" + profile.ErrOfflineVerify.Error()}, nil
}

func mutateVerify(request profile.OfflineVerifyRequest, mutate func(*profile.OfflineVerifyRequest)) profile.OfflineVerifyRequest {
	mutate(&request)
	return request
}

func mutateSpec(spec profile.OfflineIssuanceSpec, mutate func(*profile.OfflineIssuanceSpec)) profile.OfflineIssuanceSpec {
	mutate(&spec)
	return spec
}

func verifyRequest(spec profile.OfflineIssuanceSpec, artifact []byte) profile.OfflineVerifyRequest {
	return profile.OfflineVerifyRequest{Artifact: artifact, Class: spec.Class, Audience: spec.Audience, Suite: spec.Suite, IssuerRole: profile.RoleIssuer, IssuerScope: spec.IssuerScope, IssuerKey: spec.IssuerKey, Now: spec.Now, MinimumGeneration: spec.MinimumGeneration, MinimumSafetyFloor: spec.Profile.RequiredSafetyFloor, MinimumRootEpoch: spec.Profile.RootEpoch, MinimumRevocationEpoch: spec.Profile.RevocationEpoch}
}

func writeJSON(dir, name string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, name), append(raw, '\n'))
}
func writeNew(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
func hashFile(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	return hashBytes(b), nil
}
func hashBytes(b []byte) string     { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func hashStrings(v []string) string { return hashBytes([]byte(strings.Join(v, "\n"))) }
func hashCaseOwners(owners []evidenceCaseOwner) string {
	values := make([]string, 0, len(owners))
	for _, owner := range owners {
		values = append(values, owner.Case+"\x00"+owner.Test)
	}
	return hashStrings(values)
}
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
