// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package phase17evidence validates the strict, redacted Phase 17 evidence
// boundary. It never accepts raw field logs, network identifiers, credentials,
// packet captures, or operator paths.
package phase17evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const (
	SupersessionSchema = "phase17-historical-gate-supersession-v1"
	AcceptanceSchema   = "kurdistan-phase17-acceptance-v1"

	SupersessionPath = "testdata/evidence/phase17/historical-gate-supersession.json"
	AcceptancePath   = "testdata/evidence/phase17/acceptance-status.json"
	SchemaPath       = "testdata/schemas/phase17-historical-gate-supersession-v1.schema.json"
	SuccessorPolicy  = "cmd/phase17verify/artifact.go"
)

var (
	requiredSupersededRules = []string{
		"release-manifest-forbids-internet-and-access-network-state",
		"current-runtime-is-loopback-only",
	}
	requiredLocalKeys = []string{
		"api26Emulator",
		"api34Emulator",
		"api36Emulator",
		"currentArtifactPolicy",
		"historicalSupersession",
		"linuxNamespace",
		"loadRecoveryPrivacyCampaign",
		"ownedVps",
	}
	requiredExternalKeys = []string{
		"physicalApi26Device",
		"physicalApi34Device",
		"secondVpsProvider",
	}
)

type Predecessor struct {
	CommitSHA    string `json:"commitSha"`
	TreeSHA      string `json:"treeSha"`
	CIURL        string `json:"ciUrl"`
	CIConclusion string `json:"ciConclusion"`
}

type PredecessorArtifacts struct {
	ReleaseAPKSHA256     string `json:"releaseApkSha256"`
	InternalAPKSHA256    string `json:"internalApkSha256"`
	MergedManifestSHA256 string `json:"mergedManifestSha256"`
}

type Supersession struct {
	Schema                        string               `json:"schema"`
	Predecessor                   Predecessor          `json:"predecessor"`
	Artifacts                     PredecessorArtifacts `json:"artifacts"`
	HistoricalVerifierSHA256      string               `json:"historicalVerifierSha256"`
	HistoricalTestInventorySHA256 string               `json:"historicalTestInventorySha256"`
	SupersededRules               []string             `json:"supersededRules"`
	SuccessorPolicySHA256         string               `json:"successorPolicySha256"`
	SuccessorGate                 string               `json:"successorGate"`
}

type Acceptance struct {
	Schema      string            `json:"schema"`
	Phase       int               `json:"phase"`
	Complete    bool              `json:"complete"`
	Status      string            `json:"status"`
	Local       map[string]string `json:"local"`
	External    map[string]string `json:"external"`
	Limitations []string          `json:"limitations"`
}

var expectedSupersession = Supersession{
	Schema: SupersessionSchema,
	Predecessor: Predecessor{
		CommitSHA:    "07c7fcfcfea22c417c83ea7e9ffec6a6dcbd8467",
		TreeSHA:      "ae120ee345af105b5ccb9004dc2375a7541a9736",
		CIURL:        "https://github.com/saroo98/kurdistan-protocol-compiler/actions/runs/31140567216",
		CIConclusion: "success",
	},
	Artifacts: PredecessorArtifacts{
		ReleaseAPKSHA256:     "2bd10c95aee3b61cf40b817cc4131cbdcdaf0bce7f7e13539e01d99925236cf6",
		InternalAPKSHA256:    "87a5cac5876038b58723625dc7deeac68160f11c96bd9009a738c2af226ecfc2",
		MergedManifestSHA256: "c8918a762d9e8ed3458b758ce19ca1634317cc58d041ca60edea72d9dbc84117",
	},
	HistoricalVerifierSHA256:      "a7b3303c3c4bdd9866c023ad42c2de1b872096c2f68a6baeb0ce4c7c0bd2348b",
	HistoricalTestInventorySHA256: "5aebb2b87cf65011c6ac631f583dc65b0b8e82070260a383fc649f0469d4c82b",
	SupersededRules:               append([]string(nil), requiredSupersededRules...),
	SuccessorGate:                 "phase17Gate",
}

// DecodeStrict decodes one bounded JSON document and rejects unknown fields,
// duplicate object keys, trailing values, and oversized inputs.
func DecodeStrict(raw []byte, target any) error {
	const maximum = 1 << 20
	if len(raw) > maximum {
		return fmt.Errorf("JSON document exceeds %d bytes", maximum)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func ValidateSupersession(value Supersession) error {
	if value.Schema != SupersessionSchema {
		return fmt.Errorf("unexpected supersession schema %q", value.Schema)
	}
	if value.Predecessor != expectedSupersession.Predecessor {
		return errors.New("historical predecessor identity or CI result does not match the frozen Phase 16 baseline")
	}
	if value.Artifacts != expectedSupersession.Artifacts {
		return errors.New("historical predecessor artifacts do not match the frozen Phase 16 baseline")
	}
	if value.HistoricalVerifierSHA256 != expectedSupersession.HistoricalVerifierSHA256 {
		return errors.New("historical verifier digest does not match the frozen Phase 16 verifier")
	}
	if value.HistoricalTestInventorySHA256 != expectedSupersession.HistoricalTestInventorySHA256 {
		return errors.New("historical test inventory digest does not match the frozen Phase 16 inventory")
	}
	if !reflect.DeepEqual(value.SupersededRules, requiredSupersededRules) {
		return fmt.Errorf("superseded rules must be exactly %q", requiredSupersededRules)
	}
	if value.SuccessorGate != "phase17Gate" {
		return fmt.Errorf("successor gate must be phase17Gate, got %q", value.SuccessorGate)
	}
	if !validDigest(value.SuccessorPolicySHA256) {
		return errors.New("successor policy digest must be lowercase SHA-256")
	}
	return nil
}

func ValidateAcceptance(value Acceptance) error {
	if value.Schema != AcceptanceSchema || value.Phase != 17 {
		return errors.New("unexpected Phase 17 acceptance schema or phase")
	}
	if err := validateEvidenceMap("local", value.Local, requiredLocalKeys, map[string]bool{
		"PASS": true, "PENDING": true, "FAIL": true,
	}); err != nil {
		return err
	}
	if err := validateEvidenceMap("external", value.External, requiredExternalKeys, map[string]bool{
		"PASS": true, "UNVERIFIED": true, "FAIL": true,
	}); err != nil {
		return err
	}
	for _, limitation := range value.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return errors.New("limitations must not contain empty text")
		}
	}
	if value.Complete {
		if value.Status != "COMPLETE" {
			return errors.New("complete Phase 17 evidence requires COMPLETE status")
		}
		if len(value.Limitations) != 0 {
			return errors.New("complete Phase 17 evidence cannot retain limitations")
		}
		if err := requireAllPass("local", value.Local); err != nil {
			return err
		}
		if err := requireAllPass("external", value.External); err != nil {
			return err
		}
		return nil
	}
	if value.Status != "IN_PROGRESS" && value.Status != "BLOCKED" {
		return errors.New("incomplete Phase 17 evidence requires IN_PROGRESS or BLOCKED status")
	}
	if len(value.Limitations) == 0 {
		return errors.New("incomplete Phase 17 evidence must state its limitations")
	}
	return nil
}

// Verify validates the evidence schema marker, supersession record, acceptance
// status, and the digest binding to the current Phase 17 artifact policy.
func Verify(root string) error {
	if err := verifySchema(filepath.Join(root, filepath.FromSlash(SchemaPath))); err != nil {
		return err
	}
	var record Supersession
	if err := readStrict(filepath.Join(root, filepath.FromSlash(SupersessionPath)), &record); err != nil {
		return fmt.Errorf("historical supersession: %w", err)
	}
	if err := ValidateSupersession(record); err != nil {
		return fmt.Errorf("historical supersession: %w", err)
	}
	digest, err := fileSHA256(filepath.Join(root, filepath.FromSlash(SuccessorPolicy)))
	if err != nil {
		return fmt.Errorf("successor policy: %w", err)
	}
	if record.SuccessorPolicySHA256 != digest {
		return errors.New("historical supersession successor policy digest is stale")
	}
	var status Acceptance
	if err := readStrict(filepath.Join(root, filepath.FromSlash(AcceptancePath)), &status); err != nil {
		return fmt.Errorf("acceptance status: %w", err)
	}
	if err := ValidateAcceptance(status); err != nil {
		return fmt.Errorf("acceptance status: %w", err)
	}
	return nil
}

func verifySchema(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read supersession schema: %w", err)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return fmt.Errorf("supersession schema: %w", err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("decode supersession schema: %w", err)
	}
	for _, key := range []string{"$schema", "$id", "title", "type", "additionalProperties", "required", "properties"} {
		if _, ok := value[key]; !ok {
			return fmt.Errorf("supersession schema is missing %q", key)
		}
	}
	if len(value) != 7 {
		return errors.New("supersession schema contains an unexpected top-level field")
	}
	var allowAdditional bool
	if err := json.Unmarshal(value["additionalProperties"], &allowAdditional); err != nil || allowAdditional {
		return errors.New("supersession schema must set additionalProperties=false")
	}
	var required []string
	if err := json.Unmarshal(value["required"], &required); err != nil {
		return fmt.Errorf("decode supersession required fields: %w", err)
	}
	var properties map[string]json.RawMessage
	if err := json.Unmarshal(value["properties"], &properties); err != nil {
		return fmt.Errorf("decode supersession properties: %w", err)
	}
	expected := jsonFieldNames(reflect.TypeFor[Supersession]())
	if !reflect.DeepEqual(required, expected) || !sameKeys(properties, expected) {
		return errors.New("supersession schema fields do not match the strict record")
	}
	return nil
}

func validateEvidenceMap(scope string, values map[string]string, required []string, statuses map[string]bool) error {
	if len(values) != len(required) {
		return fmt.Errorf("%s evidence has %d keys, want %d", scope, len(values), len(required))
	}
	for _, key := range required {
		status, ok := values[key]
		if !ok {
			return fmt.Errorf("%s evidence is missing %q", scope, key)
		}
		if !statuses[status] {
			return fmt.Errorf("%s evidence %q has unsupported status %q", scope, key, status)
		}
	}
	return nil
}

func requireAllPass(scope string, values map[string]string) error {
	for key, status := range values {
		if status != "PASS" {
			return fmt.Errorf("%s evidence %q is %s", scope, key, status)
		}
	}
	return nil
}

func readStrict(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return DecodeStrict(raw, target)
}

func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func jsonFieldNames(typ reflect.Type) []string {
	result := make([]string, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		name := strings.Split(typ.Field(index).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			result = append(result, name)
		}
	}
	return result
}

func sameKeys(values map[string]json.RawMessage, expected []string) bool {
	if len(values) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON token")
		}
		return fmt.Errorf("trailing JSON token: %w", err)
	}
	return nil
}

func scanValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not text")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

// MarshalCanonical emits stable, indented evidence suitable for checked-in
// sanitized records. It never accepts maps with nondeterministic field sets.
func MarshalCanonical(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// SortedLocalKeys returns a defensive copy for generators and tests.
func SortedLocalKeys() []string {
	result := append([]string(nil), requiredLocalKeys...)
	sort.Strings(result)
	return result
}
