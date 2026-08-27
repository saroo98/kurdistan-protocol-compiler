// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const AcceptanceRegistrySchema = "kurdistan-phase17-acceptance-registry-v2"
const AcceptanceDefinitionSetSHA256 = "467f055345c12a225764937dd36a51f851958bdcfeb9f38afabf30aab6fba054"
const MaxAcceptanceRegistryBytes = 256 << 10

type AcceptanceImplementation struct {
	SourceStatus string   `json:"sourceStatus"`
	TestStatus   string   `json:"testStatus"`
	SourcePaths  []string `json:"sourcePaths"`
	TestPaths    []string `json:"testPaths"`
	Execution    string   `json:"execution"`
}

type AcceptanceEntry struct {
	ID                  string                   `json:"id"`
	Source              string                   `json:"source"`
	DefinitionVersion   uint32                   `json:"definitionVersion"`
	Criterion           string                   `json:"criterion"`
	ControlledInput     string                   `json:"controlledInput"`
	RequiredOracle      string                   `json:"requiredOracle"`
	RequiredAssertion   string                   `json:"requiredAssertion"`
	EvidenceRequirement string                   `json:"evidenceRequirement"`
	DefinitionSHA256    string                   `json:"definitionSha256"`
	Implementation      AcceptanceImplementation `json:"implementation"`
}

type AcceptanceGroup struct {
	Source string `json:"source"`
	Count  uint32 `json:"count"`
}

type acceptanceRegistryDocument struct {
	Schema              string            `json:"schema"`
	RegistryVersion     uint32            `json:"registryVersion"`
	DefinitionSetSHA256 string            `json:"definitionSetSha256"`
	EntryCount          uint32            `json:"entryCount"`
	Groups              []AcceptanceGroup `json:"groups"`
	ClaimPolicy         string            `json:"claimPolicy"`
	Entries             []AcceptanceEntry `json:"entries"`
}

// AcceptanceRegistry contains definitions and audited source/test mappings, never
// execution receipts. FULL means that the current source mapping is intended to
// implement the complete criterion or mapped test contract; it is not evidence
// that the test ran or that installed or operational acceptance passed. Successful
// decoding proves definition integrity only. It cannot authorize installation,
// candidates, campaigns, or release. Raw host or device results must be verified
// by their respective evidence consumers.
type AcceptanceRegistry struct{ document acceptanceRegistryDocument }

func DecodeAcceptanceRegistry(reader io.Reader) (AcceptanceRegistry, error) {
	if reader == nil {
		return AcceptanceRegistry{}, errors.New("acceptance reader missing")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxAcceptanceRegistryBytes+1))
	if err != nil {
		return AcceptanceRegistry{}, errors.New("acceptance registry read failed")
	}
	if len(raw) == 0 || len(raw) > MaxAcceptanceRegistryBytes || !utf8.Valid(raw) {
		return AcceptanceRegistry{}, errors.New("acceptance registry byte bound rejected")
	}
	var document acceptanceRegistryDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return AcceptanceRegistry{}, errors.New("acceptance registry shape rejected")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return AcceptanceRegistry{}, errors.New("acceptance registry trailing value rejected")
	}
	if err := validateAcceptanceDocument(document); err != nil {
		return AcceptanceRegistry{}, err
	}
	// Pretty whitespace is harmless. After compaction, fixed field order and
	// spelling must match the closed struct encoding. This also rejects duplicate
	// fields, case-insensitive aliases, omitted required fields, and alternate
	// escaping rather than silently normalizing them into a different contract.
	canonical, err := MarshalCanonical(document)
	if err != nil {
		return AcceptanceRegistry{}, errors.New("acceptance registry canonical encoding rejected")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return AcceptanceRegistry{}, errors.New("acceptance registry ambiguous encoding rejected")
	}
	return AcceptanceRegistry{document}, nil
}

func (r AcceptanceRegistry) Entries() []AcceptanceEntry {
	entries := make([]AcceptanceEntry, len(r.document.Entries))
	for i, entry := range r.document.Entries {
		entry.Implementation.SourcePaths = append([]string{}, entry.Implementation.SourcePaths...)
		entry.Implementation.TestPaths = append([]string{}, entry.Implementation.TestPaths...)
		entries[i] = entry
	}
	return entries
}

func (r AcceptanceRegistry) DefinitionSetSHA256() string { return r.document.DefinitionSetSHA256 }
func (r AcceptanceRegistry) Groups() []AcceptanceGroup {
	return append([]AcceptanceGroup{}, r.document.Groups...)
}

func acceptanceIDGroups() []struct {
	source string
	count  uint32
	ids    string
} {
	return []struct {
		source string
		count  uint32
		ids    string
	}{
		{"P1E", 72, "BL-01 EV-01 EV-02 EV-03 EV-04 EV-05 EV-06 EV-07 EV-08 EV-09 EV-10 EV-11 EV-12 EV-13 EV-14 FS-01 FS-02 FS-03 FS-04 FS-05 FS-06 FS-07 FS-08 FS-09 FS-10 FS-11 HR-01 HR-02 HR-03 HR-04 HR-05 HR-06 HR-07 HR-08 MB-01 MB-02 MB-03 MB-04 MB-05 MB-06 MB-07 MB-08 MB-09 MB-10 MB-11 OC-01 OC-02 OC-03 OC-04 OC-05 OC-06 RL-01 RL-02 RL-03 RL-04 RV-01 S1-01 S1-02 S1-03 S1-04 S1-05 S1-06 S1-07 S1-08 S1-09 S1-10 S1-11 S1-12 S1-13 S1-14 S1-15 TB-01"},
		{"P1I", 41, "BK-I-01 BK-I-02 BK-I-03 BK-I-04 BK-O-01 BK-U-01 BT-D-01 BT-I-01 CN-I-01 CR-D-01 CR-I-01 CR-I-02 CR-I-03 CR-I-04 CR-I-05 CR-I-06 DL-I-01 DL-I-02 KI-I-01 MG-I-01 MG-I-02 MG-I-03 MG-M-01 PS-M-01 PS-U-01 PS-U-02 PS-U-03 PS-U-04 PV-I-01 PV-I-02 PV-I-03 RB-I-01 RB-I-02 RB-I-03 RC-I-01 RC-I-02 RD-I-01 RD-I-02 RT-D-01 RT-I-01 UB-I-01"},
		{"P1J", 26, "BVM-I-01 BVM-M-01 BVM-U-01 FSD-D-01 FSD-I-01 FSD-I-02 FSD-I-03 FSD-I-04 FSD-I-05 FSD-M-01 KEY-I-01 MUT-U-01 MUT-U-02 RCV-I-01 RCV-I-02 RCV-I-03 RCV-I-04 RST-D-01 RST-I-01 RST-I-02 RST-I-03 RST-I-04 RST-I-05 RST-I-06 RST-M-01 RST-O-01"},
		{"BOOT", 35, "A01 A02 A03 A04 A05 A06 A07 A08 A09 A10 C01 C02 C03 C04 C05 C06 C07 C08 C09 C10 D01 D02 D03 D04 D05 D06 D07 D08 G01 G02 G03 G04 I01 I02 I03"},
		{"JL_BV", 15, "BV-01 BV-02 BV-03 JL-01 JL-02 JL-03 JL-04 JL-05 JL-06 JL-07 JL-08 JL-09 JL-10 JL-11 JL-12"},
	}
}

func validateAcceptanceDocument(document acceptanceRegistryDocument) error {
	reject := errors.New("acceptance registry definition or accounting rejected")
	if document.Schema != AcceptanceRegistrySchema || document.RegistryVersion != 2 ||
		document.DefinitionSetSHA256 != AcceptanceDefinitionSetSHA256 ||
		document.EntryCount != 189 || len(document.Entries) != 189 ||
		document.ClaimPolicy != "DEFINITIONS_AND_SOURCE_MAPPING_ONLY" {
		return reject
	}
	groups := acceptanceIDGroups()
	if len(document.Groups) != len(groups) {
		return reject
	}
	expected := make(map[string]string, 189)
	counts := make(map[string]uint32, len(groups))
	for i, group := range groups {
		if document.Groups[i] != (AcceptanceGroup{group.source, group.count}) {
			return reject
		}
		ids := strings.Fields(group.ids)
		if len(ids) != int(group.count) {
			return reject
		}
		for _, id := range ids {
			if _, exists := expected[id]; exists {
				return reject
			}
			expected[id] = group.source
		}
	}
	prior := ""
	for _, entry := range document.Entries {
		if entry.ID <= prior || expected[entry.ID] != entry.Source || entry.Source == "" ||
			entry.DefinitionVersion != 1 || entry.Criterion == "" {
			return reject
		}
		prior = entry.ID
		for _, field := range []string{entry.Criterion, entry.ControlledInput, entry.RequiredOracle, entry.RequiredAssertion, entry.EvidenceRequirement} {
			if len(field) > 4096 || strings.TrimSpace(field) != field || !utf8.ValidString(field) {
				return reject
			}
			for _, character := range field {
				if character < 32 || character == 127 {
					return reject
				}
			}
		}
		if entry.DefinitionSHA256 != acceptanceDefinitionDigest(entry) {
			return reject
		}
		if err := validateAcceptanceMapping(entry.Implementation); err != nil {
			return err
		}
		counts[entry.Source]++
	}
	for _, group := range groups {
		if counts[group.source] != group.count {
			return reject
		}
	}
	if acceptanceSetDigest(document.Entries) != AcceptanceDefinitionSetSHA256 {
		return reject
	}
	return nil
}

func validateAcceptanceMapping(mapping AcceptanceImplementation) error {
	reject := errors.New("acceptance source mapping or execution claim rejected")
	if mapping.Execution != "UNEXECUTED" || mapping.SourcePaths == nil || mapping.TestPaths == nil ||
		len(mapping.SourcePaths) > 32 || len(mapping.TestPaths) > 32 {
		return reject
	}
	if !validAcceptanceMappingStatus(mapping.SourceStatus, len(mapping.SourcePaths)) ||
		!validAcceptanceMappingStatus(mapping.TestStatus, len(mapping.TestPaths)) {
		return reject
	}
	for _, list := range [][]string{mapping.SourcePaths, mapping.TestPaths} {
		seen := map[string]bool{}
		for _, path := range list {
			if !validAcceptanceSourcePath(path) || seen[strings.ToLower(path)] {
				return reject
			}
			seen[strings.ToLower(path)] = true
		}
	}
	return nil
}

func validAcceptanceMappingStatus(status string, pathCount int) bool {
	switch status {
	case "FULL", "PARTIAL":
		return pathCount > 0
	case "ABSENT":
		return pathCount == 0
	default:
		return false
	}
}

func validAcceptanceSourcePath(path string) bool {
	if len(path) == 0 || len(path) > 256 || strings.ContainsAny(path, "\\:") {
		return false
	}
	for _, c := range path {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-", c)) {
			return false
		}
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || !containsExact([]string{"android", "internal", "cmd", "config", "scripts", "testdata"}, parts[0]) {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// The fixed digest domains end with one NUL byte. Integers and UTF-8 byte lengths
// are unsigned u32 big-endian. Each definition frame is domain || version ||
// length-prefixed id, source, criterion, controlledInput, requiredOracle,
// requiredAssertion, evidenceRequirement. The set frame is its separate domain ||
// registry version (2) || count (189) || repeated (length-prefixed ID || raw
// 32-byte definition digest), in strict unsigned byte order of ASCII IDs.
// Mapping metadata is deliberately outside this definition digest: it is not
// evidence and must never be used as a gate. The approved set digest was computed
// independently with .NET SHA256 over a 7,888-byte set frame.
func acceptanceDefinitionDigest(entry AcceptanceEntry) string {
	var frame bytes.Buffer
	frame.WriteString("kurdistan-phase17-acceptance-definition-v2\x00")
	acceptanceU32(&frame, entry.DefinitionVersion)
	for _, field := range []string{entry.ID, entry.Source, entry.Criterion, entry.ControlledInput, entry.RequiredOracle, entry.RequiredAssertion, entry.EvidenceRequirement} {
		acceptanceText(&frame, field)
	}
	digest := sha256.Sum256(frame.Bytes())
	return hex.EncodeToString(digest[:])
}

func acceptanceSetDigest(entries []AcceptanceEntry) string {
	var frame bytes.Buffer
	frame.WriteString("kurdistan-phase17-acceptance-registry-v2\x00")
	acceptanceU32(&frame, 2)
	acceptanceU32(&frame, uint32(len(entries)))
	for _, entry := range entries {
		acceptanceText(&frame, entry.ID)
		digest, err := hex.DecodeString(entry.DefinitionSHA256)
		if err != nil || len(digest) != 32 {
			return ""
		}
		frame.Write(digest)
	}
	digest := sha256.Sum256(frame.Bytes())
	return hex.EncodeToString(digest[:])
}

func acceptanceText(frame *bytes.Buffer, value string) {
	acceptanceU32(frame, uint32(len(value)))
	frame.WriteString(value)
}

func acceptanceU32(frame *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	frame.Write(raw[:])
}
