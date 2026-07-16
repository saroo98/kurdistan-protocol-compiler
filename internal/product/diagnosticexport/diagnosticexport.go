// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package diagnosticexport builds deterministic, redacted diagnostic bundles
// in memory. It performs no file, network, logging, telemetry, or runtime work.
package diagnosticexport

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
)

const Version = "offline-diagnostic-export-v1"
const PrivacyStatement = "local-user-initiated-redacted-no-telemetry-v1"

const (
	MaxCategories         = 6
	MaxEntriesPerCategory = 10
	MaxEntries            = 28
	MaxEncodedBytes       = 4096
)

type Category string
type Value string
type CountBucket string
type SizeBucket string

const (
	CategoryContractVersions   Category = "contract_versions"
	CategoryProfileLifecycle   Category = "profile_lifecycle"
	CategoryFallbackSelection  Category = "fallback_selection"
	CategoryRelayAdmission     Category = "relay_admission"
	CategoryRuntimeDisposition Category = "runtime_disposition"
	CategoryFailureSummary     Category = "failure_summary"
)

const (
	ValueSupported                   Value = "supported"
	ValueIncompatible                Value = "incompatible"
	ValueUnknown                     Value = "unknown"
	ValueAbsent                      Value = "absent"
	ValueAdmitted                    Value = "admitted"
	ValueSuperseded                  Value = "superseded"
	ValueRevoked                     Value = "revoked"
	ValueDisabled                    Value = "disabled"
	ValueSelected                    Value = "selected"
	ValueBlocked                     Value = "blocked"
	ValueRejected                    Value = "rejected"
	ValueEligible                    Value = "eligible"
	ValueShutdownRequired            Value = "shutdown_required"
	ValueUnavailable                 Value = "unavailable"
	ValuePermissionRequired          Value = "permission_required"
	ValueProtectedStorageUnavailable Value = "protected_storage_unavailable"
	ValueRoutingUnsafe               Value = "routing_unsafe"
	ValueDNSUnsafe                   Value = "dns_unsafe"
	ValueKillSwitchUnavailable       Value = "kill_switch_unavailable"
	ValueProfileNotAdmitted          Value = "profile_not_admitted"
	ValueFallbackNotSelected         Value = "fallback_not_selected"
	ValueRelayNotAdmitted            Value = "relay_not_admitted"
	ValueIncompatibleContract        Value = "incompatible_contract"
	ValueMalformedInput              Value = "malformed_input"
)

const (
	CountZero CountBucket = "zero"
	CountOne  CountBucket = "one"
	CountFew  CountBucket = "few"
	CountMany CountBucket = "many"

	SizeSmall   SizeBucket = "small"
	SizeMaximum SizeBucket = "maximum"
)

var (
	ErrInvalidRequest = errors.New("diagnosticexport: invalid request")
	ErrVersion        = errors.New("diagnosticexport: incompatible version")
	ErrNotInitiated   = errors.New("diagnosticexport: user initiation required")
	ErrTooLarge       = errors.New("diagnosticexport: request too large")
	ErrVocabulary     = errors.New("diagnosticexport: unknown diagnostic value")
	ErrCount          = errors.New("diagnosticexport: invalid count bucket")
	ErrDuplicate      = errors.New("diagnosticexport: duplicate diagnostic value")
	ErrState          = errors.New("diagnosticexport: invalid transition state")
	ErrConfirmation   = errors.New("diagnosticexport: confirmation mismatch")
)

type Entry struct {
	Category Category
	Value    Value
	Count    CountBucket
}

type Request struct {
	Version       string
	Revision      uint64
	UserInitiated bool
	Entries       []Entry
}

type Preview struct {
	Version      string
	Revision     uint64
	Categories   []Category
	TotalEntries CountBucket
	EncodedSize  SizeBucket
}

type Confirmation struct {
	Approved bool
	Version  string
	Revision uint64
	Preview  Preview
}

type Bundle struct {
	Version      string
	Bytes        []byte
	TotalEntries CountBucket
	EncodedSize  SizeBucket
}

type Prepared struct {
	valid    bool
	revision uint64
	entries  []Entry
}

type Previewed struct {
	valid   bool
	entries []Entry
	preview Preview
}

type Confirmed struct {
	valid   bool
	entries []Entry
	preview Preview
}

type Cancelled struct{ valid bool }

var vocabulary = []struct {
	category Category
	values   []Value
	count    bool
}{
	{CategoryContractVersions, []Value{ValueSupported, ValueIncompatible, ValueUnknown}, false},
	{CategoryProfileLifecycle, []Value{ValueAbsent, ValueAdmitted, ValueSuperseded, ValueRevoked, ValueDisabled}, false},
	{CategoryFallbackSelection, []Value{ValueSelected, ValueBlocked, ValueRejected}, false},
	{CategoryRelayAdmission, []Value{ValueAdmitted, ValueBlocked, ValueRejected}, false},
	{CategoryRuntimeDisposition, []Value{ValueEligible, ValueBlocked, ValueShutdownRequired, ValueUnavailable}, false},
	{CategoryFailureSummary, []Value{ValuePermissionRequired, ValueProtectedStorageUnavailable, ValueRoutingUnsafe, ValueDNSUnsafe, ValueKillSwitchUnavailable, ValueProfileNotAdmitted, ValueFallbackNotSelected, ValueRelayNotAdmitted, ValueIncompatibleContract, ValueMalformedInput}, true},
}

func Prepare(req Request) (Prepared, error) {
	if req.Version != Version {
		return Prepared{}, ErrVersion
	}
	if req.Revision == 0 {
		return Prepared{}, ErrInvalidRequest
	}
	if !req.UserInitiated {
		return Prepared{}, ErrNotInitiated
	}
	if len(req.Entries) > MaxCategories*MaxEntriesPerCategory {
		return Prepared{}, ErrTooLarge
	}
	perCategory := map[Category]int{}
	for _, entry := range req.Entries {
		perCategory[entry.Category]++
		if perCategory[entry.Category] > MaxEntriesPerCategory {
			return Prepared{}, ErrTooLarge
		}
	}
	if len(req.Entries) > MaxEntries {
		return Prepared{}, ErrTooLarge
	}

	entries := append([]Entry(nil), req.Entries...)
	seen := map[[2]string]bool{}
	for _, entry := range entries {
		ci, vi, needsCount, ok := vocabularyIndex(entry.Category, entry.Value)
		if !ok {
			return Prepared{}, ErrVocabulary
		}
		_ = ci
		_ = vi
		if needsCount != validCount(entry.Count) {
			return Prepared{}, ErrCount
		}
		key := [2]string{string(entry.Category), string(entry.Value)}
		if seen[key] {
			return Prepared{}, ErrDuplicate
		}
		seen[key] = true
	}
	sort.Slice(entries, func(i, j int) bool {
		ci, vi, _, _ := vocabularyIndex(entries[i].Category, entries[i].Value)
		cj, vj, _, _ := vocabularyIndex(entries[j].Category, entries[j].Value)
		return ci < cj || ci == cj && vi < vj
	})
	return Prepared{valid: true, revision: req.Revision, entries: entries}, nil
}

func PreviewPrepared(prepared Prepared) (Previewed, Preview, error) {
	if !prepared.valid || prepared.revision == 0 || !validCanonicalEntries(prepared.entries) {
		return Previewed{}, Preview{}, ErrState
	}
	encoded, err := encode(prepared.entries)
	if err != nil {
		return Previewed{}, Preview{}, err
	}
	preview := Preview{
		Version:      Version,
		Revision:     prepared.revision,
		Categories:   categories(prepared.entries),
		TotalEntries: countBucket(len(prepared.entries)),
		EncodedSize:  sizeBucket(len(encoded)),
	}
	stored := clonePreview(preview)
	return Previewed{valid: true, entries: append([]Entry(nil), prepared.entries...), preview: stored}, clonePreview(preview), nil
}

func Confirm(previewed Previewed, confirmation Confirmation) (Confirmed, error) {
	if !previewed.valid {
		return Confirmed{}, ErrState
	}
	if !confirmation.Approved || confirmation.Version != Version ||
		confirmation.Revision != previewed.preview.Revision ||
		!reflect.DeepEqual(confirmation.Preview, previewed.preview) {
		return Confirmed{}, ErrConfirmation
	}
	return Confirmed{valid: true, entries: append([]Entry(nil), previewed.entries...), preview: clonePreview(previewed.preview)}, nil
}

func Build(confirmed Confirmed) (Bundle, error) {
	if !confirmed.valid || confirmed.preview.Version != Version || confirmed.preview.Revision == 0 {
		return Bundle{}, ErrState
	}
	encoded, err := encode(confirmed.entries)
	if err != nil {
		return Bundle{}, err
	}
	expected := Preview{
		Version: Version, Revision: confirmed.preview.Revision,
		Categories: categories(confirmed.entries), TotalEntries: countBucket(len(confirmed.entries)), EncodedSize: sizeBucket(len(encoded)),
	}
	if !reflect.DeepEqual(expected, confirmed.preview) {
		return Bundle{}, ErrState
	}
	return Bundle{
		Version: Version,
		Bytes:   append([]byte(nil), encoded...), TotalEntries: countBucket(len(confirmed.entries)), EncodedSize: sizeBucket(len(encoded)),
	}, nil
}

func CancelPrepared(Prepared) Cancelled   { return Cancelled{valid: true} }
func CancelPreviewed(Previewed) Cancelled { return Cancelled{valid: true} }
func CancelConfirmed(Confirmed) Cancelled { return Cancelled{valid: true} }

func vocabularyIndex(category Category, value Value) (int, int, bool, bool) {
	for ci, item := range vocabulary {
		if item.category != category {
			continue
		}
		for vi, allowed := range item.values {
			if allowed == value {
				return ci, vi, item.count, true
			}
		}
		return 0, 0, item.count, false
	}
	return 0, 0, false, false
}

func validCount(value CountBucket) bool {
	switch value {
	case CountZero, CountOne, CountFew, CountMany:
		return true
	default:
		return false
	}
}

func categories(entries []Entry) []Category {
	result := make([]Category, 0, MaxCategories)
	seen := map[Category]bool{}
	for _, entry := range entries {
		if !seen[entry.Category] {
			seen[entry.Category] = true
			result = append(result, entry.Category)
		}
	}
	return result
}

func countBucket(count int) CountBucket {
	switch {
	case count == 0:
		return CountZero
	case count == 1:
		return CountOne
	case count <= 8:
		return CountFew
	default:
		return CountMany
	}
}

func sizeBucket(size int) SizeBucket {
	if size <= 1024 {
		return SizeSmall
	}
	return SizeMaximum
}

func clonePreview(value Preview) Preview {
	categories := make([]Category, len(value.Categories))
	copy(categories, value.Categories)
	value.Categories = categories
	return value
}

type encodedEntry struct {
	Category Category    `json:"category"`
	Value    Value       `json:"value"`
	Count    CountBucket `json:"count,omitempty"`
}

type document struct {
	Schema           string         `json:"schema"`
	PrivacyStatement string         `json:"privacy_statement"`
	Entries          []encodedEntry `json:"entries"`
}

func encode(entries []Entry) ([]byte, error) {
	if !validCanonicalEntries(entries) {
		return nil, ErrState
	}
	// Every string is selected from the fixed vocabulary and the accepted list
	// is capped at 28, so this conservative bound is checked before encoding.
	if len(entries)*128+256 > MaxEncodedBytes {
		return nil, ErrTooLarge
	}
	items := make([]encodedEntry, len(entries))
	for i, entry := range entries {
		items[i] = encodedEntry{Category: entry.Category, Value: entry.Value, Count: entry.Count}
	}
	encoded, err := json.Marshal(document{Schema: Version, PrivacyStatement: PrivacyStatement, Entries: items})
	if err != nil {
		return nil, ErrTooLarge
	}
	if err := enforceEncodedSize(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func enforceEncodedSize(encoded []byte) error {
	if len(encoded) > MaxEncodedBytes {
		return ErrTooLarge
	}
	return nil
}

func validCanonicalEntries(entries []Entry) bool {
	if len(entries) > MaxEntries {
		return false
	}
	seen := map[[2]string]bool{}
	previousCategory, previousValue := -1, -1
	for _, entry := range entries {
		category, value, needsCount, ok := vocabularyIndex(entry.Category, entry.Value)
		if !ok || needsCount != validCount(entry.Count) {
			return false
		}
		key := [2]string{string(entry.Category), string(entry.Value)}
		if seen[key] || category < previousCategory || category == previousCategory && value <= previousValue {
			return false
		}
		seen[key] = true
		previousCategory, previousValue = category, value
	}
	return true
}
