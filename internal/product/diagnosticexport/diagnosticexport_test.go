// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package diagnosticexport

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func request(entries ...Entry) Request {
	return Request{Version: Version, Revision: 7, UserInitiated: true, Entries: entries}
}

func build(t *testing.T, req Request) (Preview, Bundle) {
	t.Helper()
	prepared, err := Prepare(req)
	if err != nil {
		t.Fatal(err)
	}
	previewed, preview, err := PreviewPrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := Confirm(previewed, Confirmation{Approved: true, Version: Version, Revision: req.Revision, Preview: preview})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(confirmed)
	if err != nil {
		t.Fatal(err)
	}
	return preview, bundle
}

func allEntries() []Entry {
	var result []Entry
	for _, item := range vocabulary {
		for _, value := range item.values {
			entry := Entry{Category: item.category, Value: value}
			if item.count {
				entry.Count = CountMany
			}
			result = append(result, entry)
		}
	}
	return result
}

func TestExactVocabularyMaximumAndCanonicalOutput(t *testing.T) {
	entries := allEntries()
	if len(entries) != MaxEntries {
		t.Fatalf("reachable entries=%d", len(entries))
	}
	shuffled := append([]Entry(nil), entries...)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	previewA, bundleA := build(t, request(entries...))
	previewB, bundleB := build(t, request(shuffled...))
	if !bytes.Equal(bundleA.Bytes, bundleB.Bytes) || !reflect.DeepEqual(previewA, previewB) {
		t.Fatal("equivalent input was not canonical")
	}
	if previewA.TotalEntries != CountMany || len(previewA.Categories) != MaxCategories || bundleA.EncodedSize == "" {
		t.Fatalf("preview=%+v bundle=%+v", previewA, bundleA)
	}
	for _, forbidden := range []string{
		"payload-marker", "secret-marker", "key-marker", "credential-marker", "token-marker", "cookie-marker",
		"raw-frame-marker", "dns-query.example", "hostname.example", "192.0.2.1", "https://example.invalid",
		"endpoint-marker", "profile-id-marker", "relay-id-marker", "client-id-marker", "device-id-marker",
		"session-id-marker", "2026-07-16T00:00:00Z", "telemetry-marker",
	} {
		if strings.Contains(string(bundleA.Bytes), forbidden) {
			t.Fatalf("bundle contains forbidden marker %q", forbidden)
		}
	}
}

func TestEveryCategoryReachableMaximum(t *testing.T) {
	for _, item := range vocabulary {
		entries := make([]Entry, 0, len(item.values))
		for _, value := range item.values {
			entry := Entry{Category: item.category, Value: value}
			if item.count {
				entry.Count = CountMany
			}
			entries = append(entries, entry)
		}
		preview, bundle := build(t, request(entries...))
		if len(preview.Categories) != 1 || preview.Categories[0] != item.category {
			t.Fatalf("category %q preview=%+v", item.category, preview)
		}
		if got := len(entries); got != len(item.values) || len(bundle.Bytes) == 0 {
			t.Fatalf("category %q reachable maximum=%d", item.category, got)
		}
	}
}

func TestNilAndEmptyEntriesAreDeterministic(t *testing.T) {
	previewNil, bundleNil := build(t, request(nil...))
	previewEmpty, bundleEmpty := build(t, request([]Entry{}...))
	if !reflect.DeepEqual(previewNil, previewEmpty) || !bytes.Equal(bundleNil.Bytes, bundleEmpty.Bytes) {
		t.Fatalf("nil and empty differ: nil=%+v empty=%+v", previewNil, previewEmpty)
	}
	if previewNil.TotalEntries != CountZero || string(bundleNil.Bytes) != `{"schema":"offline-diagnostic-export-v1","privacy_statement":"local-user-initiated-redacted-no-telemetry-v1","entries":[]}` {
		t.Fatalf("unexpected empty bundle: preview=%+v bytes=%s", previewNil, bundleNil.Bytes)
	}
}

func TestPrepareRejectsMalformedInputWithoutEcho(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		err  error
	}{
		{"version", Request{Version: "attacker-version", Revision: 1, UserInitiated: true}, ErrVersion},
		{"revision", Request{Version: Version, UserInitiated: true}, ErrInvalidRequest},
		{"initiation", Request{Version: Version, Revision: 1}, ErrNotInitiated},
		{"category", request(Entry{Category: "attacker-category", Value: ValueSupported}), ErrVocabulary},
		{"value", request(Entry{Category: CategoryContractVersions, Value: "attacker-value"}), ErrVocabulary},
		{"count missing", request(Entry{Category: CategoryFailureSummary, Value: ValueMalformedInput}), ErrCount},
		{"count forbidden", request(Entry{Category: CategoryContractVersions, Value: ValueSupported, Count: CountOne}), ErrCount},
		{"duplicate", request(Entry{Category: CategoryContractVersions, Value: ValueSupported}, Entry{Category: CategoryContractVersions, Value: ValueSupported}), ErrDuplicate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Prepare(tc.req)
			if !errors.Is(err, tc.err) || !reflect.DeepEqual(got, Prepared{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if strings.Contains(err.Error(), "attacker") {
				t.Fatal("error echoed input")
			}
		})
	}
}

func TestPreflightAndSemanticBounds(t *testing.T) {
	overCategory := make([]Entry, MaxEntriesPerCategory+1)
	for i := range overCategory {
		overCategory[i] = Entry{Category: CategoryFailureSummary, Value: ValueMalformedInput, Count: CountOne}
	}
	if _, err := Prepare(request(overCategory...)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("per-category preflight err=%v", err)
	}
	overTotal := append(allEntries(), Entry{Category: CategoryFailureSummary, Value: ValueMalformedInput, Count: CountOne})
	if _, err := Prepare(request(overTotal...)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("semantic total err=%v", err)
	}
}

func TestSealedTransitionsBindingCopiesAndCancellation(t *testing.T) {
	input := []Entry{{Category: CategoryFailureSummary, Value: ValuePermissionRequired, Count: CountOne}}
	prepared, err := Prepare(request(input...))
	if err != nil {
		t.Fatal(err)
	}
	input[0].Value = "changed"
	previewed, preview, err := PreviewPrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	preview.Categories[0] = "changed"
	if _, err := Confirm(previewed, Confirmation{Approved: true, Version: Version, Revision: 7, Preview: preview}); !errors.Is(err, ErrConfirmation) {
		t.Fatalf("altered preview err=%v", err)
	}
	_, cleanPreview, _ := PreviewPrepared(prepared)
	confirmed, err := Confirm(previewed, Confirmation{Approved: true, Version: Version, Revision: 7, Preview: cleanPreview})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Confirm(previewed, Confirmation{Approved: true, Version: Version, Revision: 7, Preview: cleanPreview})
	if err != nil {
		t.Fatalf("repeated confirmation failed: %v", err)
	}
	bundleA, err := Build(confirmed)
	if err != nil {
		t.Fatal(err)
	}
	bundleA.Bytes[0] = 'X'
	bundleB, err := Build(confirmed)
	if err != nil || bundleB.Bytes[0] == 'X' {
		t.Fatal("bundle bytes alias retained output")
	}
	bundleRepeated, err := Build(repeated)
	if err != nil || !bytes.Equal(bundleB.Bytes, bundleRepeated.Bytes) {
		t.Fatal("repeated confirmation changed deterministic bundle")
	}
	if _, err := Build(Confirmed{}); !errors.Is(err, ErrState) {
		t.Fatalf("zero confirmed err=%v", err)
	}
	if _, _, err := PreviewPrepared(Prepared{}); !errors.Is(err, ErrState) {
		t.Fatalf("zero prepared err=%v", err)
	}
	forged := Prepared{valid: true, revision: 7, entries: []Entry{{Category: "attacker", Value: "secret"}}}
	if _, _, err := PreviewPrepared(forged); !errors.Is(err, ErrState) {
		t.Fatalf("forged prepared err=%v", err)
	}
	forgedConfirmed := Confirmed{valid: true, entries: forged.entries, preview: cleanPreview}
	if _, err := Build(forgedConfirmed); !errors.Is(err, ErrState) {
		t.Fatalf("forged confirmed err=%v", err)
	}
	_ = CancelPrepared(prepared)
	_ = CancelPreviewed(previewed)
	_ = CancelConfirmed(confirmed)
}

func TestBuckets(t *testing.T) {
	for count, want := range map[int]CountBucket{0: CountZero, 1: CountOne, 2: CountFew, 8: CountFew, 9: CountMany, 28: CountMany} {
		if got := countBucket(count); got != want {
			t.Fatalf("count %d=%q want %q", count, got, want)
		}
	}
	if sizeBucket(1024) != SizeSmall || sizeBucket(1025) != SizeMaximum || sizeBucket(4096) != SizeMaximum {
		t.Fatal("size bucket boundary mismatch")
	}
}

func TestEncodedSizeHardBoundary(t *testing.T) {
	if err := enforceEncodedSize(make([]byte, MaxEncodedBytes)); err != nil {
		t.Fatalf("exact maximum rejected: %v", err)
	}
	if err := enforceEncodedSize(make([]byte, MaxEncodedBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over maximum err=%v", err)
	}
}

func TestAllFailureCountBucketsAndConfirmationFailures(t *testing.T) {
	for _, bucket := range []CountBucket{CountZero, CountOne, CountFew, CountMany} {
		_, bundle := build(t, request(Entry{Category: CategoryFailureSummary, Value: ValueMalformedInput, Count: bucket}))
		if !strings.Contains(string(bundle.Bytes), `"count":"`+string(bucket)+`"`) {
			t.Fatalf("bundle omitted count bucket %q", bucket)
		}
	}
	prepared, err := Prepare(request(Entry{Category: CategoryContractVersions, Value: ValueSupported}))
	if err != nil {
		t.Fatal(err)
	}
	previewed, preview, err := PreviewPrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	for name, confirmation := range map[string]Confirmation{
		"not approved": {Version: Version, Revision: 7, Preview: preview},
		"version":      {Approved: true, Version: "older", Revision: 7, Preview: preview},
		"revision":     {Approved: true, Version: Version, Revision: 8, Preview: preview},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Confirm(previewed, confirmation)
			if !errors.Is(err, ErrConfirmation) || !reflect.DeepEqual(got, Confirmed{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}
