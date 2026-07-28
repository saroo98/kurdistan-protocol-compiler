// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "testing"

func TestCompareSymbolsIsOrderIndependentAndExact(t *testing.T) {
	if err := compareSymbols([]string{"b", "a"}, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := compareSymbols([]string{"a", "extra"}, []string{"a"}); err == nil {
		t.Fatal("unexpected symbol was accepted")
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny([][]byte{[]byte("bounded marker")}, "marker") {
		t.Fatal("marker not found")
	}
	if containsAny([][]byte{[]byte("bounded marker")}, "secret") {
		t.Fatal("absent marker reported")
	}
}

func TestForbiddenBoundaryMutationTurnsGateRed(t *testing.T) {
	if err := rejectMarkers([][]byte{[]byte("safe")}, forbiddenManifestValues); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append(append([]string(nil), forbiddenManifestValues...), forbiddenDEXValues...) {
		if err := rejectMarkers([][]byte{[]byte("prefix " + forbidden + " suffix")}, []string{forbidden}); err == nil {
			t.Fatalf("forbidden marker %q was accepted", forbidden)
		}
	}
}

func TestVersionControlInfoEntryIsForbidden(t *testing.T) {
	contents := apkContents{
		entries: map[string]struct{}{
			versionControlInfoEntry: {},
		},
	}
	if err := rejectCommitSensitiveEntries(contents); err == nil {
		t.Fatal("commit-sensitive VCS metadata entry was accepted")
	}
	if err := rejectCommitSensitiveEntries(apkContents{entries: map[string]struct{}{}}); err != nil {
		t.Fatalf("clean APK entry set was rejected: %v", err)
	}
}
