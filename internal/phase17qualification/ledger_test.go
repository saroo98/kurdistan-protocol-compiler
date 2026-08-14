// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLedgerPublicationNeverReplacesAnExistingEntry(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(23)
	directory := t.TempDir()
	payload := validAttemptPayload(1, "")
	payload.Mode = "Functional"
	payload.AuthorizationSHA256 = payload.RCLockedSHA256
	raw, err := SignStatement(privateKey, StatementAttempt, payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	path := filepath.Join(directory, fmt.Sprintf("%020d-%s.json", 1, hex.EncodeToString(digest[:])))
	want := []byte("pre-existing-entry")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(directory, raw, publicKey); err == nil {
		t.Fatal("ledger append replaced a pre-existing destination")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("pre-existing ledger entry changed to %q", got)
	}
}

func TestLedgerRejectsSymbolicLinkDirectory(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(24)
	root := t.TempDir()
	target := filepath.Join(root, "actual-ledger")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "declared-ledger")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	payload := validAttemptPayload(1, "")
	payload.Mode = "Functional"
	payload.AuthorizationSHA256 = payload.RCLockedSHA256
	raw, err := SignStatement(privateKey, StatementAttempt, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(link, raw, publicKey); err == nil {
		t.Fatal("ledger append followed a symbolic-link directory")
	}
	if _, err := VerifyLedger(link, payload.CandidateID, publicKey); err == nil {
		t.Fatal("ledger verification followed a symbolic-link directory")
	}
}

func TestLedgerIsAppendOnlyHashChainedAndRejectsDuplicateSoakConsumption(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(5)
	directory := t.TempDir()
	begin := validAttemptPayload(1, "")
	consumed := SoakConsumedPayload{
		Schema: SoakConsumedSchema, CandidateID: begin.CandidateID,
		Sequence: 1, PreviousEntrySHA256: "", SoakReadySHA256: begin.AuthorizationSHA256,
		RCLockedSHA256: begin.RCLockedSHA256,
		AttemptID:      begin.AttemptID, EnvironmentSHA256: begin.EnvironmentSHA256, PreflightSHA256: begin.PreflightSHA256,
		ConsumedAt: "2026-08-14T12:01:00Z",
	}
	consumedRaw, err := SignStatement(privateKey, StatementSoakConsumed, consumed)
	if err != nil {
		t.Fatal(err)
	}
	first, err := AppendLedger(directory, consumedRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	begin.Sequence = 2
	begin.PreviousEntrySHA256 = first
	begin.RecordedAt = "2026-08-14T12:01:30Z"
	beginRaw, err := SignStatement(privateKey, StatementAttempt, begin)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AppendLedger(directory, beginRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	state, err := VerifyLedger(directory, begin.CandidateID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if state.Entries != 2 || state.HeadSHA256 != second || state.ConsumedSoakAuthorizations != 1 {
		t.Fatalf("ledger state=%+v", state)
	}

	duplicate := consumed
	duplicate.Sequence = 3
	duplicate.PreviousEntrySHA256 = second
	duplicateRaw, err := SignStatement(privateKey, StatementSoakConsumed, duplicate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(directory, duplicateRaw, publicKey); err == nil {
		t.Fatal("duplicate final-soak authorization consumption accepted")
	}
}

func TestLedgerRequiresSoakConsumptionBeforeMatchingAttemptBegin(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(9)
	begin := validAttemptPayload(1, "")
	raw, err := SignStatement(privateKey, StatementAttempt, begin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(t.TempDir(), raw, publicKey); err == nil {
		t.Fatal("Soak12h attempt began without consuming its authorization")
	}

	for name, mutate := range map[string]func(*AttemptPayload){
		"authorization": func(value *AttemptPayload) {
			value.RCLockedSHA256 = strings.Repeat("b", 64)
			value.AuthorizationSHA256 = strings.Repeat("b", 64)
		},
		"environment": func(value *AttemptPayload) { value.EnvironmentSHA256 = strings.Repeat("c", 64) },
		"preflight":   func(value *AttemptPayload) { value.PreflightSHA256 = strings.Repeat("d", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			consumed := SoakConsumedPayload{
				Schema: SoakConsumedSchema, CandidateID: begin.CandidateID,
				Sequence: 1, PreviousEntrySHA256: "", SoakReadySHA256: begin.AuthorizationSHA256,
				RCLockedSHA256: begin.RCLockedSHA256,
				AttemptID:      begin.AttemptID, EnvironmentSHA256: begin.EnvironmentSHA256, PreflightSHA256: begin.PreflightSHA256,
				ConsumedAt: "2026-08-14T12:01:00Z",
			}
			consumedRaw, err := SignStatement(privateKey, StatementSoakConsumed, consumed)
			if err != nil {
				t.Fatal(err)
			}
			head, err := AppendLedger(directory, consumedRaw, publicKey)
			if err != nil {
				t.Fatal(err)
			}
			candidate := begin
			candidate.Sequence = 2
			candidate.PreviousEntrySHA256 = head
			candidate.RecordedAt = "2026-08-14T12:01:30Z"
			mutate(&candidate)
			candidateRaw, err := SignStatement(privateKey, StatementAttempt, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AppendLedger(directory, candidateRaw, publicKey); err == nil {
				t.Fatal("Soak12h attempt accepted with mismatched consumption")
			}
		})
	}
}

func TestLedgerTerminalMustMatchBeginIdentityAndFollowItInTime(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(10)
	for name, mutate := range map[string]func(*AttemptPayload){
		"mode": func(value *AttemptPayload) { value.Mode = "Functional" },
		"authorization": func(value *AttemptPayload) {
			value.RCLockedSHA256 = strings.Repeat("b", 64)
			value.AuthorizationSHA256 = strings.Repeat("b", 64)
		},
		"environment": func(value *AttemptPayload) { value.EnvironmentSHA256 = strings.Repeat("c", 64) },
		"preflight":   func(value *AttemptPayload) { value.PreflightSHA256 = strings.Repeat("e", 64) },
		"time":        func(value *AttemptPayload) { value.RecordedAt = "2026-08-14T11:59:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			begin := validAttemptPayload(1, "")
			begin.Mode = "Stress"
			begin.AuthorizationSHA256 = begin.RCLockedSHA256
			beginRaw, err := SignStatement(privateKey, StatementAttempt, begin)
			if err != nil {
				t.Fatal(err)
			}
			head, err := AppendLedger(directory, beginRaw, publicKey)
			if err != nil {
				t.Fatal(err)
			}
			terminal := begin
			terminal.Sequence = 2
			terminal.PreviousEntrySHA256 = head
			terminal.State = AttemptTerminal
			terminal.Outcome = "PASS"
			terminal.ResultSHA256 = strings.Repeat("d", 64)
			terminal.RecordedAt = "2026-08-14T12:02:00Z"
			mutate(&terminal)
			terminalRaw, err := SignStatement(privateKey, StatementAttempt, terminal)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AppendLedger(directory, terminalRaw, publicKey); err == nil {
				t.Fatal("mismatched terminal attempt accepted")
			}
		})
	}
}

func TestLedgerRejectsGapReorderAndTruncation(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(6)
	directory := t.TempDir()
	begin := validAttemptPayload(1, "")
	begin.Mode = "Stress"
	begin.AuthorizationSHA256 = begin.RCLockedSHA256
	raw, err := SignStatement(privateKey, StatementAttempt, begin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(directory, raw, publicKey); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ledger files=%d err=%v", len(entries), err)
	}
	path := filepath.Join(directory, entries[0].Name())
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents[:len(contents)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLedger(directory, begin.CandidateID, publicKey); err == nil {
		t.Fatal("truncated ledger accepted")
	}

	gapDirectory := t.TempDir()
	gap := validAttemptPayload(2, strings.Repeat("f", 64))
	gap.Mode = "Stress"
	gap.AuthorizationSHA256 = gap.RCLockedSHA256
	gapRaw, err := SignStatement(privateKey, StatementAttempt, gap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(gapDirectory, gapRaw, publicKey); err == nil {
		t.Fatal("ledger sequence gap accepted")
	}
}

func TestVerifyLedgerAttemptsExposesCompletedAndUnresolvedAttemptsInSequence(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(12)
	directory := t.TempDir()
	first := validAttemptPayload(1, "")
	first.Mode = "Functional"
	first.AuthorizationSHA256 = first.RCLockedSHA256
	firstRaw, err := SignStatement(privateKey, StatementAttempt, first)
	if err != nil {
		t.Fatal(err)
	}
	head, err := AppendLedger(directory, firstRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	terminal := first
	terminal.Sequence = 2
	terminal.PreviousEntrySHA256 = head
	terminal.State = AttemptTerminal
	terminal.Outcome = "PASS"
	terminal.ResultSHA256 = strings.Repeat("d", 64)
	terminal.RecordedAt = "2026-08-14T12:02:00Z"
	terminalRaw, err := SignStatement(privateKey, StatementAttempt, terminal)
	if err != nil {
		t.Fatal(err)
	}
	head, err = AppendLedger(directory, terminalRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Sequence = 3
	second.PreviousEntrySHA256 = head
	second.AttemptID = strings.Repeat("e", 32)
	second.Mode = "Stress"
	second.RecordedAt = "2026-08-14T12:03:00Z"
	secondRaw, err := SignStatement(privateKey, StatementAttempt, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(directory, secondRaw, publicKey); err != nil {
		t.Fatal(err)
	}
	_, attempts, err := VerifyLedgerAttempts(directory, first.CandidateID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || !attempts[0].Completed || attempts[0].Terminal.ResultSHA256 != terminal.ResultSHA256 || attempts[1].Completed {
		t.Fatalf("attempts=%+v", attempts)
	}
}

func TestConcurrentLedgerAppendsCommitExactlyOneNextEntry(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(13)
	directory := t.TempDir()
	const writers = 32
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		attempt := validAttemptPayload(1, "")
		attempt.Mode = "Stress"
		attempt.AuthorizationSHA256 = attempt.RCLockedSHA256
		attempt.AttemptID = strings.Repeat(string("0123456789abcdef"[index%16]), 32)
		raw, err := SignStatement(privateKey, StatementAttempt, attempt)
		if err != nil {
			t.Fatal(err)
		}
		group.Add(1)
		go func(raw []byte) {
			defer group.Done()
			<-start
			_, err := AppendLedger(directory, raw, publicKey)
			results <- err
		}(raw)
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent appends=%d, want exactly one", succeeded)
	}
	state, err := VerifyLedger(directory, strings.Repeat("6", 64), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if state.Entries != 1 {
		t.Fatalf("ledger entries=%d, want 1", state.Entries)
	}
}

func TestConcurrentSoakAuthorizationConsumptionCommitsExactlyOnce(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(18)
	directory := t.TempDir()
	begin := validAttemptPayload(1, "")
	const writers = 32
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		consumed := SoakConsumedPayload{
			Schema: SoakConsumedSchema, CandidateID: begin.CandidateID,
			Sequence: 1, PreviousEntrySHA256: "", SoakReadySHA256: begin.AuthorizationSHA256,
			RCLockedSHA256: begin.RCLockedSHA256,
			AttemptID:      strings.Repeat(string("0123456789abcdef"[index%16]), 32), EnvironmentSHA256: begin.EnvironmentSHA256,
			PreflightSHA256: begin.PreflightSHA256,
			ConsumedAt:      "2026-08-14T12:01:00Z",
		}
		raw, err := SignStatement(privateKey, StatementSoakConsumed, consumed)
		if err != nil {
			t.Fatal(err)
		}
		group.Add(1)
		go func(raw []byte) {
			defer group.Done()
			<-start
			_, err := AppendLedger(directory, raw, publicKey)
			results <- err
		}(raw)
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent soak consumptions=%d, want exactly one", succeeded)
	}
	state, err := VerifyLedger(directory, begin.CandidateID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if state.Entries != 1 || state.ConsumedSoakAuthorizations != 1 {
		t.Fatalf("ledger state=%+v, want one committed consumption", state)
	}
}

func TestConcurrentTerminalPublicationCommitsExactlyOnce(t *testing.T) {
	privateKey, publicKey := receiptKeyPair(19)
	directory := t.TempDir()
	begin := validAttemptPayload(1, "")
	begin.Mode = "Stress"
	begin.AuthorizationSHA256 = begin.RCLockedSHA256
	beginRaw, err := SignStatement(privateKey, StatementAttempt, begin)
	if err != nil {
		t.Fatal(err)
	}
	head, err := AppendLedger(directory, beginRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	const writers = 32
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		terminal := begin
		terminal.Sequence = 2
		terminal.PreviousEntrySHA256 = head
		terminal.State = AttemptTerminal
		terminal.Outcome = "PASS"
		terminal.ResultSHA256 = strings.Repeat(string("0123456789abcdef"[index%16]), 64)
		terminal.RecordedAt = "2026-08-14T12:02:00Z"
		raw, err := SignStatement(privateKey, StatementAttempt, terminal)
		if err != nil {
			t.Fatal(err)
		}
		group.Add(1)
		go func(raw []byte) {
			defer group.Done()
			<-start
			_, err := AppendLedger(directory, raw, publicKey)
			results <- err
		}(raw)
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent terminal publications=%d, want exactly one", succeeded)
	}
	state, attempts, err := VerifyLedgerAttempts(directory, begin.CandidateID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if state.Entries != 2 || len(attempts) != 1 || !attempts[0].Completed {
		t.Fatalf("state=%+v attempts=%+v, want one completed attempt", state, attempts)
	}
}

func TestStaleLedgerLockFileDoesNotBlockCrashRecovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ledger")
	if err := os.WriteFile(directory+".append.lock", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey := receiptKeyPair(17)
	payload := validAttemptPayload(1, "")
	payload.Mode = "Functional"
	payload.AuthorizationSHA256 = payload.RCLockedSHA256
	raw, err := SignStatement(privateKey, StatementAttempt, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLedger(directory, raw, publicKey); err != nil {
		t.Fatalf("stale crash lock blocked recovery: %v", err)
	}
}

func validAttemptPayload(sequence uint64, previous string) AttemptPayload {
	return AttemptPayload{
		Schema: AttemptSchema, CandidateID: strings.Repeat("6", 64),
		Sequence: sequence, PreviousEntrySHA256: previous, State: AttemptBegin,
		AttemptID: strings.Repeat("8", 32), Mode: "Soak12h",
		RCLockedSHA256: strings.Repeat("7", 64), AuthorizationSHA256: strings.Repeat("9", 64), EnvironmentSHA256: strings.Repeat("a", 64),
		PreflightSHA256: strings.Repeat("b", 64),
		Outcome:         "", ResultSHA256: "", RecordedAt: "2026-08-14T12:00:30Z",
	}
}
