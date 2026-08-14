// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maximumLedgerEntryBytes = 1 << 20

type LedgerState struct {
	CandidateID                string
	Entries                    uint64
	HeadSHA256                 string
	ConsumedSoakAuthorizations uint64
}

type LedgerAttemptRecord struct {
	Begin     AttemptPayload
	Terminal  AttemptPayload
	Completed bool
}

type ledgerVerification struct {
	state             LedgerState
	consumedSoakReady map[string]struct{}
	consumedByAttempt map[string]SoakConsumedPayload
	attemptBegun      map[string]AttemptPayload
	attemptTerminal   map[string]AttemptPayload
}

type ledgerMetadata struct {
	candidateID string
	sequence    uint64
	previous    string
	kind        string
	attemptID   string
	soakReady   string
}

func AppendLedger(directory string, raw, trustedPublicKey []byte) (digestResult string, resultErr error) {
	verified, err := VerifyStatement(raw, trustedPublicKey)
	if err != nil {
		return "", err
	}
	metadata, err := metadataForStatement(verified)
	if err != nil {
		return "", err
	}
	directory, _, err = prepareLedgerDirectory(directory, true)
	if err != nil {
		return "", err
	}
	release, err := acquireLedgerAppendLock(directory)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := release(); err != nil {
			digestResult = ""
			resultErr = errors.Join(resultErr, err)
		}
	}()
	current, err := verifyLedger(directory, metadata.candidateID, trustedPublicKey)
	if err != nil {
		return "", err
	}
	if metadata.sequence != current.state.Entries+1 || metadata.previous != current.state.HeadSHA256 {
		return "", errors.New("qualification ledger sequence or predecessor rejected")
	}
	if metadata.kind == StatementSoakConsumed {
		if _, duplicate := current.consumedSoakReady[metadata.soakReady]; duplicate {
			return "", errors.New("qualification soak authorization already consumed")
		}
		if _, duplicate := current.consumedByAttempt[metadata.attemptID]; duplicate {
			return "", errors.New("qualification soak attempt already has a consumed authorization")
		}
		if _, began := current.attemptBegun[metadata.attemptID]; began {
			return "", errors.New("qualification soak authorization was consumed after attempt begin")
		}
	}
	if metadata.kind == StatementAttempt {
		attempt := verified.Payload.(AttemptPayload)
		if attempt.State == AttemptBegin {
			if _, duplicate := current.attemptBegun[attempt.AttemptID]; duplicate {
				return "", errors.New("qualification attempt already began")
			}
			if err := validateAttemptBeginAgainstConsumption(attempt, current.consumedByAttempt); err != nil {
				return "", err
			}
		} else {
			begin, found := current.attemptBegun[attempt.AttemptID]
			if !found {
				return "", errors.New("qualification terminal attempt has no begin entry")
			}
			if _, duplicate := current.attemptTerminal[attempt.AttemptID]; duplicate {
				return "", errors.New("qualification attempt already terminated")
			}
			if err := validateTerminalAgainstBegin(attempt, begin); err != nil {
				return "", err
			}
		}
	}
	digest := sha256.Sum256(raw)
	digestHex := hex.EncodeToString(digest[:])
	name := fmt.Sprintf("%020d-%s.json", metadata.sequence, digestHex)
	path := filepath.Join(directory, name)
	if err := writeExclusiveFileWithOps(path, filepath.Dir(directory), raw, defaultAtomicFileOps()); err != nil {
		return "", err
	}
	return digestHex, nil
}

func VerifyLedger(directory, candidateID string, trustedPublicKey []byte) (LedgerState, error) {
	verified, err := verifyLedger(directory, candidateID, trustedPublicKey)
	if err != nil {
		return LedgerState{}, err
	}
	return verified.state, nil
}

func VerifyLedgerAttempts(directory, candidateID string, trustedPublicKey []byte) (LedgerState, []LedgerAttemptRecord, error) {
	verified, err := verifyLedger(directory, candidateID, trustedPublicKey)
	if err != nil {
		return LedgerState{}, nil, err
	}
	attempts := make([]LedgerAttemptRecord, 0, len(verified.attemptBegun))
	for _, begin := range verified.attemptBegun {
		terminal, completed := verified.attemptTerminal[begin.AttemptID]
		attempts = append(attempts, LedgerAttemptRecord{Begin: begin, Terminal: terminal, Completed: completed})
	}
	sort.Slice(attempts, func(left, right int) bool { return attempts[left].Begin.Sequence < attempts[right].Begin.Sequence })
	return verified.state, attempts, nil
}

func verifyLedger(directory, candidateID string, trustedPublicKey []byte) (ledgerVerification, error) {
	if !hex64Pattern.MatchString(candidateID) {
		return ledgerVerification{}, errors.New("qualification ledger candidate rejected")
	}
	result := ledgerVerification{
		state:             LedgerState{CandidateID: candidateID},
		consumedSoakReady: map[string]struct{}{},
		consumedByAttempt: map[string]SoakConsumedPayload{},
		attemptBegun:      map[string]AttemptPayload{},
		attemptTerminal:   map[string]AttemptPayload{},
	}
	directory, exists, err := prepareLedgerDirectory(directory, false)
	if err != nil {
		return ledgerVerification{}, err
	}
	if !exists {
		return result, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return ledgerVerification{}, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for index, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			return ledgerVerification{}, errors.New("qualification ledger contains an unexpected entry")
		}
		path := filepath.Join(directory, entry.Name())
		raw, err := readLedgerEntry(path, entry)
		if err != nil {
			return ledgerVerification{}, err
		}
		verified, err := VerifyStatement(raw, trustedPublicKey)
		if err != nil {
			return ledgerVerification{}, err
		}
		metadata, err := metadataForStatement(verified)
		if err != nil {
			return ledgerVerification{}, err
		}
		sequence := uint64(index + 1)
		if metadata.candidateID != candidateID || metadata.sequence != sequence || metadata.previous != result.state.HeadSHA256 {
			return ledgerVerification{}, errors.New("qualification ledger chain rejected")
		}
		digest := sha256.Sum256(raw)
		digestHex := hex.EncodeToString(digest[:])
		wantName := fmt.Sprintf("%020d-%s.json", sequence, digestHex)
		if entry.Name() != wantName {
			return ledgerVerification{}, errors.New("qualification ledger filename binding rejected")
		}
		switch metadata.kind {
		case StatementSoakConsumed:
			consumed := verified.Payload.(SoakConsumedPayload)
			if _, duplicate := result.consumedSoakReady[metadata.soakReady]; duplicate {
				return ledgerVerification{}, errors.New("qualification ledger repeats soak authorization")
			}
			if _, duplicate := result.consumedByAttempt[metadata.attemptID]; duplicate {
				return ledgerVerification{}, errors.New("qualification ledger repeats soak attempt consumption")
			}
			if _, began := result.attemptBegun[metadata.attemptID]; began {
				return ledgerVerification{}, errors.New("qualification ledger consumed soak authorization after begin")
			}
			result.consumedSoakReady[metadata.soakReady] = struct{}{}
			result.consumedByAttempt[metadata.attemptID] = consumed
			result.state.ConsumedSoakAuthorizations++
		case StatementAttempt:
			attempt := verified.Payload.(AttemptPayload)
			if attempt.State == AttemptBegin {
				if _, duplicate := result.attemptBegun[attempt.AttemptID]; duplicate {
					return ledgerVerification{}, errors.New("qualification ledger repeats attempt begin")
				}
				if err := validateAttemptBeginAgainstConsumption(attempt, result.consumedByAttempt); err != nil {
					return ledgerVerification{}, err
				}
				result.attemptBegun[attempt.AttemptID] = attempt
			} else {
				begin, found := result.attemptBegun[attempt.AttemptID]
				if !found {
					return ledgerVerification{}, errors.New("qualification ledger terminal precedes begin")
				}
				if _, duplicate := result.attemptTerminal[attempt.AttemptID]; duplicate {
					return ledgerVerification{}, errors.New("qualification ledger repeats attempt terminal")
				}
				if err := validateTerminalAgainstBegin(attempt, begin); err != nil {
					return ledgerVerification{}, err
				}
				result.attemptTerminal[attempt.AttemptID] = attempt
			}
		}
		result.state.Entries = sequence
		result.state.HeadSHA256 = digestHex
	}
	return result, nil
}

func prepareLedgerDirectory(directory string, create bool) (string, bool, error) {
	if directory == "" {
		return "", false, errors.New("qualification ledger directory rejected")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", false, errors.New("qualification ledger directory rejected")
	}
	if create {
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return "", false, err
		}
	}
	before, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) && !create {
		return absolute, false, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return "", false, errors.New("qualification ledger directory rejected")
	}
	opened, err := os.Open(absolute)
	if err != nil {
		return "", false, errors.New("qualification ledger directory unavailable")
	}
	after, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || !after.IsDir() || !os.SameFile(before, after) {
		return "", false, errors.New("qualification ledger directory changed while opening")
	}
	return absolute, true, nil
}

func readLedgerEntry(path string, entry os.DirEntry) ([]byte, error) {
	before, err := entry.Info()
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Size() < 1 || before.Size() > maximumLedgerEntryBytes {
		return nil, errors.New("qualification ledger entry is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("qualification ledger entry changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximumLedgerEntryBytes+1))
	after, finalStatErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || finalStatErr != nil || closeErr != nil || len(raw) != int(opened.Size()) ||
		!os.SameFile(opened, after) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
		return nil, errors.New("qualification ledger entry changed while reading")
	}
	return raw, nil
}

func validateAttemptBeginAgainstConsumption(attempt AttemptPayload, consumed map[string]SoakConsumedPayload) error {
	value, found := consumed[attempt.AttemptID]
	if attempt.Mode == "Soak12h" {
		if !found || value.SoakReadySHA256 != attempt.AuthorizationSHA256 || value.RCLockedSHA256 != attempt.RCLockedSHA256 ||
			value.EnvironmentSHA256 != attempt.EnvironmentSHA256 || value.PreflightSHA256 != attempt.PreflightSHA256 {
			return errors.New("qualification final soak begin lacks matching prior authorization consumption")
		}
		return nil
	}
	if found {
		return errors.New("qualification soak authorization was consumed for a non-soak attempt")
	}
	return nil
}

func validateTerminalAgainstBegin(terminal, begin AttemptPayload) error {
	if terminal.CandidateID != begin.CandidateID || terminal.Mode != begin.Mode ||
		terminal.RCLockedSHA256 != begin.RCLockedSHA256 || terminal.AuthorizationSHA256 != begin.AuthorizationSHA256 ||
		terminal.EnvironmentSHA256 != begin.EnvironmentSHA256 || terminal.PreflightSHA256 != begin.PreflightSHA256 {
		return errors.New("qualification terminal attempt identity differs from begin")
	}
	beginTime, beginErr := time.Parse(time.RFC3339, begin.RecordedAt)
	terminalTime, terminalErr := time.Parse(time.RFC3339, terminal.RecordedAt)
	if beginErr != nil || terminalErr != nil || !terminalTime.After(beginTime) {
		return errors.New("qualification terminal attempt time does not follow begin")
	}
	return nil
}

func metadataForStatement(value VerifiedStatement) (ledgerMetadata, error) {
	switch payload := value.Payload.(type) {
	case AttemptPayload:
		return ledgerMetadata{
			candidateID: payload.CandidateID, sequence: payload.Sequence,
			previous: payload.PreviousEntrySHA256, kind: StatementAttempt,
			attemptID: payload.AttemptID,
		}, nil
	case SoakConsumedPayload:
		return ledgerMetadata{
			candidateID: payload.CandidateID, sequence: payload.Sequence,
			previous: payload.PreviousEntrySHA256, kind: StatementSoakConsumed,
			attemptID: payload.AttemptID, soakReady: payload.SoakReadySHA256,
		}, nil
	default:
		return ledgerMetadata{}, errors.New("qualification statement is not a ledger entry")
	}
}
