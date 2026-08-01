// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const maxJournalRecordBytes = 16 << 20

type Store interface {
	Snapshot() State
	Update(expectedRevision uint64, mutate func(*State) error) (State, error)
}

type JournalStore struct {
	mu       sync.Mutex
	path     string
	identity os.FileInfo
	state    State
}

type journalRecord struct {
	State State  `json:"state"`
	Hash  string `json:"hash"`
}

func OpenJournalStore(path string) (*JournalStore, error) {
	if path == "" {
		return nil, ErrJournal
	}
	file, identity, err := openOrCreateJournal(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	store := &JournalStore{path: path, identity: identity, state: NewState()}
	if err := store.load(file); err != nil {
		return nil, err
	}
	return store, nil
}

func CreateJournalStore(path string) (*JournalStore, error) {
	if path == "" {
		return nil, ErrJournal
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, ErrJournal
		}
		return nil, fmt.Errorf("%w: journal already exists", ErrConflict)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if info, statErr := os.Lstat(path); statErr == nil &&
				(info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
				return nil, ErrJournal
			}
			return nil, fmt.Errorf("%w: journal already exists", ErrConflict)
		}
		return nil, err
	}
	identity, err := file.Stat()
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !identity.Mode().IsRegular() {
		return nil, ErrJournal
	}
	return &JournalStore{path: path, identity: identity, state: NewState()}, nil
}

func NewMemoryStore() *JournalStore {
	return &JournalStore{state: NewState()}
}

func (store *JournalStore) Snapshot() State {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.clone()
}

func (store *JournalStore) Update(expectedRevision uint64, mutate func(*State) error) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if expectedRevision != store.state.Revision {
		return State{}, ErrConflict
	}
	next := store.state.clone()
	if err := mutate(&next); err != nil {
		return State{}, err
	}
	next.Revision++
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	if store.path != "" {
		if err := appendJournalRecord(store.path, store.identity, next); err != nil {
			return State{}, err
		}
	}
	store.state = next
	return next.clone(), nil
}

func (store *JournalStore) load(file *os.File) error {
	state := NewState()
	reader := newJournalReader(file)
	var completeBytes int64
	for {
		line, readErr := readJournalRecord(reader)
		if errors.Is(readErr, io.EOF) && len(line) > 0 {
			if err := file.Truncate(completeBytes); err != nil {
				return err
			}
			if err := file.Sync(); err != nil {
				return err
			}
			break
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(line) == 0 {
			break
		}
		var record journalRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return ErrJournal
		}
		if err := verifyJournalRecord(record); err != nil {
			return err
		}
		if record.State.Revision != state.Revision+1 {
			return ErrJournal
		}
		state = record.State
		completeBytes += int64(len(line))
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	store.state = state
	return nil
}

func appendJournalRecord(path string, identity os.FileInfo, state State) error {
	record := journalRecord{State: state}
	hash, err := journalHash(state)
	if err != nil {
		return err
	}
	record.Hash = hash
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(raw)+1 > maxJournalRecordBytes {
		return ErrJournal
	}
	file, err := openVerifiedJournal(path, identity, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func journalHash(state State) (string, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func verifyJournalRecord(record journalRecord) error {
	if err := record.State.Validate(); err != nil {
		return ErrJournal
	}
	expected, err := journalHash(record.State)
	if err != nil || expected != record.Hash {
		return ErrJournal
	}
	return nil
}

func CopyCompleteJournal(destination io.Writer, source io.Reader) error {
	reader := newJournalReader(source)
	var previousRevision uint64
	for {
		line, readErr := readJournalRecord(reader)
		if errors.Is(readErr, io.EOF) && len(line) > 0 {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(line) == 0 {
			return nil
		}
		var record journalRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return ErrJournal
		}
		if err := verifyJournalRecord(record); err != nil {
			return err
		}
		if record.State.Revision != previousRevision+1 {
			return ErrJournal
		}
		if _, err := destination.Write(line); err != nil {
			return err
		}
		previousRevision = record.State.Revision
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
	return nil
}

func openOrCreateJournal(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		store, createErr := CreateJournalStore(path)
		if createErr != nil {
			return nil, nil, createErr
		}
		file, openErr := openVerifiedJournal(path, store.identity, os.O_RDWR)
		if openErr != nil {
			return nil, nil, openErr
		}
		return file, store.identity, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, ErrJournal
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, nil, ErrJournal
	}
	return file, openedInfo, nil
}

func openVerifiedJournal(path string, identity os.FileInfo, flags int) (*os.File, error) {
	if identity == nil {
		return nil, ErrJournal
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!os.SameFile(identity, info) {
		return nil, ErrJournal
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(identity, openedInfo) ||
		!os.SameFile(info, openedInfo) {
		file.Close()
		return nil, ErrJournal
	}
	return file, nil
}

func newJournalReader(source io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(source, maxJournalRecordBytes+1)
}

func readJournalRecord(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxJournalRecordBytes {
		return nil, ErrJournal
	}
	return line, err
}
