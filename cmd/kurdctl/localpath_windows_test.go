// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/winprivate"
)

func TestWindowsPrivateOutputIsProtectedAtCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-output")
	if err := createWindowsPrivateDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := winprivate.Verify(root, true); err != nil {
		t.Fatalf("created directory was not born private: %v", err)
	}
	file := filepath.Join(root, "artifact")
	if err := createWindowsPrivateFile(file, []byte("artifact")); err != nil {
		t.Fatal(err)
	}
	if err := winprivate.Verify(file, false); err != nil {
		t.Fatalf("created file was not born private: %v", err)
	}
	if value, err := os.ReadFile(file); err != nil || string(value) != "artifact" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestWindowsPrivateErrorMappingRetainsNestedCausesAndJoinOrder(t *testing.T) {
	injected := errors.New("injected")
	closed := errors.New("closed")
	err := mapWindowsPrivateError(errors.Join(
		&winprivate.OpError{Op: "publish", Err: &winprivate.OpError{Op: "verify", Err: injected}},
		&winprivate.OpError{Op: "close", Err: closed},
	))
	if !errors.Is(err, injected) || !errors.Is(err, closed) || errors.Is(err, errUnsupportedFilesystem) {
		t.Fatalf("lost native categories: %v", err)
	}
	if err.Error() != "kurdctl private path: publish: kurdctl private path: verify: injected\nkurdctl private path: close: closed" {
		t.Fatalf("changed join order: %v", err)
	}
	nilCause := mapWindowsPrivateError(&winprivate.OpError{Op: "invalid handle"})
	if !errors.Is(nilCause, errUnsupportedFilesystem) || nilCause.Error() != "unsupported filesystem: invalid handle" {
		t.Fatalf("nil cause classification: %v", nilCause)
	}
	for _, test := range []struct{ input, want error }{
		{winprivate.ErrUnsafe, errUnsupportedFilesystem},
		{winprivate.ErrExists, errOutputExists},
		{winprivate.ErrIncomplete, errOutputIncomplete},
	} {
		if err := mapWindowsPrivateError(test.input); !errors.Is(err, test.want) {
			t.Fatalf("mapped=%v want=%v", err, test.want)
		}
	}
	if err := mapWindowsPrivateError(nil); err != nil {
		t.Fatalf("nil mapped to %v", err)
	}
}

func TestWindowsDirectoryCompletionOnlyRemovesItsOwnFailedCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected")
	if err := completeWindowsPrivateDirectory(path, true, injected); !errors.Is(err, injected) {
		t.Fatalf("lost creation failure: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created directory retained: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := completeWindowsPrivateDirectory(path, false, winprivate.ErrExists); !errors.Is(err, errOutputExists) {
		t.Fatalf("collision classification: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("existing collision removed", err)
	}
	child := filepath.Join(path, "child")
	if err := os.WriteFile(child, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := completeWindowsPrivateDirectory(path, true, injected); !errors.Is(err, injected) {
		t.Fatalf("cleanup failure replaced original error: %v", err)
	}
	if value, err := os.ReadFile(child); err != nil || string(value) != "previous" {
		t.Fatalf("nonrecursive cleanup changed child: %v", err)
	}
	if err := completeWindowsPrivateDirectory(path, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(child); err != nil {
		t.Fatal("successful creation removed", err)
	}
}

func TestWindowsPrivateCreationCollisionsPreserveContent(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := createWindowsPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "artifact")
	if err := createWindowsPrivateFile(path, []byte("previous")); err != nil {
		t.Fatal(err)
	}
	if err := createWindowsPrivateDirectory(directory); !errors.Is(err, errOutputExists) {
		t.Fatalf("directory collision: %v", err)
	}
	if err := createWindowsPrivateFile(path, []byte("replacement")); !errors.Is(err, errOutputExists) {
		t.Fatalf("file collision: %v", err)
	}
	if value, err := os.ReadFile(path); err != nil || string(value) != "previous" {
		t.Fatalf("collision changed artifact: %v", err)
	}
	if _, _, err := openLocalParent("relative"); !errors.Is(err, errUnsupportedFilesystem) {
		t.Fatalf("root rejection: %v", err)
	}
}
