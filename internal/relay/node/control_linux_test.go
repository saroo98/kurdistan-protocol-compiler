// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package node

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxControlListenerUsesOwnerOnlySocketAndPeerCredentials(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, authorize, err := OpenControlListenerV1(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode=%v", info.Mode().Perm())
	}

	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer connection.Close()
		accepted <- authorize(connection)
	}()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("owner peer rejected: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer authorization timed out")
	}
}

func TestLinuxControlListenerRejectsLooseParentPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if listener, _, err := OpenControlListenerV1(filepath.Join(directory, "control.sock")); listener != nil || err == nil {
		t.Fatalf("loose parent accepted: listener=%v err=%v", listener, err)
	}
}
