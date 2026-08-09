// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package tun

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenExistingAttachesToTheOwnerCreatedMultiQueueTUN(t *testing.T) {
	flags := openExistingFlags()
	for _, required := range []uint16{unix.IFF_TUN, unix.IFF_NO_PI, unix.IFF_MULTI_QUEUE} {
		if flags&required == 0 {
			t.Fatalf("missing required TUN flag %#x from %#x", required, flags)
		}
	}
}

func TestOpenExistingUsesPollableNonblockingDescriptor(t *testing.T) {
	if flags := openExistingFileFlags(); flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("open flags %#x do not include O_NONBLOCK", flags)
	}
}

func TestLinuxDeviceCloseInterruptsBlockedReadAndIsIdempotent(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	device := &linuxDevice{file: reader, name: OwnedName}
	done := make(chan error, 1)
	go func() {
		_, readErr := device.Read(make([]byte, 1))
		done <- readErr
	}()
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case readErr := <-done:
		if readErr == nil {
			t.Fatal("blocked read completed without a close error")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt blocked read")
	}
}
