// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package tun

import (
	"testing"

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
