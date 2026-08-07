// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package tun

import (
	"errors"
	"runtime"
	"testing"
)

func TestOwnedTUNNameIsExactAndUnsupportedPlatformsFailClosed(t *testing.T) {
	for _, name := range []string{"", "tun0", "kurd1", "kurd0\x00other", "../kurd0"} {
		if err := ValidateName(name); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("name %q err=%v", name, err)
		}
		if device, err := OpenExisting(name); device != nil || !errors.Is(err, ErrInvalidName) {
			t.Fatalf("invalid name opened: device=%v err=%v", device, err)
		}
	}
	if runtime.GOOS != "linux" {
		if device, err := OpenExisting(OwnedName); device != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unsupported platform opened TUN: device=%v err=%v", device, err)
		}
	}
}

func TestOwnedTUNRejectsPrivilegeAndMissingExistingDevice(t *testing.T) {
	if err := validateUnprivileged(0, false, nil); !errors.Is(err, ErrPrivileged) {
		t.Fatalf("root process err=%v", err)
	}
	if err := validateUnprivileged(1000, true, nil); !errors.Is(err, ErrPrivileged) {
		t.Fatalf("CAP_NET_ADMIN process err=%v", err)
	}
	capabilityErr := errors.New("capability query failed")
	if err := validateUnprivileged(1000, false, capabilityErr); !errors.Is(err, ErrOpen) {
		t.Fatalf("capability query err=%v", err)
	}
	if err := validateUnprivileged(1000, false, nil); err != nil {
		t.Fatalf("unprivileged process err=%v", err)
	}

	missing := errors.New("missing")
	for _, test := range []struct {
		name       string
		actualName string
		lookupErr  error
		markerErr  error
	}{
		{name: OwnedName, actualName: OwnedName, lookupErr: missing},
		{name: OwnedName, actualName: OwnedName, markerErr: missing},
		{name: OwnedName, actualName: "tun0"},
	} {
		if err := validateExistingOwnedInterface(test.name, test.actualName, test.lookupErr, test.markerErr); !errors.Is(err, ErrOpen) {
			t.Fatalf("test=%+v err=%v", test, err)
		}
	}
	if err := validateExistingOwnedInterface(OwnedName, OwnedName, nil, nil); err != nil {
		t.Fatalf("existing owned TUN err=%v", err)
	}
}
