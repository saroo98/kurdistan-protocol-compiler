// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package tun attaches the unprivileged relay process to one pre-created,
// owner-assigned Linux TUN. It never configures addresses, routes, or links.
package tun

import (
	"context"
	"errors"
	"io"
)

var (
	ErrUnavailable   = errors.New("relay tun: unavailable on this platform")
	ErrInvalidName   = errors.New("relay tun: invalid owned interface name")
	ErrOpen          = errors.New("relay tun: existing interface unavailable")
	ErrPrivileged    = errors.New("relay tun: privileged process rejected")
	ErrPacketWriteV3 = errors.New("relay tun: packet write failed")
	ErrWriteHealthV3 = errors.New("relay tun: write health failed")
)

const OwnedName = "kurd0"

func ValidateName(name string) error {
	if name != OwnedName {
		return ErrInvalidName
	}
	return nil
}

func validateUnprivileged(effectiveUID int, networkAdmin bool, capabilityErr error) error {
	if capabilityErr != nil {
		return errors.Join(ErrOpen, capabilityErr)
	}
	if effectiveUID == 0 || networkAdmin {
		return ErrPrivileged
	}
	return nil
}

func validateExistingOwnedInterface(name, actualName string, lookupErr, tunMarkerErr error) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if lookupErr != nil || tunMarkerErr != nil || actualName != name {
		return ErrOpen
	}
	return nil
}

type Device interface {
	io.ReadWriteCloser
	Name() string
}

// Optional capabilities. A session cancels its own write, never the shared TUN.
type ContextPacketWriterV3 interface {
	WritePacketContextV3(context.Context, []byte) (int, error)
}

type PacketWriteControlV3 interface {
	PreparePacketWriteV3(context.Context) error
	WriteFailureV3() <-chan struct{}
}
