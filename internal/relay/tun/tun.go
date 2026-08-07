// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package tun attaches the unprivileged relay process to one pre-created,
// owner-assigned Linux TUN. It never configures addresses, routes, or links.
package tun

import (
	"errors"
	"io"
)

var (
	ErrUnavailable = errors.New("relay tun: unavailable on this platform")
	ErrInvalidName = errors.New("relay tun: invalid owned interface name")
	ErrOpen        = errors.New("relay tun: existing interface unavailable")
	ErrPrivileged  = errors.New("relay tun: privileged process rejected")
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
