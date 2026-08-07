// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !linux

package tun

func OpenExisting(name string) (Device, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	return nil, ErrUnavailable
}
