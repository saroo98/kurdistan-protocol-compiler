// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !linux

package node

import (
	"net"

	"kurdistan/internal/relay/tun"
)

func OpenControlListenerV1(path string) (net.Listener, func(net.Conn) error, error) {
	if err := validateControlSocketPathV1(path); err != nil {
		return nil, nil, err
	}
	return nil, nil, tun.ErrUnavailable
}
