// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !linux

package node

import (
	"net"

	"kurdistan/internal/relay/tun"
)

func OpenSystemdListener(expectedPort uint16) (net.Listener, error) {
	defer clearSystemdActivationEnvironmentV1()
	if expectedPort == 0 {
		return nil, ErrListenerActivation
	}
	return nil, tun.ErrUnavailable
}
