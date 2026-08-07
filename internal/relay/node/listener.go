// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"errors"
	"net"
	"os"
	"strconv"
)

var ErrListenerActivation = errors.New("relay node: invalid inherited listener")

const systemdListenerNameV1 = "kurd"

func validateSystemdActivationV1(currentPID int, listenPID, listenFDs, listenFDNames string) error {
	if currentPID <= 0 || listenPID != strconv.Itoa(currentPID) || listenFDs != "1" ||
		listenFDNames != "" && listenFDNames != systemdListenerNameV1 {
		return ErrListenerActivation
	}
	return nil
}

func validateInheritedListenerAddressV1(address net.Addr, expectedPort uint16) error {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil || expectedPort == 0 || tcpAddress.Port != int(expectedPort) ||
		tcpAddress.IP == nil || !tcpAddress.IP.IsUnspecified() {
		return ErrListenerActivation
	}
	return nil
}

func clearSystemdActivationEnvironmentV1() {
	for _, key := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(key)
	}
}
