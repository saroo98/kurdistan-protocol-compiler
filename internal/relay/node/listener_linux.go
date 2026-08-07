// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package node

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const systemdListenerFDV1 = 3

// OpenSystemdListener accepts exactly one inherited systemd TCP listener.
// It never creates, binds, or listens on a socket itself.
func OpenSystemdListener(expectedPort uint16) (net.Listener, error) {
	defer clearSystemdActivationEnvironmentV1()
	if err := validateSystemdActivationV1(os.Getpid(), os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES")); err != nil {
		return nil, err
	}
	if socketType, err := unix.GetsockoptInt(systemdListenerFDV1, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || socketType != unix.SOCK_STREAM {
		return nil, errors.Join(ErrListenerActivation, err)
	}
	if accepting, err := unix.GetsockoptInt(systemdListenerFDV1, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || accepting != 1 {
		return nil, errors.Join(ErrListenerActivation, err)
	}

	file := os.NewFile(systemdListenerFDV1, "systemd-"+systemdListenerNameV1+"-listener")
	if file == nil {
		return nil, ErrListenerActivation
	}
	listener, err := net.FileListener(file)
	closeErr := file.Close()
	if err != nil {
		return nil, errors.Join(ErrListenerActivation, err, closeErr)
	}
	if closeErr != nil {
		_ = listener.Close()
		return nil, errors.Join(ErrListenerActivation, closeErr)
	}
	if _, ok := listener.(*net.TCPListener); !ok {
		_ = listener.Close()
		return nil, ErrListenerActivation
	}
	if err := validateInheritedListenerAddressV1(listener.Addr(), expectedPort); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}
