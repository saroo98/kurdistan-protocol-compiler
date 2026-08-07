// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package node

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func OpenControlListenerV1(path string) (net.Listener, func(net.Conn) error, error) {
	if err := validateControlSocketPathV1(path); err != nil {
		return nil, nil, err
	}
	ownerUID := uint32(os.Geteuid())
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 || fileOwnerUIDV1(parent) != ownerUID {
		return nil, nil, errors.Join(ErrControlConfig, err)
	}
	if existing, statErr := os.Lstat(path); statErr == nil {
		if existing.Mode()&os.ModeSocket == 0 || fileOwnerUIDV1(existing) != ownerUID {
			return nil, nil, ErrControlConfig
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return nil, nil, errors.Join(ErrControlConfig, removeErr)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, nil, errors.Join(ErrControlConfig, statErr)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, errors.Join(ErrControlConfig, err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, nil, errors.Join(ErrControlConfig, err)
	}
	authorize := func(connection net.Conn) error {
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok || unixConnection == nil {
			return ErrControlUnauthorized
		}
		raw, err := unixConnection.SyscallConn()
		if err != nil {
			return ErrControlUnauthorized
		}
		var credential *unix.Ucred
		var credentialErr error
		if err := raw.Control(func(fd uintptr) {
			credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 0 {
			return ErrControlUnauthorized
		}
		return validateControlPeerUIDV1(ownerUID, credential.Uid)
	}
	return listener, authorize, nil
}

func fileOwnerUIDV1(info os.FileInfo) uint32 {
	if info == nil {
		return ^uint32(0)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return ^uint32(0)
	}
	return stat.Uid
}
