// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package tun

import (
	"errors"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type linuxDevice struct {
	file *os.File
	name string
}

// OpenExisting attaches to the persistent owner-created TUN named kurd0.
// TUNSETIFF is required to attach a file descriptor, but this process neither
// creates persistence nor configures link, address, route, or ownership state.
func OpenExisting(name string) (Device, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if err := requireUnprivilegedProcess(); err != nil {
		return nil, err
	}
	if err := requireExistingTUN(name); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, errors.Join(ErrOpen, err)
	}
	request.SetUint16(openExistingFlags())
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil || request.Name() != name {
		_ = unix.Close(fd)
		if err == nil {
			err = ErrOpen
		}
		return nil, errors.Join(ErrOpen, err)
	}
	file := os.NewFile(uintptr(fd), "relay-owned-tun")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrOpen
	}
	return &linuxDevice{file: file, name: name}, nil
}

func openExistingFlags() uint16 {
	return uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
}

func requireUnprivilegedProcess() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	err := unix.Capget(&header, &data[0])
	networkAdmin := err == nil && data[0].Effective&(1<<unix.CAP_NET_ADMIN) != 0
	return validateUnprivileged(unix.Geteuid(), networkAdmin, err)
}

func requireExistingTUN(name string) error {
	link, lookupErr := net.InterfaceByName(name)
	actualName := ""
	if link != nil {
		actualName = link.Name
	}
	_, markerErr := os.Stat(filepath.Join("/sys/class/net", name, "tun_flags"))
	return validateExistingOwnedInterface(name, actualName, lookupErr, markerErr)
}

func (device *linuxDevice) Name() string { return device.name }

func (device *linuxDevice) Read(buffer []byte) (int, error) {
	if device == nil || device.file == nil {
		return 0, ErrOpen
	}
	return device.file.Read(buffer)
}

func (device *linuxDevice) Write(packet []byte) (int, error) {
	if device == nil || device.file == nil {
		return 0, ErrOpen
	}
	return device.file.Write(packet)
}

func (device *linuxDevice) Close() error {
	if device == nil || device.file == nil {
		return nil
	}
	file := device.file
	device.file = nil
	return file.Close()
}

var _ Device = (*linuxDevice)(nil)
