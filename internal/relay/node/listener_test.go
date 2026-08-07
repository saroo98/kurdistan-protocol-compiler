// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
)

func TestSystemdActivationEnvironmentRequiresOneExactDescriptor(t *testing.T) {
	pid := os.Getpid()
	validPID := strconv.Itoa(pid)
	for _, test := range []struct {
		name, listenPID, listenFDs, listenFDNames string
		wantErr                                   error
	}{
		{name: "valid unnamed", listenPID: validPID, listenFDs: "1"},
		{name: "valid named", listenPID: validPID, listenFDs: "1", listenFDNames: systemdListenerNameV1},
		{name: "missing pid", listenFDs: "1", wantErr: ErrListenerActivation},
		{name: "wrong pid", listenPID: strconv.Itoa(pid + 1), listenFDs: "1", wantErr: ErrListenerActivation},
		{name: "zero descriptors", listenPID: validPID, listenFDs: "0", wantErr: ErrListenerActivation},
		{name: "multiple descriptors", listenPID: validPID, listenFDs: "2", wantErr: ErrListenerActivation},
		{name: "malformed descriptors", listenPID: validPID, listenFDs: "01", wantErr: ErrListenerActivation},
		{name: "wrong name", listenPID: validPID, listenFDs: "1", listenFDNames: "admin", wantErr: ErrListenerActivation},
		{name: "multiple names", listenPID: validPID, listenFDs: "1", listenFDNames: "kurd:extra", wantErr: ErrListenerActivation},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSystemdActivationV1(pid, test.listenPID, test.listenFDs, test.listenFDNames)
			if test.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error=%v want=%v", err, test.wantErr)
			}
		})
	}
}

func TestSystemdListenerAddressIsWildcardAndExactPort(t *testing.T) {
	for _, test := range []struct {
		name string
		addr net.Addr
		port uint16
		ok   bool
	}{
		{name: "ipv4 wildcard", addr: &net.TCPAddr{IP: net.IPv4zero, Port: 443}, port: 443, ok: true},
		{name: "ipv6 wildcard", addr: &net.TCPAddr{IP: net.IPv6zero, Port: 8443}, port: 8443, ok: true},
		{name: "wrong port", addr: &net.TCPAddr{IP: net.IPv6zero, Port: 443}, port: 8443},
		{name: "loopback", addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, port: 443},
		{name: "non tcp", addr: &net.UnixAddr{Name: "relay.sock", Net: "unix"}, port: 443},
		{name: "nil", port: 443},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateInheritedListenerAddressV1(test.addr, test.port)
			if test.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.ok && !errors.Is(err, ErrListenerActivation) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSystemdActivationEnvironmentIsCleared(t *testing.T) {
	t.Setenv("LISTEN_PID", "123")
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", systemdListenerNameV1)
	clearSystemdActivationEnvironmentV1()
	for _, key := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if _, ok := os.LookupEnv(key); ok {
			t.Fatalf("%s remained set", key)
		}
	}
}
