//go:build android || linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"kurdistan/internal/product/runtimepolicy"
)

const productionPlatformSupportedV1 = true

func productionCloseFDV1(fd int) error { return unix.Close(fd) }
func productionPrepareSocketV1(n *productionAttemptTransportV1, e runtimepolicy.EndpointV2) error {
	family := unix.AF_INET
	if e.Family == 6 && len(e.Address) == 16 {
		family = unix.AF_INET6
	} else if e.Family != 4 || len(e.Address) != 4 {
		return errors.New("protected endpoint rejected")
	}
	if err := n.leaf.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	if n.terminal != 0 || n.connectorActive || n.connectorSettled {
		n.mu.Unlock()
		return context.Canceled
	}
	n.connectorActive = true
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.connectorActive = false
		if n.terminal != 0 && !n.connectorSettled {
			n.connectorSettled = true
			close(n.connectorDone)
		}
		n.mu.Unlock()
		n.signalV1()
	}()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.fd = fd
	n.connector = productionConnectorOpsV1{productionConnectFDV1, os.NewFile, net.FileConn, func(f *os.File) error { return f.Close() }}
	n.mu.Unlock()
	return nil
}

func (n *productionAttemptTransportV1) connectV1(ctx context.Context, endpoint runtimepolicy.EndpointV2) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	if n.terminal != 0 || n.fd < 0 || n.connectorActive || n.connectorSettled {
		n.mu.Unlock()
		return context.Canceled
	}
	n.connectorActive = true
	fd, ops := n.fd, n.connector
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.connectorActive = false
		n.connectorSettled = true
		close(n.connectorDone)
		n.mu.Unlock()
		n.signalV1()
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.connect(ctx, fd, endpoint); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file := ops.newFile(uintptr(fd), "kurd-production-protected-socket")
	if file == nil {
		return errors.New("protected socket adoption failed")
	}
	var raw net.Conn
	convertErr := ctx.Err()
	if convertErr == nil {
		raw, convertErr = ops.fileConn(file)
	}
	// Register a late raw before original-file close and before checking terminal
	// state. The worker cannot retire either owner until this lease is released.
	n.mu.Lock()
	n.raw = raw
	n.mu.Unlock()
	closeErr := ops.fileClose(file)
	file = nil
	n.mu.Lock()
	n.fd = -1
	// Record the outcome before releasing the lease, even when cancellation
	// wins the operation status. Never retry a possibly recycled descriptor.
	if n.closeError == nil {
		n.closeError = closeErr
	}
	terminal := n.terminal
	n.mu.Unlock()
	if terminal != 0 || ctx.Err() != nil {
		return context.Canceled
	}
	if convertErr != nil {
		return convertErr
	}
	if closeErr != nil {
		return closeErr
	}
	if raw == nil {
		return errors.New("protected socket conversion failed")
	}
	return nil
}

func productionConnectFDV1(ctx context.Context, fd int, e runtimepolicy.EndpointV2) error {
	return productionPollConnectFDV1(ctx, fd, e, unix.Poll)
}

func productionPollConnectFDV1(ctx context.Context, fd int, e runtimepolicy.EndpointV2, pollCall func([]unix.PollFd, int) (int, error)) error {
	if ctx == nil || fd < 0 || e.Port == 0 {
		return errors.New("protected connect rejected")
	}
	var address unix.Sockaddr
	switch e.Family {
	case 4:
		if len(e.Address) != 4 {
			return errors.New("protected address rejected")
		}
		v := &unix.SockaddrInet4{Port: int(e.Port)}
		copy(v.Addr[:], e.Address)
		address = v
	case 6:
		if len(e.Address) != 16 {
			return errors.New("protected address rejected")
		}
		v := &unix.SockaddrInet6{Port: int(e.Port)}
		copy(v.Addr[:], e.Address)
		address = v
	default:
		return errors.New("protected address rejected")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Connect(fd, address); err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EALREADY) && !errors.Is(err, unix.EISCONN) {
		return err
	}
	var poll [1]unix.PollFd
	poll[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLOUT | unix.POLLERR | unix.POLLHUP}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if d, ok := ctx.Deadline(); !ok || !time.Now().Before(d) {
			return context.DeadlineExceeded
		}
		ready, err := pollCall(poll[:], 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if status != 0 {
			return unix.Errno(status)
		}
		return nil
	}
}

type productionConnectorHoldersV1 struct {
	owner                                  *productionAttemptTransportV1
	ctx                                    context.Context
	endpoint                               runtimepolicy.EndpointV2
	ops                                    productionConnectorOpsV1
	fd                                     int
	address                                unix.Sockaddr
	address6                               unix.SockaddrInet6
	poll                                   [1]unix.PollFd
	file                                   *os.File
	raw                                    net.Conn
	connectError, convertError, closeError error
	deadline                               time.Time
	pollCall                               func([]unix.PollFd, int) (int, error)
}

func productionConnectorBytesV1() uint64 {
	return uint64(unsafe.Sizeof(productionConnectorHoldersV1{})) + uint64(unsafe.Sizeof(os.File{}))
}
