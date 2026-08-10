//go:build android || linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/transport/tlstcp"
)

type platformRuntimeNetwork struct {
	mu            sync.Mutex
	closeOnce     sync.Once
	ctx           context.Context
	plan          sessionplan.PlanV2
	policy        runtimepolicy.PolicyV2
	seed          []byte
	fd            int
	endpointIndex uint8
	raw           net.Conn
	carrier       *tlstcp.Conn
	endpoint      *kruntime.ProcessClientDuplexEndpointV1
	program       liveprogram.ProgramV1
	tun           *os.File
	pump          *kruntime.PacketPumpV1
	terminalCode  androidbridge.ErrorCode
}

func newPlatformRuntimeNetwork(ctx context.Context, plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, seed []byte, endpointIndex uint8) (androidbridge.RuntimeNetworkSession, androidbridge.ErrorCode) {
	if ctx == nil || ctx.Err() != nil || len(plan.Endpoints) == 0 || int(endpointIndex) >= len(plan.Endpoints) || len(seed) == 0 {
		clear(seed)
		plan.Destroy()
		return nil, androidbridge.CodePolicyRejected
	}
	family := unix.AF_INET
	if plan.Endpoints[endpointIndex].Family == 6 {
		family = unix.AF_INET6
	} else if plan.Endpoints[endpointIndex].Family != 4 {
		clear(seed)
		plan.Destroy()
		return nil, androidbridge.CodePolicyRejected
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		clear(seed)
		plan.Destroy()
		return nil, androidbridge.CodeInternalFailure
	}
	return &platformRuntimeNetwork{ctx: ctx, plan: plan, policy: policy.Clone(), seed: seed, fd: fd, endpointIndex: endpointIndex}, androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) SocketFD() (int, androidbridge.ErrorCode) {
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.fd < 0 || network.raw != nil {
		return -1, androidbridge.CodePolicyRejected
	}
	return network.fd, androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) ConnectProtected(ctx context.Context) androidbridge.ErrorCode {
	if network == nil || ctx == nil {
		return androidbridge.CodeInvalidArgument
	}
	network.mu.Lock()
	if network.fd < 0 || network.raw != nil || len(network.plan.Endpoints) == 0 {
		network.mu.Unlock()
		return androidbridge.CodePolicyRejected
	}
	if int(network.endpointIndex) >= len(network.plan.Endpoints) {
		network.mu.Unlock()
		return androidbridge.CodePolicyRejected
	}
	fd, endpoint, timeout := network.fd, network.plan.Endpoints[network.endpointIndex], network.plan.DialTimeout
	network.mu.Unlock()
	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if releaseConnectFD(connectCtx, fd, endpoint) != nil {
		return androidbridge.CodeEndpointUnavailable
	}
	file := os.NewFile(uintptr(fd), "kurd-protected-socket")
	if file == nil {
		return androidbridge.CodeInternalFailure
	}
	raw, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return androidbridge.CodeInternalFailure
	}
	preface, err := sessionplan.NewRelayAdmissionPrefaceV1(network.plan)
	if err != nil {
		_ = raw.Close()
		return androidbridge.CodePolicyRejected
	}
	if deadline, ok := connectCtx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	if sessionplan.WriteRelayAdmissionPrefaceV1(raw, preface) != nil || raw.SetDeadline(time.Time{}) != nil {
		_ = raw.Close()
		return androidbridge.CodeEndpointUnavailable
	}
	network.mu.Lock()
	if network.fd != fd || network.raw != nil || network.ctx.Err() != nil {
		network.mu.Unlock()
		_ = raw.Close()
		return androidbridge.CodeCancelled
	}
	network.fd = -1
	network.raw = raw
	network.mu.Unlock()
	return androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) AuthenticateTLS(ctx context.Context) androidbridge.ErrorCode {
	if network == nil || ctx == nil {
		return androidbridge.CodeInvalidArgument
	}
	network.mu.Lock()
	if network.raw == nil || network.carrier != nil {
		network.mu.Unlock()
		return androidbridge.CodePolicyRejected
	}
	raw, plan, policy := network.raw, network.plan.Clone(), network.policy.Clone()
	network.mu.Unlock()
	defer plan.Destroy()
	tlsConfig, err := releaseTLSClientConfig(policy, time.Now().UTC())
	if err != nil {
		return androidbridge.CodePolicyRejected
	}
	program, err := liveprogram.DecodeV1(policy.LiveProgram)
	if err != nil || program.Limits.MaxFrameBytes <= 0 {
		return androidbridge.CodePolicyRejected
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, plan.DialTimeout)
	defer cancel()
	carrier, err := tlstcp.Client(handshakeCtx, raw, tlsConfig, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	if err != nil {
		return androidbridge.CodeTLSRejected
	}
	network.mu.Lock()
	if network.raw != raw || network.carrier != nil || network.ctx.Err() != nil {
		network.mu.Unlock()
		_ = carrier.Close()
		return androidbridge.CodeCancelled
	}
	network.carrier = carrier
	network.mu.Unlock()
	return androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) AuthenticateKurd(ctx context.Context) androidbridge.ErrorCode {
	if network == nil || ctx == nil {
		return androidbridge.CodeInvalidArgument
	}
	network.mu.Lock()
	if network.carrier == nil || network.endpoint != nil {
		network.mu.Unlock()
		return androidbridge.CodePolicyRejected
	}
	carrier, plan, policy, seed := network.carrier, network.plan.Clone(), network.policy.Clone(), append([]byte(nil), network.seed...)
	network.mu.Unlock()
	defer plan.Destroy()
	defer clear(seed)
	handshake, program, err := releaseClientHandshake(plan, policy, seed)
	if err != nil {
		return androidbridge.CodePolicyRejected
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, plan.DialTimeout)
	defer cancel()
	endpoint, err := kruntime.EstablishProcessClientDuplexEndpointV1(handshakeCtx, carrier, handshake, plan.Digest, program)
	if err != nil {
		return androidbridge.CodeKurdAuthRejected
	}
	network.mu.Lock()
	if network.carrier != carrier || network.endpoint != nil || network.ctx.Err() != nil {
		network.mu.Unlock()
		endpoint.Abort()
		return androidbridge.CodeCancelled
	}
	network.endpoint = endpoint
	network.program = program.Clone()
	network.mu.Unlock()
	return androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) AttachTUN(ctx context.Context, fd int) androidbridge.ErrorCode {
	if network == nil || ctx == nil || fd < 0 {
		return androidbridge.CodeInvalidArgument
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return androidbridge.CodeTUNIOFailed
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return androidbridge.CodeInvalidArgument
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.endpoint == nil {
		return androidbridge.CodeEndpointUnavailable
	}
	if network.tun != nil {
		return androidbridge.CodeInvalidArgument
	}
	if network.ctx.Err() != nil {
		return androidbridge.CodeCancelled
	}
	ownedFD, err := unix.Dup(fd)
	if err != nil {
		return androidbridge.CodeInternalFailure
	}
	unix.CloseOnExec(ownedFD)
	file := os.NewFile(uintptr(ownedFD), "kurd-android-tun")
	if file == nil {
		_ = unix.Close(ownedFD)
		return androidbridge.CodeInternalFailure
	}
	network.tun = file
	return androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) Start(ctx context.Context) androidbridge.ErrorCode {
	if network == nil || ctx == nil {
		return androidbridge.CodeInvalidArgument
	}
	network.mu.Lock()
	if network.tun == nil || network.carrier == nil || network.endpoint == nil || network.pump != nil || network.ctx.Err() != nil {
		network.mu.Unlock()
		return androidbridge.CodePolicyRejected
	}
	duplex, err := kruntime.NewProcessTLSTCPDuplexCarrierV1(network.ctx, network.carrier, network.plan.IdleTimeout)
	if err != nil {
		network.mu.Unlock()
		return androidbridge.CodeInternalFailure
	}
	budget, ok := releasePacketBufferBudget(network.program, network.plan.MaxQueuePackets, network.plan.MaxIncompleteOps)
	if !ok {
		network.mu.Unlock()
		_ = duplex.Close()
		return androidbridge.CodePolicyRejected
	}
	pump, err := kruntime.NewPacketPumpV1(kruntime.PacketPumpConfigV1{
		TUN: network.tun, Carrier: duplex, Endpoint: network.endpoint, Program: network.program,
		Direction: kruntime.DirectionClientV1, AssignedIPv4: network.plan.ClientIPv4, DNSIPv4: network.plan.DNSIPv4,
		AssignedIPv6: network.plan.ClientIPv6, DNSIPv6: network.plan.DNSIPv6,
		QueuePackets: network.plan.MaxQueuePackets, IncompleteOps: network.plan.MaxIncompleteOps,
		BufferBudget: budget, IdleTimeout: network.plan.IdleTimeout,
	})
	if err != nil {
		network.mu.Unlock()
		_ = duplex.Close()
		return androidbridge.CodeTUNIOFailed
	}
	network.pump = pump
	network.mu.Unlock()
	go func() {
		err := pump.Run(network.ctx)
		network.mu.Lock()
		if network.ctx.Err() != nil {
			network.terminalCode = androidbridge.CodeCancelled
		} else {
			network.terminalCode = releasePacketPumpErrorCode(err)
		}
		network.mu.Unlock()
		network.Close()
	}()
	return androidbridge.CodeOK
}

func (network *platformRuntimeNetwork) Status() androidbridge.ErrorCode {
	if network == nil {
		return androidbridge.CodeInternalFailure
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.terminalCode
}

func (network *platformRuntimeNetwork) RuntimeNetworkDiagnosticsV1() androidbridge.RuntimeNetworkDiagnosticsV1 {
	if network == nil {
		return androidbridge.RuntimeNetworkDiagnosticsV1{}
	}
	network.mu.Lock()
	pump := network.pump
	network.mu.Unlock()
	if pump == nil {
		return androidbridge.RuntimeNetworkDiagnosticsV1{}
	}
	return releaseRuntimeNetworkDiagnostics(pump.SnapshotV1())
}

func (network *platformRuntimeNetwork) Close() {
	if network == nil {
		return
	}
	network.closeOnce.Do(func() {
		network.mu.Lock()
		pump, endpoint, carrier, raw, tun, fd := network.pump, network.endpoint, network.carrier, network.raw, network.tun, network.fd
		network.pump, network.endpoint, network.carrier, network.raw, network.tun, network.fd = nil, nil, nil, nil, nil, -1
		clear(network.seed)
		network.seed = nil
		clearRuntimePolicyV2(&network.policy)
		network.plan.Destroy()
		network.program = liveprogram.ProgramV1{}
		network.mu.Unlock()
		if pump != nil {
			_ = pump.Close()
			return
		}
		if endpoint != nil {
			endpoint.Abort()
		}
		if carrier != nil {
			_ = carrier.Close()
		} else if raw != nil {
			_ = raw.Close()
		}
		if tun != nil {
			_ = tun.Close()
		}
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	})
}

func releaseConnectFD(ctx context.Context, fd int, endpoint runtimepolicy.EndpointV2) error {
	if ctx == nil || fd < 0 || endpoint.Port == 0 {
		return errors.New("release connect rejected")
	}
	var address unix.Sockaddr
	switch endpoint.Family {
	case 4:
		if len(endpoint.Address) != 4 {
			return errors.New("release connect rejected")
		}
		value := &unix.SockaddrInet4{Port: int(endpoint.Port)}
		copy(value.Addr[:], endpoint.Address)
		address = value
	case 6:
		if len(endpoint.Address) != 16 {
			return errors.New("release connect rejected")
		}
		value := &unix.SockaddrInet6{Port: int(endpoint.Port)}
		copy(value.Addr[:], endpoint.Address)
		address = value
	default:
		return errors.New("release connect rejected")
	}
	if err := unix.Connect(fd, address); err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EALREADY) && !errors.Is(err, unix.EISCONN) {
		return errors.New("release connect rejected")
	}
	for {
		if err := ctx.Err(); err != nil {
			return errors.New("release connect rejected")
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT | unix.POLLERR | unix.POLLHUP}}, 100)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return errors.New("release connect rejected")
		}
		if ready == 0 {
			continue
		}
		status, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil || status != 0 {
			return errors.New("release connect rejected")
		}
		return nil
	}
}
