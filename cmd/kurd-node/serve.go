// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sync"
	"time"

	"kurdistan/internal/relay/node"
	"kurdistan/internal/relay/tun"
	kruntime "kurdistan/internal/runtime"
)

type sessionRejectReporterV1 struct {
	mu        sync.Mutex
	output    io.Writer
	remaining uint8
}

type sessionStageReporterV1 struct {
	mu        sync.Mutex
	output    io.Writer
	remaining uint8
}

type sessionTerminationReporterV1 struct {
	mu        sync.Mutex
	output    io.Writer
	remaining uint8
}

type sessionPacketPumpSnapshotReporterV1 struct {
	mu        sync.Mutex
	output    io.Writer
	remaining uint8
}

func newSessionRejectReporterV1(output io.Writer, maximum uint8) func(node.SessionRejectCodeV1) {
	reporter := &sessionRejectReporterV1{output: output, remaining: maximum}
	return func(code node.SessionRejectCodeV1) {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		if reporter.output == nil || reporter.remaining == 0 {
			return
		}
		reporter.remaining--
		fmt.Fprintf(reporter.output, "kurd-node serve: session-rejected:%s\n", code)
	}
}

func newSessionStageReporterV1(output io.Writer, maximum uint8) func(node.SessionStageCodeV1) {
	reporter := &sessionStageReporterV1{output: output, remaining: maximum}
	return func(stage node.SessionStageCodeV1) {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		if reporter.output == nil || reporter.remaining == 0 {
			return
		}
		reporter.remaining--
		fmt.Fprintf(reporter.output, "kurd-node serve: session-stage:%s\n", stage)
	}
}

func newSessionTerminationReporterV1(output io.Writer, maximum uint8) func(node.SessionTerminationCodeV1) {
	reporter := &sessionTerminationReporterV1{output: output, remaining: maximum}
	return func(code node.SessionTerminationCodeV1) {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		if reporter.output == nil || reporter.remaining == 0 {
			return
		}
		reporter.remaining--
		fmt.Fprintf(reporter.output, "kurd-node serve: session-terminated:%s\n", code)
	}
}

func newSessionPacketPumpSnapshotReporterV1(output io.Writer, maximum uint8) func(kruntime.PacketPumpSnapshotV1) {
	reporter := &sessionPacketPumpSnapshotReporterV1{output: output, remaining: maximum}
	return func(snapshot kruntime.PacketPumpSnapshotV1) {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		if reporter.output == nil || reporter.remaining == 0 {
			return
		}
		reporter.remaining--
		fmt.Fprintf(reporter.output, "kurd-node serve: session-pump:tun-read=%d:outbound=%d:carrier-write=%d:carrier-read=%d:authenticated=%d:inner-accepted=%d:inner-rejected=%d:tun-attempts=%d:tun-failures=%d:tun-failure-code=%s:tun-errno=%d:tun-write=%d:rejected=%d:gateway-udp53=%d:gateway-checksum-fail=%d:transport-malformed=%d:return-tcp=%d:return-syn=%d:return-ack=%d:return-rst=%d:return-fin=%d:return-checksum-fail=%d:return-oversize=%d\n",
			snapshot.TUNPacketsRead, snapshot.OutboundPacketsAccepted, snapshot.CarrierRecordsWritten, snapshot.CarrierRecordsRead,
			snapshot.AuthenticatedOperations, snapshot.InnerPacketsAccepted, snapshot.InnerPacketsRejected, snapshot.TUNWriteAttempts,
			snapshot.TUNWriteFailures, snapshot.TUNWriteFailureCode, snapshot.TUNWriteErrno, snapshot.TUNPacketsWritten, snapshot.RejectedTUNPackets,
			snapshot.RelayGatewayDNSPackets, snapshot.RelayGatewayDNSChecksumFailures, snapshot.RelayTransportMalformedPackets,
			snapshot.RelayReturnTCPPackets, snapshot.RelayReturnTCPSYNPackets, snapshot.RelayReturnTCPACKPackets,
			snapshot.RelayReturnTCPRSTPackets, snapshot.RelayReturnTCPFINPackets, snapshot.RelayReturnTCPChecksumFailures,
			snapshot.RelayReturnOversizePackets)
	}
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	dataDir := set.String("data-dir", "", "verified self-host state directory")
	port := set.Uint("port", 0, "inherited Kurd listener port")
	controlSocket := set.String("control-socket", "/run/kurd-node/control.sock", "owner-local control socket")
	if ctx == nil || stderr == nil || set.Parse(args) != nil || set.NArg() != 0 || *dataDir == "" || *port == 0 || *port > 65535 {
		return 2
	}

	config := node.DefaultConfig(*dataDir, uint16(*port))
	config.ControlSocket = *controlSocket
	config.MaxHandshakeWorkers = 32
	config.MaxSessions = 64
	config.SessionQueuePackets = 256
	config.SessionIdleTimeout = 5 * time.Minute
	config.SessionBufferBudget = 64 << 20
	config.DNSReady = node.OwnedDNSReadyV1
	config.SessionRejected = newSessionRejectReporterV1(stderr, 32)
	config.SessionProgress = newSessionStageReporterV1(stderr, 64)
	config.SessionTerminated = newSessionTerminationReporterV1(stderr, 32)
	config.SessionPacketPumpSnapshot = newSessionPacketPumpSnapshotReporterV1(stderr, 32)
	if config.Validate() != nil {
		return 2
	}

	listener, err := node.OpenSystemdListener(config.ListenerPort)
	if err != nil {
		fmt.Fprintln(stderr, "kurd-node serve: unavailable:listener")
		return 1
	}
	tunnel, err := tun.OpenExisting(config.TUNName)
	if err != nil {
		_ = listener.Close()
		fmt.Fprintln(stderr, "kurd-node serve: unavailable:tunnel")
		return 1
	}
	control, authorizeControl, err := node.OpenControlListenerV1(config.ControlSocket)
	if err != nil {
		_ = tunnel.Close()
		_ = listener.Close()
		fmt.Fprintln(stderr, "kurd-node serve: unavailable:control")
		return 1
	}
	server, err := node.NewServerV1(config, listener, tunnel, control, authorizeControl)
	if err != nil {
		_ = control.Close()
		_ = tunnel.Close()
		_ = listener.Close()
		fmt.Fprintln(stderr, "kurd-node serve: unavailable:server")
		return 1
	}
	if err := server.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "kurd-node serve: stopped:%s\n", serverStopCategoryV1(err))
		return 1
	}
	return 0
}

func serverStopCategoryV1(err error) string {
	switch {
	case errors.Is(err, node.ErrServerRegistry):
		return "registry"
	case errors.Is(err, node.ErrServerListener):
		return "listener"
	case errors.Is(err, node.ErrServerControl):
		return "control"
	case errors.Is(err, node.ErrServerReload):
		return "reload"
	default:
		return "unknown"
	}
}
