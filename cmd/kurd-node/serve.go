// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"kurdistan/internal/relay/node"
	"kurdistan/internal/relay/tun"
)

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
	if config.Validate() != nil {
		return 2
	}

	listener, err := node.OpenSystemdListener(config.ListenerPort)
	if err != nil {
		fmt.Fprintln(stderr, "kurd-node serve: unavailable")
		return 1
	}
	tunnel, err := tun.OpenExisting(config.TUNName)
	if err != nil {
		_ = listener.Close()
		fmt.Fprintln(stderr, "kurd-node serve: unavailable")
		return 1
	}
	control, authorizeControl, err := node.OpenControlListenerV1(config.ControlSocket)
	if err != nil {
		_ = tunnel.Close()
		_ = listener.Close()
		fmt.Fprintln(stderr, "kurd-node serve: unavailable")
		return 1
	}
	server, err := node.NewServerV1(config, listener, tunnel, control, authorizeControl)
	if err != nil {
		_ = control.Close()
		_ = tunnel.Close()
		_ = listener.Close()
		fmt.Fprintln(stderr, "kurd-node serve: unavailable")
		return 1
	}
	if err := server.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "kurd-node serve: stopped")
		return 1
	}
	return 0
}
