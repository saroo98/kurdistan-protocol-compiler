// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"kurdistan/internal/ir"
	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/trace"
)

func main() {
	profilePath := flag.String("profile", "", "profile path")
	listen := flag.String("listen", "127.0.0.1:7000", "loopback listen address")
	target := flag.String("target", "127.0.0.1:9000", "loopback echo target")
	tracePath := flag.String("trace", "", "optional trace JSONL path")
	flag.Parse()
	if *profilePath == "" {
		fmt.Fprintln(os.Stderr, "--profile is required")
		os.Exit(2)
	}
	if !relay.IsLoopbackAddress(*listen) || !relay.IsLoopbackAddress(*target) {
		fmt.Fprintln(os.Stderr, "--listen and --target must be loopback addresses")
		os.Exit(1)
	}
	p, err := ir.LoadProfile(*profilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := ir.Validate(p); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rec, err := ktrace.OpenRecorder(*tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rec.Close()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	logger := log.New(os.Stderr, "kserver: ", log.LstdFlags)
	logger.Printf("listening on %s", ln.Addr())
	if err := relay.Serve(ctx, ln, *target, p, rec, logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
