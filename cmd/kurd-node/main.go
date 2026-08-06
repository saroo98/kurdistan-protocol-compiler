// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command kurd-node maintains the Phase 16 owner-local authority publication.
// It intentionally has no relay listener or public data plane; those are Phase
// 17 responsibilities and cannot be represented as available here.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kurdistan/internal/selfhost"
)

const version = "kurd-node-phase16-v1"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"schema": "kurd-node-version-v1", "version": version, "dataPlane": "UNAVAILABLE_PHASE_16"})
		return 0
	}
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintln(stderr, "usage: kurd-node run --data-dir DIR --publication-file FILE [--once]")
		return 2
	}
	set := flag.NewFlagSet("run", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	dataDir := set.String("data-dir", "", "state directory")
	publication := set.String("publication-file", "", "atomic publication snapshot")
	interval := set.Duration("interval", 30*time.Second, "publication refresh interval")
	once := set.Bool("once", false, "publish once and exit")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || *dataDir == "" || *publication == "" || *interval < time.Second || *interval > time.Hour {
		return 2
	}
	publish := func() error {
		report, err := selfhost.Doctor(*dataDir, time.Now().UTC())
		if err != nil || report.Overall != "PASS" {
			return errors.New("authority doctor is not green")
		}
		delivery, err := selfhost.PublicationDeliveryStatus(*dataDir)
		if err != nil {
			return err
		}
		status, err := selfhost.LoadStatus(*dataDir)
		if err != nil {
			return err
		}
		digest, revision, profileCount := delivery.Digest, delivery.DeliveredRevision, status.ProfileCount-status.RevokedProfileCount
		if delivery.Pending {
			summary, publishErr := selfhost.PublishSnapshot(*dataDir, *publication, time.Now().UTC())
			if publishErr != nil {
				return publishErr
			}
			digest, revision, profileCount = summary.Digest, summary.Revision, summary.ProfileCount
		}
		return json.NewEncoder(stdout).Encode(map[string]any{
			"schema": "kurd-node-health-v1", "status": "READY_AUTHORITY_ONLY", "dataPlane": "UNAVAILABLE_PHASE_16",
			"publicationDigest": digest, "revision": revision, "profiles": profileCount,
		})
	}
	if err := publish(); err != nil {
		fmt.Fprintf(stderr, "kurd-node: %v\n", err)
		return 1
	}
	if *once {
		return 0
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
			if err := publish(); err != nil {
				fmt.Fprintf(stderr, "kurd-node: %v\n", err)
				return 1
			}
		}
	}
}
