// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package labtrace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"

	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/trace"
)

type CorpusOptions struct {
	StartSeed int64  `json:"start_seed"`
	Count     int    `json:"count"`
	Message   string `json:"message"`
}

type CorpusTraceReport struct {
	StartSeed       int64                            `json:"start_seed"`
	Count           int                              `json:"count"`
	ProfileIDs      []string                         `json:"profile_ids"`
	ProfileReport   diversity.ProfileDiversityReport `json:"profile_report"`
	TraceScanReport ktrace.TraceScanReport           `json:"trace_scan_report"`
	TraceReports    []ktrace.TraceReport             `json:"trace_pair_reports,omitempty"`
}

func GenerateCorpus(ctx context.Context, opts CorpusOptions) (CorpusTraceReport, error) {
	if opts.Count < 0 {
		return CorpusTraceReport{}, fmt.Errorf("count must be non-negative")
	}
	if opts.Message == "" {
		opts.Message = "hello kurdistan"
	}
	profiles := make([]*ir.Profile, 0, opts.Count)
	traces := make([][]ktrace.Event, 0, opts.Count)
	ids := make([]string, 0, opts.Count)
	for i := 0; i < opts.Count; i++ {
		seed := opts.StartSeed + int64(i)
		p, err := compiler.Generate(seed)
		if err != nil {
			return CorpusTraceReport{}, err
		}
		events, err := CaptureTrace(ctx, p, []byte(opts.Message))
		if err != nil {
			return CorpusTraceReport{}, fmt.Errorf("seed %d: %w", seed, err)
		}
		profiles = append(profiles, p)
		traces = append(traces, events)
		ids = append(ids, p.ID)
	}
	pairReports := make([]ktrace.TraceReport, 0)
	for i := 0; i+1 < len(traces); i++ {
		pairReports = append(pairReports, ktrace.CompareEvents(traces[i], traces[i+1]))
	}
	return CorpusTraceReport{
		StartSeed:       opts.StartSeed,
		Count:           opts.Count,
		ProfileIDs:      ids,
		ProfileReport:   diversity.AnalyzeProfiles(profiles),
		TraceScanReport: ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold),
		TraceReports:    pairReports,
	}, nil
}

func WriteCorpusTraceReport(path string, report CorpusTraceReport) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func CaptureTrace(ctx context.Context, p *ir.Profile, payload []byte) ([]ktrace.Event, error) {
	echoCtx, stopEcho := context.WithCancel(ctx)
	defer stopEcho()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() { _ = relay.ServeEcho(echoCtx, echoLn, nil) }()

	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = echoLn.Close()
		return nil, err
	}
	var buf bytes.Buffer
	rec := ktrace.NewRecorder(&buf)
	go func() { _ = relay.Serve(serverCtx, serverLn, echoLn.Addr().String(), p, rec, nil) }()

	echo, err := relay.ClientRoundTrip(ctx, p, serverLn.Addr().String(), payload, rec)
	stopServer()
	stopEcho()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(echo, payload) {
		return nil, fmt.Errorf("echo response mismatch")
	}
	events, err := ktrace.DecodeJSONL(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, err
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].TimeUnixNano == events[j].TimeUnixNano {
			return events[i].EventType < events[j].EventType
		}
		return events[i].TimeUnixNano < events[j].TimeUnixNano
	})
	return events, nil
}
