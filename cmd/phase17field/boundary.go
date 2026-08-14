// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kurdistan/internal/assurance"
	"kurdistan/internal/phase17boundary"
	"kurdistan/internal/phase17evidence"
)

func runBoundaryMonitor(
	ctx context.Context,
	runner commandRunner,
	value config,
	qualified qualifiedRun,
	root, serial string,
	ipv6Authorized bool,
) (result phase17evidence.FieldBoundaryV3, resultErr error) {
	if qualified.boundaryDigest == "" || value.boundaryPath == "" {
		return result, errors.New("boundary monitor identity unavailable")
	}
	attemptID, err := newFieldAttemptID()
	if err != nil {
		return result, errors.New("boundary monitor attempt identity unavailable")
	}
	request := phase17boundary.Request{
		Schema: phase17boundary.RequestSchema, CampaignMode: value.mode, AttemptID: attemptID,
		ADBPath: value.adbPath, DeviceSerial: serial, SSHPath: value.sshPath,
		SSHAlias: value.sshAlias, RelayPort: uint16(value.relayPort), VerifyIPv6: ipv6Authorized,
	}
	raw, err := phase17boundary.MarshalRequest(request)
	if err != nil {
		return result, err
	}
	defer clear(raw)
	if err := os.MkdirAll(value.evidenceRoot, 0o700); err != nil {
		return result, err
	}
	directory, err := os.MkdirTemp(value.evidenceRoot, ".private-boundary-*")
	if err != nil {
		return result, err
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%w: boundary request cleanup failed", errFieldCleanup))
			return
		}
		if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("%w: boundary request retention detected", errFieldCleanup))
		}
	}()
	path := filepath.Join(directory, "request.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return result, errors.New("boundary request write failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return result, errors.New("boundary request sync failed")
	}
	if err := file.Close(); err != nil {
		return result, errors.New("boundary request close failed")
	}
	output, err := runBytesWithLimit(ctx, runner, nil, root, 7*time.Minute, 1<<20, value.boundaryPath, "-request", path)
	if err != nil {
		return result, errors.New("boundary monitor process failed")
	}
	defer clear(output)
	var receipt phase17boundary.Receipt
	if err := assurance.DecodeStrict(bytes.NewReader(output), &receipt); err != nil {
		return result, errors.New("boundary monitor receipt rejected")
	}
	if err := phase17boundary.ValidateReceipt(request, receipt); err != nil {
		return result, errors.New("boundary monitor parity rejected")
	}
	result = phase17evidence.FieldBoundaryV3{
		Result: receipt.Result, MonitorSHA256: qualified.boundaryDigest,
		RouteLeak: receipt.RouteLeak, DNSLeak: receipt.DNSLeak,
	}
	if receipt.Result != "PASS" || receipt.RouteLeak || receipt.DNSLeak || receipt.CoverageGap {
		return result, errors.New("boundary monitor found route or DNS leakage")
	}
	return result, nil
}
