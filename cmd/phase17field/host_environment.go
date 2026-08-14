// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"
)

const (
	maximumOwnerVPSClockRoundTrip = 30 * time.Second
	ownerVPSClockTolerance        = 5 * time.Second
)

func verifyOwnerVPSClock(
	ctx context.Context,
	runner commandRunner,
	value config,
	root string,
	now func() time.Time,
) error {
	if ctx == nil || now == nil {
		return fmt.Errorf("%w: owner VPS clock probe rejected", errVPSEnvironmentUnavailable)
	}
	before := now()
	raw, err := runBytesWithLimit(
		ctx, runner, nil, root, maximumOwnerVPSClockRoundTrip, 64, value.sshPath,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20", "--",
		value.sshAlias, "date -u +%s",
	)
	after := now()
	if err != nil {
		clear(raw)
		return fmt.Errorf("%w: owner VPS clock probe failed", errVPSEnvironmentUnavailable)
	}
	defer clear(raw)
	if after.Before(before) || after.Sub(before) > maximumOwnerVPSClockRoundTrip {
		return fmt.Errorf("%w: owner VPS clock probe interval rejected", errVPSEnvironmentUnavailable)
	}
	text := bytes.TrimSpace(raw)
	if len(text) == 0 || len(text) > 19 || bytes.ContainsAny(text, "+-\r\n\x00") {
		return fmt.Errorf("%w: owner VPS clock response rejected", errVPSEnvironmentUnavailable)
	}
	seconds, err := strconv.ParseInt(string(text), 10, 64)
	if err != nil || seconds < 0 {
		return fmt.Errorf("%w: owner VPS clock response rejected", errVPSEnvironmentUnavailable)
	}
	remote := time.Unix(seconds, 0)
	if remote.Before(before.Add(-ownerVPSClockTolerance)) || remote.After(after.Add(ownerVPSClockTolerance)) {
		return fmt.Errorf("%w: owner VPS clock differs from host", errVPSEnvironmentUnavailable)
	}
	return nil
}
