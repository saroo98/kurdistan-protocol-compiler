//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"reflect"
	"testing"
)

func TestAcquireHostWakeInhibitorUsesSystemRequiredUntilRelease(t *testing.T) {
	original := setThreadExecutionState
	defer func() { setThreadExecutionState = original }()
	var calls []uintptr
	setThreadExecutionState = func(flags uintptr) uintptr {
		calls = append(calls, flags)
		return 1
	}
	release, err := acquireHostWakeInhibitor()
	if err != nil {
		t.Fatal(err)
	}
	release()
	if !reflect.DeepEqual(calls, []uintptr{esContinuous | esSystemRequired, esContinuous}) {
		t.Fatalf("execution-state calls = %#v", calls)
	}
}

func TestAcquireHostWakeInhibitorRejectsZeroResult(t *testing.T) {
	original := setThreadExecutionState
	defer func() { setThreadExecutionState = original }()
	setThreadExecutionState = func(uintptr) uintptr { return 0 }
	if release, err := acquireHostWakeInhibitor(); err == nil || release != nil {
		t.Fatalf("release nil=%t error=%v, want fail-closed acquisition", release == nil, err)
	}
}
