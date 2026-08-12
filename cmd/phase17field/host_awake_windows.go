//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"runtime"
	"sync"
	"syscall"
)

const (
	esSystemRequired uintptr = 0x00000001
	esContinuous     uintptr = 0x80000000
)

var (
	setThreadExecutionStateProc = syscall.NewLazyDLL("kernel32.dll").NewProc("SetThreadExecutionState")
	setThreadExecutionState     = func(flags uintptr) uintptr {
		result, _, _ := setThreadExecutionStateProc.Call(flags)
		return result
	}
)

func acquireHostWakeInhibitor() (func(), error) {
	runtime.LockOSThread()
	if setThreadExecutionState(esContinuous|esSystemRequired) == 0 {
		runtime.UnlockOSThread()
		return nil, errors.New("execution-state acquisition failed")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			setThreadExecutionState(esContinuous)
			runtime.UnlockOSThread()
		})
	}, nil
}
