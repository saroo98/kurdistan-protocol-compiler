//go:build !android && !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
)

func newPlatformRuntimeNetwork(_ context.Context, plan sessionplan.PlanV2, _ runtimepolicy.PolicyV2, seed []byte) (androidbridge.RuntimeNetworkSession, androidbridge.ErrorCode) {
	clear(seed)
	plan.Destroy()
	return nil, androidbridge.CodeIncompatible
}
