// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package livecarrier maps a selected synthetic carrier-shape family to a
// separately reviewed live implementation. It does not dial or resolve.
package livecarrier

import (
	"errors"

	"kurdistan/internal/contracts/carrier/carrierreview"
)

const (
	Version            = "live-carrier-authority-v1"
	FamilyKurdTLS13TCP = "kurd_tls13_tcp_v1"
)

var ErrNotAuthorized = errors.New("livecarrier: implementation not authorized")

type Authority struct {
	Version                 string
	StrategyFamily          string
	ImplementationFamily    string
	LoopbackConformanceOnly bool
}

// Resolve returns the closed, reviewed mapping for one selected strategy
// family. The first authority remains loopback-conformance-only.
func Resolve(strategyFamily string) (Authority, error) {
	if strategyFamily != carrierreview.FamilyHTTPSLikeTCP {
		return Authority{}, ErrNotAuthorized
	}
	return Authority{
		Version: Version, StrategyFamily: strategyFamily,
		ImplementationFamily:    FamilyKurdTLS13TCP,
		LoopbackConformanceOnly: true,
	}, nil
}
