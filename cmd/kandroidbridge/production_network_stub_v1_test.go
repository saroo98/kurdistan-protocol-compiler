//go:build !android && !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "testing"

func TestProductionNetworkV1UnsupportedFactoryRefuses(t *testing.T) {
	f := productionNetworkFactoryV1{}
	if _, s := f.ReservationV1(nil); s != 25 {
		t.Fatal("unsupported reservation", s)
	}
	if v, s := f.PrepareV1(nil); v != nil || s != 25 {
		t.Fatal("unsupported prepare", s)
	}
}
