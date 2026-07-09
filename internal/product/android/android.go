// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package android is the DESIGN CONTRACT for a future real Android source tree
// (Stage 8).
//
// LOOM: contract. It describes the intended shape and safety invariants of a
// future android/ Gradle tree (Kotlin/Java); it is deliberately DISTINCT from
// the existing Go models in internal/contracts/android/** (which model the
// runtime behaviour) — this contract governs the real app sources that do not
// exist yet. No Android build is wired here; nothing in the live runtime imports
// this package (enforced by internal/testkit/importrules). It contains no live
// VpnService, TUN, packet capture, or networking.
package android

import (
	"errors"
	"fmt"
	"strings"
)

const Version = "product-android-sources-v1"

// SourceContract describes the intended real android/ tree and the safety
// invariants any implementation of it must satisfy. It is validated as a
// contract; it is not executable Android code.
type SourceContract struct {
	TreeRoot        string   `json:"tree_root"`        // e.g. "android/" (separate from Go models)
	Modules         []string `json:"modules"`          // intended Gradle modules
	MinSDK          int      `json:"min_sdk"`          // minimum Android SDK level
	PermissionFirst bool     `json:"permission_first"` // must request VPN permission before any foreground service

	// Safety invariants — a valid contract requires the safe values.
	FailClosed          bool `json:"fail_closed"`          // must be true: fail-closed kill switch
	BoundedFallback     bool `json:"bounded_fallback"`     // must be true: reconnect/fallback is bounded
	PayloadLogging      bool `json:"payload_logging"`      // must be false
	DestinationLogging  bool `json:"destination_logging"`  // must be false
	RedactedDiagnostics bool `json:"redacted_diagnostics"` // must be true

	Notes []string `json:"notes"`
}

// DefaultSourceContract returns the reference contract for the future android/
// tree. It is a safe baseline; implementations extend it without weakening the
// invariants.
func DefaultSourceContract() SourceContract {
	return SourceContract{
		TreeRoot:            "android/",
		Modules:             []string{"app", "vpnservice", "profileimport", "diagnostics"},
		MinSDK:              26,
		PermissionFirst:     true,
		FailClosed:          true,
		BoundedFallback:     true,
		PayloadLogging:      false,
		DestinationLogging:  false,
		RedactedDiagnostics: true,
		Notes: []string{
			"contract-only: no Kotlin/Java, no Gradle build wired",
			"distinct from internal/contracts/android/** Go runtime models",
			"live VpnService/TUN/packet capture remains out of scope pending review",
		},
	}
}

// Validate enforces the Android source-contract safety invariants. It FAILS on
// any unsafe setting (payload/destination logging, unbounded fallback, not
// fail-closed, missing redaction), so a misuse control can prove the contract
// bites.
func Validate(c SourceContract) error {
	if strings.TrimSpace(c.TreeRoot) == "" {
		return errors.New("android: tree_root is required")
	}
	if c.TreeRoot == "internal/contracts/android" || strings.HasPrefix(c.TreeRoot, "internal/") {
		return errors.New("android: tree_root must be a real android/ tree, distinct from the Go models")
	}
	if len(c.Modules) == 0 {
		return errors.New("android: at least one module is required")
	}
	if c.MinSDK <= 0 {
		return errors.New("android: min_sdk must be positive")
	}
	if !c.PermissionFirst {
		return errors.New("android: permission_first must be true (request VPN permission before any foreground service)")
	}
	if c.PayloadLogging {
		return errors.New("android: payload_logging must be false")
	}
	if c.DestinationLogging {
		return errors.New("android: destination_logging must be false")
	}
	if !c.FailClosed {
		return errors.New("android: fail_closed must be true (fail-closed kill switch)")
	}
	if !c.BoundedFallback {
		return errors.New("android: bounded_fallback must be true")
	}
	if !c.RedactedDiagnostics {
		return errors.New("android: redacted_diagnostics must be true")
	}
	return nil
}

// String renders a short, safe summary for diagnostics.
func (c SourceContract) String() string {
	return fmt.Sprintf("android source contract %s: root=%s modules=%d fail_closed=%t", Version, c.TreeRoot, len(c.Modules), c.FailClosed)
}
