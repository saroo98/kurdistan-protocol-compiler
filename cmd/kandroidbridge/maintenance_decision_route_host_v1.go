//go:build phase18outputtest && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"kurdistan/internal/androidbridge"
	"net/netip"
)

// Serialized host fixture only; reset after actual owner cleanup. Ordinary
// Android/internal/release builds have no function-variable routing hook.
var maintenanceDecisionHostRouteV1 func(string, netip.AddrPort) netip.AddrPort

func maintenanceProbeWireV1(parent androidbridge.Handle, request, output []byte, inv androidbridge.MaintenanceOutputInvocationV1) (int, int32) {
	return androidbridge.RunMaintenanceProbeHostV1(&registry, parent, request, output, maintenanceDecisionHostRouteV1, inv)
}

func maintenanceCheckDecisionV1(parent androidbridge.Handle, timeout uint16, inv androidbridge.MaintenanceOutputInvocationV1) (androidbridge.MaintenanceCandidateResultV1, bool) {
	if maintenanceDecisionHostRouteV1 == nil {
		return androidbridge.CheckSameDeploymentUpdateDecisionV1Scoped(&registry, parent, timeout, inv)
	}
	return androidbridge.CheckMaintenanceUpdateHostV1(&registry, parent, timeout, maintenanceDecisionHostRouteV1, inv)
}
