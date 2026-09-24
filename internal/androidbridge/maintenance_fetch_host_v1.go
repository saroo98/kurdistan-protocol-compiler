//go:build phase18outputtest && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import "net/netip"

// RunMaintenanceProbeHostV1 uses the ordinary decoder, admission, rate registry,
// captured socket binding and publication. Routing is below signed selection.
func RunMaintenanceProbeHostV1(registry *HandleRegistry, parent Handle, request, output []byte,
	route func(string, netip.AddrPort) netip.AddrPort, inv MaintenanceOutputInvocationV1) (int, int32) {
	return runMaintenanceProbeWireV1Scoped(registry, parent, request, output, inv, route)
}

// CheckMaintenanceUpdateHostV1 is a tagged host-only bridge to the existing
// below-policy numeric route seam. It grants no authority or cleanup receipt.
func CheckMaintenanceUpdateHostV1(registry *HandleRegistry, parent Handle, timeout uint16,
	route func(string, netip.AddrPort) netip.AddrPort, inv MaintenanceOutputInvocationV1) (MaintenanceCandidateResultV1, bool) {
	return checkSameDeploymentUpdateDecisionV1(registry, parent, timeout, route, inv)
}
