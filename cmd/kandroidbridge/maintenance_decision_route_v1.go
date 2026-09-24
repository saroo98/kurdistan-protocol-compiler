//go:build !phase18outputtest || !linux || android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import "kurdistan/internal/androidbridge"

func maintenanceProbeWireV1(parent androidbridge.Handle, request, output []byte, inv androidbridge.MaintenanceOutputInvocationV1) (int, int32) {
	return androidbridge.RunMaintenanceProbeWireV1Scoped(&registry, parent, request, output, inv)
}

func maintenanceCheckDecisionV1(parent androidbridge.Handle, timeout uint16, inv androidbridge.MaintenanceOutputInvocationV1) (androidbridge.MaintenanceCandidateResultV1, bool) {
	return androidbridge.CheckSameDeploymentUpdateDecisionV1Scoped(&registry, parent, timeout, inv)
}
