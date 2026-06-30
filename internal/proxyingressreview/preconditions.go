// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "kurdistan/internal/proxyingress"

func SecurityPreconditions(contract proxyingress.ProxyIngressContract) []string {
	out := []string{}
	for _, capability := range []string{"secure_context_required", "replay_rejection_required", "trace_hygiene_required", "bounded_queue_required"} {
		if hasCapability(contract.RequiredCapabilities, capability) {
			out = append(out, capability)
		}
	}
	return out
}
