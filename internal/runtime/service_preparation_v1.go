// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import "kurdistan/internal/product/sessionplan"

type ServicePreparationBoundsV1 struct {
	OwnedBytes, ProxyAttributedBytes uint64
	RetainedAdmissionBytes           uint64
}

// ProductionClientAttachmentPreparationV1 states caller-owned reservations;
// runtime verifies minima, while the native caller owns the actual ledger ticket.
type ProductionClientAttachmentPreparationV1 struct{ OwnedBytes, ProxyAttributedBytes uint64 }

func serviceAddBytesV1(values ...uint64) (uint64, bool) {
	var n uint64
	for _, v := range values {
		if v > ^uint64(0)-n {
			return 0, false
		}
		n += v
	}
	return n, true
}

// The plan's private builder facts permit sizing before any decoder allocation.
// Auth/framing/setup remain in the independently charged endpoint lifetime.
func ServicePreparationBoundsForPlanV1(plan sessionplan.PlanV2, proxyActive bool) (ServicePreparationBoundsV1, error) {
	f, ok := plan.ConstructionFactsV2()
	if !ok || proxyActive && f.ProxyBufferBytes == 0 {
		return ServicePreparationBoundsV1{}, ServiceResourceLimitV1
	}
	b, ok := sessionplan.AdmittedCalculationBoundsV2(f.ProfileBytes)
	if !ok {
		return ServicePreparationBoundsV1{}, ServiceResourceLimitV1
	}
	n, ok := serviceAddBytesV1(b.DecoderBytes, b.PolicyBytes, b.ProgramBytes)
	if !ok || serviceAdmissionMaximumBytesV1() > b.PolicyBytes {
		return ServicePreparationBoundsV1{}, ServiceResourceLimitV1
	}
	s := ServicePreparationBoundsV1{OwnedBytes: n, RetainedAdmissionBytes: serviceAdmissionMaximumBytesV1()}
	if proxyActive {
		s.ProxyAttributedBytes = n
	}
	return s, nil
}
