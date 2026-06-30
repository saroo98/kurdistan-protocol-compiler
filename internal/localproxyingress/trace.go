// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import ktrace "kurdistan/internal/trace"

func TraceEvents(summary LocalProxyIngressSummary) []ktrace.Event {
	return []ktrace.Event{{
		EventType:      "local_proxy_ingress",
		Note:           summary.Scenario,
		ProfileID:      summary.ContractID,
		PayloadHygiene: !summary.PayloadLogged,
		SecretHygiene:  !summary.SecretLogged,
	}}
}
