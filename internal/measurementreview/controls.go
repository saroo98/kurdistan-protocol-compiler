// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func UnsafeControlFields() []ObservationField {
	return []ObservationField{
		{Name: "raw_payload", Class: "unsafe_direct", RedactionClass: RedactionRejected, RetentionClass: RetentionRejected},
		{Name: "dns_query", Class: "unsafe_direct", RedactionClass: RedactionRejected, RetentionClass: RetentionRejected},
		{Name: "resolver_ip", Class: "unsafe_direct", RedactionClass: RedactionRejected, RetentionClass: RetentionRejected},
		{Name: "precise_location", Class: "unsafe_direct", RedactionClass: RedactionRejected, RetentionClass: RetentionRejected},
	}
}
