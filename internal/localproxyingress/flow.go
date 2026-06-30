// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

type FlowMapping struct {
	RequestID   string `json:"request_id"`
	FlowClass   string `json:"flow_class"`
	StreamClass string `json:"stream_class"`
}
