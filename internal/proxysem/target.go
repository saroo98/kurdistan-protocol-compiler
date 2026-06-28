// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

const (
	TargetEcho            = "echo"
	TargetDiscard         = "discard"
	TargetFixedResponse   = "fixed_response"
	TargetSlowResponse    = "slow_response"
	TargetChunkedResponse = "chunked_response"
	TargetLargeObject     = "large_object"
	TargetErrorResponse   = "error_response"
	TargetResetMidstream  = "reset_midstream"
	TargetDripResponse    = "drip_response"
	TargetJitteryResponse = "jittery_response"
)

func TargetClasses() []string {
	return []string{
		TargetEcho,
		TargetDiscard,
		TargetFixedResponse,
		TargetSlowResponse,
		TargetChunkedResponse,
		TargetLargeObject,
		TargetErrorResponse,
		TargetResetMidstream,
		TargetDripResponse,
		TargetJitteryResponse,
	}
}
