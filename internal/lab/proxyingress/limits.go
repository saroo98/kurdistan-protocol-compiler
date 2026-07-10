// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

func limitsBounded(l ProxyIngressLimits) bool {
	return l.MaxConcurrentRequests > 0 &&
		l.MaxConcurrentRequests <= 64 &&
		l.MaxTargetDescriptorBytes > 0 &&
		l.MaxTargetDescriptorBytes <= 4096 &&
		l.MaxMetadataFields > 0 &&
		l.MaxMetadataFields <= 32 &&
		l.MaxPendingStreams > 0 &&
		l.MaxPendingStreams <= 64 &&
		l.MaxFailureRecords > 0 &&
		l.MaxFailureRecords <= 512 &&
		l.MaxRequestBytesBucket != ""
}
