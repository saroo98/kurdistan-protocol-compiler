// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import "testing"

func TestProductionStatusV1NumericNamespace(t *testing.T) {
	want := []productionStatusV1{
		productionSuccessV1,
		productionNotAdmittedV1,
		productionInvalidRequestV1,
		productionInvalidStateV1,
		productionSizeLimitV1,
		productionResourceLimitV1,
		productionRateLimitedV1,
		productionCancelledV1,
		productionTimeoutV1,
		productionNetworkUnavailableV1,
		productionDestinationDeniedV1,
		productionUnreachableV1,
		productionAuthorityExpiredV1,
		productionAuthorityRevokedV1,
		productionTLSRejectedV1,
		productionSessionAuthenticationFailedV1,
		productionSocketProtectionFailedV1,
		productionPolicyRejectedV1,
		productionInternalFailureV1,
		productionEndOfStreamV1,
		productionNoEventV1,
		productionTrustUnavailableV1,
		productionVerificationRejectedV1,
		productionWrongRecipientV1,
		productionRollbackV1,
		productionIncompatibleV1,
		productionDNSPolicyRejectedV1,
	}
	for value, got := range want {
		if got != productionStatusV1(value) || !validProductionStatusV1(got) {
			t.Fatalf("status %d: got=%d valid=%v", value, got, validProductionStatusV1(got))
		}
	}
	for _, value := range []productionStatusV1{-1, 27, 1 << 30} {
		if validProductionStatusV1(value) {
			t.Fatalf("accepted unknown status %d", value)
		}
	}
}

func TestProductionOpeningStatusV1RejectsStreamOnlyResults(t *testing.T) {
	for _, value := range []productionStatusV1{productionEndOfStreamV1, productionNoEventV1} {
		if validProductionOpeningStatusV1(value) {
			t.Fatalf("opening accepted stream-only status %d", value)
		}
	}
	for _, value := range []productionStatusV1{productionSuccessV1, productionNotAdmittedV1, productionDNSPolicyRejectedV1} {
		if !validProductionOpeningStatusV1(value) {
			t.Fatalf("opening rejected status %d", value)
		}
	}
}
