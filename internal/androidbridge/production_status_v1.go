// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

type productionStatusV1 int32

const (
	productionSuccessV1                     productionStatusV1 = 0
	productionNotAdmittedV1                 productionStatusV1 = 1
	productionInvalidRequestV1              productionStatusV1 = 2
	productionInvalidStateV1                productionStatusV1 = 3
	productionSizeLimitV1                   productionStatusV1 = 4
	productionResourceLimitV1               productionStatusV1 = 5
	productionRateLimitedV1                 productionStatusV1 = 6
	productionCancelledV1                   productionStatusV1 = 7
	productionTimeoutV1                     productionStatusV1 = 8
	productionNetworkUnavailableV1          productionStatusV1 = 9
	productionDestinationDeniedV1           productionStatusV1 = 10
	productionUnreachableV1                 productionStatusV1 = 11
	productionAuthorityExpiredV1            productionStatusV1 = 12
	productionAuthorityRevokedV1            productionStatusV1 = 13
	productionTLSRejectedV1                 productionStatusV1 = 14
	productionSessionAuthenticationFailedV1 productionStatusV1 = 15
	productionSocketProtectionFailedV1      productionStatusV1 = 16
	productionPolicyRejectedV1              productionStatusV1 = 17
	productionInternalFailureV1             productionStatusV1 = 18
	productionEndOfStreamV1                 productionStatusV1 = 19
	productionNoEventV1                     productionStatusV1 = 20
	productionTrustUnavailableV1            productionStatusV1 = 21
	productionVerificationRejectedV1        productionStatusV1 = 22
	productionWrongRecipientV1              productionStatusV1 = 23
	productionRollbackV1                    productionStatusV1 = 24
	productionIncompatibleV1                productionStatusV1 = 25
	productionDNSPolicyRejectedV1           productionStatusV1 = 26
)

func validProductionStatusV1(status productionStatusV1) bool {
	return status >= productionSuccessV1 && status <= productionDNSPolicyRejectedV1
}

func validProductionOpeningStatusV1(status productionStatusV1) bool {
	return validProductionStatusV1(status) && status != productionEndOfStreamV1 && status != productionNoEventV1
}
