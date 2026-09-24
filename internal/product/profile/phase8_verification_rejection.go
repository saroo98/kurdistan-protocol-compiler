// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

// VerificationStage identifies the completed verification boundary at which a
// request was rejected. It is diagnostic metadata, not authenticated proof.
type VerificationStage uint8

const (
	VerificationStageUnknown          VerificationStage = 0
	VerificationStageOuter            VerificationStage = 1
	VerificationStageRecipient        VerificationStage = 2
	VerificationStageRoot             VerificationStage = 3
	VerificationStageDelegation       VerificationStage = 4
	VerificationStageRevocations      VerificationStage = 5
	VerificationStageProfileSignature VerificationStage = 6
	VerificationStageProfilePolicy    VerificationStage = 7
	VerificationStageLifecycle        VerificationStage = 8
)

// VerificationReason identifies the failed predicate without retaining
// request data or granting authority.
type VerificationReason uint8

const (
	VerificationReasonUnknown            VerificationReason = 0
	VerificationReasonMalformed          VerificationReason = 1
	VerificationReasonRootMismatch       VerificationReason = 2
	VerificationReasonSignatureInvalid   VerificationReason = 3
	VerificationReasonRecipientRejected  VerificationReason = 4
	VerificationReasonBindingMismatch    VerificationReason = 5
	VerificationReasonScopeMismatch      VerificationReason = 6
	VerificationReasonFloorRejected      VerificationReason = 7
	VerificationReasonTimeInvalid        VerificationReason = 8
	VerificationReasonExplicitRevocation VerificationReason = 9
	VerificationReasonLifecycleMismatch  VerificationReason = 10
	VerificationReasonIncompatible       VerificationReason = 11
)

type VerificationRejection struct {
	Stage  VerificationStage
	Reason VerificationReason
}

type VerificationRejectionSink func(VerificationRejection)

func firstVerificationRejectionSink(sink VerificationRejectionSink) VerificationRejectionSink {
	if sink == nil {
		return nil
	}
	emitted := false
	return func(rejection VerificationRejection) {
		if emitted {
			return
		}
		emitted = true
		sink(rejection)
	}
}

func rejectVerification(sink VerificationRejectionSink, stage VerificationStage, reason VerificationReason) {
	if sink != nil {
		sink(VerificationRejection{Stage: stage, Reason: reason})
	}
}
