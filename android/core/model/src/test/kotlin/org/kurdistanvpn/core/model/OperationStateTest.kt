// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import org.junit.Assert.*
import org.junit.Test

class OperationStateTest {
    @Test fun allOperationsLoseEphemeralConsentAndRequireReconciliationAfterRecreation() {
        val kind = OperationKind.IMPORT
        val preview = OperationPreview(kind, 2)
        val states = listOf(
            OperationState.Idle, OperationState.Loading(kind), OperationState.Previewing(preview),
            OperationState.AwaitingConfirmation(preview), OperationState.Applying(OperationProgress(kind, 1, 2)),
            OperationState.Succeeded(OperationResult(kind, 2)),
            OperationState.PartiallyApplied(PartialOperationResult(kind, 1, 1)),
            OperationState.Cancelled(kind), OperationState.Failed(kind, ProductFailure(ProductFailureCode.INVALID_INPUT)),
            OperationState.InterruptedResumable(ResumableOperation(kind, ResumptionEvidence.VERIFIED_DURABLE_JOURNAL)),
        )
        assertEquals(OperationCategory.entries.toSet(), states.map { it.category }.toSet())
        states.forEachIndexed { index, state ->
            assertEquals(ProductText.OperationTitle(state.category), state.metadata.title)
            assertEquals(ProductText.OperationExplanation(state.category), state.metadata.explanation)
            assertFalse(state.metadata.primaryAction in state.metadata.disabledActions)
            assertEquals(
                when (index) {
                    4, 9 -> OperationState.Failed(kind, ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
                    5, 6, 7, 8 -> state
                    else -> OperationState.Idle
                },
                state.processRecreated(),
            )
        }
        assertEquals(ProductAction.CONFIRM, OperationState.AwaitingConfirmation(preview).metadata.primaryAction)
        assertEquals(ProductAction.REVIEW_IMPORT, OperationState.InterruptedResumable(ResumableOperation(kind, ResumptionEvidence.VERIFIED_DURABLE_JOURNAL)).metadata.primaryAction)
    }

    @Test fun reviewActionsMatchOperationKindAndNeverPromiseAutomaticResumption() {
        val expected = mapOf(
            OperationKind.IMPORT to ProductAction.REVIEW_IMPORT,
            OperationKind.PROFILE_ACTIVATION to ProductAction.REVIEW_PROFILE,
            OperationKind.UPDATE to ProductAction.REVIEW_UPDATE,
            OperationKind.RESTORE to ProductAction.REVIEW_RESTORE,
            OperationKind.BACKUP to ProductAction.REVIEW_BACKUP,
            OperationKind.RESET to ProductAction.REVIEW_RESET,
            OperationKind.PROBE to ProductAction.REVIEW_PROBE,
            OperationKind.SETTINGS_CHANGE to ProductAction.REVIEW_SETTINGS,
        )
        assertEquals(OperationKind.entries.toSet(), expected.keys)
        expected.forEach { (kind, action) ->
            val preview = OperationState.Previewing(OperationPreview(kind, 1))
            assertEquals(action, preview.metadata.primaryAction)
            assertEquals(ProductAction.CANCEL, preview.metadata.secondaryAction)
            val partial = OperationState.PartiallyApplied(PartialOperationResult(kind, 1, 1))
            assertEquals(action, partial.metadata.primaryAction)
            assertEquals(ProductAction.NONE, partial.metadata.secondaryAction)
            assertEquals(partial, partial.processRecreated())
            assertEquals(OperationState.Failed(kind, ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED)),
                OperationState.Applying(OperationProgress(kind, 1, 2)).processRecreated())
            val interrupted = OperationState.Failed(kind, ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
            assertEquals(action, interrupted.metadata.primaryAction)
            val resumable = OperationState.InterruptedResumable(ResumableOperation(kind, ResumptionEvidence.VERIFIED_DURABLE_JOURNAL))
            assertEquals(action, resumable.metadata.primaryAction)
            assertEquals(interrupted, resumable.processRecreated())
        }
    }

    @Test fun progressAndPartialResultsRejectImpossibleCounts() {
        assertThrows(IllegalArgumentException::class.java) { OperationProgress(OperationKind.IMPORT, 3, 2) }
        assertThrows(IllegalArgumentException::class.java) { OperationPreview(OperationKind.IMPORT, 1025) }
        assertThrows(IllegalArgumentException::class.java) { PartialOperationResult(OperationKind.IMPORT, 0, 1) }
        assertThrows(IllegalArgumentException::class.java) { PartialOperationResult(OperationKind.IMPORT, 1, 0) }
        val value = OperationProgress(OperationKind.IMPORT, 1, 2)
        assertEquals(value, value.copy())
    }
}
