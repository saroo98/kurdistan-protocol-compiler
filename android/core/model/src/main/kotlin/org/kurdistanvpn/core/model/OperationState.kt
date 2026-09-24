// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

enum class OperationKind { IMPORT, PROFILE_ACTIVATION, UPDATE, RESTORE, BACKUP, RESET, PROBE, SETTINGS_CHANGE }
enum class OperationCategory {
    IDLE, LOADING, PREVIEWING, AWAITING_CONFIRMATION, APPLYING, SUCCEEDED,
    PARTIALLY_APPLIED, CANCELLED, FAILED, INTERRUPTED_RESUMABLE,
}
data class OperationPreview(val kind: OperationKind, val itemCount: Int) {
    init { require(itemCount in 0..1024) }
}
data class OperationProgress(val kind: OperationKind, val completed: Int, val total: Int) {
    init { require(total in 1..1024 && completed in 0..total) }
}
data class OperationResult(val kind: OperationKind, val applied: Int) {
    init { require(applied in 0..1024) }
}
data class PartialOperationResult(val kind: OperationKind, val applied: Int, val remaining: Int) {
    init { require(applied in 1..1023 && remaining in 1..(1024 - applied)) }
}
/** A presentation category, never a persisted native handle or an authorization to resume. */
enum class ResumptionEvidence { VERIFIED_DURABLE_JOURNAL }
data class ResumableOperation(val kind: OperationKind, val evidence: ResumptionEvidence)

private fun OperationKind.reviewAction(): ProductAction = when (this) {
    OperationKind.IMPORT -> ProductAction.REVIEW_IMPORT
    OperationKind.PROFILE_ACTIVATION -> ProductAction.REVIEW_PROFILE
    OperationKind.UPDATE -> ProductAction.REVIEW_UPDATE
    OperationKind.RESTORE -> ProductAction.REVIEW_RESTORE
    OperationKind.BACKUP -> ProductAction.REVIEW_BACKUP
    OperationKind.RESET -> ProductAction.REVIEW_RESET
    OperationKind.PROBE -> ProductAction.REVIEW_PROBE
    OperationKind.SETTINGS_CHANGE -> ProductAction.REVIEW_SETTINGS
}

sealed interface OperationState {
    data object Idle : OperationState
    data class Loading(val kind: OperationKind) : OperationState
    data class Previewing(val preview: OperationPreview) : OperationState
    data class AwaitingConfirmation(val preview: OperationPreview) : OperationState
    data class Applying(val progress: OperationProgress) : OperationState
    data class Succeeded(val result: OperationResult) : OperationState
    data class PartiallyApplied(val result: PartialOperationResult) : OperationState
    data class Cancelled(val kind: OperationKind) : OperationState
    data class Failed(val kind: OperationKind, val failure: ProductFailure) : OperationState
    data class InterruptedResumable(val operation: ResumableOperation) : OperationState

    val category: OperationCategory get() = when (this) {
        Idle -> OperationCategory.IDLE
        is Loading -> OperationCategory.LOADING
        is Previewing -> OperationCategory.PREVIEWING
        is AwaitingConfirmation -> OperationCategory.AWAITING_CONFIRMATION
        is Applying -> OperationCategory.APPLYING
        is Succeeded -> OperationCategory.SUCCEEDED
        is PartiallyApplied -> OperationCategory.PARTIALLY_APPLIED
        is Cancelled -> OperationCategory.CANCELLED
        is Failed -> OperationCategory.FAILED
        is InterruptedResumable -> OperationCategory.INTERRUPTED_RESUMABLE
    }
    val metadata: StateMetadata get() {
        val primary = when (this) {
            Idle, is Applying -> ProductAction.NONE
            is Loading -> ProductAction.CANCEL
            is Previewing -> preview.kind.reviewAction()
            is AwaitingConfirmation -> ProductAction.CONFIRM
            is Succeeded, is Cancelled -> ProductAction.DISMISS
            is Failed -> if (failure.code == ProductFailureCode.OPERATION_INTERRUPTED) kind.reviewAction() else failure.nextAction
            is PartiallyApplied -> result.kind.reviewAction()
            is InterruptedResumable -> operation.kind.reviewAction()
        }
        val secondary = when (this) {
            is Previewing, is AwaitingConfirmation -> ProductAction.CANCEL
            else -> ProductAction.NONE
        }
        return StateMetadata(
            ProductText.OperationTitle(category), ProductText.OperationExplanation(category), primary, secondary,
            ProductAction.entries.filter { it != ProductAction.NONE && it != primary && it != secondary }.toSet(),
            if (this is Failed || this is PartiallyApplied) AnnouncementPolicy.ASSERTIVE else AnnouncementPolicy.POLITE,
        )
    }
    fun processRecreated(): OperationState = when (this) {
        is Applying -> Failed(progress.kind, ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
        is InterruptedResumable -> Failed(operation.kind, ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
        is PartiallyApplied, is Succeeded, is Cancelled, is Failed -> this
        else -> Idle
    }
}
