// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.*

enum class AppLockState { UNLOCKED, LOCKED, UNAVAILABLE }
enum class UnlockResult { AUTHORIZED, NOT_REQUIRED }
data class PrivacySummary(val preferences: PrivacyPreferences, val clipboard: ClipboardState,
    val screenshotPolicy: ScreenshotPolicy)

interface PrivacyRecoveryRepository {
    fun observeAppLock(): Flow<AppLockState>
    /** DISCONNECT and RECOVER_INTERNET are never lock-gated. No authentication token leaves the adapter. */
    suspend fun unlock(action: SensitiveAction): DomainResult<UnlockResult>
    suspend fun setAppLock(preferences: PrivacyPreferences): DomainResult<Unit>
    fun observePrivacy(): Flow<PrivacySummary>
    fun observeOperation(): Flow<OperationState>
    fun observeBackup(): Flow<BackupWorkflowState>
    suspend fun previewBackup(profileIds: Set<CatalogId>): DomainResult<PendingProductOperation>
    suspend fun backup(operationId: CatalogId): DomainResult<Unit>
    suspend fun previewRestore(stagedInputId: CatalogId): DomainResult<PendingProductOperation>
    suspend fun restore(operationId: CatalogId): DomainResult<Unit>
    /** Recipient material stays inside the protected adapter; only a local reviewed staging ID crosses. */
    suspend fun previewTransfer(profileId: CatalogId, stagedRecipientId: CatalogId): DomainResult<PendingProductOperation>
    suspend fun transfer(operationId: CatalogId): DomainResult<Unit>
    suspend fun previewReset(scope: ResetScope): DomainResult<PendingProductOperation>
    suspend fun reset(operationId: CatalogId): DomainResult<Unit>
    suspend fun cancel(operationId: CatalogId): DomainResult<Unit>
    suspend fun recoverProtectedState(): DomainResult<OperationState>
    /** Explicit migration confirmation, never a side effect of reading startup state. */
    suspend fun migrateLegacyProtectedState(): DomainResult<OperationState>
    suspend fun applyPrivacy(preferences: PrivacyPreferences): DomainResult<Unit>
}
