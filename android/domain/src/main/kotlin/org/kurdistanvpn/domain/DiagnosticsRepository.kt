// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.*

data class DiagnosticExportPreview(val id: CatalogId, val display: DiagnosticWorkflowState.Preview)

interface DiagnosticsRepository {
    /** Maximum 4096 categorical events / 2 MiB. No exception text or payload logging. */
    fun observeEvents(): Flow<List<DiagnosticEvent>>
    fun observeExport(): Flow<DiagnosticWorkflowState>
    suspend fun setPreferences(preferences: DiagnosticPreferences): DomainResult<Unit>
    suspend fun clear(): DomainResult<Unit>
    suspend fun previewSafeSupportExport(): DomainResult<DiagnosticExportPreview>
    /** Writes only to an explicitly selected local destination; never sends or uploads. */
    suspend fun exportSafeSupport(operationId: CatalogId): DomainResult<Unit>
    suspend fun cancelExport(operationId: CatalogId): DomainResult<Unit>
}
