// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview

interface ProfileRepository {
    val appState: Flow<AppState>

    suspend fun preview(source: ImportSource, exactInput: ByteArray): PreviewResult

    suspend fun confirm(previewToken: PreviewToken): ActivationResult

    suspend fun cancel(previewToken: PreviewToken)

    suspend fun delete(localRecordId: String): Result<Unit>
}

@JvmInline
value class PreviewToken(val value: String)

data class PreviewResult(
    val token: PreviewToken,
    val preview: RedactedProfilePreview,
)

sealed interface ActivationResult {
    data class Activated(val localRecordId: String) : ActivationResult
    data class Rejected(val category: OperationError) : ActivationResult
}
