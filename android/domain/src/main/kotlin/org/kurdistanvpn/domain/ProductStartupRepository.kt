// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.AppState

interface ProductStartupRepository {
    fun observeStartup(): Flow<AppState>
    /** Refreshes availability only. It never provisions, migrates or resets storage. */
    suspend fun refresh(): DomainResult<Unit>
}
