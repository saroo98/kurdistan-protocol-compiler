// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.*

interface NodeMaintenanceRepository {
    fun observeUpdate(deploymentId: CatalogId): Flow<OperationState>
    suspend fun scheduleSignedUpdate(deploymentId: CatalogId, preferences: UpdatePreferences): DomainResult<Unit>
    suspend fun checkSignedUpdate(deploymentId: CatalogId): DomainResult<PendingProductOperation>
    suspend fun cancelSignedUpdate(deploymentId: CatalogId): DomainResult<Unit>
    /** Signed target and admitted method only; rate limit and network path are rechecked by the adapter. */
    suspend fun probe(profileId: CatalogId, request: ProbePreferences): DomainResult<ProbeSample>
    suspend fun cancelProbe(profileId: CatalogId): DomainResult<Unit>
    fun observeProbeHistory(profileId: CatalogId): Flow<ProbeHistory>
}
