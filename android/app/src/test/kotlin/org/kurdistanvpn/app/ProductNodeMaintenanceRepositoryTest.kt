// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class ProductNodeMaintenanceRepositoryTest {
    @Test fun unavailableStorageNeverStartsNetworkOrSchedulesWork() = runBlocking {
        val repository = ProductNodeMaintenanceRepository({ null },
            { _, _ -> error("network must not start") }, { error("network must not start") },
            { error("nothing to cancel") }, { _, _ -> error("work must not schedule") })
        val id = CatalogId("profile-one")
        assertEquals(DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED)),
            repository.probe(id, ProbePreferences()))
        assertEquals(DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED)), repository.checkSignedUpdate(id))
        assertEquals(OperationState.Failed(OperationKind.UPDATE, ProductFailure(ProductFailureCode.STORAGE_DEGRADED)),
            repository.observeUpdate(id).first())
        assertEquals(DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED)),
            repository.scheduleSignedUpdate(id, UpdatePreferences(automatic = true)))
    }
}
