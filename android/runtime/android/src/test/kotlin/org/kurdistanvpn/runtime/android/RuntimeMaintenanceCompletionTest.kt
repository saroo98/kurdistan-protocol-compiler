// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.NativeProductResult

class RuntimeMaintenanceCompletionTest {
    @Test fun cancellationCannotHideFailedCleanup() {
        assertEquals(NativeProductResult.Failure(ProductFailureCode.STORAGE_DEGRADED),
            finishRuntimeMaintenance(NativeProductResult.Success(Unit), cancelled = true, cleanupSucceeded = false))
    }

    @Test fun cancellationIsReportedAfterProvenCleanup() {
        assertEquals(NativeProductResult.Failure(ProductFailureCode.CANCELLED),
            finishRuntimeMaintenance(NativeProductResult.Success(Unit), cancelled = true, cleanupSucceeded = true))
        assertEquals(NativeProductResult.Success(Unit),
            finishRuntimeMaintenance(NativeProductResult.Success(Unit), cancelled = false, cleanupSucceeded = true))
    }
}
