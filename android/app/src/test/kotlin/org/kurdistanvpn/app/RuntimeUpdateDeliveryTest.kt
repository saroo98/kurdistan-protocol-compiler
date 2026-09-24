// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.android.RuntimeVerifiedUpdate

class RuntimeUpdateDeliveryTest {
    @Test fun cancelledDispatcherDeliveryWipesTheUndeliveredArtifact() = kotlinx.coroutines.runBlocking {
        val bytes = byteArrayOf(1, 2, 3)
        val update = RuntimeVerifiedUpdate(2u, NativeUpdateChanges(0, 1, 0, 0, 0, 0, 0, 0, 0, 0), bytes)
        try {
            deliverRuntimeUpdate {
                kotlinx.coroutines.currentCoroutineContext()[kotlinx.coroutines.Job]!!.cancel()
                NativeProductResult.Success(update)
            }
            fail("Cancelled delivery cannot transfer ownership")
        } catch (_: kotlinx.coroutines.CancellationException) { }
        assertArrayEquals(byteArrayOf(0, 0, 0), bytes)
    }
}
