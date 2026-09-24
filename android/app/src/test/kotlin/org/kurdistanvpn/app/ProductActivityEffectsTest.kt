// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.CatalogId

class ProductActivityEffectsTest {
    private val request = ActivityEffectRequest(CatalogId("request-1"), CatalogId("operation-1"), ActivityEffectKind.FILE_IMPORT)

    @Test fun claimTwiceLaunchesOnce() {
        val effects = ProductActivityEffects()
        assertTrue(effects.offer(request))
        assertFalse(effects.claim(request.id, resumed = false))
        assertTrue(effects.claim(request.id, resumed = true))
        assertFalse(effects.claim(request.id, resumed = true))
        assertEquals(EffectCompletion.COMPLETED, effects.complete(request.id, request.operationId, true))
        assertEquals(EffectCompletion.INTERRUPTED, effects.complete(request.id, request.operationId, true))
    }

    @Test fun lateResultAfterCancelCannotCommit() {
        val effects = ProductActivityEffects()
        assertTrue(effects.offer(request))
        assertTrue(effects.claim(request.id, true))
        effects.cancel(request.id)
        assertEquals(EffectCompletion.INTERRUPTED, effects.complete(request.id, request.operationId, true))
    }

    @Test fun recreatedActivityDoesNotRelaunch() {
        val effects = ProductActivityEffects()
        assertTrue(effects.offer(request))
        assertTrue(effects.claim(request.id, true))
        assertFalse(effects.offer(request))
        assertFalse(effects.claim(request.id, true))
        assertEquals(EffectCompletion.COMPLETED, effects.complete(request.id, request.operationId, true))
    }

    @Test fun lostOperationReturnsInterrupted() {
        val effects = ProductActivityEffects()
        effects.offer(request)
        effects.claim(request.id, true)
        assertEquals(EffectCompletion.INTERRUPTED, effects.complete(request.id, request.operationId, false))
        assertEquals(EffectCompletion.INTERRUPTED, ProductActivityEffects().complete(request.id, request.operationId, true))
        assertTrue(effects.offer(request.copy(id = CatalogId("request-2"))))
    }

    @Test fun unrelatedResultCannotConsumeCurrentRequest() {
        val effects = ProductActivityEffects()
        effects.offer(request)
        effects.claim(request.id, true)
        assertEquals(EffectCompletion.INTERRUPTED, effects.complete(CatalogId("old-request"), request.operationId, true))
        assertEquals(EffectCompletion.INTERRUPTED, effects.complete(request.id, CatalogId("other-operation"), true))
        assertEquals(EffectCompletion.COMPLETED, effects.complete(request.id, request.operationId, true))
    }
}
