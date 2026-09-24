// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test

class ProductExportDestinationTest {
    @Test fun rotationRetainsPayloadButDuplicateCompletionCannotWriteAgain() {
        val owner = ProductExportDestination(ProductActivityEffects())
        val bytes = byteArrayOf(1, 2, 3)
        val request = owner.stage(ExportDocumentKind.BACKUP, bytes, null, true)!!
        val document = owner.take(request.id, request.operationId)!!
        assertArrayEquals(byteArrayOf(1, 2, 3), document.bytes)
        assertNull(owner.take(request.id, request.operationId))
        document.close()
        assertArrayEquals(ByteArray(3), bytes)
    }

    @Test fun inactiveOrConcurrentExportCannotRetainBytes() {
        val owner = ProductExportDestination(ProductActivityEffects())
        val inactive = byteArrayOf(9)
        assertNull(owner.stage(ExportDocumentKind.BACKUP, inactive, null, false))
        assertEquals(0, inactive.single().toInt())
        val first = byteArrayOf(1)
        val request = owner.stage(ExportDocumentKind.BACKUP, first, null, true)!!
        val duplicate = byteArrayOf(2)
        assertNull(owner.stage(ExportDocumentKind.DIAGNOSTIC, duplicate, null, true))
        assertEquals(0, duplicate.single().toInt())
        owner.cancel(request.id)
        assertEquals(0, first.single().toInt())
        assertNull(owner.take(request.id, request.operationId))
    }

    @Test fun processLossOrWrongOperationCannotAdoptSavedIds() {
        val owner = ProductExportDestination(ProductActivityEffects())
        val request = owner.stage(ExportDocumentKind.ENROLLMENT, byteArrayOf(1), "local-record", true)!!
        assertNull(ProductExportDestination(ProductActivityEffects()).take(request.id, request.operationId))
        assertNull(owner.take(request.id, org.kurdistanvpn.core.model.CatalogId("wrong-operation")))
        owner.take(request.id, request.operationId)!!.use { assertEquals("local-record", it.enrollmentLocalId) }
    }
}
