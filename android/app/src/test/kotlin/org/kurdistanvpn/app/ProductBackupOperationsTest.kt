// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.nativeapi.*

class ProductBackupOperationsTest {
    @Test fun stagedExportPasswordIsWipedOnReplacementCancellationAndFailedPreview(): Unit = kotlinx.coroutines.runBlocking {
        val fixture = NativeFixture()
        val operations = ProductBackupOperations(fixture.core, { null }, { 0L })
        val old = byteArrayOf(1, 2)
        val current = byteArrayOf(3, 4)
        operations.stageExportPassword(emptySet(), old)
        operations.stageExportPassword(emptySet(), current)
        assertArrayEquals(ByteArray(2), old)
        assertTrue(operations.previewExport(emptySet()) is NativeResult.Failure)
        assertArrayEquals(ByteArray(2), current)
        val cancelled = byteArrayOf(5, 6)
        operations.stageExportPassword(emptySet(), cancelled)
        operations.close()
        assertArrayEquals(ByteArray(2), cancelled)
    }

    @Test fun cancellationClosesPreviewAndWipesCallerInputs(): Unit = kotlinx.coroutines.runBlocking {
        val fixture = NativeFixture()
        val operations = ProductBackupOperations(fixture.core, { null }, { 0L })
        val bytes = byteArrayOf(9)
        val password = byteArrayOf(8)
        val preview = (operations.open(bytes, password) as NativeResult.Success).value
        assertArrayEquals(byteArrayOf(0), bytes)
        assertArrayEquals(byteArrayOf(0), password)
        assertEquals(0, preview.display.recordCount)
        assertTrue(operations.review(CatalogId("missing-preview")) is NativeResult.Failure)
        assertEquals(preview, (operations.review(preview.id) as NativeResult.Success).value)
        operations.cancel(preview.id)
        assertTrue(operations.review(preview.id) is NativeResult.Failure)
        assertTrue(operations.restore(preview.id) is NativeResult.Failure)
        assertEquals(1, fixture.releases)
        assertEquals(0, fixture.restores)
    }

    @Test fun restoreConsumesOnlyMatchingIdAndRejectsInvalidDecodedPayload(): Unit = kotlinx.coroutines.runBlocking {
        val fixture = NativeFixture()
        val operations = ProductBackupOperations(fixture.core, { null }, { 0L })
        val preview = (operations.open(byteArrayOf(9), byteArrayOf(8)) as NativeResult.Success).value
        assertTrue(operations.restore(CatalogId("another-operation")) is NativeResult.Failure)
        assertTrue(operations.restore(preview.id) is NativeResult.Failure)
        assertTrue(operations.restore(preview.id) is NativeResult.Failure)
        assertEquals(1, fixture.restores)
        assertEquals(1, fixture.releases)
        assertArrayEquals(byteArrayOf(0), fixture.restored)
    }

    @Test fun throwingReleaseWipesRestoredPlaintextAndRejectsReuse(): Unit = kotlinx.coroutines.runBlocking {
        val fixture = NativeFixture()
        val operations = ProductBackupOperations(fixture.core, { null }, { 0L })
        val preview = (operations.open(byteArrayOf(9), byteArrayOf(8)) as NativeResult.Success).value
        fixture.releaseThrows = true
        assertTrue(operations.restore(preview.id) is NativeResult.Failure)
        assertArrayEquals(byteArrayOf(0), fixture.restored)
        assertTrue(operations.open(byteArrayOf(9), byteArrayOf(8)) is NativeResult.Failure)
    }

    private class NativeFixture {
        var releases = 0
        var restores = 0
        var releaseThrows = false
        val restored = byteArrayOf(9)
        val core = Proxy.newProxyInstance(KurdNativeCore::class.java.classLoader, arrayOf(KurdNativeCore::class.java)) { _, method, _ ->
            when (method.name) {
                "openBackup" -> NativeResult.Success(BackupPreviewHandle(7, byteArrayOf(75, 66, 86, 49) + ByteArray(12)))
                "restoreBackup" -> { restores++; NativeResult.Success(restored) }
                "releaseBackup" -> { releases++; check(!releaseThrows); NativeResult.Success(Unit) }
                else -> error("Unexpected native operation: ${method.name}")
            }
        } as KurdNativeCore
    }
}
