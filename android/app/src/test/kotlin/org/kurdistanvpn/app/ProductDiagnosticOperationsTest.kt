// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.*

class ProductDiagnosticOperationsTest {
    @Test fun confirmationConsumesExactPreviewAndReleasesNativeParent() {
        val fixture = NativeFixture()
        val operations = ProductDiagnosticOperations(fixture.core)
        val preview = (operations.prepare(byteArrayOf(1)) as NativeResult.Success).value
        assertEquals(2, preview.display.categoryCount)
        assertTrue(operations.confirm(CatalogId("not-current")) is NativeResult.Failure)
        val result = operations.confirm(preview.id) as NativeResult.Success
        assertArrayEquals(byteArrayOf(4, 5), result.value)
        assertEquals(1, fixture.releases)
        assertTrue(operations.confirm(preview.id) is NativeResult.Failure)
        assertEquals(1, fixture.builds)
    }

    @Test fun cancelAndMalformedPreviewReleaseWithoutExport() {
        val fixture = NativeFixture()
        val operations = ProductDiagnosticOperations(fixture.core)
        val preview = (operations.prepare(byteArrayOf(1)) as NativeResult.Success).value
        assertTrue(operations.cancel(preview.id) is NativeResult.Success)
        assertTrue(operations.confirm(preview.id) is NativeResult.Failure)
        fixture.preview = byteArrayOf(0)
        assertTrue(operations.prepare(byteArrayOf(1)) is NativeResult.Failure)
        assertEquals(2, fixture.releases)
        assertEquals(0, fixture.builds)
    }

    @Test fun unprovedReleaseWipesOutputAndPreventsAnotherOperation() {
        val fixture = NativeFixture()
        val operations = ProductDiagnosticOperations(fixture.core)
        val preview = (operations.prepare(byteArrayOf(1)) as NativeResult.Success).value
        fixture.releaseFails = true
        assertTrue(operations.confirm(preview.id) is NativeResult.Failure)
        assertArrayEquals(ByteArray(2), fixture.output)
        assertTrue(operations.prepare(byteArrayOf(1)) is NativeResult.Failure)
        assertEquals(1, fixture.prepares)
    }

    @Test fun throwingReleaseAlsoWipesOutputAndBlocksReuse() {
        val fixture = NativeFixture()
        val operations = ProductDiagnosticOperations(fixture.core)
        val preview = (operations.prepare(byteArrayOf(1)) as NativeResult.Success).value
        fixture.releaseThrows = true
        assertTrue(operations.confirm(preview.id) is NativeResult.Failure)
        assertArrayEquals(ByteArray(2), fixture.output)
        assertTrue(operations.prepare(byteArrayOf(1)) is NativeResult.Failure)
    }

    internal class NativeFixture {
        var releases = 0
        var builds = 0
        var prepares = 0
        var releaseFails = false
        var releaseThrows = false
        var preview = byteArrayOf(75, 68, 80, 49, 0, 0, 0, 0, 0, 0, 0, 1, 3, 2, 1)
        val output = byteArrayOf(4, 5)
        // Only the native boundary is substituted; the adapter/decoder/ownership are real.
        val core = Proxy.newProxyInstance(KurdNativeCore::class.java.classLoader, arrayOf(KurdNativeCore::class.java)) { _, method, _ ->
            when (method.name) {
                "prepareDiagnostic" -> { prepares++; NativeResult.Success(DiagnosticPreviewHandle(7L, preview)) }
                "confirmAndBuildDiagnostic" -> { builds++; NativeResult.Success(output) }
                "releaseDiagnostic" -> { releases++; check(!releaseThrows); if (releaseFails) NativeResult.Failure(OperationError.RECOVERY_REQUIRED) else NativeResult.Success(Unit) }
                else -> error("Unexpected native operation: ${method.name}")
            }
        } as KurdNativeCore
    }
}
