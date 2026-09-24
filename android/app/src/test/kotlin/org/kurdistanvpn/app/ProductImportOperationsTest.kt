// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.*
import org.kurdistanvpn.platform.importing.*

class ProductImportOperationsTest {
    @Test fun stagingRejectsUnboundedInputAndNeverRetainsIt() {
        val owner = ProductImportOperations({ error("No preview") }, { error("No confirmation") })
        val oversized = ByteArray(1_500_001) { 7 }
        val result = owner.stage(ImportCandidate(IngressKind.FILE, ArtifactClass.SIGNED_PUBLIC, listOf(oversized)), ImportSource.FILE)
        assertTrue(result is NativeResult.Failure)
        assertTrue(oversized.all { it == 0.toByte() })
    }

    @Test fun replacingStagedInputWipesItAndOldIdentityCannotConsumeReplacement() {
        val owner = ProductImportOperations({ ProtectedExternalPreviewResult.Rejected(ProtectedReadFailure.STATE_UNPROVEN) },
            { error("No confirmation") })
        val first = byteArrayOf(1, 2)
        val second = byteArrayOf(3, 4)
        val old = owner.stage(ImportCandidate(IngressKind.FILE, ArtifactClass.SIGNED_PUBLIC, listOf(first)), ImportSource.FILE)
        val next = owner.stage(ImportCandidate(IngressKind.FILE, ArtifactClass.SIGNED_PUBLIC, listOf(second)), ImportSource.FILE)
        assertArrayEquals(ByteArray(2), first)
        assertEquals(OperationError.CANCELLED, (owner.prepareStaged((old as NativeResult.Success).value, ImportSource.FILE) as NativeResult.Failure).error)
        assertArrayEquals(byteArrayOf(3, 4), second)
        owner.prepareStaged((next as NativeResult.Success).value, ImportSource.FILE)
        assertArrayEquals(ByteArray(2), second)
        assertEquals(OperationError.CANCELLED, (owner.prepareStaged(next.value, ImportSource.FILE) as NativeResult.Failure).error)
        owner.close()
    }

    @Test fun cleanupFailureStopsFallbackAndWipesOwnedInput(): Unit = runBlocking {
        var attempts = 0
        var encoded: ByteArray? = null
        val owner = ProductImportOperations({ input ->
            attempts++; encoded = input
            ProtectedExternalPreviewResult.Rejected(ProtectedReadFailure.CLEANUP_UNPROVEN)
        }, { error("Unapproved confirmation") })
        val bytes = byteArrayOf(1, 2)
        val result = owner.prepare(ImportCandidate(IngressKind.FILE, ArtifactClass.SIGNED_PUBLIC, listOf(bytes)), ImportSource.FILE)
        assertEquals(OperationError.RECOVERY_REQUIRED, (result as NativeResult.Failure).error)
        assertEquals(1, attempts)
        assertTrue(encoded!!.all { it == 0.toByte() })
        assertArrayEquals(ByteArray(2), bytes)
        assertTrue(owner.prepare(ImportCandidate(IngressKind.FILE, ArtifactClass.SIGNED_PUBLIC, listOf(byteArrayOf(1))), ImportSource.FILE) is NativeResult.Failure)
        assertEquals(1, attempts)
        assertTrue(owner.confirm(CatalogId("lost-operation")) is NativeResult.Failure)
    }

    @Test fun malformedCandidateNeverReachesProtectedReader() {
        val owner = ProductImportOperations({ error("Malformed input reached reader") }, { error("No confirmation") })
        assertEquals(OperationError.INVALID_INPUT, (owner.prepare(
            ImportCandidate(IngressKind.FILE, ArtifactClass.SIGNED_PUBLIC, emptyList()), ImportSource.FILE) as NativeResult.Failure).error)
    }
}
