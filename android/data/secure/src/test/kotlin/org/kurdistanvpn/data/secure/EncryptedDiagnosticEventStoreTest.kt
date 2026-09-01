// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel

class EncryptedDiagnosticEventStoreTest {
    @Test fun readOnlyDiagnosticStoreCannotUpgradeOrWriteEvenWithWritableBacking() {
        val blobs = DiagnosticMemoryBlobs()
        val events = listOf(DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "EVENT", 1))
        EncryptedDiagnosticEventStore(blobs).save(events)
        val exact = requireNotNull(blobs.bytes).copyOf()
        val reads = blobs.reads; val writes = blobs.writes
        val reader: SecureBlobReadAccess = blobs
        val store = EncryptedDiagnosticEventStore.readOnly(reader)
        assertEquals(reads, blobs.reads)
        assertEquals(events, store.load())
        val afterRead = blobs.reads
        assertThrows(IllegalStateException::class.java) { store.save(List(201) { events.single() }) }
        assertThrows(IllegalStateException::class.java) { store.clear() }
        assertEquals(afterRead, blobs.reads)
        assertEquals(writes, blobs.writes)
        assertArrayEquals(exact, blobs.bytes)
    }

    @Test fun missingAndMalformedReadOnlyDiagnosticsNeverRepairOrCreate() {
        val blobs = DiagnosticMemoryBlobs()
        val store = EncryptedDiagnosticEventStore.readOnly(blobs)
        assertEquals(emptyList<DiagnosticEvent>(), store.load())
        blobs.bytes = byteArrayOf(1, 2, 3)
        assertThrows(IllegalArgumentException::class.java) { store.load() }
        assertArrayEquals(byteArrayOf(1, 2, 3), blobs.bytes)
        assertEquals(0, blobs.writes)
    }
    @Test
    fun boundedCategoricalEventsRoundTripExactly() {
        val blobs = DiagnosticMemoryBlobs()
        val store = EncryptedDiagnosticEventStore(blobs)
        val events = listOf(
            DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.RUNTIME, "SESSION_STARTED", 1234),
            DiagnosticEvent(2, DiagnosticLogLevel.WARNING, DiagnosticComponent.PROBE, "PROBE_FAILED", 1235, "session-01", 7),
        )
        store.save(events)
        assertEquals(events, store.load())
        assertEquals(SecureDataClass.DIAGNOSTIC_EVENTS, blobs.dataClass)
    }

    @Test
    fun nonMonotonicOrOversizedHistoriesFailClosed() {
        val store = EncryptedDiagnosticEventStore(DiagnosticMemoryBlobs())
        val duplicate = DiagnosticEvent(1, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "EVENT", 1)
        assertThrows(IllegalArgumentException::class.java) { store.save(listOf(duplicate, duplicate)) }
        assertThrows(IllegalArgumentException::class.java) {
            store.save((1L..201L).map { DiagnosticEvent(it, DiagnosticLogLevel.INFO, DiagnosticComponent.APP, "EVENT", 1) })
        }
    }

    private class DiagnosticMemoryBlobs : SecureBlobAccess {
        var reads = 0
        var writes = 0
        var bytes: ByteArray? = null
        var dataClass: SecureDataClass? = null

        override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
            writes++
            this.dataClass = dataClass
            bytes?.fill(0)
            bytes = exactBytes.copyOf()
        }

        override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray { reads++; return requireNotNull(bytes).copyOf() }
        override fun delete(localRecordId: String, dataClass: SecureDataClass) { writes++; bytes?.fill(0); bytes = null }
        override fun deleteAll() { writes++; bytes?.fill(0); bytes = null }
        override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean { reads++; return bytes != null }
    }
}
