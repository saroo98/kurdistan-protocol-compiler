// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SecureRoutingPolicyStoreTest {
    @Test fun readOnlyFactoryNeverUpgradesBackingWriterAndRejectsWritesBeforeReading() {
        val blobs = MemoryBlobs()
        SecureRoutingPolicyStore(blobs).savePackages(setOf("org.example.browser"))
        val exact = requireNotNull(blobs.bytes).copyOf()
        val reader: SecureBlobReadAccess = blobs
        val reads = blobs.reads; val writes = blobs.writes
        val store = SecureRoutingPolicyStore.readOnly(reader)
        assertEquals(reads, blobs.reads)
        assertEquals(setOf("org.example.browser"), store.loadPackages())
        val afterRead = blobs.reads
        assertThrows(IllegalStateException::class.java) { store.savePackages(setOf("invalid package")) }
        assertThrows(IllegalStateException::class.java) { store.clear() }
        assertEquals(afterRead, blobs.reads)
        assertEquals(writes, blobs.writes)
        assertArrayEquals(exact, blobs.bytes)
    }

    @Test fun missingAndMalformedReadOnlyRoutingNeverRepairsOrCreates() {
        val blobs = MemoryBlobs()
        val store = SecureRoutingPolicyStore.readOnly(blobs)
        assertEquals(emptySet<String>(), store.loadPackages())
        blobs.bytes = byteArrayOf(1, 2, 3)
        assertThrows(IllegalArgumentException::class.java) { store.loadPackages() }
        assertArrayEquals(byteArrayOf(1, 2, 3), blobs.bytes)
        assertEquals(0, blobs.writes)
    }
    @Test
    fun roundTripIsCanonicalAndNotStoredAsPlainPreferences() {
        val blobs = MemoryBlobs()
        val store = SecureRoutingPolicyStore(blobs)
        store.savePackages(setOf("org.signal.app", "com.example.browser"))
        assertEquals(
            sortedSetOf("com.example.browser", "org.signal.app"),
            store.loadPackages(),
        )
        assertEquals(SecureDataClass.ROUTING_POLICY, blobs.dataClass)
    }

    @Test
    fun malformedOrDuplicatePackagesFailClosed() {
        val store = SecureRoutingPolicyStore(MemoryBlobs())
        assertThrows(IllegalArgumentException::class.java) {
            store.savePackages(setOf("not a package"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            store.savePackages((0..64).map { "org.example.app$it" }.toSet())
        }
    }

    private class MemoryBlobs : SecureBlobAccess {
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

        override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
            reads++
            return requireNotNull(bytes).copyOf()
        }

        override fun delete(localRecordId: String, dataClass: SecureDataClass) {
            writes++
            bytes?.fill(0)
            bytes = null
        }

        override fun deleteAll() = delete("routing-policy-current", SecureDataClass.ROUTING_POLICY)

        override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean { reads++; return bytes != null }
    }
}
