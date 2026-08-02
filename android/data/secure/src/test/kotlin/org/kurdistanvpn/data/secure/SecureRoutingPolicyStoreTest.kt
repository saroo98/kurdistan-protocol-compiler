// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SecureRoutingPolicyStoreTest {
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
        var bytes: ByteArray? = null
        var dataClass: SecureDataClass? = null

        override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
            this.dataClass = dataClass
            bytes?.fill(0)
            bytes = exactBytes.copyOf()
        }

        override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray =
            requireNotNull(bytes).copyOf()

        override fun delete(localRecordId: String, dataClass: SecureDataClass) {
            bytes?.fill(0)
            bytes = null
        }

        override fun deleteAll() = delete("routing-policy-current", SecureDataClass.ROUTING_POLICY)

        override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean = bytes != null
    }
}
