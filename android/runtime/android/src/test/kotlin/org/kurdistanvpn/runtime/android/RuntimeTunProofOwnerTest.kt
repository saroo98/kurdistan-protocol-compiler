// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class RuntimeTunProofOwnerTest {
    private class Source : RuntimeTunSourceV1, AutoCloseable {
        var duplicates = 0; var detached = false; var closed = 0; var duplicateClosed = 0
        override fun duplicate(): RuntimeTunDescriptorV1 {
            duplicates++
            return object : RuntimeTunDescriptorV1 {
                override val fd = 71
                override fun close() { duplicateClosed++ }
            }
        }
        fun detach(): Int { detached = true; return 70 }
        override fun close() { closed++ }
    }
    @Test fun duplicateIsOwnedBeforeValidationAndOriginalDetachesOnlyAfterProof() {
        val source = Source()
        var reads = 0
        val owner = RuntimeTunProofOwner({ true }, { fd, destination, written ->
            assertEquals(71, fd); assertEquals(1, source.duplicates)
            if (++reads == 1) assertFalse(source.detached)
            destination.put(0, 't'.code.toByte()); destination.put(1, 'u'.code.toByte()); destination.put(2, 'n'.code.toByte())
            written[0] = 3; 0
        })
        val platform = PlatformTunOwner({ source }, { owner.adoptEstablished(it) }, { it.detach() })
        assertNotNull(platform.establish())
        assertFalse(source.detached)
        assertEquals(70, platform.detachFileDescriptor())
        platform.close()
        assertTrue(source.detached); assertEquals(1, source.closed)
        assertEquals("tun", owner.interfaceName())
        owner.close(); owner.close()
        assertEquals(1, source.duplicateClosed)
        assertNull(owner.interfaceName())
    }
    @Test fun staleStartOrFailedIoctlNeverDetachesAndClosesPartialOwnership() {
        for (stale in listOf(true, false)) {
            val source = Source()
            val owner = RuntimeTunProofOwner({ !stale }, { _, _, _ -> 14 })
            val platform = PlatformTunOwner({ source }, { owner.adoptEstablished(it) }, { it.detach() })
            assertThrows(IllegalStateException::class.java) { platform.establish() }
            assertEquals(1, source.duplicates)
            assertFalse(source.detached)
            assertEquals(1, source.closed)
            owner.close()
            assertEquals(1, source.duplicateClosed)
        }
    }

    @Test fun stopBeforeDuplicateReturnsClosesLateProofWithoutHealingCleanup() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val source = Source()
        val owner = RuntimeTunProofOwner({ true }, { _, _, _ -> 14 })
        val worker = Thread {
            assertThrows(IllegalStateException::class.java) {
                owner.adoptEstablished(RuntimeTunSourceV1 {
                    entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); source.duplicate()
                })
            }
        }.apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { owner.close() }
        release.countDown(); worker.join(5000); assertFalse(worker.isAlive)
        assertEquals(1, source.duplicateClosed)
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { owner.close() }
    }
}
