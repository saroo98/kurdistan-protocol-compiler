// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test

class RuntimeProductionSocketOwnerTest {
    @Test fun tunCanUseOnlyTheActuallyProtectedAndBoundCurrentNetwork() {
        for (fail in listOf(false, true)) {
            val platform = Platform().also { it.failBind = fail }
            val owner = RuntimeProductionSocketOwner(platform, { true }, {})
            assertTrue(owner.acquire(identity()))
            assertEquals(0L, owner.boundNetworkHandle())
            assertEquals(if (fail) 9 else 0, owner.confirm(1, 0, 0))
            assertEquals(if (fail) 0L else Long.MIN_VALUE, owner.boundNetworkHandle())
            platform.usable = false
            assertEquals(0L, owner.boundNetworkHandle())
            owner.close()
            assertEquals(0L, owner.boundNetworkHandle())
        }
    }
    @Test fun initialBenignCallbacksDoNotInvalidateTheActualSelectionRevision() {
        val revision = RuntimeSocketSelectionRevisionV1()
        val before = revision.snapshot()
        // Same decisions used by onAvailable, valid capabilities and unchanged interface.
        repeat(3) { assertTrue(revision.observe(false)) }
        assertTrue(revision.unchanged(before))
    }
    @Test fun actualInvalidationAndRevisionExhaustionRemainFailClosed() {
        val revision = RuntimeSocketSelectionRevisionV1()
        val before = revision.snapshot()
        assertTrue(revision.observe(true))
        assertFalse(revision.unchanged(before))
        assertTrue(revision.unchanged(revision.snapshot()))
        revision.javaClass.getDeclaredField("value").apply { isAccessible = true }.setLong(revision, Long.MAX_VALUE)
        assertFalse(revision.observe(false))
        assertFalse(revision.observe(true))
        assertFalse(revision.unchanged(Long.MAX_VALUE))
    }
    private class Platform : RuntimeSocketPlatformV1 {
        val events = mutableListOf<String>()
        var loss: (() -> Unit)? = null
        var protect = true
        var failBind = false
        var failClose = false
        var onSelect: (() -> Unit)? = null
        var usable = true
        override fun duplicate(fd: Int) { assertEquals(7, fd); events += "duplicate" }
        override fun observe(lost: () -> Unit) { events += "observe"; loss = lost }
        override fun select(explicit: Int, has: Int, handle: Long): Long { events += "select"; onSelect?.invoke(); return Long.MIN_VALUE }
        override fun current() = usable
        override fun protect(): Boolean { events += "protect"; return protect }
        override fun bind() { events += "bind"; check(!failBind) }
        override fun close() { events += "close"; check(!failClose) }
    }
    private fun identity() = RuntimeSocketIdentityV1(1,2,3,7,0,0,0)

    @Test fun duplicateAndCallbackPrecedeSnapshotThenProtectPrecedesOneBind() {
        val platform = Platform()
        val owner = RuntimeProductionSocketOwner(platform, { true }, {})
        assertTrue(owner.acquire(identity()))
        assertEquals(listOf("duplicate","observe","select"), platform.events)
        assertEquals(0, owner.confirm(1,0,0))
        assertEquals(3, owner.confirm(1,0,0))
        assertEquals(listOf("duplicate","observe","select","protect","bind"), platform.events)
        owner.close(); owner.close()
        assertEquals(1, platform.events.count { it == "close" })
    }
    @Test fun lossFalseProtectAndBindFailureNeverProduceSuccess() {
        for (mode in 0..3) {
            val platform = Platform(); var losses = 0
            val owner = RuntimeProductionSocketOwner(platform, { true }, { losses++ })
            assertTrue(owner.acquire(identity()))
            when (mode) { 0 -> platform.loss!!(); 1 -> platform.protect = false; 2 -> platform.failBind = true }
            val status = owner.confirm(if (mode==3) 0 else 1,0,0)
            assertEquals(if (mode==0) 9 else if (mode==2) 9 else 16,status)
            assertFalse(platform.events.contains("bind") && mode!=2)
            owner.close()
            assertTrue(losses > 0)
        }
    }
    @Test fun selectedLossOrStaleSnapshotDuringAcquisitionCannotPublishAHandle() {
        for (loss in listOf(false, true)) {
            val platform = Platform()
            val owner = RuntimeProductionSocketOwner(platform, { true }, {})
            platform.onSelect = { if (loss) platform.loss!!() else platform.usable = false }
            assertFalse(owner.acquire(identity()))
            assertEquals(0L, owner.selectedHandle())
            assertEquals(9, owner.confirm(1, 0, 0))
            owner.close()
            assertEquals(1, platform.events.count { it == "close" })
            assertFalse(platform.events.contains("protect"))
            assertFalse(platform.events.contains("bind"))
        }
    }
    @Test fun staleStartStillOwnsAndClosesDuplicateAndFailedCloseCannotHeal() {
        val platform = Platform()
        val owner = RuntimeProductionSocketOwner(platform, { false }, {})
        assertThrows(IllegalStateException::class.java) { owner.acquire(identity()) }
        assertEquals(listOf("duplicate"), platform.events)
        platform.failClose = true
        assertThrows(IllegalStateException::class.java) { owner.close() }
        platform.failClose = false
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { owner.close() }
        assertEquals(1, platform.events.count { it == "close" })
    }

    @Test fun failedNativeLossSignalStillAttemptsActualDuplicateAndCallbackCleanup() {
        val platform = Platform()
        val owner = RuntimeProductionSocketOwner(platform, { true }, { error("signal failure") })
        owner.acquire(identity())
        assertThrows(IllegalStateException::class.java) { owner.close() }
        assertEquals(1, platform.events.count { it == "close" })
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { owner.close() }
    }

    @Test fun explicitHighBitSelectionIsExactAndImplicitCallerCannotInjectAnotherNetwork() {
        for ((identity, has, network, expected) in listOf(
            arrayOf(identity().copy(explicit = 1, hasNetwork = 1, network = Long.MIN_VALUE), 1, Long.MIN_VALUE, 0),
            arrayOf(identity().copy(explicit = 1, hasNetwork = 1, network = Long.MIN_VALUE), 1, 4L, 9),
            arrayOf(identity(), 1, Long.MIN_VALUE, 9),
        )) {
            val platform = Platform()
            val owner = RuntimeProductionSocketOwner(platform, { true }, {})
            owner.acquire(identity as RuntimeSocketIdentityV1)
            assertEquals(expected, owner.confirm(1, has as Int, network as Long))
            assertEquals(expected == 0, platform.events.contains("bind"))
            owner.close()
        }
    }
}
