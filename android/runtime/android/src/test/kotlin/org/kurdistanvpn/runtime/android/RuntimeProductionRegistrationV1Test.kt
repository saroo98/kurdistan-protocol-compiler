// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class RuntimeProductionRegistrationV1Test {
    @Test fun explicitMaintenanceRearmRequiresRetirementAndNeverRevivesAnInvalidatedArm() {
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long) = 0
            override fun invalidate(owner: Long, signal: Long) = 0
        })
        assertTrue(registration.register(1, 11, 111))
        assertTrue(registration.register(2, 22, 222))
        assertFalse(registration.rearmMaintenanceAfterRetirement())
        assertTrue(registration.retire(2, 22, 222))
        assertFalse(registration.register(2, 33, 333))
        assertTrue(registration.rearmMaintenanceAfterRetirement())
        assertTrue(registration.register(2, 33, 333))
        assertFalse(registration.isCurrent(2, 22, 222))
        assertFalse(registration.retire(2, 22, 222))
        assertTrue(registration.isCurrent(1, 11, 111))
        assertTrue(registration.invalidate())
        assertTrue(registration.retire(2, 33, 333))
        assertFalse(registration.rearmMaintenanceAfterRetirement())
        assertFalse(registration.register(2, 44, 444))
    }
    @Test fun pendingPublicationFencesWithoutClaimingOrJoiningRetirement() {
        val events = mutableListOf<String>()
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long): Int { events += "f$owner"; return 0 }
            override fun invalidate(owner: Long, signal: Long): Int { events += "i$owner"; return 0 }
        })
        assertTrue(registration.register(1, 11, 111))
        assertTrue(registration.register(2, 22, 222))
        assertTrue(registration.fencePendingPublication())
        assertEquals(listOf("f11", "f22"), events)
        assertFalse(registration.isCurrent(1, 11, 111))
        assertFalse(registration.isRetired())
        assertFalse(registration.register(1, 33, 333))
        assertTrue(registration.retire(1, 11, 111))
        assertFalse(registration.isRetired())
        assertTrue(registration.retire(2, 22, 222))
        assertTrue(registration.isRetired())
    }
    @Test fun retiredSubscriberCannotBeSignalledOrReplacedAndWrongIdentityCannotRetireIt() {
        val invoked = mutableListOf<Long>()
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long): Int { invoked += owner; return 0 }
            override fun invalidate(owner: Long, signal: Long): Int { invoked += owner; return 0 }
        })
        assertTrue(registration.register(1, 11, 111))
        assertTrue(registration.register(2, 22, 222))
        assertFalse(registration.retire(2, 22, 223))
        assertTrue(registration.isCurrent(2, 22, 222))
        assertTrue(registration.retire(2, 22, 222))
        assertFalse(registration.register(2, 33, 333))
        assertFalse(registration.retire(2, 22, 222))
        assertTrue(registration.invalidate())
        assertEquals(listOf(11L, 11L), invoked)
        assertTrue(registration.retire(1, 11, 111))
        assertTrue(registration.isRetired())
    }

    @Test fun bothGatesFenceBeforeEitherSinkAndFailuresDoNotSkipTheSecondSink() {
        val events = mutableListOf<String>()
        val signals = object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long): Int {
                events += "f$owner"
                assertEquals(if (owner == Long.MIN_VALUE) 11L else 22L, signal)
                return 0
            }
            override fun invalidate(owner: Long, signal: Long): Int {
                assertEquals(listOf("f${Long.MIN_VALUE}", "f2"), events.take(2))
                events += "i$owner"
                return if (owner == Long.MIN_VALUE) 25 else 0
            }
        }
        val registration = RuntimeProductionRegistrationV1(signals)
        assertTrue(registration.register(1, Long.MIN_VALUE, 11))
        assertTrue(registration.register(2, 2, 22))
        assertFalse(registration.register(2, 3, 33))
        assertFalse(registration.invalidate())
        assertEquals(listOf("f${Long.MIN_VALUE}", "f2", "i${Long.MIN_VALUE}", "i2"), events)
        assertFalse(registration.isCurrent(1, Long.MIN_VALUE, 11))
        assertFalse(registration.invalidate())
        assertEquals(4, events.size)
    }

    @Test fun failedPreFenceStillAttemptsBothFencesAndSinksWithoutHealing() {
        val events = mutableListOf<String>()
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long): Int {
                events += "f$owner"
                if (owner == 1L) throw IllegalStateException("fence failure")
                return 0
            }
            override fun invalidate(owner: Long, signal: Long): Int {
                events += "i$owner"
                return 0
            }
        })
        assertTrue(registration.register(1, 1, 11))
        assertTrue(registration.register(2, 2, 22))
        assertFalse(registration.invalidate())
        assertEquals(listOf("f1", "f2", "i1", "i2"), events)
        assertFalse(registration.invalidate())
    }

    @Test fun concurrentInvalidationAndCloseInsideHandlerNeverDuplicateOrJoin() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var sinks = 0
        lateinit var registration: RuntimeProductionRegistrationV1
        registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long) = 0
            override fun invalidate(owner: Long, signal: Long): Int {
                sinks++
                try { registration.close(); fail("handler close accepted") }
                catch (_: RuntimeAuthorityCleanupUnprovenException) { }
                entered.countDown()
                assertTrue(release.await(5, TimeUnit.SECONDS))
                return 0
            }
        })
        assertTrue(registration.register(1, 1, 11))
        var clean = true
        val worker = thread { clean = registration.invalidate() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertFalse(registration.invalidate())
        release.countDown()
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertFalse(clean)
        assertEquals(1, sinks)
    }

    @Test fun invalidationBeforeSubscriberRegistrationNeverAdmitsLateOwner() {
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long): Int = error("unexpected fence")
            override fun invalidate(owner: Long, signal: Long): Int = error("unexpected sink")
        })
        assertTrue(registration.invalidate())
        assertFalse(registration.register(1, 1, 11))
        assertFalse(registration.isCurrent(1, 1, 11))
        registration.close()
    }
}
