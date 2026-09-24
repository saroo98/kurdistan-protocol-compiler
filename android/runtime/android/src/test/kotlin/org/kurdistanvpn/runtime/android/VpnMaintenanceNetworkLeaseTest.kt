// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class VpnMaintenanceNetworkLeaseTest {
    @Test fun initialCallbackBurstDoesNotRejectUnchangedNetworkFacts() {
        val observation = RuntimeMaintenanceObservationV1()
        val expected = Platform().value
        var calls = 0
        val actual = maintenanceStableSnapshotV1({ true }) {
            calls++
            val before = observation.revision
            repeat(8) { assertFalse(observation.event { false }) }
            observation.capture(before, expected)
        }
        assertSame(expected, actual)
        assertEquals(2, calls)
        assertTrue(observation.event { it.dns[0].contentEquals(byteArrayOf(1,1,1,1)) })
        // A real invalidating event cannot be hidden by a matching later observation.
        try { observation.capture(observation.revision, expected); fail("lost selection accepted") }
        catch (failure: RuntimeMaintenanceNetworkFailureV1) { assertEquals(10, failure.status) }
    }
    @Test fun snapshotOverlapCannotReplaceItsProvisionalDnsSelection() {
        val observation = RuntimeMaintenanceObservationV1()
        val expected = Platform().value
        val before = observation.revision
        assertFalse(observation.event { false })
        assertNull(observation.capture(before, expected))
        try {
            observation.capture(observation.revision, expected.copy(dns=arrayOf(byteArrayOf(8,8,8,8))))
            fail("changed DNS accepted")
        } catch (failure: RuntimeMaintenanceNetworkFailureV1) { assertEquals(10, failure.status) }
        try { observation.capture(observation.revision, expected); fail("invalidated selection revived") }
        catch (failure: RuntimeMaintenanceNetworkFailureV1) { assertEquals(10, failure.status) }
    }
    @Test fun startupSnapshotRetriesOnlyConcurrentObservationAndRemainsBounded() {
        val expected = Platform().value
        var calls = 0
        assertSame(expected, maintenanceStableSnapshotV1({ true }) { if (++calls < 3) null else expected })
        assertEquals(3, calls)
        calls = 0
        try { maintenanceStableSnapshotV1({ true }) { calls++; null }; fail("unstable snapshot accepted") }
        catch (failure: RuntimeMaintenanceNetworkFailureV1) { assertEquals(10, failure.status) }
        assertEquals(3, calls)
        calls = 0
        val failure = RuntimeMaintenanceNetworkFailureV1(6)
        try { maintenanceStableSnapshotV1({ true }) { calls++; throw failure }; fail("failure hidden") }
        catch (actual: RuntimeMaintenanceNetworkFailureV1) { assertSame(failure, actual) }
        assertEquals(1, calls)
        for (overlap in listOf(true, false)) {
            calls = 0
            var current = true
            try {
                maintenanceStableSnapshotV1({ current }) { calls++; current = false; if (overlap) null else expected }
                fail("network replacement accepted")
            } catch (actual: RuntimeMaintenanceNetworkFailureV1) { assertEquals(10, actual.status) }
            assertEquals(1, calls)
        }
    }
    @Test fun supportedApiBoundariesKeepPrivateDnsOwnerAndVisibleVpnChecks() {
        for (api in listOf(26, 27, 28, 29, 30, 36)) {
            for ((active, name) in listOf(true to null, false to "strict.example")) {
                val platform = Platform().apply {
                    apiLevel = api
                    value = value.copy(privateDnsActive = active, privateDnsName = name)
                }
                val owner = VpnMaintenanceNetworkLease(platform, 1, { true }, { null }, { true }, {})
                assertEquals(if (api >= 28) 10 else 0, owner.acquire())
                owner.close()
            }
            val active = Platform().apply {
                apiLevel = api
                value = value.copy(vpn = true, ownerUid = 1002, interfaceName = "tun0", visibleVpn = true)
            }
            val activeOwner = VpnMaintenanceNetworkLease(active, 2, { true }, { "tun0" }, { false }, {})
            assertEquals(if (api >= 30) 10 else 0, activeOwner.acquire())
            activeOwner.close()
            val disconnected = Platform().apply { apiLevel = api; value = value.copy(visibleVpn = true) }
            val disconnectedOwner = VpnMaintenanceNetworkLease(disconnected, 1, { true }, { null }, { true }, {})
            assertEquals(10, disconnectedOwner.acquire())
            disconnectedOwner.close()
        }
    }

    private class Platform : RuntimeMaintenanceNetworkPlatformV1 {
        override var apiLevel = 30
        override val ownUid = 1001
        val events = mutableListOf<String>()
        var changed: (() -> Unit)? = null
        var value = RuntimeMaintenanceNetworkSnapshotV1(Long.MIN_VALUE, false, -1, "eth0", 1,
            arrayOf(byteArrayOf(1,1,1,1)), false, null, 2, false)
        override fun observeDefault(lost: () -> Unit) { events += "default"; changed = lost }
        override fun observeVisible(lost: () -> Unit) { events += "visible" }
        override fun snapshot(): RuntimeMaintenanceNetworkSnapshotV1 { events += "snapshot"; return value }
        override fun bind(fd: Int) { events += "bind:$fd" }
        override fun close() { events += "close" }
    }
    @Test fun bothCallbacksPrecedeBoundedSnapshotAndPrivateRowsAreExact() {
        val platform = Platform()
        val owner = VpnMaintenanceNetworkLease(platform, 1, { true }, { null }, { true }, {})
        assertEquals(0, owner.acquire())
        assertEquals(listOf("default","visible","snapshot"),platform.events)
        val dns = ByteBuffer.allocateDirect(76); val meta = IntArray(3)
        assertEquals(0, owner.copySnapshot(dns,meta))
        assertArrayEquals(intArrayOf(1,1,1),meta)
        assertEquals(4,dns.get(0).toInt()); for(i in 1..4) assertEquals(1,dns.get(i).toInt())
        assertEquals(0,dns.get(17).toInt()); assertEquals(53,dns.get(18).toInt())
        for(i in 19 until 76) assertEquals(0,dns.get(i).toInt())
        assertEquals(0,owner.bindSocket(7)); assertTrue(platform.events.contains("bind:7"))
        owner.close(); owner.close(); assertEquals(1,platform.events.count{it=="close"})
    }
    @Test fun disconnectedRefusesOtherVpnPrivateDnsOversizeAndChangedDns() {
        val variants = listOf<Pair<(RuntimeMaintenanceNetworkSnapshotV1)->RuntimeMaintenanceNetworkSnapshotV1,Int>>(
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(visibleVpn=true)} to 10,
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(privateDnsActive=true)} to 10,
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(privateDnsName="strict.example")} to 10,
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(visibleCount=65)} to 6,
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(visibleCount=0)} to 10,
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(families=2,dns=arrayOf(byteArrayOf(0xfe.toByte(),0x80.toByte())+ByteArray(13)+byteArrayOf(1)))} to 10,
            {s:RuntimeMaintenanceNetworkSnapshotV1->s.copy(dns=Array(5){byteArrayOf(1,1,1,it.toByte())})} to 6,
        )
        for((alter,status) in variants) {
            val platform=Platform();platform.value=alter(platform.value)
            val owner=VpnMaintenanceNetworkLease(platform,1,{true},{null},{true},{})
            assertEquals(status,owner.acquire());owner.close()
        }
        val platform=Platform();var loss=0
        val owner=VpnMaintenanceNetworkLease(platform,1,{true},{null},{true},{loss++})
        assertEquals(0,owner.acquire())
        platform.value=platform.value.copy(dns=arrayOf(byteArrayOf(8,8,8,8)))
        assertFalse(owner.isCurrent());assertEquals(1,loss)
        assertEquals(10,owner.bindSocket(7));assertFalse(platform.events.contains("bind:7"));owner.close()
    }
    @Test fun activeRequiresActualTunNameAndOwnUidWithoutDisconnectedFallback() {
        for((name,uid,status) in listOf(Triple("tun0",1001,0),Triple(null,1001,10),Triple("tun1",1001,10),Triple("tun0",1002,10))) {
            val platform=Platform();platform.value=platform.value.copy(vpn=true,ownerUid=uid,interfaceName="tun0",visibleVpn=true)
            val owner=VpnMaintenanceNetworkLease(platform,2,{true},{name},{false},{})
            assertEquals(status,owner.acquire());owner.close()
        }
        val platform=Platform();platform.apiLevel=26
        platform.value=platform.value.copy(vpn=true,ownerUid=-1,interfaceName="tun0",visibleVpn=true)
        val owner=VpnMaintenanceNetworkLease(platform,2,{true},{"tun0"},{false},{})
        assertEquals(0,owner.acquire());owner.close()
    }
}
