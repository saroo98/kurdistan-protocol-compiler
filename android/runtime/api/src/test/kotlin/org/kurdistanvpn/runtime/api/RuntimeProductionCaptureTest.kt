// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Test

class RuntimeProductionCaptureTest {
    @Test fun exactSizesAreAvailableBeforeAllocatingAnyRowCopy() {
        val rows = listOf(2, 3, 5, 7, 11).map { ByteArray(it) { 9 } }
        val encoded = ByteBuffer.allocate(60)
        RuntimeCaptureCodecV1.encode(parts(rows), encoded)
        val snapshot = RuntimeCaptureCodecV1.decode(encoded)
        val sizes = IntArray(5) { -9 }
        snapshot.copySizesInto(sizes)
        assertArrayEquals(intArrayOf(2, 3, 5, 7, 11), sizes)
        for (count in listOf(0, 4, 6)) {
            val invalid = IntArray(count) { -9 }
            assertThrows(IllegalArgumentException::class.java) { snapshot.copySizesInto(invalid) }
            assertArrayEquals(IntArray(count) { -9 }, invalid)
        }
        snapshot.close()
        sizes.fill(-9)
        assertThrows(IllegalArgumentException::class.java) { snapshot.copySizesInto(sizes) }
        assertArrayEquals(IntArray(5) { -9 }, sizes)
    }

    @Test fun legacyPolicyFacadeKeepsExactKrsBytes() {
        val expected="4b52533101010101010005dc00000000000000000001000000010101".chunked(2).map{it.toInt(16).toByte()}.toByteArray()
        assertArrayEquals(expected,RuntimeStartWire.encodeLegacyBootstrapPolicy(VpnRuntimeConfig(VpnRoutingPolicy())))
        assertThrows(IllegalArgumentException::class.java){
            RuntimeStartWire.encodeLegacyBootstrapPolicy(VpnRuntimeConfig(VpnRoutingPolicy(),manualStrategyId=" ".repeat(257)))
        }
    }
    private val minimum = byteArrayOf(75,67,84,49,1,0,0,0,0,0,0,37,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,11,22,33,44,55)
    private fun parts(rows: List<ByteArray>) = RuntimeCapturePartsV1(ByteBuffer.wrap(rows[0]),ByteBuffer.wrap(rows[1]),ByteBuffer.wrap(rows[2]),ByteBuffer.wrap(rows[3]),ByteBuffer.wrap(rows[4]))
    private fun rejects(block: () -> Unit) { try { block(); fail("accepted invalid capture") } catch (_: IllegalArgumentException) {} }

    @Test fun exactIndependentMinimumAndCallerSpans() {
        val rows = listOf(11,22,33,44,55).map { ByteBuffer.wrap(byteArrayOf(99,it.toByte(),88)).apply { position(1); limit(2); order(ByteOrder.LITTLE_ENDIAN) } }
        val input = RuntimeCapturePartsV1(rows[0],rows[1],rows[2],rows[3],rows[4])
        val output = ByteBuffer.allocate(39).apply { position(1); limit(38); order(ByteOrder.LITTLE_ENDIAN) }
        assertEquals(37, RuntimeCaptureCodecV1.encode(input, output))
        assertArrayEquals(minimum, output.array().copyOfRange(1,38))
        assertEquals(1, output.position()); assertEquals(ByteOrder.LITTLE_ENDIAN,output.order())
        rows.forEach { assertEquals(1,it.position()); assertEquals(2,it.limit()) }
    }

    @Test fun snapshotOwnsOneIsolatedEncodingAndCloses() {
        val source = minimum.copyOf()
        val snapshot = RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(source))
        source.fill(0)
        val output = ByteBuffer.allocate(3).apply { position(1); limit(2) }
        assertEquals(1,snapshot.copyVerifyRequestTo(output)); assertEquals(11,output.get(1).toInt())
        assertEquals(1,snapshot.copyActivationRecordTo(output)); assertEquals(22,output.get(1).toInt())
        assertEquals(1,snapshot.copyRecipientRequestTo(output)); assertEquals(33,output.get(1).toInt())
        assertEquals(1,snapshot.copyRecipientPrivateTo(output)); assertEquals(44,output.get(1).toInt())
        assertEquals(1,snapshot.copySettingsTo(output)); assertEquals(55,output.get(1).toInt())
        assertEquals(1,output.position()); assertEquals(37,snapshot.length)
        snapshot.close(); snapshot.close()
        rejects { snapshot.copySettingsTo(output) }
    }

    @Test fun headerMutationsAndOtherFormatsRejectBeforeCopy() {
        for (offset in 0 until 32) {
            val mutation = minimum.copyOf(); mutation[offset] = (mutation[offset].toInt() xor 1).toByte()
            rejects { RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(mutation)) }
        }
        for (length in 0 until minimum.size) rejects { RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(minimum.copyOf(length))) }
        rejects { RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(minimum + 0)) }
        for (magic in listOf("KPO1","KRV2")) {
            val mutation=minimum.copyOf(); magic.toByteArray().copyInto(mutation)
            rejects { RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(mutation)) }
        }
    }

    @Test fun maximumAndEveryRowBoundaryWithNoPartialWrite() {
        val maxima = listOf(1_405_996,1_118_299,512,128,196_608)
        val rows=maxima.map { ByteArray(it) { 7 } }
        val output=ByteBuffer.allocate(2_721_575)
        assertEquals(2_721_575,RuntimeCaptureCodecV1.encode(parts(rows),output))
        RuntimeCaptureCodecV1.decode(output).use { assertEquals(2_721_575,it.length) }
        for(index in maxima.indices) for(size in listOf(0,maxima[index]+1)) {
            val invalid=rows.toMutableList(); invalid[index]=ByteArray(size)
            val sentinel=ByteBuffer.wrap(ByteArray(64) { 99 })
            rejects { RuntimeCaptureCodecV1.encode(parts(invalid),sentinel) }
            assertTrue(sentinel.array().all { it == 99.toByte() })
        }
        rejects { RuntimeCaptureCodecV1.encode(parts(List(5) { byteArrayOf(1) }),ByteBuffer.allocate(36)) }
        rejects { RuntimeCaptureCodecV1.encode(parts(List(5) { byteArrayOf(1) }),ByteBuffer.allocate(37).asReadOnlyBuffer()) }
        RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(minimum)).use {
            rejects { it.copySettingsTo(ByteBuffer.allocate(0)) }
            rejects { it.copySettingsTo(ByteBuffer.allocate(1).asReadOnlyBuffer()) }
        }
    }
}
