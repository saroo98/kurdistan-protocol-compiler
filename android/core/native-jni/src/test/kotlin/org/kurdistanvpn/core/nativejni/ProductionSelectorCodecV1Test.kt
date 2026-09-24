// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class ProductionSelectorCodecV1Test {
    private fun facts()=BootstrapBindingCodecV1.decodeProduction(ByteBuffer.wrap(
        byteArrayOf(0x80.toByte(),0,0,0,0,0,0,1)+ByteArray(32){1}+byteArrayOf(5,0,5,3)))
    private fun wire()=byteArrayOf(75,80,65,49,1,1,0,0,0,0,0,71,
        0x80.toByte(),0,0,0,0,0,0,1)+ByteArray(32){1}+
        byteArrayOf(0,2,7,112,114,111,98,101,45,57,8,112,114,111,98,101,45,49,48)
    @Test fun pairedScopeRoleOwnersAndExactCopy() {
        val input=wire()
        val active=ProductionSelectorCodecV1.decodeActive(ByteBuffer.wrap(input),facts())
        val disconnected=ProductionSelectorCodecV1.decodeDisconnected(ByteBuffer.wrap(input),facts())
        input.fill(0)
        assertTrue(active.containsProbe(9));assertTrue(disconnected.containsProbe(10));assertFalse(active.containsProbe(1))
        val output=ByteBuffer.allocate(73).apply{position(1);limit(72)}
        assertEquals(71,active.copyTo(output));assertEquals(1,output.position())
        assertArrayEquals(wire(),output.array().copyOfRange(1,72))
        assertThrows(IllegalArgumentException::class.java){active.copyTo(ByteBuffer.allocate(70))}
        assertThrows(IllegalArgumentException::class.java){active.copyTo(ByteBuffer.allocate(71).asReadOnlyBuffer())}
        active.close();disconnected.close()
        assertThrows(IllegalStateException::class.java){active.containsProbe(9)}
    }
    @Test fun rejectBadGrammarFramingScopeAndOrder() {
        val good=wire()
        val bad=listOf(good+byteArrayOf(0),good.copyOf(70),
            good.copyOf().apply{this[19]=2},good.copyOf().apply{this[20]=0},
            good.copyOf().apply{this[4]=2},good.copyOf().apply{this[6]=1},
            good.copyOf().apply{this[61]=7})
        bad.forEach{assertThrows(IllegalArgumentException::class.java){
            ProductionSelectorCodecV1.decodeActive(ByteBuffer.wrap(it),facts())}}
    }
}
