// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProductFailureCode

class BootstrapBindingCodecV1Test {
    @Test fun capacityInvariantSignalIsCanonicalInternalAndPermanentlyRefusesBothRoles() {
        val calls=BootstrapBindingCallOwnerV1(BootstrapBindingGuardV1())
        val first=calls.legacy(material(),ByteBuffer.wrap(byteArrayOf(1)),{
            assertEquals(14,it);OperationError.INTERNAL_FAILURE
        }){_,_,_,_,_->-6401}
        assertEquals(OperationError.INTERNAL_FAILURE,(first as NativeResult.Failure).error)
        val next=calls.production(material(),ByteBuffer.wrap(byteArrayOf(1))){_,_,_,_,_->2}
        assertEquals(ProductFailureCode.RESOURCE_LIMIT,(next as NativeProductResult.Failure).code)
    }
    @Test fun productionCapacitySignalWipesButCannotReopenForLegacy() {
        val calls=BootstrapBindingCallOwnerV1(BootstrapBindingGuardV1())
        var held=listOf<ByteBuffer>()
        val result=calls.production(material(),ByteBuffer.wrap(byteArrayOf(1))){spans,facts,a,d,m->
            held=spans.toList()+listOf(facts,checkNotNull(a),checkNotNull(d),checkNotNull(m))
            held.forEach{buffer->repeat(buffer.capacity()){buffer.put(it,17)}}
            -6401
        }
        assertEquals(ProductFailureCode.INTERNAL_FAILURE,(result as NativeProductResult.Failure).code)
        assertWiped(held)
        val next=calls.legacy(material(),ByteBuffer.wrap(byteArrayOf(1)),{assertEquals(24,it);OperationError.RESOURCE_LIMIT}){_,_,_,_,_->fail("terminal guard invoked native");0}
        assertEquals(OperationError.RESOURCE_LIMIT,(next as NativeResult.Failure).error)
    }
    private fun assertWiped(buffers:List<ByteBuffer>) {
        buffers.forEach{buffer->val full=buffer.duplicate().apply{clear()};repeat(full.capacity()){assertEquals(0,full.get(it).toInt())}}
    }
    private fun catalogue(probe:Int):ByteArray {
        // Independent fixed KPA1 syntax: no strategy and exactly one named probe.
        val id="probe-$probe".toByteArray(Charsets.US_ASCII)
        return ByteBuffer.allocate(55+id.size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(0x4b504131);put(1);put(1);putShort(0);putInt(capacity())
            putLong(0x8000000000000001uL.toLong());put(ByteArray(32){1})
            put(0);put(1);put(id.size.toByte());put(id)
        }.array()
    }
    @Test fun actualProductionBoundaryKeepsDifferentRoleLanesAndClosesOwners() {
        val calls=BootstrapBindingCallOwnerV1(BootstrapBindingGuardV1())
        val a=catalogue(2);val d=catalogue(10);var held=listOf<ByteBuffer>()
        val input=material()
        val result=calls.production(input,ByteBuffer.wrap(byteArrayOf(1))){spans,facts,active,disconnected,metadata->
            held=spans.toList()+listOf(facts,checkNotNull(active),checkNotNull(disconnected),checkNotNull(metadata))
            facts.duplicate().put(wire());active.duplicate().put(a);disconnected.duplicate().put(d)
            metadata.duplicate().order(ByteOrder.BIG_ENDIAN).putInt(a.size).putInt(d.size);0
        }
        val pair=(result as NativeProductResult.Success).value
        assertTrue(pair.activeSelectors.containsProbe(2));assertFalse(pair.activeSelectors.containsProbe(10))
        assertTrue(pair.disconnectedSelectors.containsProbe(10));assertFalse(pair.disconnectedSelectors.containsProbe(2))
        assertWiped(held);assertEquals(1,input.verifyRequest.position());assertEquals(1,input.verifyRequest.get(1).toInt())
        pair.close()
        assertThrows(IllegalStateException::class.java){pair.activeSelectors.containsProbe(2)}
        assertThrows(IllegalStateException::class.java){pair.disconnectedSelectors.containsProbe(10)}
    }
    @Test fun malformedSecondCatalogueOrMetadataNeverPublishesAndWipesAllStaging() {
        for(kind in listOf("second","active-length","disconnected-length")) {
            val calls=BootstrapBindingCallOwnerV1(BootstrapBindingGuardV1());var held=listOf<ByteBuffer>()
            val a=catalogue(2);val d=catalogue(10)
            val result=calls.production(material(),ByteBuffer.wrap(byteArrayOf(1))){spans,facts,active,disconnected,metadata->
                held=spans.toList()+listOf(facts,checkNotNull(active),checkNotNull(disconnected),checkNotNull(metadata))
                facts.duplicate().put(wire());active.duplicate().put(a);disconnected.duplicate().put(d)
                if(kind=="second")disconnected.put(0,0)
                metadata.duplicate().order(ByteOrder.BIG_ENDIAN).putInt(if(kind=="active-length")513 else a.size).putInt(if(kind=="disconnected-length")53 else d.size);0
            }
            assertEquals(kind,ProductFailureCode.INTERNAL_FAILURE,(result as NativeProductResult.Failure).code)
            assertWiped(held)
            val next=calls.production(material(),ByteBuffer.wrap(byteArrayOf(1))){_,_,_,_,_->5}
            assertEquals(ProductFailureCode.RESOURCE_LIMIT,(next as NativeProductResult.Failure).code)
            val last=calls.production(material(),ByteBuffer.wrap(byteArrayOf(1))){_,_,_,_,_->2}
            assertEquals(ProductFailureCode.INVALID_INPUT,(last as NativeProductResult.Failure).code)
        }
    }
    @Test fun malformedSecondCatalogueRetiresAlreadyDecodedActualFirstOwner() {
        val facts=BootstrapBindingCodecV1.decodeProduction(ByteBuffer.wrap(wire()))
        val first=ProductionSelectorCodecV1.decodeActive(ByteBuffer.wrap(catalogue(2)),facts)
        val owner=first.javaClass.getDeclaredField("owner").run{isAccessible=true;get(first)}
        val bytes=owner.javaClass.getDeclaredField("bytes").run{isAccessible=true;get(owner) as ByteArray}
        assertTrue(bytes.any{it!=0.toByte()})
        val malformed=catalogue(10).apply{this[0]=0}
        assertThrows(IllegalArgumentException::class.java){completeBootstrapSelectorPairV1(facts,first,ByteBuffer.wrap(malformed),malformed.size)}
        assertTrue(bytes.all{it==0.toByte()})
        assertThrows(IllegalStateException::class.java){first.containsProbe(2)}
    }
    @Test fun changedOwnedBufferLimitDoesNotDefeatFullCapacityWipe() {
        var held:Array<ByteBuffer>?=null
        val result=BootstrapBindingCallsV1.legacy(material(),ByteBuffer.wrap(byteArrayOf(1)),{OperationError.INTERNAL_FAILURE}) { spans,_,_,_,_ ->
            held=spans;spans[0].limit(0);throw IllegalStateException("boundary changed span")
        }
        assertTrue(result is NativeResult.Failure)
        checkNotNull(held).forEach{buffer->val full=buffer.duplicate().apply{clear()};repeat(full.capacity()){assertEquals(0,full.get(it).toInt())}}
        val next=BootstrapBindingCallsV1.production(material(),ByteBuffer.wrap(byteArrayOf(1))){_,_,_,_,_->2}
        assertEquals(ProductFailureCode.INVALID_INPUT,(next as NativeProductResult.Failure).code)
    }
    private fun material():NativeBootstrapMaterialV1 {
        fun span()=ByteBuffer.wrap(byteArrayOf(8,1,9)).order(ByteOrder.LITTLE_ENDIAN).apply{position(1);limit(2)}.asReadOnlyBuffer()
        return NativeBootstrapMaterialV1(span(),span(),span(),span())
    }
    @Test fun actualStagingRejectsContentionAndWipesExceptionBeforeReadmission() {
        val input=material();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        var held:Array<ByteBuffer>?=null;var output:ByteBuffer?=null
        var result:NativeResult<NativeLegacyBootstrapFactsV1>?=null
        val worker=Thread {
            result=BootstrapBindingCallsV1.legacy(input,ByteBuffer.wrap(byteArrayOf(1)),{OperationError.INTERNAL_FAILURE}) { spans,facts,_,_,_ ->
                held=spans;output=facts
                assertEquals(1,input.verifyRequest.position())
                assertEquals(1,spans[0].remaining())
                entered.countDown();check(release.await(5,TimeUnit.SECONDS))
                // A JNI/copy exception must wipe every allocated owner.
                throw IllegalStateException("test boundary failure")
            }
        }
        worker.start();assertTrue(entered.await(5,TimeUnit.SECONDS))
        val competing=BootstrapBindingCallsV1.production(input,ByteBuffer.wrap(byteArrayOf(1))) { _,_,_,_,_ -> fail("competing call staged");0 }
        assertEquals(ProductFailureCode.RESOURCE_LIMIT,(competing as NativeProductResult.Failure).code)
        release.countDown();worker.join(5000);assertFalse(worker.isAlive)
        assertTrue(result is NativeResult.Failure)
        checkNotNull(held).forEach{buffer->repeat(buffer.capacity()){assertEquals(0,buffer.get(it).toInt())}}
        repeat(checkNotNull(output).capacity()){assertEquals(0,checkNotNull(output).get(it).toInt())}
        val next=BootstrapBindingCallsV1.legacy(input,ByteBuffer.wrap(byteArrayOf(1)),{OperationError.INTERNAL_FAILURE}) { _,facts,_,_,_ ->
            facts.put(wire().copyOfRange(0,40)+byteArrayOf(5));facts.position(0);0
        }
        assertTrue(next is NativeResult.Success)
        assertEquals(1,input.verifyRequest.position());assertEquals(1,input.verifyRequest.get(1).toInt())
    }
    private fun wire() = byteArrayOf(0x80.toByte(),0,0,0,0,0,0,1) + ByteArray(32) { 1 } + byteArrayOf(5,0,5,3)
    @Test fun independentFactsPreserveUnsignedAndCallerSpan() {
        val raw = byteArrayOf(9) + wire() + byteArrayOf(9)
        val input = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).apply { position(1); limit(45) }
        val facts = BootstrapBindingCodecV1.decodeProduction(input)
        assertEquals(0x8000000000000001uL, facts.generation)
        assertEquals(1280,facts.effectiveMtu); assertEquals(5,facts.signedRetryMaximum)
        assertEquals(3,facts.effectiveAutomaticReconnectMaximum)
        assertEquals(1,input.position()); assertEquals(ByteOrder.LITTLE_ENDIAN,input.order())
        raw.fill(0); val digest=facts.planDigest; digest.fill(0)
        assertArrayEquals(ByteArray(32){1},facts.planDigest)
        val legacy=BootstrapBindingCodecV1.decodeLegacy(ByteBuffer.wrap(wire().copyOfRange(0,40)+byteArrayOf(5)))
        assertEquals(facts.generation,legacy.generation);assertEquals(5,legacy.signedRetryMaximum)
    }
    @Test fun malformedSuccessFactsNeverDecode() {
        val valid=wire()
        val variants=(0 until valid.size).map { valid.copyOf(it) } + listOf(valid+byteArrayOf(0),
            valid.copyOf().apply { fill(0,0,8) },valid.copyOf().apply { fill(0,8,40) },
            valid.copyOf().apply { this[40]=0;this[41]=0 },valid.copyOf().apply { this[42]=6 },
            valid.copyOf().apply { this[40]=5;this[41]=1 },
            valid.copyOf().apply { this[43]=6 })
        variants.forEach { assertThrows(IllegalArgumentException::class.java) { BootstrapBindingCodecV1.decodeProduction(ByteBuffer.wrap(it)) } }
    }
    @Test fun sharedGuardContendsBeforeStagingAndHoldsThroughCleanup() {
        val entered=CountDownLatch(1);val leave=CountDownLatch(1);val cleaned=CountDownLatch(1)
        val guard=BootstrapBindingGuardV1()
        val first=Thread {
            assertTrue(guard.tryAcquire())
            try { entered.countDown();assertTrue(leave.await(5,TimeUnit.SECONDS)) }
            finally { cleaned.countDown();guard.finish(true) }
        }
        first.start();assertTrue(entered.await(5,TimeUnit.SECONDS))
        assertFalse(guard.tryAcquire())
        leave.countDown();first.join(5000);assertFalse(first.isAlive);assertEquals(0L,cleaned.count)
        assertTrue(guard.tryAcquire());guard.finish(false)
        assertFalse(guard.tryAcquire())
    }
}
