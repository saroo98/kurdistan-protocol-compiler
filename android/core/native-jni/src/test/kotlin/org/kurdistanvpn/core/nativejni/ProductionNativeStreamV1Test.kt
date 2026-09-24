// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.lang.reflect.Proxy
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class ProductionNativeStreamV1Test {
    @Test fun completedParentRetirementProvesChildCleanupAfterInterruptedChildClose() {
        val parent = ProductionNativeParentV1({ 0 }, { 0 }).apply { bind(-9) }
        val calls = Proxy.newProxyInstance(ProductionNativeStreamCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeStreamCallsV1::class.java)) { _, _, _ -> 25 } as ProductionNativeStreamCallsV1
        val stream = ProductionNativeStreamV1(parent, calls).apply { bind(-7) }
        assertThrows(IllegalStateException::class.java) { stream.close() }
        assertThrows(IllegalStateException::class.java) { stream.close() }
        assertEquals(0, parent.cancelStatus())
        stream.close()
        parent.close()
    }
    @Test fun parentChildProofObservesOnlyClaimedResultsAndNeverRetiresRegistration() {
        for (failure in listOf(0,24,99)) {
            var cancels=0;var closes=0;var childCalls=0
            val parent=ProductionNativeParentV1({cancels++;failure},{closes++;0}).apply{bind(-9)}
            assertNull(parent.childrenRetirementStatus());assertEquals(0,cancels);assertEquals(0,closes)
            val calls=Proxy.newProxyInstance(ProductionNativeStreamCallsV1::class.java.classLoader,
                arrayOf(ProductionNativeStreamCallsV1::class.java)){_,_,_->childCalls++;0} as ProductionNativeStreamCallsV1
            val stream=ProductionNativeStreamV1(parent,calls).apply{bind(-7)}
            assertEquals(if(failure==99)18 else failure,parent.cancelStatus())
            if(failure==0)stream.close() else {
                try {stream.close();fail("failed cancellation proved child cleanup")} catch(e:IllegalStateException){assertEquals("NATIVE_PRODUCTION_CLEANUP_UNPROVEN",e.message)}
            }
            assertEquals(1,cancels);assertEquals(0,closes);assertEquals(0,childCalls);assertNull(parent.retirementStatus())
            parent.close();assertEquals(0,parent.childrenRetirementStatus());assertEquals(1,closes)
            val afterClose=ProductionNativeStreamV1(parent,calls).apply{bind(-8)}
            afterClose.close();assertEquals(0,childCalls)
        }
    }

    @Test fun pendingParentCancellationDoesNotPublishEarlyChildProof() {
        val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        var childCalls=0;var closes=0
        val parent=ProductionNativeParentV1({entered.countDown();check(release.await(5,java.util.concurrent.TimeUnit.SECONDS));0},{closes++;0}).apply{bind(-9)}
        val calls=Proxy.newProxyInstance(ProductionNativeStreamCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeStreamCallsV1::class.java)){_,_,_->childCalls++;0} as ProductionNativeStreamCallsV1
        val stream=ProductionNativeStreamV1(parent,calls).apply{bind(-7)}
        val executor=java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val cancellation=executor.submit<Int>{parent.cancelStatus()}
            assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS))
            val childClose=executor.submit{stream.close()}
            try {childClose.get(100,java.util.concurrent.TimeUnit.MILLISECONDS);fail("early child proof")}
            catch (_:java.util.concurrent.TimeoutException) { }
            assertEquals(0,childCalls);assertEquals(0,closes)
            release.countDown();assertEquals(0,cancellation.get(5,java.util.concurrent.TimeUnit.SECONDS))
            childClose.get(5,java.util.concurrent.TimeUnit.SECONDS)
            assertEquals(0,childCalls);assertEquals(0,closes);assertNull(parent.retirementStatus())
        } finally {release.countDown();executor.shutdownNow();parent.close()}
    }

    @Test fun dataRequiresExplicitConfirmationAndOnlyExactEofIsAccepted() {
        var confirms = 0; var receives = 0; var closes = 0
        val parent = ProductionNativeParentV1({0},{closes++;0}).apply { bind(-9) }
        val output = ByteBuffer.allocateDirect(100000).order(ByteOrder.LITTLE_ENDIAN).apply { position(7);limit(16391) }
        val calls = Proxy.newProxyInstance(ProductionNativeStreamCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeStreamCallsV1::class.java)) { _,method,args ->
            assertEquals(-9L,args[0]);assertEquals(Long.MIN_VALUE,args[1])
            when (method.name) {
                "receive" -> {
                    receives++;assertSame(output,args[2]);assertEquals(7,args[3]);assertEquals(16391,args[4])
                    val metadata=args[5] as LongArray
                    when(receives){1->{metadata[0]=3;metadata[1]=-8;0};2->19;else->{metadata[1]=-8;19}}
                }
                "confirm" -> {confirms++;assertEquals(-8L,args[2]);assertEquals(3L,args[3]);0}
                else -> error("unexpected call")
            }
        } as ProductionNativeStreamCallsV1
        val stream=ProductionNativeStreamV1(parent,calls).apply { bind(Long.MIN_VALUE) }
        assertEquals(NativeProductResult.Success(NativeStreamRead.Data(3,-8)),stream.receive(output));assertEquals(0,confirms)
        assertEquals(NativeProductResult.Success(Unit),stream.confirmDelivery(-8,3));assertEquals(1,confirms)
        assertEquals(NativeProductResult.Success(NativeStreamRead.EndOfStream),stream.receive(output))
        assertEquals(7,output.position());assertEquals(16391,output.limit());assertEquals(ByteOrder.LITTLE_ENDIAN,output.order())
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),stream.receive(output));assertEquals(1,closes)
        stream.close();stream.close();assertEquals(1,closes)
    }

    @Test fun rawStreamCommandsHaveDistinctStickyLifecycleAndBorrowedPrefix() {
        val seen=mutableListOf<String>()
        val parent=ProductionNativeParentV1({0},{0}).apply {bind(-9)}
        val input=ByteBuffer.allocateDirect(100000).asReadOnlyBuffer().apply {position(7);limit(55)}
        val calls=Proxy.newProxyInstance(ProductionNativeStreamCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeStreamCallsV1::class.java)){_,method,args->
            assertEquals(-9L,args[0]);assertEquals(-7L,args[1]);seen+=method.name
            if(method.name=="send"){assertSame(input,args[2]);assertEquals(7,args[3]);assertEquals(10,args[4])}
            0
        } as ProductionNativeStreamCallsV1
        val stream=ProductionNativeStreamV1(parent,calls).apply{bind(-7)}
        assertEquals(NativeProductResult.Success(Unit),stream.send(input,3))
        assertEquals(NativeProductResult.Success(Unit),stream.halfClose())
        assertEquals(NativeProductResult.Success(Unit),stream.rejectDelivery(-8))
        assertEquals(NativeProductResult.Success(Unit),stream.cancel());assertEquals(NativeProductResult.Success(Unit),stream.cancel())
        stream.close();stream.close()
        assertEquals(listOf("send","halfClose","reject","cancel","close"),seen)
        assertEquals(NativeProductResult.Failure(ProductFailureCode.CANCELLED),stream.send(input,3))
        assertEquals(7,input.position());assertEquals(55,input.limit());parent.close()
    }
}
