// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.nio.ByteBuffer
import java.io.Closeable
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.NativeProductResult

class ProductionNativeOpenV1Test {
    @Test fun capturedAcquisitionAdoptsSameParentBeforeConstruction() {
        val delegate = Proxy.newProxyInstance(AndroidProductionPlatformDelegateV1::class.java.classLoader,
            arrayOf(AndroidProductionPlatformDelegateV1::class.java)) { _, method, args ->
            assertEquals(51L,args[0])
            when (method.name) {
                "captureSizes" -> { (args[1] as IntArray).fill(1); 0 }
                "captureCopyInto" -> { (args[6] as IntArray).fill(1); 0 }
                else -> error("unexpected delegate call")
            }
        } as AndroidProductionPlatformDelegateV1
        var adopted: Closeable? = null; var request: ByteBuffer? = null; var closes = 0
        val result = openProductionCapturedV1(delegate, 51,
            nativeOpen = { input, output, metadata ->
                request = input; assertEquals(37,input.capacity()); assertEquals('K'.code.toByte(),input.get(0))
                val bytes = ProductionResultCodecV1Test.tunSnapshot()
                output.duplicate().put(bytes); metadata[0] = -19; metadata[1] = bytes.size.toLong(); 0
            }, cancel = { 0 }, close = { assertEquals(-19L,it); closes++; 0 }, adopt = { adopted = it },
            failedOpening = { fail("published parent abandoned") }, construct = { _, parent ->
                assertSame(adopted,parent)
                val input = checkNotNull(request)
                assertTrue((0 until input.capacity()).all { input.get(it) == 0.toByte() })
                "constructed"
            })
        assertEquals(NativeProductResult.Success("constructed"),result)
        checkNotNull(adopted).close(); assertEquals(1,closes)
    }

    @Test fun capturedOpeningUsesExactFiveSpansAndWipesAllOwnedCopies() {
        val spans = mutableListOf<ByteBuffer>(); var encoded: ByteBuffer? = null
        val delegate = Proxy.newProxyInstance(AndroidProductionPlatformDelegateV1::class.java.classLoader,
            arrayOf(AndroidProductionPlatformDelegateV1::class.java)) { _, method, args ->
            assertEquals(Long.MIN_VALUE, args[0])
            when (method.name) {
                "captureSizes" -> { intArrayOf(2,3,4,5,6).copyInto(args[1] as IntArray); 0 }
                "captureCopyInto" -> {
                    val written = args[6] as IntArray
                    for (i in 0..4) {
                        val span = args[i+1] as ByteBuffer; spans += span
                        assertTrue(span.isDirect); assertFalse(span.isReadOnly)
                        assertEquals(i+2, span.capacity()); assertEquals(0,span.position())
                        for (at in 0 until span.capacity()) span.put(at,(i+1).toByte())
                        written[i] = span.capacity()
                    }; 0
                }
                else -> error("unexpected delegate call")
            }
        } as AndroidProductionPlatformDelegateV1
        val status = captureProductionOpeningV1(delegate, Long.MIN_VALUE, ProductionOpeningPurposeV1.SESSION) { request ->
            encoded = request
            val expected = "4b504f3101010000000000340000000600000002000000030004000500000000" +
                "0505050505050101020202030303030404040404"
            assertEquals(expected, (0 until request.remaining()).joinToString("") { "%02x".format(request.get(it)) })
            assertEquals(52, request.capacity()); 7
        }
        assertEquals(7,status)
        for (span in spans + checkNotNull(encoded)) assertTrue((0 until span.capacity()).all { span.get(it) == 0.toByte() })
    }

    @Test fun oversizedCaptureRefusesBeforeCopyAndNativeAcquisition() {
        val delegate = Proxy.newProxyInstance(AndroidProductionPlatformDelegateV1::class.java.classLoader,
            arrayOf(AndroidProductionPlatformDelegateV1::class.java)) { _, method, args ->
            check(method.name == "captureSizes")
            intArrayOf(1405997,1,1,1,1).copyInto(args[1] as IntArray); 0
        } as AndroidProductionPlatformDelegateV1
        assertEquals(4, captureProductionOpeningV1(delegate, 1, ProductionOpeningPurposeV1.SESSION) {
            fail("oversized capture reached native acquisition"); 0
        })
    }

    @Test fun acquisitionExceptionStillWipesFullOwnedCapacityAfterBoundsChange() {
        var encoded: ByteBuffer? = null
        val delegate = Proxy.newProxyInstance(AndroidProductionPlatformDelegateV1::class.java.classLoader,
            arrayOf(AndroidProductionPlatformDelegateV1::class.java)) { _, method, args ->
            when (method.name) {
                "captureSizes" -> { (args[1] as IntArray).fill(1); 0 }
                "captureCopyInto" -> {
                    for (i in 1..5) (args[i] as ByteBuffer).put(0, 9)
                    (args[6] as IntArray).fill(1); 0
                }
                else -> error("unexpected delegate call")
            }
        } as AndroidProductionPlatformDelegateV1
        try {
            captureProductionOpeningV1(delegate, 1, ProductionOpeningPurposeV1.SESSION) {
                encoded = it; it.limit(1); throw IllegalStateException("acquisition refused")
            }
            fail("acquisition exception swallowed")
        } catch (e: IllegalStateException) { assertEquals("acquisition refused", e.message) }
        val stage = checkNotNull(encoded).duplicate().apply { clear() }
        assertTrue((0 until stage.capacity()).all { stage.get(it) == 0.toByte() })
    }

    @Test fun openingAdoptsBeforeConstructorAndWipesNativeStage() {
        var adopted: Closeable? = null; var stage: ByteBuffer? = null; var closes = 0
        val bytes = ProductionResultCodecV1Test.tunSnapshot()
        val result = openProductionOwnedV1(
            acquire = { output, metadata -> stage = output; output.duplicate().put(bytes); metadata[0] = Long.MIN_VALUE; metadata[1] = bytes.size.toLong(); 0 },
            cancel = { 0 }, close = { assertEquals(Long.MIN_VALUE, it); closes++; 0 },
            adopt = { adopted = it }, failedOpening = { fail("published parent abandoned") },
            construct = { _, parent -> assertSame(adopted, parent); throw IllegalArgumentException("private test detail") },
        )
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), result)
        assertEquals(1, closes)
        val output = checkNotNull(stage)
        assertTrue((0 until output.capacity()).all { output.get(it) == 0.toByte() })
        checkNotNull(adopted).close()
        assertEquals(1, closes)
    }

    @Test fun malformedMetadataStillAdoptsExactNonzeroParentBeforeRefusal() {
        for (written in listOf(0L, 219L, 32769L, Long.MAX_VALUE)) {
            val events = mutableListOf<String>()
            val result = openProductionOwnedV1(
                acquire = { _, metadata -> metadata[0] = -1; metadata[1] = written; 0 },
                cancel = { 0 }, close = { events += "close"; 0 }, adopt = { events += "adopt" },
                failedOpening = { fail("nonzero owner abandoned") }, construct = { _, _ -> fail("bad metadata decoded") },
            )
            assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), result)
            assertEquals(listOf("adopt", "close"), events)
        }
    }

    @Test fun sameGuardStopDuringAdoptionClosesOnlyOnce() {
        var closes = 0
        val result = openProductionOwnedV1(
            acquire = { _, metadata -> metadata[0] = 9; metadata[1] = 235; 0 },
            cancel = { 0 }, close = { closes++; 0 },
            adopt = { it.close(); throw IllegalStateException("stop won") },
            failedOpening = { fail("claimed parent abandoned") }, construct = { _, _ -> fail("construction after stop") },
        )
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), result)
        assertEquals(1, closes)
    }

    @Test fun zeroParentFailureUsesExactFailedOpeningHandoffAndRetainsItsFailure() {
        var finalized = 0
        try {
            openProductionOwnedV1(acquire = { _, _ -> 2 }, cancel = { 0 }, close = { fail("no parent"); 0 },
                adopt = { fail("no parent") }, failedOpening = { finalized++; throw IllegalStateException("OPENING_CLEANUP_UNPROVEN") },
                construct = { _, _ -> fail("no snapshot") })
            fail("unproven finalization swallowed")
        } catch (e: IllegalStateException) { assertEquals("OPENING_CLEANUP_UNPROVEN", e.message) }
        assertEquals(1, finalized)
    }

    @Test fun rawHighBitParentAndDistinctCancelCloseRemainExactlyOwned() {
        val ids = mutableListOf<Long>()
        val parent = ProductionNativeParentV1({ ids += it; 0 }, { ids += it; 0 })
        parent.bind(Long.MIN_VALUE)
        assertTrue(parent.isLive())
        assertEquals(0, parent.cancelStatus())
        assertFalse(parent.isLive())
        assertEquals(0, parent.cancelStatus())
        assertEquals(listOf(Long.MIN_VALUE), ids)
        parent.close(); parent.close()
        assertEquals(listOf(Long.MIN_VALUE, Long.MIN_VALUE), ids)
    }

    @Test fun closeWaitsOutsideMonitorForClaimedCancellation() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val closed = CountDownLatch(1); val cancelled = CountDownLatch(1)
        val closeCalls = AtomicInteger()
        val parent = ProductionNativeParentV1({ entered.countDown(); release.await(); 0 }, { closeCalls.incrementAndGet(); 0 })
        parent.bind(5)
        val cancellation = Thread { parent.cancelStatus(); cancelled.countDown() }
        cancellation.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val closing = Thread { parent.close(); closed.countDown() }
        closing.start()
        // isLive takes the owner monitor. A native-blocking monitor would hang.
        assertFalse(parent.isLive())
        assertEquals(0, closeCalls.get())
        release.countDown()
        assertTrue(cancelled.await(5, TimeUnit.SECONDS)); assertTrue(closed.await(5, TimeUnit.SECONDS))
        cancellation.join(); closing.join()
        parent.close()
        assertEquals(1, closeCalls.get())
    }

    @Test fun failedOrUnknownCloseIsStickyAndCategorical() {
        for (native in listOf(18, 99)) {
            var calls = 0
            val parent = ProductionNativeParentV1({ 0 }, { calls++; native })
            parent.bind(-1)
            repeat(2) {
                try { parent.close(); fail("failed close returned clean") }
                catch (e: IllegalStateException) { assertEquals("NATIVE_PRODUCTION_CLEANUP_UNPROVEN", e.message) }
            }
            assertEquals(1, calls)
            assertEquals(18, parent.cancelStatus())
        }
    }

    @Test fun completedCloseDoesNotCallNativeCancel() {
        var cancelCalls = 0; var closeCalls = 0
        val parent = ProductionNativeParentV1({ cancelCalls++; 0 }, { closeCalls++; 0 })
        parent.bind(7)
        parent.close()
        assertEquals(0, parent.cancelStatus())
        assertEquals(0, cancelCalls); assertEquals(1, closeCalls)
    }

    @Test fun laterSuccessfulCloseDoesNotRewriteCompletedCancellationResult() {
        val parent = ProductionNativeParentV1({ 7 }, { 0 })
        parent.bind(7)
        assertEquals(7, parent.cancelStatus())
        parent.close()
        assertEquals(7, parent.cancelStatus())
    }

    @Test fun boundedCallerAdmissionPrecedesAllocationAndStopsOnCancel() {
        val parent = ProductionNativeParentV1({ 0 }, { 0 })
        parent.bind(11)
        repeat(266) { assertEquals(0, parent.beginCall()) }
        assertEquals(5, parent.beginCall())
        parent.finishCall()
        assertEquals(0, parent.beginCall())
        assertEquals(11L, parent.rawHandle())
        parent.cancelStatus()
        assertEquals(7, parent.beginCall())
        repeat(266) { parent.finishCall() }
        parent.close()
        assertEquals(0, parent.retirementStatus())
    }
}
