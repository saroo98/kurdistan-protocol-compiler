// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class ProductionOperationCodecV1Test {
    @Test fun proxyProbeAndUpdateRequestsUseExactBytes() {
        val proxy = ByteBuffer.allocate(259)
        val domain = ("a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61)).toByteArray()
        assertEquals(NativeProductResult.Success(259), ProductionOperationCodecV1.encodeProxy(NativeProxyRequest(NativeProxyAddressKind.DOMAIN, domain, 65535), proxy))
        assertEquals(1, proxy.array()[0].toInt()); assertEquals(2, proxy.array()[1].toInt()); assertEquals(253, ByteBuffer.wrap(proxy.array(),2,2).short.toInt() and 65535)

        val probe = ByteBuffer.allocateDirect(11).apply { position(1); limit(10); order(ByteOrder.LITTLE_ENDIAN) }
        assertEquals(NativeProductResult.Success(9), ProductionOperationCodecV1.encodeProbe(NativeProbeRequest(65535, NativeProbeMethod.TCP_CONNECT, 1000, 30000, 10), probe))
        assertArrayEquals(byteArrayOf(1,-1,-1,1,3,-24,117,48,10), ByteArray(9).also { probe.duplicate().get(it) })
        assertEquals(1, probe.position()); assertEquals(10, probe.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN, probe.order())
        val update = ByteBuffer.allocateDirect(5).apply { position(1); limit(4); order(ByteOrder.LITTLE_ENDIAN) }
        assertEquals(NativeProductResult.Success(3), ProductionOperationCodecV1.encodeUpdate(NativeUpdateRequest(30000), update))
        assertArrayEquals(byteArrayOf(1,117,48), ByteArray(3).also { update.duplicate().get(it) })
        assertEquals(1, update.position()); assertEquals(4, update.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN, update.order())
    }

    @Test fun noChangeIsNotACandidateAndHighBitCandidateIsPreserved() {
        assertEquals(NativeProductResult.Success(NativeUpdateCheck.NoChange), ProductionOperationCodecV1.decodeUpdate(ByteBuffer.wrap(byteArrayOf(1, 0, 1)), 7uL))
        val candidate = ByteBuffer.allocate(38).apply {
            put(1); putShort(0); putLong(Long.MIN_VALUE); put(1); putLong(8); put(1); put(7); put(0); put(0)
            repeat(10) { put((it % 2).toByte()) }; putInt(1052763)
        }.array()
        val result = ProductionOperationCodecV1.decodeUpdate(ByteBuffer.wrap(candidate), 7uL)
        assertTrue(result is NativeProductResult.Success && result.value is NativeUpdateCheck.Candidate)
        assertEquals(Long.MIN_VALUE, ((result as NativeProductResult.Success).value as NativeUpdateCheck.Candidate).candidate.handle)
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT), ProductionOperationCodecV1.decodeUpdate(ByteBuffer.wrap(candidate), ULong.MAX_VALUE))
    }

    @Test fun probeCrossFieldsAreValidated() {
        val request = NativeProbeRequest(1, NativeProbeMethod.TCP_CONNECT, 1000, 3000, 3)
        val good = ByteBuffer.allocate(21).apply { put(1); put(2); put(1); put(3); put(2); put(1); put(0); put(3); putInt(1000); putInt(100); putShort(333); put(2); putShort(8) }.array()
        val result = ProductionOperationCodecV1.decodeProbe(ByteBuffer.wrap(good), request, NativeProbePath.ACTIVE_RELAY_END_TO_END)
        assertTrue(result is NativeProductResult.Success)
        good[18] = 1
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), ProductionOperationCodecV1.decodeProbe(ByteBuffer.wrap(good), request, NativeProbePath.ACTIVE_RELAY_END_TO_END))
    }

    @Test fun requestEncodersAreAtomicAndPreserveNioViews() {
        val request = NativeProxyRequest(NativeProxyAddressKind.IPV4, byteArrayOf(1, 1, 1, 1), 443)
        val output = ByteBuffer.allocate(15).apply { array().fill(0x55); position(3); limit(13); order(ByteOrder.LITTLE_ENDIAN) }
        assertEquals(NativeProductResult.Success(10), ProductionOperationCodecV1.encodeProxy(request, output))
        assertArrayEquals(byteArrayOf(1, 1, 0, 4, 1, 1, 1, 1, 1, -69), output.array().copyOfRange(3, 13))
        assertEquals(3, output.position()); assertEquals(13, output.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN, output.order())

        val short = ByteBuffer.allocate(8).apply { array().fill(0x66) }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT), ProductionOperationCodecV1.encodeProbe(NativeProbeRequest(1, NativeProbeMethod.TCP_CONNECT, 1000, 1000, 1), short))
        assertTrue(short.array().all { it == 0x66.toByte() })
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT), ProductionOperationCodecV1.encodeUpdate(NativeUpdateRequest(1000), ByteBuffer.allocate(3).asReadOnlyBuffer()))
    }

    @Test fun probeMutantsAndCompletionStatusesFailClosedOrPreserveMeaning() {
        val request = NativeProbeRequest(1, NativeProbeMethod.TCP_CONNECT, 1000, 3000, 3)
        fun exact(completion: Int) = ByteBuffer.allocate(21).apply {
            put(1); put(1); put(1); put(3); put(3); put(0); put(0); put(3); putInt(1000); putInt(250); putShort(0); put(1); putShort(completion.toShort())
        }.array()
        for (status in listOf(0, 6, 8)) {
            assertTrue(ProductionOperationCodecV1.decodeProbe(ByteBuffer.wrap(exact(status)), request, NativeProbePath.DISCONNECTED_TCP_CONNECT) is NativeProductResult.Success)
        }
        val mutations = listOf(
            0 to 2, 1 to 2, 2 to 2, 3 to 0, 4 to 2, 5 to 1, 6 to 1, 7 to 7,
            18 to 2, 20 to 7,
        )
        mutations.forEach { (offset, value) ->
            val bad = exact(0).also { it[offset] = value.toByte() }
            assertEquals("offset $offset", NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),
                ProductionOperationCodecV1.decodeProbe(ByteBuffer.wrap(bad), request, NativeProbePath.DISCONNECTED_TCP_CONNECT))
        }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), ProductionOperationCodecV1.decodeProbe(ByteBuffer.wrap(exact(0) + byteArrayOf(0)), request, NativeProbePath.DISCONNECTED_TCP_CONNECT))
    }

    @Test fun maintenanceStatusesAndHighBitGenerationRemainContextual() {
        val expected = listOf(
            ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.PROFILE_INCOMPATIBLE,
            ProductFailureCode.INVALID_INPUT, ProductFailureCode.OPERATION_INTERRUPTED, ProductFailureCode.SIZE_LIMIT,
            ProductFailureCode.RESOURCE_LIMIT, ProductFailureCode.RATE_LIMITED, ProductFailureCode.CANCELLED,
            ProductFailureCode.OPERATION_TIMED_OUT, ProductFailureCode.NETWORK_UNAVAILABLE, ProductFailureCode.ROUTE_POLICY_REJECTED,
            ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.UPDATE_FETCH_REJECTED,
            ProductFailureCode.UPDATE_SIGNATURE_INVALID, ProductFailureCode.PROFILE_WRONG_DEVICE, ProductFailureCode.PROFILE_UNTRUSTED,
            ProductFailureCode.UPDATE_ROLLBACK, ProductFailureCode.PROFILE_EXPIRED, ProductFailureCode.PROFILE_REVOKED,
            ProductFailureCode.UPDATE_INCOMPATIBLE, ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.INTERNAL_FAILURE,
        )
        (2..23).forEach { status ->
            val decoded = ProductionOperationCodecV1.decodeUpdate(ByteBuffer.wrap(byteArrayOf(1, 0, status.toByte())), 1uL)
            assertEquals("M1 $status", NativeProductResult.Failure(expected[status]), decoded)
        }
        for (status in listOf(24, 27, 65535)) {
            val bytes = byteArrayOf(1, (status ushr 8).toByte(), status.toByte())
            assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), ProductionOperationCodecV1.decodeUpdate(ByteBuffer.wrap(bytes), 1uL))
        }
        val highGeneration = ByteBuffer.allocate(38).apply {
            put(1); putShort(0); putLong(-1); put(1); putLong(Long.MIN_VALUE); put(0); put(0); put(0); put(0)
            repeat(10) { put(1) }; putInt(1)
        }.array()
        val decoded = ProductionOperationCodecV1.decodeUpdate(ByteBuffer.wrap(highGeneration), (1uL shl 63) - 1uL)
        val candidate = ((decoded as NativeProductResult.Success).value as NativeUpdateCheck.Candidate).candidate
        assertEquals(1uL shl 63, candidate.generation); assertEquals(10, candidate.changes.totalChangedCategories)
    }
}
