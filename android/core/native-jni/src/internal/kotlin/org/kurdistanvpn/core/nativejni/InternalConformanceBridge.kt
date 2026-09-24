// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeResult

/** Historical genuine conformance only. Not a runtime capability constructor. */
class InternalConformanceBridge {
    fun phase11RoundTrip(payload: ByteArray): NativeResult<ByteArray> {
        if (payload.isEmpty() || payload.size > MAX_PHASE11_PAYLOAD_BYTES) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        val output = ByteBuffer.allocateDirect(MAX_PHASE11_PAYLOAD_BYTES)
        val length = IntArray(1)
        val code = nativePhase11RoundTrip(payload, output, length)
        return if (code == CODE_OK) {
            NativeResult.Success(readBytes(output, length[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    private external fun nativePhase11RoundTrip(
        input: ByteArray,
        output: ByteBuffer,
        outputLength: IntArray,
    ): Int
    private external fun nativeRuntimeSessionRoundTrip(
        handle: Long,
        input: ByteArray,
        output: ByteBuffer,
        outputLength: IntArray,
    ): Int
    companion object {
        private const val CODE_OK = 0
        private const val MAX_PHASE11_PAYLOAD_BYTES = 32 * 1024
        init {
            System.loadLibrary("kurdistan_bridge")
            System.loadLibrary("kurdistan_jni")
        }
        private fun readBytes(buffer: ByteBuffer, length: Int): ByteArray {
            require(length in 0..buffer.capacity())
            val result = ByteArray(length)
            try {
                buffer.position(0)
                buffer.get(result)
            } finally {
                val wipe = buffer.duplicate()
                wipe.position(0)
                repeat(length) { wipe.put(0.toByte()) }
            }
            return result
        }
        private fun mapError(code: Int): OperationError =
            when (code) {
                1 -> OperationError.INVALID_INPUT
                2 -> OperationError.SIZE_LIMIT
                3, 4, 5 -> OperationError.INVALID_INPUT
                6 -> OperationError.CANCELLED
                7 -> OperationError.AUTHORITY_UNAVAILABLE
                8 -> OperationError.TRUST_REJECTED
                9 -> OperationError.POLICY_REJECTED
                10 -> OperationError.STORAGE_FAILURE
                11 -> OperationError.RECOVERY_REQUIRED
                12 -> OperationError.QUARANTINED
                13 -> OperationError.INCOMPATIBLE_NATIVE_CORE
                15 -> OperationError.ENDPOINT_UNAVAILABLE
                16 -> OperationError.TLS_REJECTED
                17 -> OperationError.KURD_AUTH_REJECTED
                18 -> OperationError.TUN_IO_FAILED
                19 -> OperationError.DNS_UNAVAILABLE
                20 -> OperationError.NETWORK_LOST
                21 -> OperationError.FALLBACK_EXHAUSTED
                22 -> OperationError.NODE_DRAINED
                23 -> OperationError.DEPLOYMENT_DISABLED
                24 -> OperationError.RESOURCE_LIMIT
                25 -> OperationError.STATE_CORRUPT
                else -> OperationError.INTERNAL_FAILURE
            }
    }
}
