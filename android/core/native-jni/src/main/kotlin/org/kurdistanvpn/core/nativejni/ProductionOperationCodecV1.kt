// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

internal object ProductionOperationCodecV1 {
    fun encodeProxy(request: NativeProxyRequest, output: ByteBuffer): NativeProductResult<Int> {
        val address = request.address
        val writer = ProductionWriterV1(maximum = 259)
        return try {
            writer.u8(1)
            writer.u8(when (request.kind) {
                NativeProxyAddressKind.IPV4 -> 1
                NativeProxyAddressKind.DOMAIN -> 2
                NativeProxyAddressKind.IPV6 -> 3
            })
            writer.u16(address.size)
            writer.bytes(address)
            writer.u16(request.port)
            val bytes = writer.result()
            try { atomicWriteV1(bytes, output, 259) } finally { bytes.fill(0) }
        } finally {
            writer.close()
            address.fill(0)
        }
    }

    fun encodeProbe(request: NativeProbeRequest, output: ByteBuffer): NativeProductResult<Int> {
        val writer = ProductionWriterV1(maximum = 9, initialCapacity = 9)
        return try {
            writer.u8(1)
            writer.u16(request.targetId)
            writer.u8(1)
            writer.u16(request.attemptTimeoutMillis)
            writer.u16(request.totalTimeoutMillis)
            writer.u8(request.samples)
            val bytes = writer.result()
            try { atomicWriteV1(bytes, output, 9) } finally { bytes.fill(0) }
        } finally {
            writer.close()
        }
    }

    fun decodeProbe(input: ByteBuffer, request: NativeProbeRequest, expectedPath: NativeProbePath): NativeProductResult<NativeProbeResult> {
        if (input.remaining() != 21) return internalFailure()
        return try {
            val reader = ProductionReaderV1(input, 21)
            val version = reader.u8()
            val path = when (reader.u8()) {
                1 -> NativeProbePath.DISCONNECTED_TCP_CONNECT
                2 -> NativeProbePath.ACTIVE_RELAY_END_TO_END
                else -> null
            }
            val method = reader.u8()
            val attempted = reader.u8()
            val succeeded = reader.u8()
            val failed = reader.u8()
            val unstarted = reader.u8()
            val presence = reader.u8()
            val meanRaw = reader.u32()
            val jitterRaw = reader.u32()
            val loss = reader.u16()
            val stabilityWire = reader.u8()
            val completionWire = reader.u16()
            if (!reader.end() || version != 1 || path != expectedPath || method != 1 ||
                attempted !in 1..request.samples || succeeded + failed != attempted ||
                unstarted != request.samples - attempted || presence and 0xfc != 0 ||
                meanRaw > 30000000 || jitterRaw > 30000000 || loss != failed * 1000 / attempted
            ) return internalFailure()

            val mean = if (presence and 1 != 0) meanRaw.toInt() else null
            val jitter = if (presence and 2 != 0) jitterRaw.toInt() else null
            if ((mean != null) != (succeeded >= 1) || (jitter != null) != (succeeded >= 2) ||
                mean == null && meanRaw != 0L || jitter == null && jitterRaw != 0L
            ) return internalFailure()
            val expectedStability = if (attempted < 3) 0 else if (failed == 0 && jitter!! <= mean!! / 4) 1 else 2
            if (stabilityWire != expectedStability) return internalFailure()
            val completion = when (completionWire) {
                0 -> NativeProbeCompletion.COMPLETE
                8 -> NativeProbeCompletion.TIMED_OUT
                6 -> NativeProbeCompletion.RATE_LIMITED
                else -> return internalFailure()
            }
            if (completion == NativeProbeCompletion.COMPLETE && unstarted != 0) return internalFailure()
            val stability = when (stabilityWire) {
                0 -> NativeProbeStability.NOT_ENOUGH_SAMPLES
                1 -> NativeProbeStability.STABLE
                else -> NativeProbeStability.VARIABLE
            }
            NativeProductResult.Success(
                NativeProbeResult(path, NativeProbeMethod.TCP_CONNECT, attempted, succeeded, failed, unstarted, mean, jitter, loss, stability, completion),
            )
        } catch (_: IllegalArgumentException) {
            internalFailure()
        }
    }

    fun encodeUpdate(request: NativeUpdateRequest, output: ByteBuffer): NativeProductResult<Int> {
        val writer = ProductionWriterV1(maximum = 3, initialCapacity = 3)
        return try {
            writer.u8(1)
            writer.u16(request.requestedTimeoutMillis)
            val bytes = writer.result()
            try { atomicWriteV1(bytes, output, 3) } finally { bytes.fill(0) }
        } finally {
            writer.close()
        }
    }

    fun decodeUpdate(input: ByteBuffer, currentGeneration: ULong): NativeProductResult<NativeUpdateCheck> {
        if (currentGeneration == 0uL || currentGeneration == ULong.MAX_VALUE) {
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        }
        if (input.remaining() !in listOf(3, 38)) return internalFailure()
        return try {
            val reader = ProductionReaderV1(input, 38)
            val version = reader.u8()
            val status = reader.u16()
            if (version != 1) return internalFailure()
            if (status == 1) {
                if (!reader.end()) internalFailure() else NativeProductResult.Success(NativeUpdateCheck.NoChange)
            } else if (status != 0) {
                if (!reader.end()) internalFailure() else NativeProductResult.Failure(maintenanceFailureV1(status))
            }
            else {
                if (input.remaining() != 38) return internalFailure()
                val handle = reader.opaque64()
                val deployment = reader.u8()
                val generation = reader.u64()
                val expiry = reader.u8()
                val rotation = reader.u8()
                val revocation = reader.u8()
                val compatibility = reader.u8()
                val counts = IntArray(10) { reader.u8() }
                val artifactBytes = reader.u32()
                if (!reader.end() || handle == 0L || deployment != 1 || generation != currentGeneration + 1uL ||
                    expiry !in 0..1 || rotation !in 0..7 || revocation != 0 || compatibility != 0 ||
                    counts.any { it !in 0..1 } || artifactBytes !in 1..1052763
                ) return internalFailure()
                val changes = NativeUpdateChanges(
                    counts[0], counts[1], counts[2], counts[3], counts[4],
                    counts[5], counts[6], counts[7], counts[8], counts[9],
                )
                val candidate = NativeUpdateCandidate(
                    handle,
                    NativeDeploymentMatch.SAME_DEPLOYMENT,
                    generation,
                    if (expiry == 0) NativeCandidateExpiry.VALID else NativeCandidateExpiry.EXPIRING_SOON,
                    rotation,
                    NativeCandidateRevocation.NOT_REVOKED,
                    NativeCandidateCompatibility.COMPATIBLE,
                    changes,
                    artifactBytes.toInt(),
                )
                NativeProductResult.Success(NativeUpdateCheck.Candidate(candidate))
            }
        } catch (_: IllegalArgumentException) {
            internalFailure()
        }
    }

    private fun <T> internalFailure(): NativeProductResult<T> =
        NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
}
