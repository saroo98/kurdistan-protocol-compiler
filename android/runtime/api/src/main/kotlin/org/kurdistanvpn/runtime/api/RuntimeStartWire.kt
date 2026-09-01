// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.DnsMode

object RuntimeStartWire {
    private const val POLICY_HEADER_BYTES = 26
    private const val LIVE_HEADER_BYTES = 24
    private const val MAX_VERIFY_REQUEST_BYTES = 1_500_000
    private const val MAX_ACTIVATION_RECORD_BYTES = 1_200_000
    private const val MAX_RECIPIENT_REQUEST_BYTES = 512
    private const val MAX_RECIPIENT_PRIVATE_BYTES = 128
    const val MAX_RUNTIME_OPEN_BYTES = MAX_VERIFY_REQUEST_BYTES +
        MAX_ACTIVATION_RECORD_BYTES + MAX_RECIPIENT_REQUEST_BYTES +
        MAX_RECIPIENT_PRIVATE_BYTES + 32 * 1024

    fun encode(
        verifyRequest: ByteArray,
        activationRecord: ByteArray,
        recipientRequest: ByteArray,
        recipientPrivate: ByteArray,
        config: VpnRuntimeConfig,
    ): ByteArray {
        require(verifyRequest.size in 1..MAX_VERIFY_REQUEST_BYTES) {
            "INVALID_VERIFY_REQUEST"
        }
        require(activationRecord.size in 1..MAX_ACTIVATION_RECORD_BYTES) {
            "INVALID_ACTIVATION_RECORD"
        }
        require(recipientRequest.size in 1..MAX_RECIPIENT_REQUEST_BYTES) {
            "INVALID_RECIPIENT_REQUEST"
        }
        require(recipientPrivate.size in 1..MAX_RECIPIENT_PRIVATE_BYTES) {
            "INVALID_RECIPIENT_PRIVATE"
        }
        // Structural allocation bounds above precede copying. All semantic validation below
        // observes owned byte arrays and a single bounded snapshot of nested configuration.
        val owned = ArrayList<ByteArray>(4)
        var policy: ByteArray? = null
        var output: ByteArray? = null
        try {
            owned += verifyRequest.copyOf()
            owned += activationRecord.copyOf()
            owned += recipientRequest.copyOf()
            owned += recipientPrivate.copyOf()
            require(config.manualStrategyId.length <= 256 && config.customDns.length <= 45)
            require(config.routingPolicy.packages.size <= VpnRoutingPolicy.MAX_PACKAGES)
            val packages = linkedSetOf<String>()
            val iterator = config.routingPolicy.packages.iterator()
            while (iterator.hasNext()) {
                require(packages.size < VpnRoutingPolicy.MAX_PACKAGES)
                val item = iterator.next()
                require(item.length in 1..VpnRoutingPolicy.MAX_PACKAGE_NAME_LENGTH && packages.add(item))
            }
            val captured = config.copy(routingPolicy = config.routingPolicy.copy(packages = packages))
            policy = encodePolicy(captured.validatedForLiveTransport())
            val size = LIVE_HEADER_BYTES.toLong() + policy.size + owned.sumOf { it.size.toLong() }
            require(policy.size <= 0xffff && size <= MAX_RUNTIME_OPEN_BYTES) { "RUNTIME_START_TOO_LARGE" }
            output = ByteArray(size.toInt())
            return ByteBuffer.wrap(output).order(ByteOrder.BIG_ENDIAN).apply {
                put(byteArrayOf('K'.code.toByte(), 'R'.code.toByte(), 'V'.code.toByte(), '2'.code.toByte()))
                put(2)
                put(0)
                putShort(policy.size.toShort())
                putInt(owned[0].size)
                putInt(owned[1].size)
                putShort(owned[2].size.toShort())
                putShort(owned[3].size.toShort())
                putInt(size.toInt())
                put(policy)
                owned.forEach { put(it) }
            }.array()
        } catch (error: Throwable) {
            output?.fill(0)
            throw error
        } finally {
            policy?.fill(0)
            owned.forEach { it.fill(0) }
        }
    }

    private fun encodePolicy(validated: VpnRuntimeConfig): ByteArray {
        val packages = mutableListOf<ByteArray>()
        var manual = ByteArray(0)
        var customDns = ByteArray(0)
        var outputBytes: ByteArray? = null
        try {
            validated.routingPolicy.packages.forEach { packages += it.encodeToByteArray() }
            manual = validated.manualStrategyId.encodeToByteArray()
            customDns = validated.customDns.encodeToByteArray()
            require(manual.size <= 256 && customDns.size <= 45)
            packages.forEach { require(it.size in 1..255) }
            val size = POLICY_HEADER_BYTES + packages.sumOf { 2 + it.size } + manual.size +
                customDns.size + 2
            outputBytes = ByteArray(size)
            val output = ByteBuffer.wrap(outputBytes).order(ByteOrder.BIG_ENDIAN)
            output.put(byteArrayOf('K'.code.toByte(), 'R'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte()))
            output.put(1)
            output.put((validated.selectionMode.ordinal + 1).toByte())
            output.put((validated.routingPolicy.perAppMode.ordinal + 1).toByte())
            output.put((validated.ipMode.ordinal + 1).toByte())
            output.put(
                when (validated.dnsMode) {
                    DnsMode.INTERNAL_TUN -> 1
                    DnsMode.CUSTOM -> 2
                    else -> error("EXTERNAL_DNS_REQUIRES_RELAY_EGRESS")
                }.toByte(),
            )
            var flags = 0
            if (validated.metered) flags = flags or 1
            if (validated.allowLan) flags = flags or 2
            output.put(flags.toByte())
            output.putShort(validated.mtu.toShort())
            output.putShort(packages.size.toShort())
            output.putShort(manual.size.toShort())
            output.putShort(customDns.size.toShort())
            output.putInt(1)
            output.putInt(1)
            packages.forEach { value ->
                output.putShort(value.size.toShort())
                output.put(value)
            }
            output.put(manual)
            output.put(customDns)
            output.put(1)
            output.put(1)
            return output.array()
        } catch (error: Throwable) { outputBytes?.fill(0); throw error }
        finally { packages.forEach { it.fill(0) }; manual.fill(0); customDns.fill(0) }
    }
}
