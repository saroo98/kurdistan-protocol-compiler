// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativeapi

import java.nio.ByteBuffer

/** Synchronous availability calculation only. No runtime handle or platform authority. */
interface NativeBootstrapValidator {
    fun readLegacyBinding(material: NativeBootstrapMaterialV1, legacyPolicy: ByteBuffer): NativeResult<NativeLegacyBootstrapFactsV1>
    fun readProductionBinding(material: NativeBootstrapMaterialV1, settings: ByteBuffer): NativeProductResult<NativeProductionBootstrapReadV1>
}

/** Call-scoped borrowed views. The validator never retains these aliases. */
class NativeBootstrapMaterialV1(val verifyRequest: ByteBuffer, val activationRecord: ByteBuffer,
    val recipientRequest: ByteBuffer, val recipientPrivate: ByteBuffer) {
    override fun toString() = "NativeBootstrapMaterialV1(redacted)"
}

class NativeLegacyBootstrapFactsV1(val generation: ULong, planDigest: ByteArray, val signedRetryMaximum: Int) {
    private val digest: ByteArray
    init {
        require(generation != 0uL && planDigest.size == 32 && planDigest.any { it != 0.toByte() })
        require(signedRetryMaximum in 1..5)
        digest = planDigest.copyOf()
    }
    val planDigest: ByteArray get() = digest.copyOf()
    override fun toString() = "NativeLegacyBootstrapFactsV1(redacted)"
}

class NativeProductionBootstrapFactsV1(val generation: ULong, planDigest: ByteArray, val effectiveMtu: Int,
    val signedRetryMaximum: Int, val effectiveAutomaticReconnectMaximum: Int) {
    private val digest: ByteArray
    init {
        require(generation != 0uL && planDigest.size == 32 && planDigest.any { it != 0.toByte() })
        // The current V2 plan validator admits only this effective MTU.
        require(effectiveMtu == 1280 && signedRetryMaximum in 1..5)
        require(effectiveAutomaticReconnectMaximum in 0..signedRetryMaximum)
        digest = planDigest.copyOf()
    }
    val planDigest: ByteArray get() = digest.copyOf()
    override fun toString() = "NativeProductionBootstrapFactsV1(redacted)"
}

/** Availability only. These interfaces cannot authorize a session or execution. */
interface NativeActiveProductionSelectorsV1 : AutoCloseable {
    fun copyTo(output: ByteBuffer): Int
    fun containsStrategy(id: String): Boolean
    fun containsProbe(target: Int): Boolean
}
interface NativeDisconnectedProductionSelectorsV1 : AutoCloseable {
    fun copyTo(output: ByteBuffer): Int
    fun containsStrategy(id: String): Boolean
    fun containsProbe(target: Int): Boolean
}

class NativeProductionBootstrapReadV1(val facts: NativeProductionBootstrapFactsV1,
    val activeSelectors: NativeActiveProductionSelectorsV1,
    val disconnectedSelectors: NativeDisconnectedProductionSelectorsV1) : AutoCloseable {
    override fun close() { try { activeSelectors.close() } finally { disconnectedSelectors.close() } }
    override fun toString() = "NativeProductionBootstrapReadV1(redacted)"
}
