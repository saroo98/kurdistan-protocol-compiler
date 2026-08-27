// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder

private const val ROUTING_MAGIC = 0x4B525031
private const val ROUTING_RECORD_ID = "routing-policy-current"
private const val MAX_PACKAGES = 64
private const val MAX_PACKAGE_BYTES = 255

class SecureRoutingPolicyStore private constructor(
    private val blobs: SecureBlobReadAccess,
    private val writer: SecureBlobAccess?,
) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)

    companion object {
        /** Never obtains a writer, including when the supplied reader also implements one. */
        fun readOnly(blobs: SecureBlobReadAccess): SecureRoutingPolicyStore = SecureRoutingPolicyStore(blobs, null)
    }

    private fun writes(): SecureBlobAccess = checkNotNull(writer) { "READ_ONLY_ROUTING_VIEW" }

    fun loadPackages(): Set<String> {
        if (!blobs.exists(ROUTING_RECORD_ID, SecureDataClass.ROUTING_POLICY)) return emptySet()
        val encoded = blobs.reopen(ROUTING_RECORD_ID, SecureDataClass.ROUTING_POLICY)
        return try {
            decode(encoded)
        } finally {
            encoded.fill(0)
        }
    }

    fun savePackages(packages: Set<String>) {
        val writable = writes()
        require(packages.size <= MAX_PACKAGES) { "TOO_MANY_PACKAGES" }
        val normalized = packages.map { packageName ->
            require(packageName.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+"))) {
                "INVALID_PACKAGE"
            }
            require(packageName.encodeToByteArray().size <= MAX_PACKAGE_BYTES) { "PACKAGE_TOO_LONG" }
            packageName
        }.distinct().sorted()
        val size = 4 + 2 + normalized.sumOf { 2 + it.encodeToByteArray().size }
        val encoded = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(ROUTING_MAGIC)
            putShort(normalized.size.toShort())
            normalized.forEach { packageName ->
                val bytes = packageName.encodeToByteArray()
                putShort(bytes.size.toShort())
                put(bytes)
                bytes.fill(0)
            }
        }.array()
        try {
            writable.stage(ROUTING_RECORD_ID, SecureDataClass.ROUTING_POLICY, encoded)
        } finally {
            encoded.fill(0)
        }
    }

    fun clear() {
        writes().delete(ROUTING_RECORD_ID, SecureDataClass.ROUTING_POLICY)
    }

    private fun decode(encoded: ByteArray): Set<String> {
        require(encoded.size in 6..(6 + MAX_PACKAGES * (2 + MAX_PACKAGE_BYTES))) { "INVALID_ROUTING_POLICY_SIZE" }
        val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(input.int == ROUTING_MAGIC) { "INVALID_ROUTING_POLICY_MAGIC" }
        val count = input.short.toInt() and 0xffff
        require(count <= MAX_PACKAGES) { "TOO_MANY_PACKAGES" }
        val result = linkedSetOf<String>()
        repeat(count) {
            require(input.remaining() >= 2) { "TRUNCATED_ROUTING_POLICY" }
            val length = input.short.toInt() and 0xffff
            require(length in 1..MAX_PACKAGE_BYTES && input.remaining() >= length) {
                "INVALID_PACKAGE_LENGTH"
            }
            val bytes = ByteArray(length)
            input.get(bytes)
            val packageName = try {
                bytes.decodeToString(throwOnInvalidSequence = true)
            } finally {
                bytes.fill(0)
            }
            require(packageName.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+"))) {
                "INVALID_PACKAGE"
            }
            require(result.add(packageName)) { "DUPLICATE_PACKAGE" }
        }
        require(!input.hasRemaining()) { "TRAILING_ROUTING_POLICY_DATA" }
        return result.toSortedSet()
    }
}
