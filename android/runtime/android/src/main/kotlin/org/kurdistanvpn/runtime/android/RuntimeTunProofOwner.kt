// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.nio.ByteBuffer

internal interface RuntimeTunDescriptorV1 : Closeable { val fd: Int }
internal fun interface RuntimeTunSourceV1 {
    fun duplicate(): RuntimeTunDescriptorV1
}
private class ParcelTunDescriptorV1 : RuntimeTunDescriptorV1 {
    private var owned: ParcelFileDescriptor? = null
    fun acquire(original: ParcelFileDescriptor) { owned = ParcelFileDescriptor.dup(original.fileDescriptor) }
    override val fd: Int get() = checkNotNull(owned).fd
    override fun close() { checkNotNull(owned).close(); owned = null }
}

/** Adopted by the exact service attempt while empty, before Builder.establish. */
internal class RuntimeTunProofOwner(
    private val current: () -> Boolean,
    private val reader: ((Int, ByteBuffer, IntArray) -> Int)? = null,
) : Closeable {
    private val ioctlLock = Any()
    private val name = ByteBuffer.allocateDirect(15)
    private val written = IntArray(1)
    private val bytes = ByteArray(15)
    private var duplicate: RuntimeTunDescriptorV1? = null
    private var acquired = false
    private var acquiring = false
    private var closed = false
    private var unproven = false
    private var duplicateCloseAttempted = false

    fun adoptEstablished(original: ParcelFileDescriptor) = adoptEstablished(object : RuntimeTunSourceV1 {
        override fun duplicate(): RuntimeTunDescriptorV1 {
            val owned = ParcelTunDescriptorV1()
            owned.acquire(original)
            return owned
        }
    })

    /** PlatformTunOwner still owns the original throughout this validation;
     * only that existing owner may detach it after this method returns. */
    internal fun adoptEstablished(source: RuntimeTunSourceV1) {
        try {
            synchronized(ioctlLock) { check(!closed && !acquired); acquired = true; acquiring = true }
            // Duplicate before any start, ioctl or other fallible validation.
            val owned = source.duplicate()
            synchronized(ioctlLock) {
                duplicate = owned
                if (closed) retireDuplicateLocked()
            }
            check(current() && interfaceName() != null)
            synchronized(ioctlLock) { check(!closed && !unproven) }
        } catch (failure: Throwable) {
            synchronized(ioctlLock) { acquiring = false }
            try { close() } catch (_: Throwable) { synchronized(ioctlLock) { unproven = true } }
            throw failure
        } finally { synchronized(ioctlLock) { acquiring = false } }
    }

    fun interfaceName(): String? {
        if (!current()) return null
        val result = synchronized(ioctlLock) {
            val owned = duplicate
            if (closed || unproven || owned == null) return null
            for (i in 0 until 15) name.put(i, 0)
            written[0] = 0
            val status = reader?.invoke(owned.fd, name, written) ?: readTunIdentity(owned.fd, name, written)
            if (status != 0 || written[0] !in 1..15) return null
            for (i in 0 until written[0]) {
                val byte = name.get(i)
                if (byte.toInt() !in 33..126 || byte == '/'.code.toByte()) return null
                bytes[i] = byte
            }
            String(bytes, 0, written[0], Charsets.US_ASCII).also { bytes.fill(0) }
        }
        return result.takeIf { current() && synchronized(ioctlLock) { !closed && !unproven } }
    }

    override fun close(): Unit = synchronized(ioctlLock) {
        closed = true
        retireDuplicateLocked()
        if (acquiring) unproven = true
        if (unproven) throw RuntimeAuthorityCleanupUnprovenException()
    }

    private fun retireDuplicateLocked() {
        val owned = duplicate ?: return
        if (duplicateCloseAttempted) return
        duplicateCloseAttempted = true
        try { owned.close(); duplicate = null }
        catch (failure: Throwable) { unproven = true; throw failure }
    }

    private external fun readTunIdentity(fd: Int, destination: ByteBuffer, written: IntArray): Int
}
