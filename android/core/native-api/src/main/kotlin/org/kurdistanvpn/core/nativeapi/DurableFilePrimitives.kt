// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.nativeapi

import java.io.Closeable
import java.io.IOException
import java.nio.ByteBuffer
import java.util.Collections

object DurableBounds {
    const val MAX_BYTES = 8 * 1024 * 1024 + 4096
    const val MAX_LEAF_BYTES = 255
    const val MAX_ENTRIES = 4096
    fun validFd(value: Long): Boolean = value in 0..Int.MAX_VALUE.toLong()
    // uid_t(-1) is a sentinel, not an admissible owner.
    fun validUid(value: Long): Boolean = value in 0..0xffff_fffeL
    fun validLimit(value: Int): Boolean = value in 1..MAX_BYTES
    fun leaf(value: String): ByteArray? =
        if (value.length in 1..MAX_LEAF_BYTES && value != "." && value != ".." &&
            value.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '_' || it == '-' }
        ) value.toByteArray(Charsets.US_ASCII) else null
}

data class DurableFileIdentity(val device: Long, val inode: Long) {
    init { require(device >= 0 && inode > 0) }
}

/** Borrowed descriptor. Native code duplicates it; this object never closes the caller's FD. */
data class DurableDirectory(val directoryFd: Long, val expectedUid: Long, val identity: DurableFileIdentity) {
    init { require(DurableBounds.validFd(directoryFd) && DurableBounds.validUid(expectedUid)) }
}

interface DurableOwnedDirectory : Closeable {
    /** Borrowed snapshot. Callers must keep this owner alive until native duplication completes. */
    fun borrow(): DurableDirectory?
    /** Serializes owner close with the complete callback. Do not retain the borrowed FD outside it. */
    fun <T> withBorrow(block: (DurableDirectory) -> T): T?
    fun closeResult(): DurableCode
}

data class DurableChildDirectoryResult(val code: DurableCode, val owner: DurableOwnedDirectory? = null) {
    init { require((code == DurableCode.OK) == (owner != null)); require(code != DurableCode.CLOSED) }
}

/** Owns a copy of the bytes. Native verifies regular type, mode 0600, owner and nlink=1. */
class DurableSnapshot(val identity: DurableFileIdentity, bytes: ByteArray) {
    private val content = bytes.copyOf()
    init {
        if (content.size > DurableBounds.MAX_BYTES) {
            content.fill(0)
            throw IllegalArgumentException("Durable snapshot exceeds limit")
        }
    }
    val bytes: ByteArray get() = content.copyOf()
    val size: Int get() = content.size
}

enum class DurableCode(val wire: Int) {
    OK(0), ABSENT(1), CONFLICT(2), INVALID(3), UNSAFE(4), IO_FAILURE(5), UNSUPPORTED(6),
    MUTATION_UNPROVEN(7), CLOSE_UNPROVEN(8), CLOSED(9);
    companion object { fun fromWire(value: Int): DurableCode? = entries.firstOrNull { it.wire == value } }
}

data class DurableReadResult(val code: DurableCode, val snapshot: DurableSnapshot? = null) {
    init {
        require((code == DurableCode.OK) == (snapshot != null))
        require(code != DurableCode.MUTATION_UNPROVEN)
    }
}
data class DurableIdentityResult(val code: DurableCode, val identity: DurableFileIdentity? = null) {
    init {
        require((code == DurableCode.OK) == (identity != null))
        require(code != DurableCode.ABSENT && code != DurableCode.CLOSED)
    }
}
data class DurableOpenResult(val code: DurableCode, val writer: DurableWriter? = null) {
    init {
        require((code == DurableCode.OK) == (writer != null))
        require(code != DurableCode.MUTATION_UNPROVEN && code != DurableCode.CLOSED)
    }
}
data class DurableMutationResult(val code: DurableCode) {
    init { require(code != DurableCode.ABSENT && code != DurableCode.CLOSE_UNPROVEN) }
}
data class DurableSyncResult(val code: DurableCode, val snapshot: DurableSnapshot? = null) {
    init {
        require((code == DurableCode.OK) == (snapshot != null))
        require(code != DurableCode.ABSENT && code != DurableCode.CLOSE_UNPROVEN)
    }
}

/** Immutable observation only: no descriptor ownership, authority, or byte payload is transferred. */
class DurablePipeObservation internal constructor(
    val identity: DurableFileIdentity, val uid: Long, val mode: Int,
    val access: Int, val nonblocking: Boolean,
) {
    init { require(DurableBounds.validUid(uid) && mode == 4480 && access in 0..1 && nonblocking) }
}

data class DurablePipeResult(val code: DurableCode, val observation: DurablePipeObservation? = null) {
    init {
        require((code == DurableCode.OK) == (observation != null))
        require(code != DurableCode.ABSENT && code != DurableCode.CLOSED && code != DurableCode.CLOSE_UNPROVEN)
    }
}
data class DurableDirectoryEntry(val leaf: String, val identity: DurableFileIdentity, val length: Long) {
    init { require(DurableBounds.leaf(leaf) != null && length in 0..DurableBounds.MAX_BYTES.toLong()) }
}
class DurableListResult(val code: DurableCode, entries: List<DurableDirectoryEntry>? = null) {
    // Entries, identities and names contain only immutable values. The list itself is
    // independently snapshotted before validation and cannot be mutated through a cast.
    val entries: List<DurableDirectoryEntry>? = entries?.let { Collections.unmodifiableList(ArrayList(it)) }
    init {
        require((code == DurableCode.OK) == (this.entries != null))
        require(code != DurableCode.MUTATION_UNPROVEN)
        require(this.entries == null || this.entries.size <= DurableBounds.MAX_ENTRIES)
    }
}

interface DurableFilePrimitives {
    /**
     * API-26 libc helper. Caller holds its owner mutex across this borrow, including against
     * close, detach and flag mutation. F_SETFL affects duplicated descriptors too. No close or
     * byte I/O occurs here. Any failed/ambiguous preparation must not authorize pipe use.
     */
    fun prepareBorrowedPipe(fd: Long, expectedUid: Long, expectedAccess: Int): DurablePipeResult =
        DurablePipeResult(DurableCode.UNSUPPORTED)
    /** Never creates. A null expectedChild discovers identity only beneath the supplied trusted parent. */
    fun openChildDirectory(parent: DurableDirectory, leaf: String, expectedChild: DurableFileIdentity? = null): DurableChildDirectoryResult =
        DurableChildDirectoryResult(DurableCode.UNSUPPORTED)
    /** Explicit interactive initialization only; an existing leaf is always a conflict. */
    fun createChildDirectoryExclusive(parent: DurableDirectory, leaf: String): DurableChildDirectoryResult =
        DurableChildDirectoryResult(DurableCode.UNSUPPORTED)
    fun read(directory: DurableDirectory, leaf: String, maxBytes: Int): DurableReadResult
    fun list(directory: DurableDirectory, maxEntries: Int): DurableListResult
    /** Explicit first provisioning only. Never used by restoration or openWriter. */
    fun bootstrapLock(directory: DurableDirectory, lockLeaf: String): DurableIdentityResult
    fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity): DurableOpenResult
}

/**
 * Cooperative same-UID writers must all lock the same known inode. This is not a boundary
 * against malicious same-UID code, which can replace names or change files outside flock.
 * One writer holds its lease across multiple primitives until explicit close. A primitive OK
 * is not whole-operation success until closeResult is OK. Unproven mutation poisons the lease.
 */
interface DurableWriter : Closeable {
    fun read(leaf: String, maxBytes: Int): DurableReadResult
    fun list(maxEntries: Int): DurableListResult
    fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray, maxBytes: Int): DurableMutationResult
    fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int): DurableMutationResult
    /** Only for already quiesced and closed store files; never for live SQLite or DataStore files. */
    fun syncAndObserveExisting(leaf: String, expected: DurableSnapshot, maxBytes: Int): DurableSyncResult =
        DurableSyncResult(DurableCode.UNSUPPORTED)
    fun closeResult(): DurableCode
}

/**
 * Narrow JNI transport, with independent constructor snapshots and defensive getter copies.
 * A returned result is owned by the checked decoder, which wipes its retained copies after
 * decoding. Transport callers remain responsible for wiping their own source arrays.
 */
class DurableRawResult(val code: Int, metadata: LongArray, bytes: ByteArray?) {
    private val ownedMetadata = metadata.copyOf()
    private val ownedBytes = try { bytes?.copyOf() } catch (failure: Throwable) {
        ownedMetadata.fill(0)
        throw failure
    }
    val metadata: LongArray get() = ownedMetadata.copyOf()
    val bytes: ByteArray? get() = ownedBytes?.copyOf()
    // Scalar inspection establishes descriptor ownership before any getter allocation.
    // No backing array is exposed, and all full-width values still require validation.
    internal val metadataCount: Int get() = ownedMetadata.size
    internal fun metadataValue(index: Int): Long = ownedMetadata[index]
    internal fun wipeOwnedBuffers() { ownedMetadata.fill(0); ownedBytes?.fill(0) }
}

interface DurableNativeTransport {
    fun preparePipe(fd: Long, expectedUid: Long, expectedAccess: Int): DurableRawResult =
        DurableRawResult(DurableCode.UNSUPPORTED.wire, longArrayOf(), null)
    fun openChildDirectory(directory: DurableDirectory, leaf: ByteArray, expected: DurableFileIdentity?): DurableRawResult =
        DurableRawResult(DurableCode.UNSUPPORTED.wire, longArrayOf(), null)
    fun createChildDirectoryExclusive(directory: DurableDirectory, leaf: ByteArray): DurableRawResult =
        DurableRawResult(DurableCode.UNSUPPORTED.wire, longArrayOf(), null)
    fun closeDirectory(fd: Long): DurableRawResult = DurableRawResult(DurableCode.UNSUPPORTED.wire, longArrayOf(), null)
    fun read(directory: DurableDirectory, leaf: ByteArray, maxBytes: Int): DurableRawResult
    fun list(directory: DurableDirectory, maxEntries: Int): DurableRawResult
    fun bootstrapLock(directory: DurableDirectory, leaf: ByteArray): DurableRawResult
    fun openWriter(directory: DurableDirectory, leaf: ByteArray, lock: DurableFileIdentity): DurableRawResult
    /** Retains both session FDs until close, including on failure. */
    fun mutate(session: LongArray, directory: DurableDirectory, lockLeaf: ByteArray, lock: DurableFileIdentity,
        leaf: ByteArray, tempLeaf: ByteArray?, expected: DurableSnapshot?, replacement: ByteArray?, maxBytes: Int): DurableRawResult
    fun close(session: LongArray): DurableRawResult
    fun syncExisting(session: LongArray, directory: DurableDirectory, lockLeaf: ByteArray,
        lock: DurableFileIdentity, leaf: ByteArray, expected: DurableSnapshot, maxBytes: Int): DurableRawResult =
        DurableRawResult(DurableCode.UNSUPPORTED.wire, longArrayOf(), null)
}

internal enum class DurableConstructionBoundary {
    BEFORE_METADATA_COPY, BEFORE_PAYLOAD_COPY, BEFORE_VALIDATION,
    BEFORE_OWNER_WRAPPER, BEFORE_RESULT_WRAPPER, BEFORE_TRANSFER,
}

/** Constructor-scoped observation only. It cannot provide data, resources or success values. */
internal fun interface DurableConstructionObserver { fun before(boundary: DurableConstructionBoundary) }

/** Validates the JNI boundary without narrowing any untrusted metadata first. */
class CheckedDurableFilePrimitives internal constructor(
    private val native: DurableNativeTransport,
    private val construction: DurableConstructionObserver,
) : DurableFilePrimitives {
    constructor(native: DurableNativeTransport) : this(native, DurableConstructionObserver { })
    override fun prepareBorrowedPipe(fd: Long, expectedUid: Long, expectedAccess: Int): DurablePipeResult {
        if (!DurableBounds.validFd(fd) || !DurableBounds.validUid(expectedUid) || expectedAccess !in 0..1)
            return DurablePipeResult(DurableCode.INVALID)
        return try {
            decode(native.preparePipe(fd, expectedUid, expectedAccess)) { wire, observed, payload ->
                val code = DurableCode.fromWire(wire)
                if (code == null || code == DurableCode.ABSENT || code == DurableCode.CLOSED || code == DurableCode.CLOSE_UNPROVEN ||
                    (code != DurableCode.OK && (observed.isNotEmpty() || payload != null))) {
                    DurablePipeResult(DurableCode.MUTATION_UNPROVEN)
                } else if (code != DurableCode.OK) {
                    DurablePipeResult(code)
                } else {
                    if (payload != null || observed.size != 6 || observed[0] < 0 || observed[1] <= 0 ||
                        !DurableBounds.validUid(observed[2]) || observed[2] != expectedUid ||
                        observed[3] != 4480L || observed[4] != expectedAccess.toLong() || observed[5] != 1L) {
                        DurablePipeResult(DurableCode.MUTATION_UNPROVEN)
                    } else {
                        // Narrow only after checking the complete values; 010600 is S_IFIFO | 0600.
                        DurablePipeResult(DurableCode.OK, DurablePipeObservation(DurableFileIdentity(observed[0], observed[1]),
                            observed[2], observed[3].toInt(), observed[4].toInt(), true))
                    }
                }
            }
        } catch (_: Throwable) {
            // F_SETFL may already have occurred. The caller still owns and must discard the FD.
            DurablePipeResult(DurableCode.MUTATION_UNPROVEN)
        }
    }

    override fun openChildDirectory(parent: DurableDirectory, leaf: String, expectedChild: DurableFileIdentity?): DurableChildDirectoryResult =
        acquireChild(parent, leaf, expectedChild, creating = false)

    override fun createChildDirectoryExclusive(parent: DurableDirectory, leaf: String): DurableChildDirectoryResult =
        acquireChild(parent, leaf, expected = null, creating = true)

    private fun acquireChild(parent: DurableDirectory, leaf: String, expected: DurableFileIdentity?, creating: Boolean): DurableChildDirectoryResult {
        val name = DurableBounds.leaf(leaf) ?: return DurableChildDirectoryResult(DurableCode.INVALID)
        val malformed = if (creating) DurableCode.MUTATION_UNPROVEN else DurableCode.IO_FAILURE
        // The guard is fully allocated before native code can acquire a descriptor.
        val acquisition = NativeAcquisitionGuard(parent.directoryFd, writer = false)
        fun reject(code: DurableCode): DurableChildDirectoryResult {
            val closed = acquisition.closeResult()
            return DurableChildDirectoryResult(if (creating && acquisition.everOwned) DurableCode.MUTATION_UNPROVEN
                else if (closed != DurableCode.OK) DurableCode.CLOSE_UNPROVEN else code)
        }
        return try {
            val raw = if (creating) native.createChildDirectoryExclusive(parent, name) else native.openChildDirectory(parent, name, expected)
            acquisition.register(raw)
            decode(raw, acquiring = true) { wire, m, payload ->
                val code = checkedCode(wire, m, payload, malformed)
                if (code != DurableCode.OK) {
                    DurableChildDirectoryResult(if (code == DurableCode.CLOSED || (creating && code == DurableCode.ABSENT) ||
                        (!creating && code == DurableCode.MUTATION_UNPROVEN)) malformed else code)
                } else {
                    if (!acquisition.hasOwned || payload != null || m[1] != parent.identity.device || m[2] <= 0 ||
                        !DurableBounds.validUid(m[3]) || m[3] != parent.expectedUid || m[4] != 448L || m[5] < 1 ||
                        (m[1] == parent.identity.device && m[2] == parent.identity.inode)
                    ) reject(malformed)
                    else {
                        val identity = DurableFileIdentity(m[1], m[2])
                        if (expected != null && expected != identity) reject(DurableCode.CONFLICT)
                        else {
                            construction.before(DurableConstructionBoundary.BEFORE_OWNER_WRAPPER)
                            val owned = OwnedChild(DurableDirectory(acquisition.firstFd, parent.expectedUid, identity), creating)
                            construction.before(DurableConstructionBoundary.BEFORE_RESULT_WRAPPER)
                            val result = DurableChildDirectoryResult(DurableCode.OK, owned)
                            construction.before(DurableConstructionBoundary.BEFORE_TRANSFER)
                            acquisition.transfer()
                            result
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            // JNI itself closes a transferred FD if Java result allocation fails.
            // An unexpected transport exception cannot prove that cleanup succeeded.
            val closed = acquisition.closeResult()
            DurableChildDirectoryResult(if (creating) DurableCode.MUTATION_UNPROVEN
                else if (acquisition.everOwned && closed == DurableCode.OK) DurableCode.IO_FAILURE else DurableCode.CLOSE_UNPROVEN)
        } finally { acquisition.closeResult() }
    }

    /**
     * One native acquisition. Scalar registration allocates nothing and precedes decoding.
     * The writer's close-array is also allocated before acquisition. It is transferred to
     * the finished owner or wiped after one close attempt, never recopied during cleanup.
     */
    private inner class NativeAcquisitionGuard(private val borrowedFd: Long, private val writer: Boolean) {
        private var session: LongArray? = if (writer) longArrayOf(-1, -1) else null
        var firstFd: Long = -1
            private set
        var everOwned: Boolean = false
            private set
        var sawResult: Boolean = false
            private set
        private var terminal: DurableCode? = null
        val hasOwned: Boolean get() = firstFd >= 0 && terminal == null

        fun register(raw: DurableRawResult) {
            sawResult = true
            if (raw.code != 0 || raw.metadataCount != if (writer) 2 else 6) return
            val first = raw.metadataValue(0)
            if (first < 0 || first > Int.MAX_VALUE.toLong() || first == borrowedFd) return
            if (writer) {
                val second = raw.metadataValue(1)
                if (second < 0 || second > Int.MAX_VALUE.toLong() || second == first || second == borrowedFd) return
                // Preallocated, private, fixed-length storage. No caller array is retained.
                session!![0] = first
                session!![1] = second
            }
            firstFd = first
            everOwned = true
        }

        fun writerSession(): LongArray = requireNotNull(session)

        fun transfer() {
            // No fallible work is permitted between this transfer and returning the owner.
            firstFd = -1
            session = null
            terminal = DurableCode.CLOSED
        }

        fun closeResult(): DurableCode {
            terminal?.let { return it }
            val fd = firstFd
            val ownedSession = session
            firstFd = -1
            session = null
            // Consume first. A thrown result allocation or uncertain close never retries.
            terminal = DurableCode.CLOSE_UNPROVEN
            val closed = if (fd < 0) DurableCode.OK else if (!writer) closeChildHandle(fd) else try {
                decode(native.close(requireNotNull(ownedSession))) { wire, metadata, payload ->
                    if (wire == 0 && metadata.isEmpty() && payload == null) DurableCode.OK else DurableCode.CLOSE_UNPROVEN
                }
            } catch (_: Throwable) { DurableCode.CLOSE_UNPROVEN }
            ownedSession?.fill(0)
            terminal = closed
            return closed
        }
    }

    private fun closeChildHandle(fd: Long): DurableCode = try {
        decode(native.closeDirectory(fd)) { wire, metadata, payload ->
            if (wire == DurableCode.OK.wire && metadata.isEmpty() && payload == null) DurableCode.OK
            else DurableCode.CLOSE_UNPROVEN
        }
    } catch (_: Throwable) { DurableCode.CLOSE_UNPROVEN }

    private inner class OwnedChild(private var capability: DurableDirectory?, private val created: Boolean) : DurableOwnedDirectory {
        private var activeBorrows = 0
        private var terminalClose: DurableCode? = null
        @Synchronized override fun borrow(): DurableDirectory? = capability
        @Synchronized override fun <T> withBorrow(block: (DurableDirectory) -> T): T? {
            val current = capability ?: return null
            activeBorrows++
            return try { block(current) } finally { activeBorrows-- }
        }
        @Synchronized override fun closeResult(): DurableCode {
            // Only a reentrant callback can enter here with an active borrow;
            // concurrent close waits for withBorrow to release the monitor.
            if (activeBorrows != 0) return DurableCode.CONFLICT
            val current = capability ?: return terminalClose?.takeUnless { it == DurableCode.OK } ?: DurableCode.CLOSED
            capability = null
            val code = closeChildHandle(current.directoryFd)
            val result = if (code == DurableCode.OK) code else if (created) DurableCode.MUTATION_UNPROVEN else DurableCode.CLOSE_UNPROVEN
            terminalClose = result
            return result
        }
        override fun close() {
            val code = closeResult()
            if (code != DurableCode.OK && code != DurableCode.CLOSED) throw IOException("Owned directory close unproven or borrowed")
        }
    }

    override fun list(directory: DurableDirectory, maxEntries: Int): DurableListResult {
        if (maxEntries !in 1..DurableBounds.MAX_ENTRIES) return DurableListResult(DurableCode.INVALID)
        return try {
            decode(native.list(directory, maxEntries)) { wire, rawMetadata, payload ->
                val code = checkedCode(wire, rawMetadata, payload, DurableCode.IO_FAILURE)
                if (code != DurableCode.OK) {
                    DurableListResult(if (code == DurableCode.MUTATION_UNPROVEN || code == DurableCode.CLOSED) DurableCode.IO_FAILURE else code)
                } else {
                    require(rawMetadata.size == 1 && rawMetadata[0] in 0..maxEntries.toLong())
                    val bytes = requireNotNull(payload)
                    require(bytes.size <= maxEntries * (1 + DurableBounds.MAX_LEAF_BYTES + 48))
                    val buffer = ByteBuffer.wrap(bytes)
                    val names = mutableSetOf<String>()
                    val entries = List(rawMetadata[0].toInt()) {
                        val length = buffer.get().toInt() and 0xff
                        require(length in 1..DurableBounds.MAX_LEAF_BYTES && length + 48 <= buffer.remaining())
                        val nameBytes = ByteArray(length).also(buffer::get)
                        require(nameBytes.all { it in 1..127 })
                        val name = nameBytes.toString(Charsets.US_ASCII)
                        require(DurableBounds.leaf(name) != null && names.add(name))
                        val metadata = LongArray(6) { buffer.long }
                        val id = requireNotNull(fileIdentity(metadata, directory.expectedUid, DurableBounds.MAX_BYTES))
                        DurableDirectoryEntry(name, id, metadata[5])
                    }
                    require(!buffer.hasRemaining())
                    DurableListResult(DurableCode.OK, entries.sortedBy { it.leaf })
                }
            }
        } catch (_: Throwable) { DurableListResult(DurableCode.IO_FAILURE) }
    }

    override fun read(directory: DurableDirectory, leaf: String, maxBytes: Int): DurableReadResult {
        val encoded = DurableBounds.leaf(leaf)
        if (encoded == null || !DurableBounds.validLimit(maxBytes)) return DurableReadResult(DurableCode.INVALID)
        return try {
            decode(native.read(directory, encoded, maxBytes)) { wire, metadata, bytes ->
                val code = checkedCode(wire, metadata, bytes, DurableCode.IO_FAILURE)
                if (code != DurableCode.OK) {
                    DurableReadResult(if (code == DurableCode.MUTATION_UNPROVEN || code == DurableCode.CLOSED) DurableCode.IO_FAILURE else code)
                } else {
                    val id = fileIdentity(metadata, directory.expectedUid, maxBytes)
                    if (id == null || bytes == null || metadata[5] != bytes.size.toLong()) DurableReadResult(DurableCode.IO_FAILURE)
                    else DurableReadResult(DurableCode.OK, DurableSnapshot(id, bytes))
                }
            }
        } catch (_: Throwable) { DurableReadResult(DurableCode.IO_FAILURE) }
    }

    override fun bootstrapLock(directory: DurableDirectory, lockLeaf: String): DurableIdentityResult {
        val leaf = DurableBounds.leaf(lockLeaf) ?: return DurableIdentityResult(DurableCode.INVALID)
        return try {
            decode(native.bootstrapLock(directory, leaf)) { wire, metadata, payload ->
                val code = checkedCode(wire, metadata, payload, DurableCode.MUTATION_UNPROVEN)
                if (code != DurableCode.OK) DurableIdentityResult(code)
                else {
                    val id = fileIdentity(metadata, directory.expectedUid, 0)
                    if (id == null || payload != null) DurableIdentityResult(DurableCode.MUTATION_UNPROVEN)
                    else DurableIdentityResult(DurableCode.OK, id)
                }
            }
        } catch (_: Throwable) { DurableIdentityResult(DurableCode.MUTATION_UNPROVEN) }
    }

    override fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity): DurableOpenResult {
        val leaf = DurableBounds.leaf(lockLeaf) ?: return DurableOpenResult(DurableCode.INVALID)
        val acquisition = NativeAcquisitionGuard(directory.directoryFd, writer = true)
        return try {
            val raw = native.openWriter(directory, leaf, expectedLock)
            acquisition.register(raw)
            decode(raw, acquiring = true) { wire, handles, payload ->
                val code = checkedCode(wire, handles, payload, DurableCode.IO_FAILURE)
                if (code != DurableCode.OK) DurableOpenResult(code)
                else if (!acquisition.hasOwned || payload != null) {
                    val closed = acquisition.closeResult()
                    DurableOpenResult(if (closed == DurableCode.OK) DurableCode.IO_FAILURE else DurableCode.CLOSE_UNPROVEN)
                } else {
                    construction.before(DurableConstructionBoundary.BEFORE_OWNER_WRAPPER)
                    val writer = Writer(acquisition.writerSession(), directory, leaf, expectedLock)
                    construction.before(DurableConstructionBoundary.BEFORE_RESULT_WRAPPER)
                    val opened = DurableOpenResult(DurableCode.OK, writer)
                    construction.before(DurableConstructionBoundary.BEFORE_TRANSFER)
                    acquisition.transfer()
                    opened
                }
            }
        } catch (_: Throwable) {
            val closed = acquisition.closeResult()
            DurableOpenResult(if (acquisition.sawResult && closed == DurableCode.OK) DurableCode.IO_FAILURE else DurableCode.CLOSE_UNPROVEN)
        } finally { acquisition.closeResult() }
    }

    private inner class Writer(private var handles: LongArray?, private val directory: DurableDirectory,
        private val lockLeaf: ByteArray, private val lock: DurableFileIdentity) : DurableWriter {
        private var poisoned = false
        private var changed = false
        private var terminalClose: DurableCode? = null

        @Synchronized override fun read(leaf: String, maxBytes: Int): DurableReadResult {
            val owned = handles ?: return DurableReadResult(DurableCode.CLOSED)
            if (poisoned) return DurableReadResult(DurableCode.CLOSED)
            return this@CheckedDurableFilePrimitives.read(directory.copy(directoryFd = owned[0]), leaf, maxBytes)
        }
        @Synchronized override fun list(maxEntries: Int): DurableListResult {
            val owned = handles ?: return DurableListResult(DurableCode.CLOSED)
            if (poisoned) return DurableListResult(DurableCode.CLOSED)
            return this@CheckedDurableFilePrimitives.list(directory.copy(directoryFd = owned[0]), maxEntries)
        }
        @Synchronized override fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray,
            maxBytes: Int): DurableMutationResult = mutate(leaf, tempLeaf, expectedOld, bytes, maxBytes)

        @Synchronized override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int): DurableMutationResult =
            mutate(leaf, null, expectedOld, null, maxBytes)

        @Synchronized override fun syncAndObserveExisting(leaf: String, expected: DurableSnapshot, maxBytes: Int): DurableSyncResult {
            val owned = handles ?: return DurableSyncResult(DurableCode.CLOSED)
            if (poisoned) return DurableSyncResult(DurableCode.CLOSED)
            val name = DurableBounds.leaf(leaf)
            if (name == null || name.contentEquals(lockLeaf) || !DurableBounds.validLimit(maxBytes) || expected.size > maxBytes) {
                return DurableSyncResult(DurableCode.INVALID)
            }
            val comparison = expected.bytes
            val result = try {
                decode(native.syncExisting(owned.copyOf(), directory.copy(directoryFd = owned[0]), lockLeaf.copyOf(), lock, name, expected, maxBytes)) { wire, metadata, observed ->
                    val code = checkedCode(wire, metadata, observed, DurableCode.MUTATION_UNPROVEN)
                    if (code != DurableCode.OK) {
                        DurableSyncResult(if (code == DurableCode.ABSENT || code == DurableCode.CLOSE_UNPROVEN || code == DurableCode.CLOSED) DurableCode.MUTATION_UNPROVEN else code)
                    } else if (metadata.size != 6 || observed == null || observed.size > maxBytes) {
                        DurableSyncResult(DurableCode.MUTATION_UNPROVEN)
                    } else {
                        val id = fileIdentity(metadata, directory.expectedUid, maxBytes)
                        if (id != expected.identity || metadata[5] != comparison.size.toLong() ||
                            observed.size != comparison.size || !observed.contentEquals(comparison)
                        ) DurableSyncResult(DurableCode.MUTATION_UNPROVEN)
                        else DurableSyncResult(DurableCode.OK, DurableSnapshot(id, observed))
                    }
                }
            } catch (_: Throwable) { DurableSyncResult(DurableCode.MUTATION_UNPROVEN) }
            finally { comparison.fill(0) }
            // A successful fsync may publish preceding projection writes. It is
            // provisional until this writer's terminal close also succeeds.
            if (result.code == DurableCode.OK) changed = true
            if (result.code == DurableCode.MUTATION_UNPROVEN) { changed = true; poisoned = true }
            return result
        }

        private fun mutate(leaf: String, tempLeaf: String?, expected: DurableSnapshot?, bytes: ByteArray?, maxBytes: Int): DurableMutationResult {
            val owned = handles ?: return DurableMutationResult(DurableCode.CLOSED)
            if (poisoned) return DurableMutationResult(DurableCode.CLOSED)
            val name = DurableBounds.leaf(leaf)
            val temporary = tempLeaf?.let(DurableBounds::leaf)
            if (name == null || name.contentEquals(lockLeaf) || !DurableBounds.validLimit(maxBytes) ||
                (bytes != null && (temporary == null || temporary.contentEquals(name) || temporary.contentEquals(lockLeaf) || bytes.size > maxBytes)) ||
                (expected != null && expected.size > maxBytes)
            ) return DurableMutationResult(DurableCode.INVALID)
            val input = bytes?.copyOf()
            val result = try {
                decode(native.mutate(owned, directory, lockLeaf, lock, name, temporary, expected, input, maxBytes)) { wire, metadata, payload ->
                    val code = checkedCode(wire, metadata, payload, DurableCode.MUTATION_UNPROVEN)
                    DurableMutationResult(if (metadata.isNotEmpty() || payload != null ||
                        code == DurableCode.ABSENT || code == DurableCode.CLOSE_UNPROVEN || code == DurableCode.CLOSED
                    ) DurableCode.MUTATION_UNPROVEN else code)
                }
            } catch (_: Throwable) { DurableMutationResult(DurableCode.MUTATION_UNPROVEN) }
            finally { input?.fill(0) }
            if (result.code == DurableCode.OK) changed = true
            if (result.code == DurableCode.MUTATION_UNPROVEN) { changed = true; poisoned = true }
            return result
        }

        @Synchronized override fun closeResult(): DurableCode {
            val owned = handles ?: return terminalClose?.takeUnless { it == DurableCode.OK } ?: DurableCode.CLOSED
            handles = null
            val result = try {
                decode(native.close(owned)) { wire, metadata, payload ->
                    if (wire == 0 && metadata.isEmpty() && payload == null && !poisoned) DurableCode.OK
                    else if (changed) DurableCode.MUTATION_UNPROVEN else DurableCode.CLOSE_UNPROVEN
                }
            } catch (_: Throwable) { if (changed) DurableCode.MUTATION_UNPROVEN else DurableCode.CLOSE_UNPROVEN }
            finally { owned.fill(0) }
            terminalClose = result
            return result
        }

        override fun close() {
            val code = closeResult()
            if (code == DurableCode.CLOSE_UNPROVEN || code == DurableCode.MUTATION_UNPROVEN) throw IOException("Directory writer close unproven")
        }
    }

    private inline fun <T> decode(raw: DurableRawResult, acquiring: Boolean = false, block: (Int, LongArray, ByteArray?) -> T): T {
        var metadata: LongArray? = null
        var payload: ByteArray? = null
        return try {
            // Exactly one getter snapshot per array. The callback never receives raw backing
            // arrays; output objects must own copies before this scope wipes its working data.
            if (acquiring) construction.before(DurableConstructionBoundary.BEFORE_METADATA_COPY)
            metadata = raw.metadata
            if (acquiring) construction.before(DurableConstructionBoundary.BEFORE_PAYLOAD_COPY)
            payload = raw.bytes
            if (acquiring) construction.before(DurableConstructionBoundary.BEFORE_VALIDATION)
            block(raw.code, metadata, payload)
        } finally {
            metadata?.fill(0)
            payload?.fill(0)
            raw.wipeOwnedBuffers()
        }
    }

    private fun checkedCode(wire: Int, metadata: LongArray, bytes: ByteArray?, malformed: DurableCode): DurableCode {
        val code = DurableCode.fromWire(wire) ?: return malformed
        return if (code != DurableCode.OK && (metadata.isNotEmpty() || bytes != null)) malformed else code
    }

    private fun fileIdentity(values: LongArray, uid: Long, max: Int): DurableFileIdentity? {
        if (values.size != 6 || values[0] < 0 || values[1] <= 0 || !DurableBounds.validUid(values[2]) ||
            values[2] != uid || values[3] != 384L || values[4] != 1L || values[5] !in 0..max.toLong()
        ) return null
        return DurableFileIdentity(values[0], values[1])
    }
}
