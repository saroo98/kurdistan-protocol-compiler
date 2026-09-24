// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import android.content.Context
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption.READ
import java.nio.file.attribute.BasicFileAttributes

interface SecureBlobReadAccess {
    fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray
    fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean
    /** Null means absent; authentication and committed-object failures must propagate. */
    fun reopenIfPresent(localRecordId: String, dataClass: SecureDataClass): ByteArray? =
        if (exists(localRecordId, dataClass)) reopen(localRecordId, dataClass) else null
}

interface SecureBlobAccess : SecureBlobReadAccess {
    fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray)
    fun delete(localRecordId: String, dataClass: SecureDataClass)
    fun deleteAll()
}

class SecureBlobStore internal constructor(
    root: File,
    private val codec: SecureEnvelopeCodec,
    kek: KeyEncryptionKey,
    private val syncDirectory: (File) -> Unit,
    identityKey: (Path) -> Any = ProcessFileLock::nioIdentityKey,
) : SecureBlobAccess {
    constructor(context: Context, codec: SecureEnvelopeCodec, kek: KeyEncryptionKey) :
        this(File(context.noBackupFilesDir, "phase9-v1"), codec, kek, ::syncAndroidDirectory)

    private val root: File
    private val lock: ProcessFileLock
    private val keys = linkedMapOf(kek.generation to kek)
    private var activeKek = kek

    init {
        require(root.name == "phase9-v1")
        check(root.exists() || root.mkdirs()) { "secure blob root unavailable" }
        check(!Files.isSymbolicLink(root.toPath())) { "unsafe secure blob root" }
        check(root.canonicalFile.parentFile == checkNotNull(root.absoluteFile.parentFile).canonicalFile)
        this.root = root.canonicalFile
        lock = ProcessFileLock(this.root, identityKey)
    }

    override fun stage(
        localRecordId: String,
        dataClass: SecureDataClass,
        exactBytes: ByteArray,
    ) = lock.withLock {
        recoverTemporaries()
        stageUnlocked(localRecordId, dataClass, exactBytes, activeKek, "staging")
    }

    private fun stageUnlocked(
        localRecordId: String,
        dataClass: SecureDataClass,
        exactBytes: ByteArray,
        key: KeyEncryptionKey,
        suffix: String,
    ) {
        val target = target(localRecordId, dataClass)
        val temporary = File(root, ".${target.name}.$suffix")
        check(!Files.exists(temporary.toPath(), NOFOLLOW_LINKS)) { "unrecovered secure temporary" }
        val encoded = codec.seal(localRecordId, dataClass, exactBytes, key)
        try {
            // CREATE_NEW prevents following a pre-existing temporary alias.
            Files.createFile(temporary.toPath())
            FileOutputStream(temporary).use { stream ->
                stream.write(encoded)
                stream.fd.sync()
            }
            Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            syncDirectory(root)
        } finally {
            encoded.fill(0)
        }
    }

    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray =
        reopen(localRecordId, dataClass) {}

    internal fun reopen(
        localRecordId: String,
        dataClass: SecureDataClass,
        afterDecryption: (ByteArray) -> Unit,
    ): ByteArray {
        var owned: ByteArray? = null
        try {
            lock.withLock {
                val plaintext = reopenUnlocked(localRecordId, dataClass)
                owned = plaintext
                afterDecryption(plaintext)
            }
            // Ownership transfers only after lock release and channel cleanup succeed.
            return checkNotNull(owned)
        } catch (failure: Throwable) {
            owned?.fill(0)
            throw failure
        }
    }

    private fun reopenUnlocked(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        val encoded = readBounded(target(localRecordId, dataClass))
        return try {
            val key = keys[codec.keyGeneration(encoded)] ?: throw MissingKeyException()
            val opened = codec.open(encoded, localRecordId, key)
            if (opened.dataClass != dataClass) {
                opened.plaintext.fill(0)
                error("secure blob role mismatch")
            }
            opened.plaintext
        } finally {
            encoded.fill(0)
        }
    }

    fun update(localRecordId: String, dataClass: SecureDataClass, transform: (ByteArray?) -> ByteArray) = lock.withLock {
        recoverTemporaries()
        val previous = if (existsUnlocked(localRecordId, dataClass)) reopenUnlocked(localRecordId, dataClass) else null
        var replacement: ByteArray? = null
        try {
            replacement = transform(previous)
            stageUnlocked(localRecordId, dataClass, replacement, activeKek, "staging")
        } finally {
            previous?.fill(0)
            replacement?.fill(0)
        }
    }

    fun rotate(
        localRecordId: String,
        dataClass: SecureDataClass,
        replacement: KeyEncryptionKey,
    ) = lock.withLock {
        require(replacement.generation > activeKek.generation)
        require(keys[replacement.generation] == null || keys[replacement.generation] === replacement)
        recoverTemporaries()
        val plaintext = reopenUnlocked(localRecordId, dataClass)
        // Retain the new key even if directory sync fails after atomic publication.
        keys[replacement.generation] = replacement
        try {
            stageUnlocked(localRecordId, dataClass, plaintext, replacement, "rotation")
        } finally {
            plaintext.fill(0)
        }
    }

    fun activateReplacement(replacement: KeyEncryptionKey) = lock.withLock {
        require(keys[replacement.generation] === replacement)
        recoverTemporaries()
        val generations = checkNotNull(root.listFiles())
            .filter { it.isFile && it.name.endsWith(".blob") }
            .map {
                val encoded = readBounded(it)
                try {
                    codec.keyGeneration(encoded)
                } finally {
                    encoded.fill(0)
                }
            }
            .toSet()
        require(generations.isEmpty() || generations == setOf(replacement.generation))
        activeKek = replacement
        keys.keys.removeAll { it < replacement.generation }
    }

    override fun delete(localRecordId: String, dataClass: SecureDataClass) = lock.withLock {
        recoverTemporaries()
        val target = target(localRecordId, dataClass)
        if (Files.deleteIfExists(target.toPath())) {
            syncDirectory(root)
        }
    }

    override fun deleteAll() = lock.withLock {
        for (child in checkNotNull(root.listFiles())) {
            val role = recordName.matchEntire(child.name)?.groupValues?.get(2)
                ?: temporaryName.matchEntire(child.name)?.groupValues?.get(2)
            if (SecureDataClass.entries.any { it.wireValue.toString() == role }) {
                check(Files.isRegularFile(child.toPath(), NOFOLLOW_LINKS)) { "unsafe secure storage entry" }
                Files.delete(child.toPath())
                syncDirectory(root)
            }
        }
    }

    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean = lock.withLock {
        existsUnlocked(localRecordId, dataClass)
    }

    private fun existsUnlocked(localRecordId: String, dataClass: SecureDataClass): Boolean {
        val path = target(localRecordId, dataClass).toPath()
        val attributes = try { Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
        catch (_: NoSuchFileException) { return false }
        check(attributes.isRegularFile && !attributes.isSymbolicLink) { "unsafe secure blob" }
        return true
    }

    private fun recoverTemporaries() {
        for (temporary in checkNotNull(root.listFiles())) {
            val match = temporaryName.matchEntire(temporary.name) ?: continue
            val role = SecureDataClass.entries.firstOrNull { it.wireValue.toString() == match.groupValues[2] } ?: continue
            check(Files.isRegularFile(temporary.toPath(), NOFOLLOW_LINKS)) { "unsafe secure temporary" }
            val id = match.groupValues[1]
            if (existsUnlocked(id, role)) reopenUnlocked(id, role).fill(0)
            Files.delete(temporary.toPath())
            syncDirectory(root)
        }
    }

    private fun readBounded(file: File): ByteArray {
        check(Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) { "unsafe secure blob" }
        var owned: ByteArray? = null
        try {
            return FileChannel.open(file.toPath(), READ, NOFOLLOW_LINKS).use { channel ->
                val size = channel.size()
                require(size in 1..(MAX_SECURE_BLOB_BYTES.toLong() + 2048))
                val encoded = ByteArray(size.toInt()).also { owned = it }
                val buffer = ByteBuffer.wrap(encoded)
                while (buffer.hasRemaining()) check(channel.read(buffer) > 0) { "truncated secure blob" }
                check(channel.size() == size) { "secure blob size changed" }
                encoded
            }
        } catch (failure: Throwable) {
            // Includes channel close failure after a successful read.
            owned?.fill(0)
            throw failure
        }
    }

    private fun target(localRecordId: String, dataClass: SecureDataClass): File {
        require(localRecordId.matches(Regex("[a-z0-9-]{1,64}")))
        val target = File(root, "$localRecordId.${dataClass.wireValue}.blob")
        check(target.canonicalFile.parentFile == root.canonicalFile)
        check(!Files.isSymbolicLink(target.toPath())) { "unsafe secure blob" }
        return target
    }

    private companion object {
        val recordName = Regex("([a-z0-9-]{1,64})\\.([0-9]+)\\.blob")
        val temporaryName = Regex("\\.([a-z0-9-]{1,64})\\.([0-9]+)\\.blob\\.(staging|rotation)")

        fun syncAndroidDirectory(root: File) {
            val before = Os.lstat(root.absolutePath)
            check(OsConstants.S_ISDIR(before.st_mode)) { "unsafe secure directory" }
            val descriptor = Os.open(root.absolutePath, OsConstants.O_RDONLY or OsConstants.O_NONBLOCK or
                OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            var failure: Throwable? = null
            try {
                val opened = Os.fstat(descriptor)
                val current = Os.lstat(root.absolutePath)
                check(OsConstants.S_ISDIR(opened.st_mode) && OsConstants.S_ISDIR(current.st_mode) &&
                    opened.st_dev == before.st_dev && opened.st_ino == before.st_ino &&
                    opened.st_dev == current.st_dev && opened.st_ino == current.st_ino) { "unsafe secure directory" }
                Os.fsync(descriptor)
            }
            catch (caught: Throwable) { failure = caught; throw caught }
            finally {
                try { Os.close(descriptor) }
                catch (caught: Throwable) { if (failure != null) failure.addSuppressed(caught) else throw caught }
            }
        }
    }
}
