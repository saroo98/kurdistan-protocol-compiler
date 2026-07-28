// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

interface SecureBlobAccess {
    fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray)
    fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray
    fun delete(localRecordId: String, dataClass: SecureDataClass)
    fun deleteAll()
    fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean
}

class SecureBlobStore(
    context: Context,
    private val codec: SecureEnvelopeCodec,
    kek: KeyEncryptionKey,
) : SecureBlobAccess {
    private val root = File(context.noBackupFilesDir, "phase9-v1")
    private val keys = linkedMapOf(kek.generation to kek)
    private var activeKek = kek

    init {
        check(root.exists() || root.mkdirs()) { "secure blob root unavailable" }
        check(root.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
    }

    override fun stage(
        localRecordId: String,
        dataClass: SecureDataClass,
        exactBytes: ByteArray,
    ) {
        val encoded = codec.seal(localRecordId, dataClass, exactBytes, activeKek)
        val target = target(localRecordId, dataClass)
        val temporary = File(root, ".${target.name}.staging")
        FileOutputStream(temporary).use { stream ->
            stream.write(encoded)
            stream.fd.sync()
        }
        Files.move(
            temporary.toPath(),
            target.toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        val encoded = target(localRecordId, dataClass).readBytes()
        return try {
            val key = keys[codec.keyGeneration(encoded)] ?: throw MissingKeyException()
            codec.open(encoded, localRecordId, key).also {
                check(it.dataClass == dataClass)
            }.plaintext
        } finally {
            encoded.fill(0)
        }
    }

    fun rotate(
        localRecordId: String,
        dataClass: SecureDataClass,
        replacement: KeyEncryptionKey,
    ) {
        require(replacement.generation > activeKek.generation)
        keys[replacement.generation] = replacement
        val plaintext = reopen(localRecordId, dataClass)
        val encoded = try {
            codec.seal(localRecordId, dataClass, plaintext, replacement)
        } finally {
            plaintext.fill(0)
        }
        val target = target(localRecordId, dataClass)
        val temporary = File(root, ".${target.name}.rotation")
        FileOutputStream(temporary).use { stream ->
            stream.write(encoded)
            stream.fd.sync()
        }
        Files.move(
            temporary.toPath(),
            target.toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    fun activateReplacement(replacement: KeyEncryptionKey) {
        require(keys[replacement.generation] === replacement)
        val generations = root.listFiles()
            .orEmpty()
            .filter { it.isFile && it.name.endsWith(".blob") }
            .map {
                val encoded = it.readBytes()
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

    override fun delete(localRecordId: String, dataClass: SecureDataClass) {
        val target = target(localRecordId, dataClass)
        if (target.exists() && !target.delete()) {
            throw IllegalStateException("secure blob deletion failed")
        }
    }

    override fun deleteAll() {
        root.listFiles().orEmpty().forEach { child ->
            check(child.canonicalFile.parentFile == root.canonicalFile)
            check(child.isFile) { "unexpected secure storage directory" }
            check(child.delete()) { "secure blob deletion failed" }
        }
    }

    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean =
        target(localRecordId, dataClass).isFile

    private fun target(localRecordId: String, dataClass: SecureDataClass): File {
        require(localRecordId.matches(Regex("[a-z0-9-]{1,64}")))
        val target = File(root, "$localRecordId.${dataClass.wireValue}.blob")
        check(target.canonicalFile.parentFile == root.canonicalFile)
        return target
    }
}
