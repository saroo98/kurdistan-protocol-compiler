// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeRecipient
import org.kurdistanvpn.core.nativeapi.NativeResult

private const val CLIENT_KEY_INDEX_MAGIC = 0x4B434931
private const val CLIENT_KEY_BUNDLE_MAGIC = 0x4B434231
private const val CLIENT_KEY_INDEX_ID = "recipient-index"
private const val CLIENT_KEY_VERSION = 1
private const val MAX_CLIENT_KEYS = 32
private const val MAX_BOUND_PROFILES = 64
private const val MAX_RECIPIENT_REQUEST_BYTES = 512
private const val MAX_RECIPIENT_PRIVATE_BYTES = 128
private val LOCAL_KEY_ID = Regex("[a-z0-9-]{1,64}")
private val PROFILE_RECORD_ID = Regex("[a-z0-9-]{1,64}")

enum class ClientKeyStatus(val wireValue: Int) {
    PREPARED(1),
    REQUEST_READY(2),
    AWAITING_PROFILE(3),
    PROFILE_VERIFIED(4),
}

data class ClientKeySummary(
    val localRecordId: String,
    val requestFingerprint: String,
    val createdAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val status: ClientKeyStatus,
    val boundProfileCount: Int,
)

sealed interface ClientKeyResult {
    data class Success(val summary: ClientKeySummary) : ClientKeyResult
    data class Failure(val error: OperationError) : ClientKeyResult
}

data class ClientKeyBackupRecord(
    val sourceRecordId: String,
    val createdAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val publicRequest: ByteArray,
    val privateBundle: ByteArray,
) {
    fun destroy() {
        publicRequest.fill(0)
        privateBundle.fill(0)
    }
}

sealed interface ClientKeyRestoreResult {
    data class Success(val restored: Int, val localRecordIds: List<String>) : ClientKeyRestoreResult
    data class Failure(val error: OperationError) : ClientKeyRestoreResult
}

class RecipientCredentialLease internal constructor(
    val localRecordId: String,
    val publicRequest: ByteArray,
    val privateBundle: ByteArray,
) : AutoCloseable {
    override fun close() {
        publicRequest.fill(0)
        privateBundle.fill(0)
    }
}

interface RecipientKeyNative {
    fun create(validitySeconds: Int): NativeResult<NativeRecipient>
    fun validate(publicRequest: ByteArray, privateBundle: ByteArray): NativeResult<Unit>
}

class KurdRecipientKeyNative(
    private val nativeCore: KurdNativeCore,
) : RecipientKeyNative {
    override fun create(validitySeconds: Int): NativeResult<NativeRecipient> =
        nativeCore.createRecipient(validitySeconds)

    override fun validate(
        publicRequest: ByteArray,
        privateBundle: ByteArray,
    ): NativeResult<Unit> = nativeCore.validateRecipient(publicRequest, privateBundle)
}

/**
 * Encrypted local registry for device enrollment capabilities. The index is
 * itself a Keystore-wrapped blob and contains only local random identifiers,
 * request fingerprints, coarse lifecycle state, and local profile bindings.
 * Exact public and private capability bytes remain together in a separately
 * bound encrypted record.
 */
class ClientKeyBundleStore(
    private val blobs: SecureBlobAccess,
    private val native: RecipientKeyNative,
    private val newLocalRecordId: () -> String = { UUID.randomUUID().toString() },
) {
    private val lock = Any()

    init {
        synchronized(lock) { recoverPreparedLocked() }
    }

    fun create(validitySeconds: Int, nowEpochSeconds: Long): ClientKeyResult = synchronized(lock) {
        if (validitySeconds !in 1..24 * 60 * 60 || nowEpochSeconds <= 0) {
            return@synchronized ClientKeyResult.Failure(OperationError.INVALID_INPUT)
        }
        val handle = when (val result = native.create(validitySeconds)) {
            is NativeResult.Failure -> return@synchronized ClientKeyResult.Failure(result.error)
            is NativeResult.Success -> result.value
        }
        handle.use { recipient ->
            val request = when (val result = recipient.publicRequest()) {
                is NativeResult.Failure -> return@synchronized ClientKeyResult.Failure(result.error)
                is NativeResult.Success -> result.value
            }
            val privateBundle = when (val result = recipient.privateBundle()) {
                is NativeResult.Failure -> {
                    request.fill(0)
                    return@synchronized ClientKeyResult.Failure(result.error)
                }
                is NativeResult.Success -> result.value
            }
            try {
                if (request.size !in 1..MAX_RECIPIENT_REQUEST_BYTES ||
                    privateBundle.size !in 1..MAX_RECIPIENT_PRIVATE_BYTES
                ) {
                    return@synchronized ClientKeyResult.Failure(OperationError.SIZE_LIMIT)
                }
                val entries = readIndexLocked().toMutableList()
                if (entries.size >= MAX_CLIENT_KEYS) {
                    return@synchronized ClientKeyResult.Failure(OperationError.SIZE_LIMIT)
                }
                val fingerprint = fingerprint(request)
                if (entries.any { it.requestFingerprint == fingerprint }) {
                    return@synchronized ClientKeyResult.Failure(OperationError.DUPLICATE)
                }
                val localId = newUniqueLocalId(entries)
                val entry = ClientKeyIndexEntry(
                    localRecordId = localId,
                    requestFingerprint = fingerprint,
                    createdAtEpochSeconds = nowEpochSeconds,
                    expiresAtEpochSeconds = Math.addExact(nowEpochSeconds, validitySeconds.toLong()),
                    status = ClientKeyStatus.PREPARED,
                    boundProfiles = emptySet(),
                )
                entries += entry
                writeIndexLocked(entries)
                val payload = encodeBundle(localId, entry.createdAtEpochSeconds, entry.expiresAtEpochSeconds, request, privateBundle)
                try {
                    blobs.stage(localId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, payload)
                } finally {
                    payload.fill(0)
                }
                val ready = entry.copy(status = ClientKeyStatus.REQUEST_READY)
                entries[entries.lastIndex] = ready
                writeIndexLocked(entries)
                ClientKeyResult.Success(ready.summary())
            } catch (_: KeyInvalidatedException) {
                ClientKeyResult.Failure(OperationError.KEY_INVALIDATED)
            } catch (_: ArithmeticException) {
                ClientKeyResult.Failure(OperationError.INVALID_INPUT)
            } catch (_: Throwable) {
                ClientKeyResult.Failure(OperationError.STORAGE_FAILURE)
            } finally {
                request.fill(0)
                privateBundle.fill(0)
            }
        }
    }

    fun list(): List<ClientKeySummary> = synchronized(lock) {
        recoverPreparedLocked()
        readIndexLocked().filter { it.status != ClientKeyStatus.PREPARED }
            .sortedByDescending { it.createdAtEpochSeconds }
            .map(ClientKeyIndexEntry::summary)
    }

    fun publicRequest(localRecordId: String): ByteArray = synchronized(lock) {
        val entry = requireEntryLocked(localRecordId)
        val bundle = openBundleLocked(entry)
        try {
            bundle.publicRequest.clone()
        } finally {
            bundle.destroy()
        }
    }

    fun markRequestExported(localRecordId: String) = synchronized(lock) {
        val entries = readIndexLocked().toMutableList()
        val index = entries.indexOfFirst { it.localRecordId == localRecordId }
        require(index >= 0)
        val entry = entries[index]
        if (entry.status == ClientKeyStatus.REQUEST_READY) {
            entries[index] = entry.copy(status = ClientKeyStatus.AWAITING_PROFILE)
            writeIndexLocked(entries)
        }
    }

    fun credentials(localRecordId: String): RecipientCredentialLease = synchronized(lock) {
        val entry = requireEntryLocked(localRecordId)
        val bundle = openBundleLocked(entry)
        RecipientCredentialLease(
            localRecordId = localRecordId,
            publicRequest = bundle.publicRequest,
            privateBundle = bundle.privateBundle,
        )
    }

    fun credentialCandidates(): List<RecipientCredentialLease> = synchronized(lock) {
        recoverPreparedLocked()
        val leases = mutableListOf<RecipientCredentialLease>()
        try {
            readIndexLocked().asSequence()
                .filter { it.status != ClientKeyStatus.PREPARED }
                .sortedByDescending { it.createdAtEpochSeconds }
                .forEach { entry ->
                val bundle = openBundleLocked(entry)
                    leases += RecipientCredentialLease(
                        entry.localRecordId,
                        bundle.publicRequest,
                        bundle.privateBundle,
                    )
                }
            leases
        } catch (error: Throwable) {
            leases.forEach(RecipientCredentialLease::close)
            throw error
            }
    }

    fun bindProfile(localRecordId: String, profileRecordId: String) = synchronized(lock) {
        require(profileRecordId.matches(PROFILE_RECORD_ID))
        val entries = readIndexLocked().toMutableList()
        val index = entries.indexOfFirst { it.localRecordId == localRecordId }
        require(index >= 0)
        val bound = entries[index].boundProfiles + profileRecordId
        require(bound.size <= MAX_BOUND_PROFILES)
        entries[index] = entries[index].copy(
            status = ClientKeyStatus.PROFILE_VERIFIED,
            boundProfiles = bound,
        )
        writeIndexLocked(entries)
    }

    fun unbindProfile(profileRecordId: String): ClientKeySummary? = synchronized(lock) {
        require(profileRecordId.matches(PROFILE_RECORD_ID))
        val entries = readIndexLocked().toMutableList()
        var offered: ClientKeySummary? = null
        entries.indices.forEach { index ->
            val entry = entries[index]
            if (profileRecordId in entry.boundProfiles) {
                val remaining = entry.boundProfiles - profileRecordId
                val updated = entry.copy(
                    status = if (remaining.isEmpty()) ClientKeyStatus.REQUEST_READY else ClientKeyStatus.PROFILE_VERIFIED,
                    boundProfiles = remaining,
                )
                entries[index] = updated
                if (remaining.isEmpty()) offered = updated.summary()
            }
        }
        writeIndexLocked(entries)
        offered
    }

    fun delete(localRecordId: String): Boolean = synchronized(lock) {
        val entries = readIndexLocked().toMutableList()
        val target = entries.singleOrNull { it.localRecordId == localRecordId } ?: return@synchronized false
        require(target.boundProfiles.isEmpty())
        blobs.delete(localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        entries.remove(target)
        writeIndexLocked(entries)
        true
    }

    fun backupRecords(profileRecordId: String? = null): List<ClientKeyBackupRecord> = synchronized(lock) {
        recoverPreparedLocked()
        val records = mutableListOf<ClientKeyBackupRecord>()
        try {
            readIndexLocked().filter {
                it.status != ClientKeyStatus.PREPARED &&
                    (profileRecordId == null || profileRecordId in it.boundProfiles)
            }.forEach { entry ->
                val bundle = openBundleLocked(entry)
                records += ClientKeyBackupRecord(
                    sourceRecordId = entry.localRecordId,
                    createdAtEpochSeconds = entry.createdAtEpochSeconds,
                    expiresAtEpochSeconds = entry.expiresAtEpochSeconds,
                    publicRequest = bundle.publicRequest,
                    privateBundle = bundle.privateBundle,
                )
            }
            records
        } catch (error: Throwable) {
            records.forEach(ClientKeyBackupRecord::destroy)
            throw error
        }
    }

    fun restore(records: List<ClientKeyBackupRecord>): ClientKeyRestoreResult = synchronized(lock) {
        if (records.size > MAX_CLIENT_KEYS) {
            return@synchronized ClientKeyRestoreResult.Failure(OperationError.SIZE_LIMIT)
        }
        val current = readIndexLocked().toMutableList()
        val createdIds = mutableListOf<String>()
        try {
            records.forEach { record ->
                if (!record.sourceRecordId.matches(LOCAL_KEY_ID) ||
                    record.createdAtEpochSeconds <= 0 ||
                    record.expiresAtEpochSeconds <= record.createdAtEpochSeconds ||
                    record.publicRequest.size !in 1..MAX_RECIPIENT_REQUEST_BYTES ||
                    record.privateBundle.size !in 1..MAX_RECIPIENT_PRIVATE_BYTES
                ) {
                    return@synchronized rollbackRestoreLocked(
                        current,
                        createdIds,
                        OperationError.INVALID_INPUT,
                    )
                }
                when (val validation = native.validate(record.publicRequest, record.privateBundle)) {
                    is NativeResult.Failure -> return@synchronized rollbackRestoreLocked(
                        current,
                        createdIds,
                        validation.error,
                    )
                    is NativeResult.Success -> Unit
                }
                val requestFingerprint = fingerprint(record.publicRequest)
                if (current.any { it.requestFingerprint == requestFingerprint }) {
                    return@forEach
                }
                if (current.size >= MAX_CLIENT_KEYS) {
                    return@synchronized rollbackRestoreLocked(current, createdIds, OperationError.SIZE_LIMIT)
                }
                val localId = newUniqueLocalId(current)
                val payload = encodeBundle(
                    localId,
                    record.createdAtEpochSeconds,
                    record.expiresAtEpochSeconds,
                    record.publicRequest,
                    record.privateBundle,
                )
                try {
                    blobs.stage(localId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, payload)
                } finally {
                    payload.fill(0)
                }
                createdIds += localId
                current += ClientKeyIndexEntry(
                    localRecordId = localId,
                    requestFingerprint = requestFingerprint,
                    createdAtEpochSeconds = record.createdAtEpochSeconds,
                    expiresAtEpochSeconds = record.expiresAtEpochSeconds,
                    status = ClientKeyStatus.AWAITING_PROFILE,
                    boundProfiles = emptySet(),
                )
            }
            writeIndexLocked(current)
            ClientKeyRestoreResult.Success(createdIds.size, createdIds.toList())
        } catch (_: KeyInvalidatedException) {
            rollbackRestoreLocked(current, createdIds, OperationError.KEY_INVALIDATED)
        } catch (_: Throwable) {
            rollbackRestoreLocked(current, createdIds, OperationError.STORAGE_FAILURE)
        }
    }

    fun rollbackRestored(localRecordIds: List<String>) = synchronized(lock) {
        val entries = readIndexLocked().toMutableList()
        localRecordIds.forEach { localId ->
            entries.removeAll { it.localRecordId == localId && it.boundProfiles.isEmpty() }
            blobs.delete(localId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        }
        writeIndexLocked(entries)
    }

    internal fun forcePreparedForTesting(localRecordId: String) = synchronized(lock) {
        val entries = readIndexLocked().toMutableList()
        val index = entries.indexOfFirst { it.localRecordId == localRecordId }
        require(index >= 0)
        entries[index] = entries[index].copy(status = ClientKeyStatus.PREPARED)
        writeIndexLocked(entries)
    }

    private fun recoverPreparedLocked() {
        val entries = readIndexLocked().toMutableList()
        var changed = false
        val iterator = entries.listIterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.status != ClientKeyStatus.PREPARED) continue
            if (!blobs.exists(entry.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)) {
                iterator.remove()
                changed = true
                continue
            }
            val valid = runCatching { openBundleLocked(entry).useBundle { Unit } }.isSuccess
            if (valid) {
                iterator.set(entry.copy(status = ClientKeyStatus.REQUEST_READY))
            } else {
                blobs.delete(entry.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
                iterator.remove()
            }
            changed = true
        }
        if (changed) writeIndexLocked(entries)
    }

    private fun requireEntryLocked(localRecordId: String): ClientKeyIndexEntry {
        require(localRecordId.matches(LOCAL_KEY_ID))
        return readIndexLocked().singleOrNull { it.localRecordId == localRecordId }
            ?: throw IllegalArgumentException("unknown recipient key")
    }

    private fun openBundleLocked(entry: ClientKeyIndexEntry): OpenClientKeyBundle {
        val encoded = blobs.reopen(entry.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        return try {
            val bundle = decodeBundle(encoded, entry.localRecordId)
            try {
                require(bundle.createdAtEpochSeconds == entry.createdAtEpochSeconds)
                require(bundle.expiresAtEpochSeconds == entry.expiresAtEpochSeconds)
                require(fingerprint(bundle.publicRequest) == entry.requestFingerprint)
                when (native.validate(bundle.publicRequest, bundle.privateBundle)) {
                    is NativeResult.Success -> Unit
                    is NativeResult.Failure -> throw IllegalArgumentException("recipient key pair rejected")
                }
                bundle
            } catch (error: Throwable) {
                bundle.destroy()
                throw error
            }
        } finally {
            encoded.fill(0)
        }
    }

    private fun rollbackRestoreLocked(
        original: List<ClientKeyIndexEntry>,
        createdIds: List<String>,
        error: OperationError,
    ): ClientKeyRestoreResult.Failure {
        createdIds.forEach { blobs.delete(it, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL) }
        writeIndexLocked(original.filter { it.localRecordId !in createdIds })
        return ClientKeyRestoreResult.Failure(error)
    }

    private fun newUniqueLocalId(existing: List<ClientKeyIndexEntry>): String {
        repeat(16) {
            val candidate = newLocalRecordId()
            require(candidate.matches(LOCAL_KEY_ID))
            if (existing.none { it.localRecordId == candidate }) return candidate
        }
        throw IllegalStateException("unable to allocate recipient record ID")
    }

    private fun readIndexLocked(): List<ClientKeyIndexEntry> {
        if (!blobs.exists(CLIENT_KEY_INDEX_ID, SecureDataClass.RECIPIENT_KEY_INDEX)) return emptyList()
        val encoded = blobs.reopen(CLIENT_KEY_INDEX_ID, SecureDataClass.RECIPIENT_KEY_INDEX)
        return try {
            decodeIndex(encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun writeIndexLocked(entries: List<ClientKeyIndexEntry>) {
        if (entries.isEmpty()) {
            blobs.delete(CLIENT_KEY_INDEX_ID, SecureDataClass.RECIPIENT_KEY_INDEX)
            return
        }
        val encoded = encodeIndex(entries)
        try {
            blobs.stage(CLIENT_KEY_INDEX_ID, SecureDataClass.RECIPIENT_KEY_INDEX, encoded)
        } finally {
            encoded.fill(0)
        }
    }
}

private data class ClientKeyIndexEntry(
    val localRecordId: String,
    val requestFingerprint: String,
    val createdAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val status: ClientKeyStatus,
    val boundProfiles: Set<String>,
) {
    fun summary(): ClientKeySummary = ClientKeySummary(
        localRecordId = localRecordId,
        requestFingerprint = requestFingerprint,
        createdAtEpochSeconds = createdAtEpochSeconds,
        expiresAtEpochSeconds = expiresAtEpochSeconds,
        status = status,
        boundProfileCount = boundProfiles.size,
    )
}

private class OpenClientKeyBundle(
    val createdAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val publicRequest: ByteArray,
    val privateBundle: ByteArray,
) {
    fun destroy() {
        publicRequest.fill(0)
        privateBundle.fill(0)
    }
}

private inline fun <T> OpenClientKeyBundle.useBundle(block: (OpenClientKeyBundle) -> T): T =
    try {
        block(this)
    } finally {
        destroy()
    }

private fun encodeIndex(entries: List<ClientKeyIndexEntry>): ByteArray {
    require(entries.size <= MAX_CLIENT_KEYS)
    val encoded = entries.map { entry ->
        require(entry.localRecordId.matches(LOCAL_KEY_ID))
        require(entry.requestFingerprint.matches(Regex("[0-9a-f]{64}")))
        require(entry.createdAtEpochSeconds > 0 && entry.expiresAtEpochSeconds > entry.createdAtEpochSeconds)
        require(entry.boundProfiles.size <= MAX_BOUND_PROFILES)
        val localId = entry.localRecordId.encodeToByteArray()
        val fingerprint = entry.requestFingerprint.encodeToByteArray()
        val profiles = entry.boundProfiles.sorted().map { profile ->
            require(profile.matches(PROFILE_RECORD_ID))
            profile.encodeToByteArray()
        }
        Triple(entry, localId, fingerprint) to profiles
    }
    val size = encoded.fold(4 + 1 + 1) { total, item ->
        val (entryTuple, profiles) = item
        val (_, localId, fingerprint) = entryTuple
        total + 1 + localId.size + 1 + 8 + 8 + 1 + fingerprint.size + 1 + profiles.sumOf { 1 + it.size }
    }
    return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
        putInt(CLIENT_KEY_INDEX_MAGIC)
        put(CLIENT_KEY_VERSION.toByte())
        put(entries.size.toByte())
        encoded.forEach { item ->
            val (entryTuple, profiles) = item
            val (entry, localId, fingerprint) = entryTuple
            put(localId.size.toByte())
            put(localId)
            put(entry.status.wireValue.toByte())
            putLong(entry.createdAtEpochSeconds)
            putLong(entry.expiresAtEpochSeconds)
            put(fingerprint.size.toByte())
            put(fingerprint)
            put(profiles.size.toByte())
            profiles.forEach { profile ->
                put(profile.size.toByte())
                put(profile)
            }
        }
    }.array()
}

private fun decodeIndex(encoded: ByteArray): List<ClientKeyIndexEntry> {
    require(encoded.size in 6..64 * 1024)
    val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
    require(reader.int == CLIENT_KEY_INDEX_MAGIC)
    require(reader.get().toInt() and 0xff == CLIENT_KEY_VERSION)
    val count = reader.get().toInt() and 0xff
    require(count <= MAX_CLIENT_KEYS)
    val entries = List(count) {
        val localId = reader.readBoundedString(64)
        val statusWire = reader.get().toInt() and 0xff
        val status = ClientKeyStatus.entries.singleOrNull { it.wireValue == statusWire }
            ?: throw IllegalArgumentException("unknown recipient key status")
        val created = reader.long
        val expires = reader.long
        val fingerprint = reader.readBoundedString(64)
        val profileCount = reader.get().toInt() and 0xff
        require(profileCount <= MAX_BOUND_PROFILES)
        val profiles = buildSet {
            repeat(profileCount) { add(reader.readBoundedString(64)) }
        }
        ClientKeyIndexEntry(localId, fingerprint, created, expires, status, profiles).also { entry ->
            require(entry.localRecordId.matches(LOCAL_KEY_ID))
            require(entry.requestFingerprint.matches(Regex("[0-9a-f]{64}")))
            require(entry.createdAtEpochSeconds > 0 && entry.expiresAtEpochSeconds > entry.createdAtEpochSeconds)
            require(entry.boundProfiles.all { it.matches(PROFILE_RECORD_ID) })
        }
    }
    require(!reader.hasRemaining())
    require(entries.map { it.localRecordId }.distinct().size == entries.size)
    require(entries.map { it.requestFingerprint }.distinct().size == entries.size)
    return entries
}

private fun encodeBundle(
    localRecordId: String,
    createdAtEpochSeconds: Long,
    expiresAtEpochSeconds: Long,
    publicRequest: ByteArray,
    privateBundle: ByteArray,
): ByteArray {
    val localId = localRecordId.encodeToByteArray()
    require(localRecordId.matches(LOCAL_KEY_ID))
    require(createdAtEpochSeconds > 0 && expiresAtEpochSeconds > createdAtEpochSeconds)
    require(publicRequest.size in 1..MAX_RECIPIENT_REQUEST_BYTES)
    require(privateBundle.size in 1..MAX_RECIPIENT_PRIVATE_BYTES)
    return ByteBuffer.allocate(4 + 1 + 1 + localId.size + 8 + 8 + 2 + publicRequest.size + 2 + privateBundle.size)
        .order(ByteOrder.BIG_ENDIAN)
        .apply {
            putInt(CLIENT_KEY_BUNDLE_MAGIC)
            put(CLIENT_KEY_VERSION.toByte())
            put(localId.size.toByte())
            put(localId)
            putLong(createdAtEpochSeconds)
            putLong(expiresAtEpochSeconds)
            putShort(publicRequest.size.toShort())
            put(publicRequest)
            putShort(privateBundle.size.toShort())
            put(privateBundle)
        }.array()
}

private fun decodeBundle(encoded: ByteArray, expectedLocalRecordId: String): OpenClientKeyBundle {
    require(encoded.size in 4 + 1 + 1 + 1 + 8 + 8 + 2 + 1 + 2 + 1..2048)
    val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
    require(reader.int == CLIENT_KEY_BUNDLE_MAGIC)
    require(reader.get().toInt() and 0xff == CLIENT_KEY_VERSION)
    require(reader.readBoundedString(64) == expectedLocalRecordId)
    val created = reader.long
    val expires = reader.long
    require(created > 0 && expires > created)
    val request = reader.readBoundedBytes16(MAX_RECIPIENT_REQUEST_BYTES)
    val privateBundle = reader.readBoundedBytes16(MAX_RECIPIENT_PRIVATE_BYTES)
    require(!reader.hasRemaining())
    return OpenClientKeyBundle(created, expires, request, privateBundle)
}

private fun ByteBuffer.readBoundedString(maximum: Int): String =
    readBoundedBytes(maximum).toString(Charsets.UTF_8).also { require(it.isNotEmpty()) }

private fun ByteBuffer.readBoundedBytes(maximum: Int): ByteArray {
    require(hasRemaining())
    val length = get().toInt() and 0xff
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get)
}

private fun ByteBuffer.readBoundedBytes16(maximum: Int): ByteArray {
    require(remaining() >= 2)
    val length = short.toInt() and 0xffff
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get)
}

private fun fingerprint(value: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
