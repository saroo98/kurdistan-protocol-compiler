// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.kurdistanvpn.core.model.*

data class UsageAggregate(val epochDay: Long, val uploadedBytes: Long, val downloadedBytes: Long, val activeSeconds: Long) {
    init { require(epochDay >= 0 && uploadedBytes >= 0 && downloadedBytes >= 0 && activeSeconds in 0..86400) }
    fun plus(other: UsageAggregate): UsageAggregate {
        require(epochDay == other.epochDay)
        return UsageAggregate(epochDay, Math.addExact(uploadedBytes, other.uploadedBytes),
            Math.addExact(downloadedBytes, other.downloadedBytes), Math.addExact(activeSeconds, other.activeSeconds))
    }
    override fun toString(): String = "UsageAggregate(redacted)"
}
class StoredUsageAggregates(val currentEpochDay: Long, entries: List<UsageAggregate>) {
    val entries: List<UsageAggregate>
    init {
        require(currentEpochDay >= 0 && entries.size <= 30)
        val owned = entries.sortedBy { it.epochDay }
        require(owned.map { it.epochDay }.distinct().size == owned.size)
        require(owned.all { it.epochDay <= currentEpochDay && currentEpochDay - it.epochDay < 30 })
        this.entries = java.util.Collections.unmodifiableList(owned)
    }
    /** Used only by an explicit policy-authorized mutation, never a read-side prune. */
    fun retained(retentionDays: Int): StoredUsageAggregates {
        require(retentionDays in 1..30)
        return StoredUsageAggregates(currentEpochDay, entries.filter { currentEpochDay - it.epochDay < retentionDays })
    }
    fun encode(): ByteArray = encodeRecord(0x50363234, SecureDataClass.USAGE_AGGREGATES, MAX_BYTES) { w ->
        w.writeLong(currentEpochDay); w.writeShort(entries.size)
        entries.forEach { w.writeLong(it.epochDay); w.writeLong(it.uploadedBytes); w.writeLong(it.downloadedBytes); w.writeLong(it.activeSeconds) }
    }
    override fun toString(): String = "StoredUsageAggregates(redacted)"
    companion object {
        const val RECORD_ID = "usage-aggregates-current"
        const val MAX_BYTES = 2048
        fun decode(input: ByteArray): StoredUsageAggregates = decodeRecord(input, MAX_BYTES, 0x50363234, SecureDataClass.USAGE_AGGREGATES,
            { r -> val current = r.readLong(); StoredUsageAggregates(current, List(r.recordCount(30)) { UsageAggregate(r.readLong(), r.readLong(), r.readLong(), r.readLong()) }) },
            { it.encode() })
    }
}
class StoredAppLockState(val settingsRevision: Long, val enabled: Boolean, allowedAuthenticators: Set<AllowedAuthenticator>,
    val failedAttempts: Int, val nextEligibleEpochMinute: Long) {
    val allowedAuthenticators: Set<AllowedAuthenticator> = java.util.Collections.unmodifiableSet(allowedAuthenticators.sortedBy { it.name }.toSet())
    init {
        require(settingsRevision > 0 && failedAttempts in 0..10 && nextEligibleEpochMinute >= 0)
        PrivacyPreferences(appLockEnabled = enabled, allowedAuthenticators = this.allowedAuthenticators)
    }
    fun encode(): ByteArray = encodeRecord(0x50363235, SecureDataClass.APP_LOCK_STATE, MAX_BYTES) { w ->
        w.writeLong(settingsRevision); w.recordBoolean(enabled); w.writeShort(allowedAuthenticators.size)
        allowedAuthenticators.forEach(w::recordEnum); w.writeByte(failedAttempts); w.writeLong(nextEligibleEpochMinute)
    }
    override fun toString(): String = "StoredAppLockState(redacted)"
    companion object {
        const val RECORD_ID = "app-lock-current"
        const val MAX_BYTES = 1024
        fun decode(input: ByteArray): StoredAppLockState = decodeRecord(input, MAX_BYTES, 0x50363235, SecureDataClass.APP_LOCK_STATE, { r ->
            val revision = r.readLong(); val enabled = r.recordBoolean()
            val names = List(r.recordCount(2)) { r.recordEnum<AllowedAuthenticator>() }
            require(names == names.distinct().sortedBy { it.name })
            StoredAppLockState(revision, enabled, names.toSet(), r.readUnsignedByte(), r.readLong())
        }, { it.encode() })
    }
}
class StoredProxyPolicy(val settingsRevision: Long, val preferences: LocalProxyPreferences) {
    init { require(settingsRevision > 0) }
    fun encode(): ByteArray = encodeRecord(0x50363238, SecureDataClass.LOCAL_PROXY_POLICY, MAX_BYTES) { w ->
        w.writeLong(settingsRevision); w.writeInt(preferences.socksPort); w.writeInt(preferences.httpConnectPort)
        w.writeInt(preferences.limits.clients); w.writeInt(preferences.limits.streams)
        w.writeInt(preferences.limits.idleSeconds); w.writeInt(preferences.limits.memoryMiB)
    }
    override fun toString(): String = "StoredProxyPolicy(redacted)"
    companion object {
        const val RECORD_ID = "local-proxy-current"
        const val MAX_BYTES = 1024
        fun decode(input: ByteArray): StoredProxyPolicy = decodeRecord(input, MAX_BYTES, 0x50363238, SecureDataClass.LOCAL_PROXY_POLICY,
            { r -> StoredProxyPolicy(r.readLong(), LocalProxyPreferences(r.readInt(), r.readInt(), ProxyLimits(r.readInt(), r.readInt(), r.readInt(), r.readInt()))) },
            { it.encode() })
    }
}

class UsageAggregatesStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): StoredUsageAggregates? {

        val raw = blobs.reopenIfPresent(StoredUsageAggregates.RECORD_ID, SecureDataClass.USAGE_AGGREGATES) ?: return null
        return try { StoredUsageAggregates.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: StoredUsageAggregates) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        val raw = value.encode()
        try { writable.stage(StoredUsageAggregates.RECORD_ID, SecureDataClass.USAGE_AGGREGATES, raw) } finally { raw.fill(0) }
    }
    fun delete() {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        writable.delete(StoredUsageAggregates.RECORD_ID, SecureDataClass.USAGE_AGGREGATES)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = UsageAggregatesStore(blobs, null) }
}

class AppLockStateStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): StoredAppLockState? {

        val raw = blobs.reopenIfPresent(StoredAppLockState.RECORD_ID, SecureDataClass.APP_LOCK_STATE) ?: return null
        return try { StoredAppLockState.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: StoredAppLockState) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        val raw = value.encode()
        try { writable.stage(StoredAppLockState.RECORD_ID, SecureDataClass.APP_LOCK_STATE, raw) } finally { raw.fill(0) }
    }
    fun delete() {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        writable.delete(StoredAppLockState.RECORD_ID, SecureDataClass.APP_LOCK_STATE)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = AppLockStateStore(blobs, null) }
}

class LocalProxyPolicyStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): StoredProxyPolicy? {

        val raw = blobs.reopenIfPresent(StoredProxyPolicy.RECORD_ID, SecureDataClass.LOCAL_PROXY_POLICY) ?: return null
        return try { StoredProxyPolicy.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: StoredProxyPolicy) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        val raw = value.encode()
        try { writable.stage(StoredProxyPolicy.RECORD_ID, SecureDataClass.LOCAL_PROXY_POLICY, raw) } finally { raw.fill(0) }
    }
    fun delete() {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        writable.delete(StoredProxyPolicy.RECORD_ID, SecureDataClass.LOCAL_PROXY_POLICY)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = LocalProxyPolicyStore(blobs, null) }
}
