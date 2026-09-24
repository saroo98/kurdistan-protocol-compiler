// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.kurdistanvpn.core.model.*

class StoredProfileProjection(val profile: ProfileProjection, val deployment: DeploymentProjection?) {
    fun encode(): ByteArray = encodeRecord(0x50363139, SecureDataClass.PROFILE_PROJECTION, MAX_BYTES) { w ->
        w.recordId(profile.id.value); w.recordAlias(profile.alias); w.writeLong(profile.generation.toLong())
        w.writeLong(profile.expiresAtEpochSeconds); w.recordEnum(profile.status)
        w.recordBoolean(deployment != null)
        deployment?.let { d ->
            w.recordAlias(d.alias); w.optionalGeneration(d.publicationGeneration); w.optionalGeneration(d.profileGeneration)
            w.recordBoolean(d.profileExpiryEpochSeconds != null); d.profileExpiryEpochSeconds?.let(w::writeLong)
            w.recordEnum(d.relayCompatibility); w.recordEnum(d.rotationState); w.recordEnum(d.emergencyDenyState)
            w.recordEnum(d.update.status); w.recordEnum(d.update.category); w.writeInt(d.update.changeCount)
            w.nodeFields(d.node.status, d.node.id, d.node.alias)
            w.nodeFields(d.strategy.status, d.strategy.id, d.strategy.alias)
            w.nodeFields(d.path.status, d.path.id, d.path.alias)
            w.recordEnum(d.exit.status); w.recordEnum(d.exit.region); w.recordEnum(d.health.status); w.recordEnum(d.health.category)
        }
    }
    override fun toString(): String = "StoredProfileProjection(redacted)"
    companion object {
        const val MAX_BYTES = 16 * 1024
        fun decode(input: ByteArray): StoredProfileProjection = decodeRecord(input, MAX_BYTES, 0x50363139, SecureDataClass.PROFILE_PROJECTION, { r ->
            val profile = ProfileProjection(CatalogId(r.recordId()), r.recordAlias(), r.readLong().toULong(), r.readLong(), r.recordEnum<ProjectionStatus>())
            val deployment = if (!r.recordBoolean()) null else DeploymentProjection(
                r.recordAlias(), r.optionalGeneration(), r.optionalGeneration(), if (r.recordBoolean()) r.readLong() else null,
                r.recordEnum<ProjectionStatus>(), r.recordEnum<ProjectionStatus>(), r.recordEnum<ProjectionStatus>(),
                UpdateProjection(r.recordEnum<ProjectionStatus>(), r.recordEnum<UpdateCategory>(), r.readInt()),
                NodeProjection(r.recordEnum<ProjectionStatus>(), r.optionalId()?.let(::CatalogId), r.optionalAlias()),
                StrategyProjection(r.recordEnum<ProjectionStatus>(), r.optionalId()?.let(::CatalogId), r.optionalAlias()),
                PathProjection(r.recordEnum<ProjectionStatus>(), r.optionalId()?.let(::CatalogId), r.optionalAlias()),
                ExitProjection(r.recordEnum<ProjectionStatus>(), r.recordEnum<ExitRegion>()),
                HealthProjection(r.recordEnum<ProjectionStatus>(), r.recordEnum<HealthCategory>()))
            StoredProfileProjection(profile, deployment)
        }, { it.encode() })
    }
}
private fun java.io.DataOutputStream.nodeFields(status: ProjectionStatus, id: CatalogId?, alias: SafeAlias?) {
    recordEnum(status); optionalId(id?.value); recordBoolean(alias != null); alias?.let(::recordAlias)
}
private fun java.io.DataInputStream.optionalAlias(): SafeAlias? = if (recordBoolean()) recordAlias() else null

class ProfileProjectionStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(profileId: String): StoredProfileProjection? {
        org.kurdistanvpn.core.model.CatalogId(profileId)
        if (!blobs.exists(profileId, SecureDataClass.PROFILE_PROJECTION)) return null
        val raw = blobs.reopen(profileId, SecureDataClass.PROFILE_PROJECTION)
        return try { StoredProfileProjection.decode(raw).also { require(it.profile.id.value == profileId) } } finally { raw.fill(0) }
    }
    /** Cache consistency only. This does not certify native authority or catalog availability. */
    fun requireStoredPreviewIdentity(value: StoredProfileProjection) {
        val raw = blobs.reopen(value.profile.id.value, SecureDataClass.PROFILE_PREVIEW)
        try {
            val preview = ProfilePreviewCodec.decode(raw).first
            check(value.profile.generation == preview.generation && value.profile.expiresAtEpochSeconds == preview.validUntilEpochSeconds)
            value.deployment?.profileGeneration?.let { generation ->
                check(generation == preview.generation && value.deployment.profileExpiryEpochSeconds == preview.validUntilEpochSeconds)
            }
        } finally { raw.fill(0) }
    }
    fun save(profileId: String, value: StoredProfileProjection) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        org.kurdistanvpn.core.model.CatalogId(profileId)
        require(value.profile.id.value == profileId)
        val raw = value.encode()
        try { writable.stage(profileId, SecureDataClass.PROFILE_PROJECTION, raw) } finally { raw.fill(0) }
    }
    fun delete(profileId: String) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        org.kurdistanvpn.core.model.CatalogId(profileId)
        writable.delete(profileId, SecureDataClass.PROFILE_PROJECTION)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = ProfileProjectionStore(blobs, null) }
}
