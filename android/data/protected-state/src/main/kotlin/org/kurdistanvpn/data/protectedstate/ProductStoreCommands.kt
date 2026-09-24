// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.data.settings.ProductSettingsImage
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.CatalogQuarantineReason
import org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity

internal fun productOperationDescriptor(operation: ByteArray, kind: OperationKind?, scope: String?, attempt: Int,
    hour: Long, settingsBefore: Long, settingsAfter: Long, rollback: Boolean = false): ProductOperationProjectionEntity? =
    kind?.let { ProductOperationProjectionEntity(operation.joinToString("") { "%02x".format(it) }, it.name, scope,
        if (rollback) "ROLLED_BACK" else "APPLIED", attempt, settingsBefore, settingsAfter, hour, false) }

internal fun encodeProductCatalog(rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>,
    descriptor: ProductOperationProjectionEntity?): ByteArray = if (descriptor == null) ProfileCatalogProjectionCodec.encode(rows)
    else ProductCatalogProjectionCodec.encode(rows, descriptor)

internal fun productSettingsRevision(snapshot: ProtectedStateSnapshot): Long {
    val bytes = snapshot.settingsBytes()
    return try { if (ProductSettingsImage.isVersionTwo(bytes)) ProductSettingsImage.decode(bytes).revision else 0L }
    finally { bytes.fill(0) }
}

internal fun validateProductOperationTransition(record: ProductOperationState, prior: ProtectedStateSnapshot,
    candidate: ProtectedStateSnapshot) {
    check(record.internalMutationKind == MutationKind.PRODUCT_STATE.wire)
    val before = prior.objects().associateBy { it.dataClass to it.logicalId }
    val after = candidate.objects().associateBy { it.dataClass to it.logicalId }
    fun exact(reference: ProtectedObjectReference?): ByteArray = java.io.ByteArrayOutputStream().use { output ->
        java.io.DataOutputStream(output).use { writer -> reference?.write(writer) }; output.toByteArray()
    }
    val changed = (before.keys + after.keys).filter { identity ->
        val a = exact(before[identity]); val b = exact(after[identity])
        try { !a.contentEquals(b) } finally { a.fill(0); b.fill(0) }
    }
    check(changed.isNotEmpty())
    val roles = changed.map { it.first }.toSet()
    when (record.displayKind) {
        OperationKind.UPDATE -> check(record.scopeRecordId != null && changed == listOf(21 to record.scopeRecordId))
        OperationKind.PROBE -> check(record.scopeRecordId != null && changed == listOf(22 to record.scopeRecordId))
        OperationKind.SETTINGS_CHANGE -> {
            check(record.scopeRecordId == null)
            check(roles == setOf(23) || roles.all { it == 19 || it == 20 })
            check(changed.filter { it.first == 20 }.all { it.second == DeploymentDisplayMetadata.RECORD_ID })
        }
        null -> { check(record.scopeRecordId == null && roles.size == 1 && roles.single() in setOf(24, 25, 29)) }
        else -> error("INVALID_PRODUCT_OPERATION_KIND")
    }
    val operation = candidate.operationId()
    try { changed.mapNotNull(after::get).forEach {
        check(it.binding.revision == candidate.revision && it.binding.operationId().contentEquals(operation))
    } } finally { operation.fill(0) }
    val oldCatalog = prior.catalogBytes(); val newCatalog = candidate.catalogBytes()
    try {
        val restamped = encodeProductCatalog(ProfileCatalogProjectionCodec.decode(oldCatalog).map {
            it.stampCommitted(candidate.operationId().joinToString("") { byte -> "%02x".format(byte) }, candidate.revision, CatalogQuarantineReason.NONE)
        }, productOperationDescriptor(record.operationId(), record.displayKind, record.scopeRecordId, record.attempt,
            record.startedEpochHour, record.settingsRevisionBefore, record.settingsRevisionAfter))
        try { check(restamped.contentEquals(newCatalog)) } finally { restamped.fill(0) }
    } finally { oldCatalog.fill(0); newCatalog.fill(0) }
}

/** Closed product observations. None can supply profile/native authority or an arbitrary role. */
internal sealed interface ProductStoreCommand {
    data class SetDeploymentDisplay(val value: DeploymentDisplayMetadata) : ProductStoreCommand
    data class RecordUpdate(val profileId: String, val value: StoredUpdateState) : ProductStoreCommand
    data class RecordProbe(val profileId: String, val value: StoredProbeHistory) : ProductStoreCommand
    data class ReplaceTrustedRules(val value: StoredTrustedNetworks) : ProductStoreCommand
    data class RecordUsage(val value: StoredUsageAggregates) : ProductStoreCommand
    data class RecordAppLockFailure(val expectedSettingsRevision: Long, val nextEligibleEpochMinute: Long) : ProductStoreCommand
    data class RecordCleanStop(val epochHour: Long) : ProductStoreCommand
    data class RecordStart(val epochHour: Long) : ProductStoreCommand
}

internal val ProductStoreCommand.displayKind: OperationKind? get() = when (this) {
    is ProductStoreCommand.SetDeploymentDisplay, is ProductStoreCommand.ReplaceTrustedRules -> OperationKind.SETTINGS_CHANGE
    is ProductStoreCommand.RecordUpdate -> OperationKind.UPDATE
    is ProductStoreCommand.RecordProbe -> OperationKind.PROBE
    else -> null
}
internal val ProductStoreCommand.scopeRecordId: String? get() = when (this) {
    is ProductStoreCommand.RecordUpdate -> profileId
    is ProductStoreCommand.RecordProbe -> profileId
    else -> null
}

internal fun validateProductPolicyMirrors(settings: ProductSettings, revision: Long, blobs: SecureBlobReadAccess): ProductSettings {
    PauseStateStore.readOnly(blobs).load()?.let { check(settings.pausePolicy == PausePolicy.UNTIL_RESUMED) }
    val selected = TrustedNetworkStore.readOnly(blobs).load()?.use {
        check(it.settingsRevision == revision)
        it.selectedRuleIds.toSet()
    }.orEmpty()
    AppLockStateStore.readOnly(blobs).load()?.let {
        check(it.settingsRevision == revision && it.enabled == settings.privacy.appLockEnabled &&
            it.allowedAuthenticators == settings.privacy.allowedAuthenticators)
        check(it.enabled || (it.failedAttempts == 0 && it.nextEligibleEpochMinute == 0L))
    }
    LocalProxyPolicyStore.readOnly(blobs).load()?.let {
        check(it.settingsRevision == revision && it.preferences == settings.localProxy)
    }
    UsageAggregatesStore.readOnly(blobs).load()?.let {
        check(settings.privacy.collectUsageAggregates)
        check(it.entries.all { entry -> it.currentEpochDay - entry.epochDay < settings.privacy.usageRetentionDays })
    }
    return settings.copy(networkTrust = settings.networkTrust.copy(protectedRuleIds = selected))
}

/** Also consumed by independent reconstruction and the later read-only product facade. */
internal fun validateProductRecordScopes(references: List<ProtectedObjectReference>, profileIds: Set<String>,
    blobs: SecureBlobReadAccess) {
    for (reference in references) {
        val id = reference.logicalId
        when (reference.dataClass) {
            19 -> {
                check(id in profileIds)
                val value = checkNotNull(ProfileProjectionStore.readOnly(blobs).load(id))
                check(value.profile.id.value == id)
            }
            20 -> when (id) {
                ProductSettingsMetadata.RECORD_ID -> Unit
                DeploymentDisplayMetadata.RECORD_ID -> checkNotNull(DeploymentDisplayMetadataStore.readOnly(blobs).load()).also {
                    check(it.entries.all { entry -> entry.profileId.value in profileIds })
                }
                else -> error("INVALID_PRODUCT_SCOPE")
            }
            21 -> { check(id in profileIds); checkNotNull(UpdateStateStore.readOnly(blobs).load(id)) }
            22 -> { check(id in profileIds); checkNotNull(ProbeHistoryStore.readOnly(blobs).load(id)) }
            23 -> check(id == StoredTrustedNetworks.RECORD_ID)
            24 -> check(id == StoredUsageAggregates.RECORD_ID)
            25 -> check(id == StoredAppLockState.RECORD_ID)
            26 -> check(id == RuntimeBootstrapRecord.RECORD_ID)
            28 -> check(id == StoredProxyPolicy.RECORD_ID)
            29 -> { check(id == StoredCrashSafeMode.RECORD_ID); checkNotNull(CrashSafeModeStore.readOnly(blobs).load()) }
            30 -> { check(id == StoredPauseState.RECORD_ID); checkNotNull(PauseStateStore.readOnly(blobs).load()) }
        }
    }
}

internal fun validateProductProfileRelationships(references: List<ProtectedObjectReference>,
    profileIds: Set<String>, blobs: SecureBlobReadAccess) {
    val display = DeploymentDisplayMetadataStore.readOnly(blobs).load()?.entries.orEmpty().associateBy { it.profileId.value }
    for (reference in references.filter { it.dataClass == 19 }) {
        check(reference.logicalId in profileIds)
        val store = ProfileProjectionStore.readOnly(blobs)
        val value = checkNotNull(store.load(reference.logicalId))
        store.requireStoredPreviewIdentity(value)
        val metadata = checkNotNull(display[reference.logicalId])
        check(value.profile.alias == metadata.alias && value.profile.status == ProjectionStatus.VERIFIED)
        value.deployment?.let {
            check(it.alias == metadata.alias)
            check(it.publicationGeneration == null && it.relayCompatibility == ProjectionStatus.UNAVAILABLE &&
                it.rotationState == ProjectionStatus.UNAVAILABLE && it.emergencyDenyState == ProjectionStatus.UNAVAILABLE &&
                it.node == NodeProjection() && it.strategy == StrategyProjection() && it.path == PathProjection() &&
                it.exit == ExitProjection() && it.health == HealthProjection() && it.update == UpdateProjection())
        }
    }
}
