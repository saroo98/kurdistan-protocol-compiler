// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Collections
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.SAFE_EXCLUDED_ROUTES
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeBootstrapValidator
import org.kurdistanvpn.core.nativeapi.NativeProductionBootstrapReadV1
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.NativeRuntimeState
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.ProfileCatalogReadAccess
import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.KeyInvalidatedException
import org.kurdistanvpn.data.secure.ProfileAdmissionJournal
import org.kurdistanvpn.data.secure.RuntimeAuthorityResult
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.secure.SecureRoutingPolicyStore
import org.kurdistanvpn.data.settings.SettingsProjectionCodec
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.RuntimeStartWire
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.data.settings.ProductSettingsImage
import org.kurdistanvpn.data.secure.RuntimeBootstrapRecord
import org.kurdistanvpn.data.secure.RuntimeProductionBootstrapRecord
import org.kurdistanvpn.runtime.api.RuntimeCaptureCodecV1
import org.kurdistanvpn.runtime.api.RuntimeCapturePartsV1
import org.kurdistanvpn.data.secure.SecureDataClass

/** Shared exact runtime-open input mapping. Unsupported native semantics are never approximated. */
internal fun runtimeConfigForSettings(settings: ProductSettings, packages: Set<String>): VpnRuntimeConfig {
    require(settings.routing.excludedCidrs.isEmpty() || settings.routing.excludedCidrs.toSet() == SAFE_EXCLUDED_ROUTES.toSet())
    require(!settings.connection.connectOnlyOnUntrustedNetworks && settings.tunnel.secondaryCustomDns.isEmpty())
    require(settings.tunnelMode == org.kurdistanvpn.core.model.TunnelMode.TUN_ONLY)
    return VpnRuntimeConfig(routingPolicy = VpnRoutingPolicy(PerAppRoutingMode.valueOf(settings.routing.mode.name), packages),
        selectionMode = settings.connection.selectionMode, manualStrategyId = settings.connection.manualStrategyId?.value.orEmpty(),
        ipMode = settings.tunnel.ipMode, dnsMode = settings.tunnel.dnsMode, customDns = settings.tunnel.customDns,
        mtu = settings.tunnel.mtu, metered = settings.tunnel.metered, allowLan = settings.connection.allowLan).validatedForLiveTransport()
}

/** Implemented by the default-process Android owner, never from Intent fields. */
/** Minimal default-process provider contract. It admits only a restore of committed state. */
interface ProtectedAuthorityEnvironment {
    fun isUserUnlocked(): Boolean
    fun isConsentPrepared(): Boolean
    fun isCancelled(): Boolean
    fun elapsedRealtimeMillis(): Long
}

enum class AuthorityReadFailure {
    LOCKED, CONSENT_REQUIRED, CANCELLED, EXPIRED, POLICY_REJECTED,
    STATE_UNPROVEN, AUTHORITY_REJECTED, CLEANUP_UNPROVEN,
}

sealed interface AuthorityReadResult {
    /** The validated committed policy is safe to expose; authority bytes never are. */
    data class Ready(val authority: ReissuedAuthority, val committedConfig: VpnRuntimeConfig) : AuthorityReadResult
    data class Rejected(val category: AuthorityReadFailure, val error: OperationError? = null) : AuthorityReadResult
}

/** No backing array, persistent runtime token, writer, or caller-selected policy escapes. */
sealed interface ReissuedAuthority : AutoCloseable {
    val revision: Long
    val signedRetryBudget: Int
    val length: Int
    fun writeTo(output: OutputStream)
}

private class AuthorityDenied(val category: AuthorityReadFailure, val error: OperationError? = null) :
    IllegalStateException(category.name)

/**
 * One canonical reconstruction path for both manual and unmarked system starts.
 * It is deliberately unable to open Room, DataStore, a writable blob root, or a
 * key-creation API. The Android composition root must check unlock before even
 * loading the existing key. Native validation opens no socket in VERIFIED state.
 */
internal class ProtectedStateAuthorityFactory(
    private val snapshots: ProtectedStateSnapshotReader,
    private val encryptedObject: (String, Int) -> ByteArray?,
    private val codec: SecureEnvelopeCodec,
    private val existingKey: KeyEncryptionKey,
    private val native: KurdNativeCore,
    private val projections: ProtectedProjectionReadAccess,
    private val environment: ProtectedAuthorityEnvironment,
    private val finalCurrent: ((ProtectedStateSnapshot) -> Unit)? = null,
) {
    fun reconstructProductionCapture():ProductionCaptureReadResult {
        var wire:ByteArray?=null
        var paired:NativeProductionBootstrapReadV1?=null
        val result:ProductionCaptureReadResult=try {
            val started=environment.elapsedRealtimeMillis();requireAdmission(started)
            val snapshot=snapshots.readCheckpointSnapshot()
            check(snapshot.disposition==ProtectedStateDisposition.VERIFIED)
            val imageBytes=snapshot.settingsBytes()
            val settingsRevision=try {
                // Capture requires a committed versioned bootstrap, not raw migration inputs.
                check(ProductSettingsImage.isVersionTwo(imageBytes))
                ProductSettingsImage.decode(imageBytes).revision
            } finally{imageBytes.fill(0)}
            val observed=projections.readForCheckpoint(snapshot);observed.requireMatches(snapshot)
            snapshots.requirePhysicalProjection(snapshot,observed.physical())
            val selected=snapshot.selectedProfile ?: throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED)
            val reader=SelectedAuthorityObjectReader(snapshot.objects(),encryptedObject){requireAdmission(started)}
            val blobs=ReadOnlyProtectedBlobView(snapshot.objects(),reader::read,codec,existingKey)
            val bootstrap=blobs.reopen(RuntimeBootstrapRecord.RECORD_ID,SecureDataClass.RUNTIME_BOOTSTRAP)
            var settingsWire=ByteArray(0)
            var signedBudget=0
            try {
                val settings=readProductSettings(snapshot,blobs,bootstrap)
                check(settings.profiles.activeLocalRecordId==selected)
                val validator=native as? NativeBootstrapValidator
                    ?: throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED,OperationError.INCOMPATIBLE_NATIVE_CORE)
                val compatibility=(native.compatibility() as? NativeResult.Success)?.value
                    ?: throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED)
                settingsWire=when(val encoded=encodeProductionSettingsOwnedV1(settings)) {
                    is NativeProductResult.Success->encoded.value
                    is NativeProductResult.Failure->throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED,bootstrapOperationErrorV1(encoded.code))
                }
                val catalogBytes=snapshot.catalogBytes()
                val catalog=try{SnapshotCatalog(ProfileCatalogProjectionCodec.decode(catalogBytes))}finally{catalogBytes.fill(0)}
                val admission=ProfileAdmissionJournal.readOnly(native,catalog,blobs,false)
                val material=when(val opened=runBlocking{admission.openRuntimeAuthority(selected)}) {
                    is RuntimeAuthorityResult.Success->opened.material
                    is RuntimeAuthorityResult.Failure->throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED,opened.error)
                }
                material.use {
                    val spans=bootstrapMaterialV1(it)
                    when(bootstrap.getOrNull(4)?.toInt()) {
                        1 -> {
                            val record=RuntimeBootstrapRecord.decode(bootstrap)
                            val policy=RuntimeStartWire.encodeLegacyBootstrapPolicy(runtimeConfigForSettings(settings,settings.routing.packages))
                            val facts=try {
                                when(val read=validator.readLegacyBinding(spans,ByteBuffer.wrap(policy))) {
                                    is NativeResult.Success->read.value
                                    is NativeResult.Failure->throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED,read.error)
                                }
                            } finally{policy.fill(0)}
                            check(facts.generation<=Long.MAX_VALUE.toULong())
                            val digest=facts.planDigest
                            try{check(record.matches(settingsRevision,selected,facts.generation.toLong(),digest,compatibility))}
                            finally{digest.fill(0)}
                            signedBudget=facts.signedRetryMaximum
                        }
                        2 -> RuntimeProductionBootstrapRecord.decode(bootstrap)
                        else -> throw AuthorityDenied(AuthorityReadFailure.STATE_UNPROVEN)
                    }
                    // Version 1 reaches this only after its independent legacy digest matched.
                    // The two catalogue roles match their OWN production facts, never that legacy digest.
                    paired=when(val read=validator.readProductionBinding(spans,ByteBuffer.wrap(settingsWire))) {
                        is NativeProductResult.Success->read.value
                        is NativeProductResult.Failure->throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED,bootstrapOperationErrorV1(read.code))
                    }
                    val production=checkNotNull(paired).facts
                    if(bootstrap[4]==2.toByte()) {
                        val record=RuntimeProductionBootstrapRecord.decode(bootstrap)
                        val digest=production.planDigest
                        try{check(record.matches(settingsRevision,selected,production.generation,digest,compatibility))}
                        finally{digest.fill(0)}
                        signedBudget=production.signedRetryMaximum
                    }
                    val total=32L+it.verifyRequest.size+it.activationRecord.size+it.recipientRequest.size+it.recipientPrivate.size+settingsWire.size
                    require(total in 37..RuntimeCaptureCodecV1.MAX_BYTES.toLong())
                    wire=ByteArray(total.toInt())
                    RuntimeCaptureCodecV1.encode(RuntimeCapturePartsV1(spans.verifyRequest,spans.activationRecord,
                        spans.recipientRequest,spans.recipientPrivate,ByteBuffer.wrap(settingsWire)),ByteBuffer.wrap(checkNotNull(wire)))
                }
            } finally{bootstrap.fill(0);settingsWire.fill(0)}
            requireAdmission(started);requireCurrent(snapshot)
            val activeTrust = checkNotNull(snapshot.objectFor(selected, SecureDataClass.ACTIVATION_ACTIVE.wireValue))
            val presentation = org.kurdistanvpn.runtime.api.RuntimeProfilePresentation(selected,
                checkNotNull(paired).facts.generation, activeTrust.binding.revision, settingsRevision)
            val capture=OwnedReissuedProductionCapture(checkNotNull(wire),snapshot.revision,signedBudget,checkNotNull(paired),presentation){
                requireAdmission(started);(finalCurrent ?: ::requireCurrent)(snapshot)
            }
            wire=null;paired=null
            ProductionCaptureReadResult.Ready(capture)
        } catch(denied:AuthorityDenied){ProductionCaptureReadResult.Rejected(denied.category,denied.error)}
        catch(_:KeyInvalidatedException){ProductionCaptureReadResult.Rejected(AuthorityReadFailure.AUTHORITY_REJECTED,OperationError.KEY_INVALIDATED)}
        catch(_:Throwable){ProductionCaptureReadResult.Rejected(AuthorityReadFailure.STATE_UNPROVEN)}
        finally{wire?.fill(0)}
        return try{paired?.close();result}catch(_:Throwable){ProductionCaptureReadResult.Rejected(AuthorityReadFailure.CLEANUP_UNPROVEN)}
    }

    fun reconstruct(): AuthorityReadResult {
        var wire: ByteArray? = null
        return try {
            val started = environment.elapsedRealtimeMillis()
            requireAdmission(started)
            val snapshot = snapshots.readCheckpointSnapshot()
            val migrationImage = snapshot.settingsBytes()
            try { if (org.kurdistanvpn.data.settings.RawLegacySettingsImage.isRaw(migrationImage))
                throw AuthorityDenied(AuthorityReadFailure.STATE_UNPROVEN) }
            finally { migrationImage.fill(0) }
            if (snapshot.disposition != ProtectedStateDisposition.VERIFIED) throw AuthorityDenied(AuthorityReadFailure.STATE_UNPROVEN)
            val observed = projections.read()
            observed.requireMatches(snapshot)
            snapshots.requirePhysicalProjection(snapshot, observed.physical())
            val selected = snapshot.selectedProfile ?: throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED)
            val objectReader = SelectedAuthorityObjectReader(snapshot.objects(), encryptedObject) { requireAdmission(started) }
            val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), objectReader::read, codec, existingKey)
            val settings = readProductSettings(snapshot, blobs)
            check(settings.profiles.activeLocalRecordId == selected)
            // Empty is the no-bypass default. The exact legacy default remains a no-op marker;
            // neither list creates native bypass routes. Every actual exclusion is still rejected.
            if ((settings.routing.excludedCidrs.isNotEmpty() && settings.routing.excludedCidrs.toSet() != SAFE_EXCLUDED_ROUTES.toSet()) ||
                settings.connection.connectOnlyOnUntrustedNetworks) throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED)
            val packages = SecureRoutingPolicyStore.readOnly(blobs).loadPackages()
            val config = try {
                runtimeConfigForSettings(settings, packages)
            } catch (_: IllegalArgumentException) { throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED) }
            val catalogBytes = snapshot.catalogBytes()
            val catalog = try { SnapshotCatalog(ProfileCatalogProjectionCodec.decode(catalogBytes)) }
            finally { catalogBytes.fill(0) }
            val admission = ProfileAdmissionJournal.readOnly(native, catalog, blobs, false)
            // Global structural consistency was proved before this authenticated checkpoint's
            // commit. Reissue reads only the selected profile, its exact recipient and routing;
            // it must not decrypt every unrelated profile merely to restore one tunnel.
            when (val opened = runBlocking { admission.openRuntimeAuthority(selected) }) {
                is RuntimeAuthorityResult.Failure -> throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED, opened.error)
                is RuntimeAuthorityResult.Success -> opened.material.use { material ->
                    wire = RuntimeStartWire.encode(material.verifyRequest, material.activationRecord,
                        material.recipientRequest, material.recipientPrivate, config)
                }
            }
            val session = when (val opened = native.openLiveRuntimeSession(checkNotNull(wire))) {
                is NativeResult.Failure -> throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED, opened.error)
                is NativeResult.Success -> opened.value
            }
            val budget: Int
            try {
                check((session.status() as? NativeResult.Success)?.value == NativeRuntimeState.VERIFIED)
                val state = session.snapshot
                check(state.generation > 0 && state.maxReconnectAttempts in 0..5)
                val image = snapshot.settingsBytes()
                try { if (ProductSettingsImage.isVersionTwo(image)) {
                    val raw = blobs.reopen(RuntimeBootstrapRecord.RECORD_ID, SecureDataClass.RUNTIME_BOOTSTRAP)
                    val bootstrap = try { RuntimeBootstrapRecord.decode(raw) } finally { raw.fill(0) }
                    val compatibility = (native.compatibility() as? NativeResult.Success)?.value
                        ?: throw AuthorityDenied(AuthorityReadFailure.AUTHORITY_REJECTED)
                    check(bootstrap.matches(ProductSettingsImage.decode(image).revision, selected, state.generation,
                        state.planDigest, compatibility)) { "STALE_RUNTIME_BOOTSTRAP" }
                } } finally { image.fill(0) }
                budget = state.maxReconnectAttempts
                // Never call prepareSocket, connect, attachTun, or persist native authority here.
            } finally {
                try { session.close() } catch (_: Throwable) { throw AuthorityDenied(AuthorityReadFailure.CLEANUP_UNPROVEN) }
            }
            requireAdmission(started)
            requireCurrent(snapshot)
            AuthorityReadResult.Ready(OwnedReissuedAuthority(checkNotNull(wire), snapshot.revision, budget) {
                requireAdmission(started)
                requireCurrent(snapshot)
            }, config)
        } catch (denied: AuthorityDenied) { AuthorityReadResult.Rejected(denied.category, denied.error) }
        catch (_: KeyInvalidatedException) { AuthorityReadResult.Rejected(AuthorityReadFailure.AUTHORITY_REJECTED, OperationError.KEY_INVALIDATED) }
        catch (_: Exception) { AuthorityReadResult.Rejected(AuthorityReadFailure.STATE_UNPROVEN) }
        finally { wire?.fill(0) }
    }

    private fun requireAdmission(started: Long) {
        if (!environment.isUserUnlocked()) throw AuthorityDenied(AuthorityReadFailure.LOCKED)
        if (!environment.isConsentPrepared()) throw AuthorityDenied(AuthorityReadFailure.CONSENT_REQUIRED)
        if (environment.isCancelled()) throw AuthorityDenied(AuthorityReadFailure.CANCELLED)
        val now = environment.elapsedRealtimeMillis()
        if (started < 0 || now < started || now - started >= JournalLimits.RESTORE_NANOS / 1_000_000)
            throw AuthorityDenied(AuthorityReadFailure.EXPIRED)
    }

    internal fun requireCurrent(expected: ProtectedStateSnapshot) {
        val current = snapshots.readCheckpointSnapshot()
        val observed = projections.readForCheckpoint(current)
        observed.requireMatches(current)
        snapshots.requirePhysicalProjection(current, observed.physical())
        val old = expected.encode(); val actual = current.encode()
        try { check(MessageDigest.isEqual(old, actual)) { "TRUSTED_STATE_CHANGED" } }
        finally { old.fill(0); actual.fill(0) }
    }
}

/** Bounds selected authority reads before I/O, without caching mutable authority or plaintext. */
internal class SelectedAuthorityObjectReader(references: List<ProtectedObjectReference>,
    private val readEncrypted: (String, Int) -> ByteArray?, private val checkLive: () -> Unit) {
    private val references = references.toTypedArray().associateBy { it.physicalId }
    private val seen = hashSetOf<String>()
    private var selectedBytes = 0L
    private var attempts = 0
    @Synchronized fun read(physical: String): ByteArray? {
        checkLive()
        check(++attempts <= 64) { "AUTHORITY_READ_ATTEMPT_LIMIT" }
        val reference = checkNotNull(references[physical]) { "UNCOMMITTED_AUTHORITY_OBJECT" }
        if (physical !in seen) {
            check(seen.size < 16 && reference.length <= 16L * 1024 * 1024 - selectedBytes) { "AUTHORITY_READ_LIMIT" }
            selectedBytes += reference.length
            seen += physical
        }
        // The authenticated reference already bounds ciphertext size before native allocation.
        val owned = checkNotNull(readEncrypted(physical, reference.length)) { "AUTHORITY_OBJECT_MISSING" }
        return try {
            checkLive()
            check(reference.matches(owned)) { "AUTHORITY_OBJECT_MISMATCH" }
            owned
        } catch (failure: Throwable) { owned.fill(0); throw failure }
    }
}

private class OwnedReissuedAuthority(raw: ByteArray, override val revision: Long,
    override val signedRetryBudget: Int, private val finalRead: () -> Unit) : ReissuedAuthority {
    private val wire = raw.clone()
    override val length = wire.size
    private var terminal = false
    @Synchronized override fun writeTo(output: OutputStream) {
        check(!terminal) { "AUTHORITY_ALREADY_CONSUMED" }
        terminal = true
        var outgoing: ByteArray? = null
        try {
            finalRead()
            outgoing = wire.clone()
            output.write(outgoing, 0, outgoing.size)
        } finally { outgoing?.fill(0); wire.fill(0) }
    }
    @Synchronized override fun close() { terminal = true; wire.fill(0) }
}

private class SnapshotCatalog(rows: List<ProfileCatalogEntity>) : ProfileCatalogReadAccess {
    private val owned = Collections.unmodifiableList(ArrayList(rows))
    override fun observeAll(): Flow<List<ProfileCatalogEntity>> = flowOf(owned)
    override suspend fun get(localRecordId: String): ProfileCatalogEntity? = owned.singleOrNull { it.localRecordId == localRecordId }
    override suspend fun listAll(): List<ProfileCatalogEntity> = owned
}
