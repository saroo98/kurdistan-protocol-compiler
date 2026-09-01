// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.io.OutputStream
import java.security.MessageDigest
import java.util.Collections
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.SAFE_EXCLUDED_ROUTES
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeResult
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
    private val encryptedObject: (String) -> ByteArray?,
    private val codec: SecureEnvelopeCodec,
    private val existingKey: KeyEncryptionKey,
    private val native: KurdNativeCore,
    private val projections: ProtectedProjectionReadAccess,
    private val environment: ProtectedAuthorityEnvironment,
) {
    fun reconstruct(): AuthorityReadResult {
        var wire: ByteArray? = null
        return try {
            val started = environment.elapsedRealtimeMillis()
            requireAdmission(started)
            val snapshot = snapshots.readCheckpointSnapshot()
            if (snapshot.disposition != ProtectedStateDisposition.VERIFIED) throw AuthorityDenied(AuthorityReadFailure.STATE_UNPROVEN)
            val observed = projections.read()
            observed.requireMatches(snapshot)
            snapshots.requirePhysicalProjection(snapshot, observed.physical())
            val selected = snapshot.selectedProfile ?: throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED)
            val settingsBytes = snapshot.settingsBytes()
            val settings = try { SettingsProjectionCodec.toModel(settingsBytes) } finally { settingsBytes.fill(0) }
            check(settings.profiles.activeLocalRecordId == selected)
            // These policies have no signed wire representation in the current runtime.
            if (settings.routing.excludedCidrs.toSet() != SAFE_EXCLUDED_ROUTES.toSet() ||
                settings.connection.connectOnlyOnUntrustedNetworks) throw AuthorityDenied(AuthorityReadFailure.POLICY_REJECTED)
            val objectReader = SelectedAuthorityObjectReader(snapshot.objects(), encryptedObject) { requireAdmission(started) }
            val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), objectReader::read, codec, existingKey)
            val packages = SecureRoutingPolicyStore.readOnly(blobs).loadPackages()
            val config = try {
                VpnRuntimeConfig(
                    routingPolicy = VpnRoutingPolicy(PerAppRoutingMode.valueOf(settings.routing.mode.name), packages),
                    selectionMode = settings.connection.selectionMode,
                    ipMode = settings.tunnel.ipMode, dnsMode = settings.tunnel.dnsMode,
                    customDns = settings.tunnel.customDns, mtu = settings.tunnel.mtu,
                    metered = settings.tunnel.metered, allowLan = settings.connection.allowLan,
                ).validatedForLiveTransport()
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

    private fun requireCurrent(expected: ProtectedStateSnapshot) {
        val current = snapshots.readCheckpointSnapshot()
        val observed = projections.read()
        observed.requireMatches(current)
        snapshots.requirePhysicalProjection(current, observed.physical())
        val old = expected.encode(); val actual = current.encode()
        try { check(MessageDigest.isEqual(old, actual)) { "TRUSTED_STATE_CHANGED" } }
        finally { old.fill(0); actual.fill(0) }
    }
}

/** Bounds selected authority reads before I/O, without caching mutable authority or plaintext. */
internal class SelectedAuthorityObjectReader(references: List<ProtectedObjectReference>,
    private val readEncrypted: (String) -> ByteArray?, private val checkLive: () -> Unit) {
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
        val owned = checkNotNull(readEncrypted(physical)) { "AUTHORITY_OBJECT_MISSING" }
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
