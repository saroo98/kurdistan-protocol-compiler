// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.settings

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.mutablePreferencesOf
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.SettingsIdentifiers
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.DiagnosticRetention
import org.kurdistanvpn.core.model.ResolverPolicy
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProbeDisplay
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences

// Canonical snapshot decoding must not initialize a DataStore delegate. Only the explicitly
// composed interactive projection adapter can reach this lazy, single-process owner.
private object ProductPreferenceOwner {
    val Context.value by preferencesDataStore(name = "phase9_nonsecret_settings")
}
private val Context.productPreferences get() = with(ProductPreferenceOwner) { value }

class ProductSettingsStore private constructor(
    private val dataStore: DataStore<Preferences>,
    private val ownedJob: kotlinx.coroutines.Job?,
) {
    constructor(context: Context) : this(context.productPreferences, null)
    @Volatile private var closed = false
    private val store: DataStore<Preferences> get() {
        check(!closed) { "SETTINGS_OWNER_CLOSED" }; return dataStore
    }

    /** Cancels and joins the sole owner's scope. This is quiescence, not a durability receipt.
     * The broker must retain write errors and independently sync/reopen the resulting file. */
    suspend fun closeOwned() {
        val job = checkNotNull(ownedJob) { "SHARED_LEGACY_OWNER_CANNOT_BE_CLOSED" }
        closed = true
        job.cancelAndJoin()
    }
    val settings: Flow<ProductSettings> =
        store.data.map { values ->
            if (ProductSettingsImage.hasProductKeys(values)) ProductSettingsImage.fromPreferences(values).resolve(SettingsIdentifiers())
            else decodeLegacySettings(values)
        }

    internal fun decode(values: Preferences): ProductSettings = decodeLegacySettings(values)

    /** One DataStore snapshot. This is not a claim of cross-store atomicity or an independent disk reread. */
    suspend fun readProjection(): SettingsProjection {
        val current = store.data.first()
        return SettingsProjection(SettingsProjectionCodec.encodePhysicalProjection(current), SettingsProjectionIdentity.fromPreferences(current))
    }

    /** Explicit migration capture only. No normalization or persistence occurs on this read. */
    suspend fun readLegacyMigrationProjection(): SettingsProjection {
        val current = store.data.first()
        require(SettingsProjectionIdentity.fromPreferences(current) == null && !ProductSettingsImage.hasProductKeys(current))
        return SettingsProjection(SettingsProjectionCodec.encodePhysicalProjection(current, true), null)
    }

    /** Broker-only composition. Image and equality witness share the same updateData operation. */
    suspend fun publishProjection(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) =
        writeProjection(expected, replacement, next, false)

    /** Exact endpoints are authorized by the DIRTY broker before this physical compare-and-write. */
    suspend fun recoverProjection(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) =
        writeProjection(expected, replacement, next, true)

    private suspend fun writeProjection(expected: SettingsProjection, replacement: ByteArray,
        next: SettingsProjectionIdentity, recovering: Boolean) {
        val image = replacement.clone()
        val old = expected.image()
        try {
            val rawMigration = RawLegacySettingsImage.isRaw(image)
            val decoded = if (rawMigration) RawLegacySettingsImage.decode(image) else SettingsProjectionCodec.decode(image)
            require(next.matches(image))
            store.updateData { current ->
                val observed = SettingsProjectionCodec.encodePhysicalProjection(current,
                    expected.witness == null && RawLegacySettingsImage.isRaw(old))
                try {
                    check(MessageDigest.isEqual(old, observed) && SettingsProjectionIdentity.fromPreferences(current) == expected.witness) {
                        "STALE_SETTINGS_PROJECTION"
                    }
                } finally { observed.fill(0) }
                expected.witness?.let {
                    require(next.storeEpoch == it.storeEpoch && (next.revision > it.revision ||
                        (recovering && next.revision == it.revision && next.operationId == it.operationId)))
                }
                SettingsProjectionCodec.mergeProjection(current, decoded, rawMigration).also { next.writeTo(it) }
            }
        } finally { image.fill(0); old.fill(0) }
    }


    companion object {
        /** Only a broker-held DIRTY operation may compose this writable adapter in production.
         * No parent or fallback path is created here. Restoration must use fromStoredBytes. */
        fun openOwnedProjection(file: java.io.File): ProductSettingsStore {
            require(file.isAbsolute && file.name.endsWith(".preferences_pb"))
            val parent = requireNotNull(file.parentFile)
            require(parent.isDirectory && parent.canonicalFile == parent.absoluteFile)
            require(!java.nio.file.Files.isSymbolicLink(file.toPath()))
            val job = SupervisorJob()
            return try {
                ProductSettingsStore(PreferenceDataStoreFactory.create(
                    scope = CoroutineScope(Dispatchers.IO + job), produceFile = { file }), job)
            } catch (failure: Throwable) { job.cancel(); throw failure }
        }
        val THEME = stringPreferencesKey("theme")
        val HIGH_CONTRAST = booleanPreferencesKey("high_contrast")
        val REDUCED_MOTION = booleanPreferencesKey("reduced_motion")
        val SELECTION_MODE = stringPreferencesKey("selection_mode")
        val AUTO_CONNECT_LAUNCH = booleanPreferencesKey("auto_connect_launch")
        val AUTO_CONNECT_BOOT = booleanPreferencesKey("auto_connect_boot")
        val RECONNECT = booleanPreferencesKey("reconnect_on_failure")
        val KILL_SWITCH = booleanPreferencesKey("kill_switch_requested")
        val ALLOW_LAN = booleanPreferencesKey("allow_lan")
        val UNTRUSTED_ONLY = booleanPreferencesKey("untrusted_networks_only")
        val IP_MODE = stringPreferencesKey("ip_mode")
        val DNS_MODE = stringPreferencesKey("dns_mode")
        val CUSTOM_DNS = stringPreferencesKey("custom_dns")
        val MTU = intPreferencesKey("mtu")
        val METERED = booleanPreferencesKey("metered")
        val SHOW_SPEED = booleanPreferencesKey("show_speed")
        val ROUTING_MODE = stringPreferencesKey("routing_mode")
        val ROUTING_PACKAGES = stringSetPreferencesKey("routing_packages")
        val EXCLUDED_CIDRS = stringSetPreferencesKey("excluded_cidrs")
        val AUTO_UPDATE = booleanPreferencesKey("automatic_updates")
        val UPDATE_INTERVAL = intPreferencesKey("update_interval_hours")
        val UPDATE_ON_LAUNCH = booleanPreferencesKey("update_on_launch")
        val NOTIFY_ON_CHANGE = booleanPreferencesKey("notify_on_change")
        val PROBE_AFTER_UPDATE = booleanPreferencesKey("probe_after_update")
        val PROBE_METHOD = stringPreferencesKey("probe_method")
        val PROBE_DISPLAY = stringPreferencesKey("probe_display")
        val TEST_URL = stringPreferencesKey("test_url")
        val PROBE_TIMEOUT = intPreferencesKey("probe_timeout_seconds")
        val LOG_LEVEL = stringPreferencesKey("log_level")
        val LOG_RETENTION = stringPreferencesKey("log_retention")
        val IDLE_TIMEOUT = intPreferencesKey("idle_timeout_seconds")
        val TCP_LIMIT = intPreferencesKey("tcp_connection_limit")
        val UDP_LIMIT = intPreferencesKey("udp_connection_limit")
        val MEMORY_LIMIT = intPreferencesKey("memory_limit_mb")
        val ACTIVE_PROFILE = stringPreferencesKey("active_profile")
        val FAVORITE_PROFILES = stringSetPreferencesKey("favorite_profiles")
    }
}

// Legacy wire names are serialization details, not production resolver identities or authority.
enum class LegacySettingsResiduePolicy { PRESERVE, DISCARD }

/** Inactive codec-only residue. It is never supplied to product state, UI, or probe execution. */
class LegacySettingsResidue internal constructor(private val probeUrl: String?, private val boot: Boolean?, private val kill: Boolean?) {
    init { require(probeUrl == null || probeUrl.length <= 4096) }
    internal fun applyTo(values: androidx.datastore.preferences.core.MutablePreferences) {
        boot?.let { values[booleanPreferencesKey("auto_connect_boot")] = it }
        kill?.let { values[booleanPreferencesKey("kill_switch_requested")] = it }
        val key = stringPreferencesKey("test_url")
        if (probeUrl == null) values.remove(key) else values[key] = probeUrl
    }
    override fun toString(): String = "LegacySettingsResidue(redacted)"
}

private val LEGACY_RESOLVER_NAMES = listOf("INTERNAL_TUN", "CLOUDFLARE_GOOGLE", "GOOGLE", "CLOUDFLARE", "QUAD9", "CUSTOM")
private val LEGACY_RESOLVER_CATALOG = mapOf(
    "CLOUDFLARE_GOOGLE" to CatalogId("legacy-resolver-1"),
    "GOOGLE" to CatalogId("legacy-resolver-2"),
    "CLOUDFLARE" to CatalogId("legacy-resolver-3"),
    "QUAD9" to CatalogId("legacy-resolver-4"),
)
private fun legacyResolverCatalog(value: String?): CatalogId? = LEGACY_RESOLVER_CATALOG[value]
private fun legacyResolverPolicy(value: String?): ResolverPolicy = when {
    value == "CUSTOM" -> ResolverPolicy.CUSTOM
    value in LEGACY_RESOLVER_CATALOG -> ResolverPolicy.PRESET
    else -> ResolverPolicy.INTERNAL
}
private fun legacyResolverName(value: TunnelPreferences): String {
    require(value.secondaryCustomDns.isEmpty()) { "RESOLVER_REQUIRES_NEW_CODEC" }
    return when (value.dnsMode) {
        ResolverPolicy.INTERNAL -> "INTERNAL_TUN"
        ResolverPolicy.CUSTOM -> "CUSTOM"
        ResolverPolicy.PRESET -> requireNotNull(LEGACY_RESOLVER_CATALOG.entries.find { it.value == value.resolverCatalogId }?.key) { "RESOLVER_REQUIRES_NEW_CODEC" }
        ResolverPolicy.PROFILE_DEFINED -> throw IllegalArgumentException("RESOLVER_REQUIRES_NEW_CODEC")
    }
}

internal data class LegacyAuthorityValues(val connection: ConnectionPreferences, val tunnel: TunnelPreferences,
    val routing: RoutingPreferences, val profiles: ProfilePreferences)

/** Missing legacy keys have documented defaults; present authority never uses a fallback decoder. */
internal fun decodeLegacyAuthority(values: Preferences): LegacyAuthorityValues = try {
    values.asMap().forEach { (key, value) ->
        if (key.name in SettingsMigration.authorityKeys) require(SettingsProjectionCodec.isLegacyValueType(key.name, value))
    }
    fun text(name: String) = values[stringPreferencesKey(name)]
    fun flag(name: String) = values[booleanPreferencesKey(name)] ?: false
    fun <T : Enum<T>> enum(name: String, entries: List<T>, default: T): T =
        text(name)?.let { raw -> requireNotNull(entries.find { it.name == raw }) } ?: default
    val connection = ConnectionPreferences(
        selectionMode = enum("selection_mode", SelectionMode.entries, SelectionMode.AUTOMATIC),
        autoConnectOnLaunch = flag("auto_connect_launch"), reconnectOnFailure = flag("reconnect_on_failure"),
        allowLan = flag("allow_lan"), connectOnlyOnUntrustedNetworks = flag("untrusted_networks_only"))
    val resolver = text("dns_mode") ?: "INTERNAL_TUN"
    require(resolver in LEGACY_RESOLVER_NAMES)
    val tunnel = TunnelPreferences(ipMode = enum("ip_mode", IpMode.entries, IpMode.AUTO),
        dnsMode = legacyResolverPolicy(resolver), resolverCatalogId = legacyResolverCatalog(resolver),
        customDns = text("custom_dns").orEmpty(), mtu = values[intPreferencesKey("mtu")] ?: 1500, metered = flag("metered"))
    require(tunnel == tunnel.validated())
    val routing = RoutingPreferences(mode = enum("routing_mode", PerAppSelectionMode.entries, PerAppSelectionMode.ALL_APPS),
        packages = values[stringSetPreferencesKey("routing_packages")].orEmpty(),
        excludedCidrs = values[stringSetPreferencesKey("excluded_cidrs")]?.toList() ?: emptyList())
    // The separate secure package owner may supply a missing INCLUDE_ONLY set later. Never infer ALL_APPS.
    val canonical = routing.validatedMetadata()
    require(routing.packages == canonical.packages && routing.excludedCidrs.toSet() == canonical.excludedCidrs.toSet())
    require(routing.mode != PerAppSelectionMode.ALL_APPS || routing.packages.isEmpty())
    val profiles = ProfilePreferences(text("active_profile"), values[stringSetPreferencesKey("favorite_profiles")].orEmpty()).validated()
    LegacyAuthorityValues(connection, tunnel, routing, profiles)
} catch (_: RuntimeException) { throw IllegalArgumentException("INVALID_LEGACY_AUTHORITY") }

private fun isCanonicalLegacyProbeUrl(value: String): Boolean {
    if (value.length !in 9..2048 || !value.startsWith("https://")) return false
    val authority = value.substringAfter("https://").substringBefore('/').substringBefore('?').substringBefore('#')
    if (authority.isEmpty() || '@' in authority || authority.any { it.isWhitespace() }) return false
    val host = authority.substringBeforeLast(':', authority)
    if (host.isEmpty() || host.length > 253) return false
    return host == "localhost" || runCatching { org.kurdistanvpn.core.model.NumericAddress(host) }.isSuccess ||
        host.split('.').all { label ->
            label.length in 1..63 && label.first().isLetterOrDigit() && label.last().isLetterOrDigit() &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
}

internal fun decodeLegacySettings(values: Preferences): ProductSettings =
    ProductSettings(
        theme = enumPreference(values[stringPreferencesKey("theme")], ThemePreference.SYSTEM),
        highContrast = values[booleanPreferencesKey("high_contrast")] ?: false,
        reducedMotion = values[booleanPreferencesKey("reduced_motion")] ?: false,
        connection = ConnectionPreferences(
            selectionMode = enumPreference(values[stringPreferencesKey("selection_mode")], SelectionMode.AUTOMATIC),
            autoConnectOnLaunch = values[booleanPreferencesKey("auto_connect_launch")] ?: false,
            reconnectOnFailure = values[booleanPreferencesKey("reconnect_on_failure")] ?: false,
            allowLan = values[booleanPreferencesKey("allow_lan")] ?: false,
            connectOnlyOnUntrustedNetworks = values[booleanPreferencesKey("untrusted_networks_only")] ?: false,
        ),
        tunnel = runCatching {
            TunnelPreferences(
                ipMode = enumPreference(values[stringPreferencesKey("ip_mode")], IpMode.AUTO),
                dnsMode = legacyResolverPolicy(values[stringPreferencesKey("dns_mode")]),
                resolverCatalogId = legacyResolverCatalog(values[stringPreferencesKey("dns_mode")]),
                customDns = values[stringPreferencesKey("custom_dns")].orEmpty(),
                mtu = values[intPreferencesKey("mtu")] ?: 1500,
                metered = values[booleanPreferencesKey("metered")] ?: false,
                showSpeedInNotification = values[booleanPreferencesKey("show_speed")] ?: false,
            ).validated()
        }.getOrDefault(TunnelPreferences()),
        routing = runCatching {
            RoutingPreferences(
                mode = enumPreference(values[stringPreferencesKey("routing_mode")], PerAppSelectionMode.ALL_APPS),
                packages = values[stringSetPreferencesKey("routing_packages")].orEmpty(),
                excludedCidrs = values[stringSetPreferencesKey("excluded_cidrs")]?.toList() ?: emptyList(),
            ).validatedMetadata()
        }.getOrDefault(RoutingPreferences()),
        updates = runCatching {
            UpdatePreferences(
                automatic = values[booleanPreferencesKey("automatic_updates")] ?: false,
                intervalHours = values[intPreferencesKey("update_interval_hours")] ?: 2,
                onLaunch = values[booleanPreferencesKey("update_on_launch")] ?: false,
                notifyOnChange = values[booleanPreferencesKey("notify_on_change")] ?: true,
                probeAfterUpdate = values[booleanPreferencesKey("probe_after_update")] ?: false,
            ).validated()
        }.getOrDefault(UpdatePreferences()),
        probes = runCatching {
            ProbePreferences(
                method = enumPreference(values[stringPreferencesKey("probe_method")], ProbeMethod.KURD_SESSION),
                display = enumPreference(values[stringPreferencesKey("probe_display")], ProbeDisplay.MILLISECONDS),
                timeoutSeconds = values[intPreferencesKey("probe_timeout_seconds")] ?: 3,
            ).validated()
        }.getOrDefault(ProbePreferences()),
        diagnostics = DiagnosticPreferences(
            level = enumPreference(values[stringPreferencesKey("log_level")], DiagnosticLogLevel.WARNING),
            retention = enumPreference(values[stringPreferencesKey("log_retention")], DiagnosticRetention.ONE_DAY),
        ),
        expert = runCatching {
            ExpertPreferences(
                idleTimeoutSeconds = values[intPreferencesKey("idle_timeout_seconds")] ?: 300,
                tcpConnectionLimit = values[intPreferencesKey("tcp_connection_limit")] ?: 256,
                udpConnectionLimit = values[intPreferencesKey("udp_connection_limit")] ?: 128,
                memoryLimitMb = values[intPreferencesKey("memory_limit_mb")] ?: 80,
            ).validated()
        }.getOrDefault(ExpertPreferences()),
        profiles = runCatching {
            ProfilePreferences(
                activeLocalRecordId = values[stringPreferencesKey("active_profile")]?.ifBlank { null },
                favoriteLocalRecordIds = values[stringSetPreferencesKey("favorite_profiles")].orEmpty(),
            ).validated()
        }.getOrDefault(ProfilePreferences()),
    )

private inline fun <reified T : Enum<T>> enumPreference(value: String?, fallback: T): T =
    value?.let { runCatching { enumValueOf<T>(it) }.getOrNull() } ?: fallback

class SettingsProjection(image: ByteArray, val witness: SettingsProjectionIdentity?) {
    private val owned = image.clone().also {
        if (RawLegacySettingsImage.isRaw(it)) RawLegacySettingsImage.decode(it) else SettingsProjectionCodec.decode(it)
    }
    fun image(): ByteArray = owned.clone()
}

/** Public fields are nonsecret equality identifiers. Construction recomputes the image digest. */
class SettingsProjectionIdentity private constructor(
    val storeEpoch: String, val operationId: String, val revision: Long, val imageDigest: String,
) {
    override fun equals(other: Any?): Boolean = other is SettingsProjectionIdentity &&
        storeEpoch == other.storeEpoch && operationId == other.operationId && revision == other.revision && imageDigest == other.imageDigest
    override fun hashCode(): Int = arrayOf<Any>(storeEpoch, operationId, revision, imageDigest).contentHashCode()
    override fun toString(): String = "SettingsProjectionIdentity(revision=$revision)"
    fun matches(image: ByteArray): Boolean = imageDigest == digest(image)
    internal fun writeTo(preferences: androidx.datastore.preferences.core.MutablePreferences) {
        preferences[stringPreferencesKey(WITNESS_PREFIX + "store")] = storeEpoch
        preferences[stringPreferencesKey(WITNESS_PREFIX + "operation")] = operationId
        preferences[longPreferencesKey(WITNESS_PREFIX + "revision")] = revision
        preferences[stringPreferencesKey(WITNESS_PREFIX + "digest")] = imageDigest
    }
    companion object {
        internal const val WITNESS_PREFIX = "protected_projection_"
        private fun validate(store: String, operation: String, revision: Long) {
            require(store.matches(Regex("[0-9a-f]{32}")) && store.any { it != '0' })
            require(operation.matches(Regex("[0-9a-f]{64}")) && operation.any { it != '0' })
            require(revision > 0 && revision and 1L == 0L)
        }
        fun capture(store: String, operation: String, revision: Long, image: ByteArray): SettingsProjectionIdentity {
            validate(store, operation, revision)
            val owned = image.clone()
            return try {
                if (RawLegacySettingsImage.isRaw(owned)) RawLegacySettingsImage.decode(owned) else SettingsProjectionCodec.decode(owned)
                SettingsProjectionIdentity(store, operation, revision, digest(owned))
            } finally { owned.fill(0) }
        }
        internal fun fromPreferences(values: Preferences): SettingsProjectionIdentity? {
            val names = values.asMap().keys.map { it.name }.filter { it.startsWith(WITNESS_PREFIX) }
            if (names.isEmpty()) return null
            require(names.toSet() == setOf("store", "operation", "revision", "digest").map { WITNESS_PREFIX + it }.toSet())
            val store = requireNotNull(values[stringPreferencesKey(WITNESS_PREFIX + "store")])
            val operation = requireNotNull(values[stringPreferencesKey(WITNESS_PREFIX + "operation")])
            val revision = requireNotNull(values[longPreferencesKey(WITNESS_PREFIX + "revision")])
            val digest = requireNotNull(values[stringPreferencesKey(WITNESS_PREFIX + "digest")])
            validate(store, operation, revision)
            require(digest.matches(Regex("[0-9a-f]{64}")))
            return SettingsProjectionIdentity(store, operation, revision, digest)
        }
        private fun digest(input: ByteArray): String {
            val owned = input.clone()
            return try {
                require(owned.size <= 65536)
                MessageDigest.getInstance("SHA-256").apply {
                    update("kurdistan-settings-projection-v1\u0000".toByteArray(Charsets.US_ASCII))
                    update(ByteBuffer.allocate(4).putInt(owned.size).array())
                }.digest(owned).joinToString("") { "%02x".format(it) }
            } finally { owned.fill(0) }
        }
    }
}

/** Canonical KSP1 image. No default population, sanitization, repair or persistence occurs here. */
object SettingsProjectionCodec {
    /** Pure serialization of a validated projection. This has no file or DataStore
     * owner and is not a durability receipt. The broker still publishes, closes,
     * synchronizes and independently rereads the exact resulting file bytes. */
    suspend fun toStoredBytes(image: ByteArray, identity: SettingsProjectionIdentity): ByteArray {
        val owned = image.clone()
        try {
            check(identity.matches(owned)) { "SETTINGS_PROJECTION_IDENTITY_MISMATCH" }
            val values = (if (RawLegacySettingsImage.isRaw(owned)) RawLegacySettingsImage.decode(owned) else decode(owned)).toMutablePreferences()
            identity.writeTo(values)
            val output = java.io.ByteArrayOutputStream()
            androidx.datastore.preferences.core.PreferencesFileSerializer.writeTo(values, output)
            return output.toByteArray().also { require(it.size in 1..65536) }
        } finally { owned.fill(0) }
    }

    /** Parses an already bounded, independently read file image. No Context, DataStore owner,
     * corruption handler, migration, default write, or filesystem capability is constructed. */
    suspend fun fromStoredBytes(input: ByteArray): SettingsProjection {
        val owned = input.clone()
        try {
            require(owned.size in 1..65536)
            val stream = java.io.ByteArrayInputStream(owned)
            val values = androidx.datastore.preferences.core.PreferencesFileSerializer.readFrom(stream)
            require(stream.available() == 0)
            val image = encodePhysicalProjection(values)
            try {
                val identity = SettingsProjectionIdentity.fromPreferences(values)
                check(identity == null || identity.matches(image)) { "STORED_SETTINGS_WITNESS_MISMATCH" }
                return SettingsProjection(image, identity)
            } finally { image.fill(0) }
        } finally { owned.fill(0) }
    }

    /** Explicit unjournaled legacy source capture. Authenticated images cannot enter this path. */
    suspend fun captureLegacyStoredBytes(input: ByteArray): SettingsProjection {
        val owned = input.clone()
        try {
            require(owned.size in 1..65536)
            val stream = java.io.ByteArrayInputStream(owned)
            val values = androidx.datastore.preferences.core.PreferencesFileSerializer.readFrom(stream)
            require(stream.available() == 0 && SettingsProjectionIdentity.fromPreferences(values) == null && !ProductSettingsImage.hasProductKeys(values))
            return SettingsProjection(encodePhysicalProjection(values, true), null)
        } finally { owned.fill(0) }
    }

    /** Typed broker command encoding. No persistence or fallback/default repair is performed. */
    fun fromModel(input: ProductSettings, residue: LegacySettingsResidue? = null): ByteArray {
        val defaults = ProductSettings()
        require(input.tunnelMode == defaults.tunnelMode && input.networkMeteredPolicy == defaults.networkMeteredPolicy &&
            input.pausePolicy == defaults.pausePolicy && input.localProxy == defaults.localProxy &&
            input.privacy == defaults.privacy && input.notifications == defaults.notifications &&
            input.automation == defaults.automation && input.networkTrust == defaults.networkTrust &&
            input.connection.manualStrategyId == null && input.connection.reconnectMaximum == 3) { "PREFERENCES_REQUIRE_NEW_CODEC" }
        val owned = input.copy(routing = input.routing.copy(packages = input.routing.packages.toTypedArray().toSet(),
            excludedCidrs = input.routing.excludedCidrs.toTypedArray().toList()),
            profiles = input.profiles.copy(favoriteLocalRecordIds = input.profiles.favoriteLocalRecordIds.toTypedArray().toSet()))
        require(owned.routing.packages.isEmpty()) { "ROUTING_IDENTITIES_REQUIRE_ENCRYPTED_OBJECT" }
        require(owned.tunnel.validated() == owned.tunnel && owned.probes.validated() == owned.probes)
        require(owned.probes.signedTargetId == null) { "PROBE_TARGET_REQUIRES_NEW_CODEC" }
        owned.updates.validated(); owned.expert.validated(); owned.profiles.validated()
        val routing = owned.routing.validatedMetadata()
        require(routing.excludedCidrs.toSet() == owned.routing.excludedCidrs.toSet() &&
            owned.routing.excludedCidrs.distinct().size == owned.routing.excludedCidrs.size)
        val values = mutablePreferencesOf()
        fun text(name: String, value: String) { values[stringPreferencesKey(name)] = value }
        fun flag(name: String, value: Boolean) { values[booleanPreferencesKey(name)] = value }
        fun number(name: String, value: Int) { values[intPreferencesKey(name)] = value }
        text("theme", owned.theme.name); flag("high_contrast", owned.highContrast); flag("reduced_motion", owned.reducedMotion)
        owned.connection.let {
            text("selection_mode", it.selectionMode.name); flag("auto_connect_launch", it.autoConnectOnLaunch)
            flag("auto_connect_boot", false); flag("reconnect_on_failure", it.reconnectOnFailure)
            flag("kill_switch_requested", false); flag("allow_lan", it.allowLan)
            flag("untrusted_networks_only", it.connectOnlyOnUntrustedNetworks)
        }
        owned.tunnel.let {
            text("ip_mode", it.ipMode.name); text("dns_mode", legacyResolverName(it)); text("custom_dns", it.customDns)
            number("mtu", it.mtu); flag("metered", it.metered); flag("show_speed", it.showSpeedInNotification)
        }
        text("routing_mode", routing.mode.name)
        values[stringSetPreferencesKey("excluded_cidrs")] = routing.excludedCidrs.toSet()
        owned.updates.let {
            flag("automatic_updates", it.automatic); number("update_interval_hours", it.intervalHours)
            flag("update_on_launch", it.onLaunch); flag("notify_on_change", it.notifyOnChange); flag("probe_after_update", it.probeAfterUpdate)
        }
        owned.probes.let {
            text("probe_method", it.method.name); text("probe_display", it.display.name)
            text("test_url", ""); number("probe_timeout_seconds", it.timeoutSeconds)
        }
        text("log_level", owned.diagnostics.level.name); text("log_retention", owned.diagnostics.retention.name)
        owned.expert.let {
            number("idle_timeout_seconds", it.idleTimeoutSeconds); number("tcp_connection_limit", it.tcpConnectionLimit)
            number("udp_connection_limit", it.udpConnectionLimit); number("memory_limit_mb", it.memoryLimitMb)
        }
        owned.profiles.activeLocalRecordId?.let { text("active_profile", it) }
        values[stringSetPreferencesKey("favorite_profiles")] = owned.profiles.favoriteLocalRecordIds
        residue?.applyTo(values)
        return encode(values)
    }

    fun legacyResidue(input: ByteArray): LegacySettingsResidue = decode(input).let {
        LegacySettingsResidue(it[stringPreferencesKey("test_url")], it[booleanPreferencesKey("auto_connect_boot")],
            it[booleanPreferencesKey("kill_switch_requested")])
    }

    fun preserveLegacyResidue(current: ByteArray, replacement: ByteArray): ByteArray {
        val values = decode(replacement).toMutablePreferences()
        legacyResidue(current).applyTo(values)
        return encode(values)
    }

    fun toModel(input: ByteArray): ProductSettings = (if (ProductSettingsImage.isVersionTwo(input))
        ProductSettingsImage.decode(input).resolve(SettingsIdentifiers())
        else if (RawLegacySettingsImage.isRaw(input)) SettingsMigration.decodeMigrationValues(RawLegacySettingsImage.decode(input))
        else decodeLegacySettings(decode(input))).let { value ->
        value.copy(routing = value.routing.copy(packages = java.util.Collections.unmodifiableSet(HashSet(value.routing.packages)),
            excludedCidrs = java.util.Collections.unmodifiableList(ArrayList(value.routing.excludedCidrs))),
            profiles = value.profiles.copy(favoriteLocalRecordIds = java.util.Collections.unmodifiableSet(HashSet(value.profiles.favoriteLocalRecordIds))))
    }

    /** Complete values require authenticated secure identifiers after KSP2 migration. */
    fun toProductModel(input: ByteArray, identifiers: SettingsIdentifiers): ProductSettings =
        if (ProductSettingsImage.isVersionTwo(input)) ProductSettingsImage.decode(input).resolve(identifiers)
        else toModel(input).also { require(identifiers == SettingsIdentifiers.from(it)) }

    private val booleanKeys = setOf("high_contrast", "reduced_motion", "auto_connect_launch", "auto_connect_boot",
        "reconnect_on_failure", "kill_switch_requested", "allow_lan", "untrusted_networks_only", "metered",
        "show_speed", "automatic_updates", "update_on_launch", "notify_on_change", "probe_after_update")
    private val intKeys = setOf("mtu", "update_interval_hours", "probe_timeout_seconds", "idle_timeout_seconds",
        "tcp_connection_limit", "udp_connection_limit", "memory_limit_mb")
    private val stringKeys = setOf("theme", "selection_mode", "ip_mode", "dns_mode", "custom_dns", "routing_mode",
        "probe_method", "probe_display", "test_url", "log_level", "log_retention", "active_profile")
    private val setKeys = setOf("routing_packages", "excluded_cidrs", "favorite_profiles")
    private val known = booleanKeys + intKeys + stringKeys + setKeys
    internal fun isLegacyValueType(name: String, value: Any): Boolean = when (name) {
        in booleanKeys -> value is Boolean
        in intKeys -> value is Int
        in stringKeys -> value is String
        in setKeys -> value is Set<*> && value.all { it is String }
        else -> false
    }

    internal fun mergeProjection(current: Preferences, replacement: Preferences, rawMigration: Boolean = false): androidx.datastore.preferences.core.MutablePreferences {
        if (ProductSettingsImage.hasProductKeys(replacement)) ProductSettingsImage.fromPreferences(replacement)
        else if (rawMigration) encodeRawLegacy(replacement).fill(0)
        else encode(replacement).fill(0)
        return current.toMutablePreferences().also { merged ->
            current.asMap().keys.filter { it.name in known || it.name.startsWith("product_settings_") ||
                it.name.startsWith(SettingsProjectionIdentity.WITNESS_PREFIX) }.forEach { merged.remove(it) }
            merged += replacement
        }
    }

    /** Unrelated physical keys stay outside KSP1; the broker separately authenticates the entire file. */
    internal fun encodePhysicalProjection(values: Preferences, allowUnwitnessedRaw: Boolean = false): ByteArray {
        if (ProductSettingsImage.hasProductKeys(values)) return encode(values)
        val owned = values.toMutablePreferences()
        values.asMap().keys.filter { it.name !in known && !it.name.startsWith(SettingsProjectionIdentity.WITNESS_PREFIX) }
            .forEach { owned.remove(it) }
        val existingWitness = SettingsProjectionIdentity.fromPreferences(values)
        if (existingWitness != null) {
            val raw = encodeRawLegacy(owned)
            if (existingWitness.matches(raw)) return raw
            raw.fill(0)
        }
        return try { encode(owned) } catch (failure: IllegalArgumentException) {
            val raw = encodeRawLegacy(owned)
            val witness = SettingsProjectionIdentity.fromPreferences(values)
            if ((allowUnwitnessedRaw && witness == null) || witness?.matches(raw) == true) raw
            else { raw.fill(0); throw failure }
        }
    }

    fun encode(values: Preferences): ByteArray {
        if (ProductSettingsImage.hasProductKeys(values)) {
            require(values.asMap().keys.none { it.name in known }) { "LEGACY_VALUES_IN_PRODUCT_PROJECTION" }
            return ProductSettingsImage.fromPreferences(values).encode()
        }
        return encodeLegacy(values, false)
    }
    internal fun encodeRawLegacy(values: Preferences): ByteArray = encodeLegacy(values, true)
    private fun encodeLegacy(values: Preferences, rawMigration: Boolean): ByteArray {
        // Preferences.asMap is snapshotted before validation; nested sets are copied too.
        val fields = values.asMap().entries.toTypedArray().associate { (key, value) ->
            key.name to if (value is Set<*>) value.toTypedArray().toSet() else value
        }.filterKeys { !it.startsWith(SettingsProjectionIdentity.WITNESS_PREFIX) }
        require(fields.size <= 48 && fields.keys.all { it in known })
        for ((name, value) in fields) require(if (rawMigration) value is Boolean || value is Int || value is String ||
            (value is Set<*> && value.all { it is String }) else when (name) {
            in booleanKeys -> value is Boolean
            in intKeys -> value is Int
            in stringKeys -> value is String
            in setKeys -> value is Set<*> && value.all { it is String }
            else -> false
        })
        val snapshot = mutablePreferencesOf()
        for ((name, value) in fields) when (value) {
            is Boolean -> snapshot[booleanPreferencesKey(name)] = value
            is Int -> snapshot[intPreferencesKey(name)] = value
            is String -> snapshot[stringPreferencesKey(name)] = value
            is Set<*> -> snapshot[stringSetPreferencesKey(name)] = value.map { it as String }.toSet()
        }
        if (rawMigration) {
            val authority = snapshot.toMutablePreferences()
            authority.asMap().keys.filter { it.name !in SettingsMigration.authorityKeys }.forEach { authority.remove(it) }
            encodeLegacy(authority, false).fill(0)
        } else validateSemantics(snapshot.toPreferences(), fields)
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { writer ->
            writer.writeInt(if (rawMigration) 0x4b535231 else 0x4b535031); writer.writeByte(1); writer.writeShort(fields.size)
            for ((name, value) in fields.toSortedMap()) {
                val key = name.toByteArray(Charsets.US_ASCII)
                writer.writeByte(key.size); writer.write(key)
                when (value) {
                    is Boolean -> { writer.writeByte(1); writer.writeByte(if (value) 1 else 0) }
                    is Int -> { writer.writeByte(2); writer.writeInt(value) }
                    is String -> { writer.writeByte(3); writeText(writer, value) }
                    is Set<*> -> {
                        val strings = value.map { it as String }.sorted()
                        require(strings.size <= 512)
                        writer.writeByte(4); writer.writeShort(strings.size)
                        strings.forEach { writeText(writer, it) }
                    }
                    else -> error("UNSUPPORTED_PREFERENCE_TYPE")
                }
                require(output.size() <= 65536)
            }
        }
        return output.toByteArray()
    }

    fun decode(input: ByteArray): Preferences {
        if (ProductSettingsImage.isVersionTwo(input)) return ProductSettingsImage.decode(input).preferences()
        return decodeLegacyImage(input, false)
    }
    internal fun decodeRawLegacy(input: ByteArray): Preferences = decodeLegacyImage(input, true)
    private fun decodeLegacyImage(input: ByteArray, rawMigration: Boolean): Preferences {
        val owned = input.clone()
        try {
            require(owned.size in 7..65536)
            val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
            require(reader.int == (if (rawMigration) 0x4b535231 else 0x4b535031) && reader.get().toInt() == 1)
            val count = reader.short.toInt() and 65535
            require(count <= 48)
            val result = mutablePreferencesOf()
            val names = mutableSetOf<String>()
            repeat(count) {
                val length = reader.get().toInt() and 255
                require(length in 1..64 && length < reader.remaining())
                val bytes = ByteArray(length).also(reader::get)
                require(bytes.all { it in 1..127 })
                val key = String(bytes, Charsets.US_ASCII)
                require(key in known && names.add(key))
                when (reader.get().toInt()) {
                    1 -> { val value = reader.get().toInt(); require(value in 0..1); result[booleanPreferencesKey(key)] = value == 1 }
                    2 -> result[intPreferencesKey(key)] = reader.int
                    3 -> result[stringPreferencesKey(key)] = readText(reader)
                    4 -> {
                        val size = reader.short.toInt() and 65535
                        require(size <= 512)
                        val members = List(size) { readText(reader) }
                        require(members.toSet().size == size)
                        result[stringSetPreferencesKey(key)] = members.toSet()
                    }
                    else -> throw IllegalArgumentException("UNKNOWN_PREFERENCE_TYPE")
                }
            }
            require(!reader.hasRemaining())
            val canonical = encodeLegacy(result, rawMigration)
            try { require(MessageDigest.isEqual(owned, canonical)) } finally { canonical.fill(0) }
            return result.toPreferences()
        } catch (_: java.nio.BufferUnderflowException) { throw IllegalArgumentException("TRUNCATED_SETTINGS_IMAGE") }
        finally { owned.fill(0) }
    }

    private fun validateSemantics(values: Preferences, fields: Map<String, Any>) {
        decodeLegacyAuthority(values)
        fun enum(name: String, allowed: List<String>) { fields[name]?.let { require(it in allowed) } }
        enum("theme", ThemePreference.entries.map { it.name })
        enum("selection_mode", SelectionMode.entries.map { it.name })
        enum("ip_mode", IpMode.entries.map { it.name }); enum("dns_mode", LEGACY_RESOLVER_NAMES)
        enum("routing_mode", PerAppSelectionMode.entries.map { it.name })
        enum("probe_method", ProbeMethod.entries.map { it.name }); enum("probe_display", ProbeDisplay.entries.map { it.name })
        enum("log_level", DiagnosticLogLevel.entries.map { it.name }); enum("log_retention", DiagnosticRetention.entries.map { it.name })
        val decoded = decodeLegacySettings(values)
        val legacyProbe = fields["test_url"] as? String
        if (legacyProbe != null) {
            require(legacyProbe == legacyProbe.trim()) { "NORMALIZATION_REQUIRES_EXPLICIT_MIGRATION" }
            if (legacyProbe.isNotEmpty() && fields["probe_method"] in setOf("HTTP_GET", "HTTP_HEAD")) {
                require(isCanonicalLegacyProbeUrl(legacyProbe)) { "INVALID_LEGACY_PROBE" }
            }
        }
        val exact = mapOf("mtu" to decoded.tunnel.mtu, "update_interval_hours" to decoded.updates.intervalHours,
            "probe_timeout_seconds" to decoded.probes.timeoutSeconds, "idle_timeout_seconds" to decoded.expert.idleTimeoutSeconds,
            "tcp_connection_limit" to decoded.expert.tcpConnectionLimit, "udp_connection_limit" to decoded.expert.udpConnectionLimit,
            "memory_limit_mb" to decoded.expert.memoryLimitMb, "custom_dns" to decoded.tunnel.customDns,
            "active_profile" to decoded.profiles.activeLocalRecordId,
            "favorite_profiles" to decoded.profiles.favoriteLocalRecordIds, "excluded_cidrs" to decoded.routing.excludedCidrs.toSet())
        exact.forEach { (name, expected) -> fields[name]?.let { require(it == expected) { "NORMALIZATION_REQUIRES_EXPLICIT_MIGRATION" } } }
    }
    private fun writeText(writer: DataOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.size <= 4096 && decodeText(bytes) == value)
        writer.writeShort(bytes.size); writer.write(bytes)
    }
    private fun readText(reader: ByteBuffer): String {
        val length = reader.short.toInt() and 65535
        require(length <= 4096 && length <= reader.remaining())
        return decodeText(ByteArray(length).also(reader::get))
    }
    private fun decodeText(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()
}
