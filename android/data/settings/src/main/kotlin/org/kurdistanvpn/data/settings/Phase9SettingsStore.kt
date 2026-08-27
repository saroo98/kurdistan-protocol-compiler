// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.settings

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
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
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.DiagnosticRetention
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProbeDisplay
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.SAFE_EXCLUDED_ROUTES
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences

// Canonical snapshot decoding must not initialize a DataStore delegate. Only the explicitly
// composed interactive projection adapter can reach this lazy, single-process owner.
private object Phase9PreferenceOwner {
    val Context.value by preferencesDataStore(name = "phase9_nonsecret_settings")
}
private val Context.phase9Preferences get() = with(Phase9PreferenceOwner) { value }

class Phase9SettingsStore private constructor(
    private val dataStore: DataStore<Preferences>,
    private val ownedJob: kotlinx.coroutines.Job?,
) {
    constructor(context: Context) : this(context.phase9Preferences, null)
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
    val settings: Flow<Phase9Settings> =
        store.data.map(::decodePhase9Settings)

    internal fun decode(values: Preferences): Phase9Settings = decodePhase9Settings(values)

    /** One DataStore snapshot. This is not a claim of cross-store atomicity or an independent disk reread. */
    suspend fun readProjection(): SettingsProjection {
        val current = store.data.first()
        return SettingsProjection(SettingsProjectionCodec.encode(current), SettingsProjectionIdentity.fromPreferences(current))
    }

    /** Broker-only composition. Image and equality witness share the same updateData operation. */
    suspend fun publishProjection(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) {
        val image = replacement.clone()
        val old = expected.image()
        try {
            val decoded = SettingsProjectionCodec.decode(image)
            require(next.matches(image))
            store.updateData { current ->
                val observed = SettingsProjectionCodec.encode(current)
                try {
                    check(MessageDigest.isEqual(old, observed) && SettingsProjectionIdentity.fromPreferences(current) == expected.witness) {
                        "STALE_SETTINGS_PROJECTION"
                    }
                } finally { observed.fill(0) }
                expected.witness?.let {
                    require(next.storeEpoch == it.storeEpoch && next.revision > it.revision)
                }
                decoded.toMutablePreferences().also { next.writeTo(it) }
            }
        } finally { image.fill(0); old.fill(0) }
    }

    suspend fun setTheme(theme: ThemePreference) {
        store.edit { it[THEME] = theme.name }
    }

    suspend fun setHighContrast(enabled: Boolean) {
        store.edit { it[HIGH_CONTRAST] = enabled }
    }

    suspend fun setReducedMotion(enabled: Boolean) {
        store.edit { it[REDUCED_MOTION] = enabled }
    }

    suspend fun setConnection(value: ConnectionPreferences) {
        store.edit {
            it[SELECTION_MODE] = value.selectionMode.name
            it[AUTO_CONNECT_LAUNCH] = value.autoConnectOnLaunch
            it[AUTO_CONNECT_BOOT] = value.autoConnectOnBoot
            it[RECONNECT] = value.reconnectOnFailure
            it[KILL_SWITCH] = value.killSwitchRequested
            it[ALLOW_LAN] = value.allowLan
            it[UNTRUSTED_ONLY] = value.connectOnlyOnUntrustedNetworks
        }
    }

    suspend fun setTunnel(value: TunnelPreferences) {
        val valid = value.validated()
        store.edit {
            it[IP_MODE] = valid.ipMode.name
            it[DNS_MODE] = valid.dnsMode.name
            it[CUSTOM_DNS] = valid.customDns
            it[MTU] = valid.mtu
            it[METERED] = valid.metered
            it[SHOW_SPEED] = valid.showSpeedInNotification
        }
    }

    suspend fun setRouting(value: RoutingPreferences) {
        val valid = value.validated()
        store.edit {
            it[ROUTING_MODE] = valid.mode.name
            it.remove(ROUTING_PACKAGES)
            it[EXCLUDED_CIDRS] = valid.excludedCidrs.toSet()
        }
    }

    suspend fun clearLegacyRoutingPackages() {
        store.edit { it.remove(ROUTING_PACKAGES) }
    }

    suspend fun setUpdates(value: UpdatePreferences) {
        val valid = value.validated()
        store.edit {
            it[AUTO_UPDATE] = valid.automatic
            it[UPDATE_INTERVAL] = valid.intervalHours
            it[UPDATE_ON_LAUNCH] = valid.onLaunch
            it[NOTIFY_ON_CHANGE] = valid.notifyOnChange
            it[PROBE_AFTER_UPDATE] = valid.probeAfterUpdate
        }
    }

    suspend fun setProbes(value: ProbePreferences) {
        val valid = value.validated()
        store.edit {
            it[PROBE_METHOD] = valid.method.name
            it[PROBE_DISPLAY] = valid.display.name
            it[TEST_URL] = valid.testUrl
            it[PROBE_TIMEOUT] = valid.timeoutSeconds
        }
    }

    suspend fun setDiagnostics(value: DiagnosticPreferences) {
        store.edit {
            it[LOG_LEVEL] = value.level.name
            it[LOG_RETENTION] = value.retention.name
        }
    }

    suspend fun setExpert(value: ExpertPreferences) {
        val valid = value.validated()
        store.edit {
            it[IDLE_TIMEOUT] = valid.idleTimeoutSeconds
            it[TCP_LIMIT] = valid.tcpConnectionLimit
            it[UDP_LIMIT] = valid.udpConnectionLimit
            it[MEMORY_LIMIT] = valid.memoryLimitMb
        }
    }

    suspend fun setProfiles(value: ProfilePreferences) {
        val valid = value.validated()
        store.edit {
            val active = valid.activeLocalRecordId
            if (active == null) it.remove(ACTIVE_PROFILE)
            else it[ACTIVE_PROFILE] = active
            it[FAVORITE_PROFILES] = valid.favoriteLocalRecordIds
        }
    }

    suspend fun resetAll() {
        store.edit { it.clear() }
    }

    suspend fun resetSettings() {
        store.edit {
            it.remove(THEME)
            it.remove(HIGH_CONTRAST)
            it.remove(REDUCED_MOTION)
            it.remove(SELECTION_MODE)
            it.remove(AUTO_CONNECT_LAUNCH)
            it.remove(AUTO_CONNECT_BOOT)
            it.remove(RECONNECT)
            it.remove(KILL_SWITCH)
            it.remove(ALLOW_LAN)
            it.remove(UNTRUSTED_ONLY)
            it.remove(IP_MODE)
            it.remove(DNS_MODE)
            it.remove(CUSTOM_DNS)
            it.remove(MTU)
            it.remove(METERED)
            it.remove(SHOW_SPEED)
            it.remove(AUTO_UPDATE)
            it.remove(UPDATE_INTERVAL)
            it.remove(UPDATE_ON_LAUNCH)
            it.remove(NOTIFY_ON_CHANGE)
            it.remove(PROBE_AFTER_UPDATE)
            it.remove(PROBE_METHOD)
            it.remove(PROBE_DISPLAY)
            it.remove(TEST_URL)
            it.remove(PROBE_TIMEOUT)
            it.remove(IDLE_TIMEOUT)
            it.remove(TCP_LIMIT)
            it.remove(UDP_LIMIT)
            it.remove(MEMORY_LIMIT)
        }
    }

    suspend fun resetProfiles() {
        store.edit {
            it.remove(ACTIVE_PROFILE)
            it.remove(FAVORITE_PROFILES)
        }
    }

    suspend fun resetRouting() {
        store.edit {
            it.remove(ROUTING_MODE)
            it.remove(ROUTING_PACKAGES)
            it.remove(EXCLUDED_CIDRS)
        }
    }

    suspend fun resetDiagnostics() {
        store.edit {
            it.remove(LOG_LEVEL)
            it.remove(LOG_RETENTION)
        }
    }

    companion object {
        /** Only a broker-held DIRTY operation may compose this writable adapter in production.
         * No parent or fallback path is created here. Restoration must use fromStoredBytes. */
        fun openOwnedProjection(file: java.io.File): Phase9SettingsStore {
            require(file.isAbsolute && file.name.endsWith(".preferences_pb"))
            val parent = requireNotNull(file.parentFile)
            require(parent.isDirectory && parent.canonicalFile == parent.absoluteFile)
            require(!java.nio.file.Files.isSymbolicLink(file.toPath()))
            val job = SupervisorJob()
            return try {
                Phase9SettingsStore(PreferenceDataStoreFactory.create(
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

internal fun decodePhase9Settings(values: Preferences): Phase9Settings =
    Phase9Settings(
        theme = enumPreference(values[stringPreferencesKey("theme")], ThemePreference.SYSTEM),
        highContrast = values[booleanPreferencesKey("high_contrast")] ?: false,
        reducedMotion = values[booleanPreferencesKey("reduced_motion")] ?: false,
        connection = ConnectionPreferences(
            selectionMode = enumPreference(values[stringPreferencesKey("selection_mode")], SelectionMode.AUTOMATIC),
            autoConnectOnLaunch = values[booleanPreferencesKey("auto_connect_launch")] ?: false,
            autoConnectOnBoot = values[booleanPreferencesKey("auto_connect_boot")] ?: false,
            reconnectOnFailure = values[booleanPreferencesKey("reconnect_on_failure")] ?: false,
            killSwitchRequested = values[booleanPreferencesKey("kill_switch_requested")] ?: false,
            allowLan = values[booleanPreferencesKey("allow_lan")] ?: false,
            connectOnlyOnUntrustedNetworks = values[booleanPreferencesKey("untrusted_networks_only")] ?: false,
        ),
        tunnel = runCatching {
            TunnelPreferences(
                ipMode = enumPreference(values[stringPreferencesKey("ip_mode")], IpMode.AUTO),
                dnsMode = enumPreference(values[stringPreferencesKey("dns_mode")], DnsMode.INTERNAL_TUN),
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
                excludedCidrs = values[stringSetPreferencesKey("excluded_cidrs")]?.toList() ?: SAFE_EXCLUDED_ROUTES,
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
                testUrl = values[stringPreferencesKey("test_url")]
                    ?: "",
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
    private val owned = image.clone().also { SettingsProjectionCodec.decode(it) }
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
                SettingsProjectionCodec.decode(owned)
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
            val values = decode(owned).toMutablePreferences()
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
            val image = encode(values)
            try {
                val identity = SettingsProjectionIdentity.fromPreferences(values)
                check(identity == null || identity.matches(image)) { "STORED_SETTINGS_WITNESS_MISMATCH" }
                return SettingsProjection(image, identity)
            } finally { image.fill(0) }
        } finally { owned.fill(0) }
    }

    /** Typed broker command encoding. No persistence or fallback/default repair is performed. */
    fun fromModel(input: Phase9Settings): ByteArray {
        val owned = input.copy(routing = input.routing.copy(packages = input.routing.packages.toTypedArray().toSet(),
            excludedCidrs = input.routing.excludedCidrs.toTypedArray().toList()),
            profiles = input.profiles.copy(favoriteLocalRecordIds = input.profiles.favoriteLocalRecordIds.toTypedArray().toSet()))
        require(owned.routing.packages.isEmpty()) { "ROUTING_IDENTITIES_REQUIRE_ENCRYPTED_OBJECT" }
        require(owned.tunnel.validated() == owned.tunnel && owned.probes.validated() == owned.probes)
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
            flag("auto_connect_boot", it.autoConnectOnBoot); flag("reconnect_on_failure", it.reconnectOnFailure)
            flag("kill_switch_requested", it.killSwitchRequested); flag("allow_lan", it.allowLan)
            flag("untrusted_networks_only", it.connectOnlyOnUntrustedNetworks)
        }
        owned.tunnel.let {
            text("ip_mode", it.ipMode.name); text("dns_mode", it.dnsMode.name); text("custom_dns", it.customDns)
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
            text("test_url", it.testUrl); number("probe_timeout_seconds", it.timeoutSeconds)
        }
        text("log_level", owned.diagnostics.level.name); text("log_retention", owned.diagnostics.retention.name)
        owned.expert.let {
            number("idle_timeout_seconds", it.idleTimeoutSeconds); number("tcp_connection_limit", it.tcpConnectionLimit)
            number("udp_connection_limit", it.udpConnectionLimit); number("memory_limit_mb", it.memoryLimitMb)
        }
        owned.profiles.activeLocalRecordId?.let { text("active_profile", it) }
        values[stringSetPreferencesKey("favorite_profiles")] = owned.profiles.favoriteLocalRecordIds
        return encode(values)
    }

    fun toModel(input: ByteArray): Phase9Settings = decodePhase9Settings(decode(input)).let { value ->
        value.copy(routing = value.routing.copy(packages = java.util.Collections.unmodifiableSet(HashSet(value.routing.packages)),
            excludedCidrs = java.util.Collections.unmodifiableList(ArrayList(value.routing.excludedCidrs))),
            profiles = value.profiles.copy(favoriteLocalRecordIds = java.util.Collections.unmodifiableSet(HashSet(value.profiles.favoriteLocalRecordIds))))
    }

    private val booleanKeys = setOf("high_contrast", "reduced_motion", "auto_connect_launch", "auto_connect_boot",
        "reconnect_on_failure", "kill_switch_requested", "allow_lan", "untrusted_networks_only", "metered",
        "show_speed", "automatic_updates", "update_on_launch", "notify_on_change", "probe_after_update")
    private val intKeys = setOf("mtu", "update_interval_hours", "probe_timeout_seconds", "idle_timeout_seconds",
        "tcp_connection_limit", "udp_connection_limit", "memory_limit_mb")
    private val stringKeys = setOf("theme", "selection_mode", "ip_mode", "dns_mode", "custom_dns", "routing_mode",
        "probe_method", "probe_display", "test_url", "log_level", "log_retention", "active_profile")
    private val setKeys = setOf("routing_packages", "excluded_cidrs", "favorite_profiles")
    private val known = booleanKeys + intKeys + stringKeys + setKeys

    fun encode(values: Preferences): ByteArray {
        // Preferences.asMap is snapshotted before validation; nested sets are copied too.
        val fields = values.asMap().entries.toTypedArray().associate { (key, value) ->
            key.name to if (value is Set<*>) value.toTypedArray().toSet() else value
        }.filterKeys { !it.startsWith(SettingsProjectionIdentity.WITNESS_PREFIX) }
        require(fields.size <= 48 && fields.keys.all { it in known })
        for ((name, value) in fields) require(when (name) {
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
        validateSemantics(snapshot.toPreferences(), fields)
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { writer ->
            writer.writeInt(0x4b535031); writer.writeByte(1); writer.writeShort(fields.size)
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
        val owned = input.clone()
        try {
            require(owned.size in 7..65536)
            val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
            require(reader.int == 0x4b535031 && reader.get().toInt() == 1)
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
            val canonical = encode(result)
            try { require(MessageDigest.isEqual(owned, canonical)) } finally { canonical.fill(0) }
            return result.toPreferences()
        } catch (_: java.nio.BufferUnderflowException) { throw IllegalArgumentException("TRUNCATED_SETTINGS_IMAGE") }
        finally { owned.fill(0) }
    }

    private fun validateSemantics(values: Preferences, fields: Map<String, Any>) {
        fun enum(name: String, allowed: List<String>) { fields[name]?.let { require(it in allowed) } }
        enum("theme", ThemePreference.entries.map { it.name })
        enum("selection_mode", SelectionMode.entries.map { it.name })
        enum("ip_mode", IpMode.entries.map { it.name }); enum("dns_mode", DnsMode.entries.map { it.name })
        enum("routing_mode", PerAppSelectionMode.entries.map { it.name })
        enum("probe_method", ProbeMethod.entries.map { it.name }); enum("probe_display", ProbeDisplay.entries.map { it.name })
        enum("log_level", DiagnosticLogLevel.entries.map { it.name }); enum("log_retention", DiagnosticRetention.entries.map { it.name })
        val decoded = decodePhase9Settings(values)
        val exact = mapOf("mtu" to decoded.tunnel.mtu, "update_interval_hours" to decoded.updates.intervalHours,
            "probe_timeout_seconds" to decoded.probes.timeoutSeconds, "idle_timeout_seconds" to decoded.expert.idleTimeoutSeconds,
            "tcp_connection_limit" to decoded.expert.tcpConnectionLimit, "udp_connection_limit" to decoded.expert.udpConnectionLimit,
            "memory_limit_mb" to decoded.expert.memoryLimitMb, "custom_dns" to decoded.tunnel.customDns,
            "test_url" to decoded.probes.testUrl, "active_profile" to decoded.profiles.activeLocalRecordId,
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
