// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.settings

import java.io.*
import androidx.datastore.preferences.core.*
import org.kurdistanvpn.core.model.*

/** Pure migration decision. Only the protected broker can publish a Ready value. */
object SettingsMigration {
    internal val authorityKeys = setOf("selection_mode", "auto_connect_launch", "reconnect_on_failure", "allow_lan",
        "untrusted_networks_only", "ip_mode", "dns_mode", "custom_dns", "mtu", "metered", "routing_mode",
        "routing_packages", "excluded_cidrs", "active_profile", "favorite_profiles")
    sealed interface Decision
    data class Ready(val requested: ProductSettings) : Decision
    data object Required : Decision { override fun toString() = "MIGRATION_REQUIRED" }
    fun planLegacyImage(image: ByteArray, selected: String?, securePackages: Set<String>, appliedStateProven: Boolean): Decision =
        try { planLegacy(if (RawLegacySettingsImage.isRaw(image)) RawLegacySettingsImage.decode(image)
            else SettingsProjectionCodec.decode(image), selected, securePackages, appliedStateProven) }
        catch (_: RuntimeException) { Required }
    fun planLegacy(values: Preferences, selected: String?, securePackages: Set<String>, appliedStateProven: Boolean): Decision {
        if (!appliedStateProven || ProductSettingsImage.hasProductKeys(values)) return Required
        return try {
            val decoded = decodeMigrationValues(values)
            if (decoded.profiles.activeLocalRecordId != selected) return Required
            val legacyPackages = decoded.routing.packages
            if (legacyPackages.isNotEmpty() && securePackages.isNotEmpty() && legacyPackages != securePackages) return Required
            val packages = if (securePackages.isNotEmpty()) securePackages.toSet() else legacyPackages
            if (decoded.routing.excludedCidrs.isNotEmpty() && decoded.routing.excludedCidrs.toSet() != SAFE_EXCLUDED_ROUTES.toSet()) return Required
            if (selected != null && decoded.tunnel.dnsMode in setOf(ResolverPolicy.PRESET, ResolverPolicy.PROFILE_DEFINED)) return Required
            val tunnel = if (selected == null && decoded.tunnel.dnsMode != ResolverPolicy.INTERNAL)
                decoded.tunnel.copy(dnsMode = ResolverPolicy.INTERNAL, resolverCatalogId = null, customDns = "", secondaryCustomDns = "") else decoded.tunnel
            val routing = decoded.routing.copy(packages = packages, excludedCidrs = emptyList()).validated()
            Ready(decoded.copy(tunnel = tunnel, routing = routing))
        } catch (_: RuntimeException) { Required }
    }
    /** A migration-only view; the captured source bytes remain untouched for proof and restoration. */
    internal fun decodeMigrationValues(values: Preferences): ProductSettings {
        require(!ProductSettingsImage.hasProductKeys(values)) { "LEGACY_FORMAT_MISMATCH" }
        val authority = decodeLegacyAuthority(values)
        val cleaned = values.toMutablePreferences().also { safe ->
            values.asMap().forEach { (key, value) ->
                if (key.name !in authorityKeys && !SettingsProjectionCodec.isLegacyValueType(key.name, value)) safe.remove(key)
            }
        }
        val display = decodeLegacySettings(cleaned)
        return display.copy(connection = authority.connection,
            tunnel = authority.tunnel.copy(showSpeedInNotification = cleaned[booleanPreferencesKey("show_speed")] ?: false),
            routing = authority.routing, profiles = authority.profiles)
    }
}

/** KSR1/version1 is exact migration input, never an executable runtime settings image. */
object RawLegacySettingsImage {
    fun isRaw(input: ByteArray): Boolean = input.size >= 4 && java.nio.ByteBuffer.wrap(input).int == 0x4b535231
    fun capture(values: Preferences): ByteArray {
        require(SettingsProjectionIdentity.fromPreferences(values) == null && !ProductSettingsImage.hasProductKeys(values)) {
            "AUTHENTICATED_IMAGE_REQUIRES_STRICT_DECODING"
        }
        return SettingsProjectionCodec.encodeRawLegacy(values)
    }
    fun decode(input: ByteArray): Preferences = SettingsProjectionCodec.decodeRawLegacy(input)
}

/** KSP2 is a nonsecret requested snapshot, never authority or a settings commit. */
class ProductSettingsImage private constructor(private val fields: NonsecretSettingsFields, val revision: Long) {
    /** Only an authenticated secure composition may provide these profile-derived values. */
    fun resolve(identifiers: SettingsIdentifiers): ProductSettings = fields.resolve(identifiers)
    fun preferences(): Preferences = mutablePreferencesOf(SCHEMA to 2, REVISION to revision, SNAPSHOT to encode()).toPreferences()
    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { w ->
            fun text(value: String) { require(value.length <= 128); w.writeUTF(value) }
            fun enum(value: Enum<*>) = text(value.name)
            val s = fields
            w.writeInt(0x4b535032); w.writeByte(2); w.writeLong(revision)
            enum(s.theme); w.writeBoolean(s.highContrast); w.writeBoolean(s.reducedMotion)
            s.connection.let { enum(it.selectionMode); w.writeBoolean(it.autoConnectOnLaunch); w.writeBoolean(it.reconnectOnFailure)
                w.writeBoolean(it.allowLan); w.writeBoolean(it.connectOnlyOnUntrustedNetworks); w.writeBoolean(s.manualReference); w.writeInt(it.reconnectMaximum) }
            s.tunnel.let { enum(it.ipMode); enum(it.dnsMode); text(it.customDns); w.writeInt(it.mtu); w.writeBoolean(it.metered)
                w.writeBoolean(it.showSpeedInNotification); w.writeBoolean(s.resolverReference); text(it.secondaryCustomDns) }
            enum(s.routing.mode); w.writeInt(s.routing.excludedCidrs.size); s.routing.excludedCidrs.forEach(::text)
            s.updates.let { w.writeBoolean(it.automatic); w.writeInt(it.intervalHours); w.writeBoolean(it.onLaunch)
                w.writeBoolean(it.notifyOnChange); w.writeBoolean(it.probeAfterUpdate) }
            s.probes.let { enum(it.method); enum(it.display); w.writeBoolean(s.probeReference); w.writeInt(it.timeoutSeconds) }
            enum(s.diagnostics.level); enum(s.diagnostics.retention)
            s.expert.let { w.writeInt(it.idleTimeoutSeconds); w.writeInt(it.tcpConnectionLimit); w.writeInt(it.udpConnectionLimit); w.writeInt(it.memoryLimitMb) }
            enum(s.tunnelMode); enum(s.networkMeteredPolicy); enum(s.pausePolicy)
            s.localProxy.let { w.writeInt(it.socksPort); w.writeInt(it.httpConnectPort); w.writeInt(it.limits.clients)
                w.writeInt(it.limits.streams); w.writeInt(it.limits.idleSeconds); w.writeInt(it.limits.memoryMiB) }
            s.privacy.let { w.writeBoolean(it.collectUsageAggregates); w.writeInt(it.usageRetentionDays); w.writeBoolean(it.appLockEnabled)
                w.writeInt(it.allowedAuthenticators.size); it.allowedAuthenticators.sortedBy { a -> a.name }.forEach(::enum) }
            w.writeBoolean(s.notifications.showSpeed); w.writeBoolean(s.notifications.notifyOnUpdates)
            w.writeBoolean(s.automation.enabled); w.writeBoolean(s.networkTrust.enabled)
        }
        return out.toByteArray().also { require(it.size <= MAX_BYTES) }
    }
    override fun toString(): String = "ProductSettingsImage(redacted)"
    companion object {
        const val MAX_BYTES = 16384
        val SCHEMA = intPreferencesKey("product_settings_schema_version")
        val REVISION = longPreferencesKey("product_settings_revision")
        val SNAPSHOT = byteArrayPreferencesKey("product_settings_snapshot")
        fun isVersionTwo(input: ByteArray): Boolean = input.size >= 4 &&
            java.nio.ByteBuffer.wrap(input, 0, 4).int == 0x4b535032
        internal fun hasProductKeys(values: Preferences): Boolean = values.asMap().keys.any { it.name.startsWith("product_settings_") }
        internal fun fromPreferences(values: Preferences): ProductSettingsImage {
            try {
                require(values.asMap().keys.filter { it.name.startsWith("product_settings_") }.map { it.name }.toSet() ==
                    setOf(SCHEMA.name, REVISION.name, SNAPSHOT.name))
                require(values[SCHEMA] == 2)
                return decode(requireNotNull(values[SNAPSHOT])).also { require(values[REVISION] == it.revision) }
            } catch (_: RuntimeException) { throw IllegalArgumentException("MALFORMED_SETTINGS_PROJECTION") }
        }
        fun create(requested: ProductSettings, revision: Long): ProductSettingsImage {
            require(revision > 0) { "INVALID_SETTINGS_REVISION" }
            require(requested.profiles == ProfilePreferences() && requested.routing.packages.isEmpty() &&
                requested.networkTrust.protectedRuleIds.isEmpty()) { "PROTECTED_SETTINGS_VALUE" }
            require(requested.tunnel.validated() == requested.tunnel && requested.routing.validatedMetadata() == requested.routing)
            requested.updates.validated(); requested.probes.validated(); requested.expert.validated()
            return ProductSettingsImage(NonsecretSettingsFields.from(requested), revision)
        }
        fun decode(input: ByteArray): ProductSettingsImage {
            require(input.size in 13..MAX_BYTES) { "INVALID_SETTINGS_IMAGE_SIZE" }
            val owned = input.clone()
            try {
                val r = DataInputStream(ByteArrayInputStream(owned))
                require(r.readInt() == 0x4b535032 && r.readUnsignedByte() == 2) { "INVALID_SETTINGS_IMAGE_VERSION" }
                val revision = r.readLong()
                fun text(): String = r.readUTF().also { require(it.length <= 128) }
                fun flag(): Boolean = r.readUnsignedByte().let { require(it in 0..1); it == 1 }
                val theme = enumValueOf<ThemePreference>(text()); val contrast = flag(); val motion = flag()
                val selection = enumValueOf<SelectionMode>(text()); val launch = flag(); val reconnect = flag(); val lan = flag(); val untrusted = flag(); val manualReference = flag()
                val connection = ConnectionPreferences(selectionMode = selection, autoConnectOnLaunch = launch,
                    reconnectOnFailure = reconnect, allowLan = lan, connectOnlyOnUntrustedNetworks = untrusted, reconnectMaximum = r.readInt())
                val ip = enumValueOf<IpMode>(text()); val dns = enumValueOf<ResolverPolicy>(text()); val custom = text()
                val mtu = r.readInt(); val tunnelMetered = flag(); val speed = flag(); val resolverReference = flag()
                val tunnel = NonsecretTunnelFields(ip, dns, custom, mtu, tunnelMetered, speed, text())
                val mode = enumValueOf<PerAppSelectionMode>(text())
                val routeCount = r.readInt().also { require(it in 0..64) }
                val routing = RoutingPreferences(mode, excludedCidrs = List(routeCount) { text() })
                val updates = UpdatePreferences(flag(), r.readInt(), flag(), flag(), flag())
                val method = enumValueOf<ProbeMethod>(text()); val display = enumValueOf<ProbeDisplay>(text()); val probeReference = flag()
                val probes = ProbePreferences(method, display, timeoutSeconds = r.readInt())
                val diagnostics = DiagnosticPreferences(enumValueOf(text()), enumValueOf(text()))
                val expert = ExpertPreferences(r.readInt(), r.readInt(), r.readInt(), r.readInt())
                val tunnelMode = enumValueOf<TunnelMode>(text()); val metered = enumValueOf<NetworkMeteredPolicy>(text()); val pause = enumValueOf<PausePolicy>(text())
                val proxy = LocalProxyPreferences(r.readInt(), r.readInt(), ProxyLimits(r.readInt(), r.readInt(), r.readInt(), r.readInt()))
                val usage = flag(); val retention = r.readInt(); val locked = flag()
                val count = r.readInt().also { require(it in 0..2) }
                val authenticators = List(count) { enumValueOf<AllowedAuthenticator>(text()) }.also { require(it.distinct().size == count) }
                val privacy = PrivacyPreferences(usage, retention, locked, authenticators.toSet())
                val notifications = NotificationPreferences(flag(), flag()); val automation = AutomationPreferences(flag()); val trust = NetworkTrustPreferences(flag())
                require(r.available() == 0) { "TRAILING_SETTINGS_IMAGE" }
                require(revision > 0)
                val result = ProductSettingsImage(NonsecretSettingsFields(theme, contrast, motion, connection, tunnel, routing, updates, probes, diagnostics,
                    expert, tunnelMode, metered, pause, proxy, privacy, notifications, automation, trust,
                    manualReference, resolverReference, probeReference), revision)
                val canonical = result.encode()
                try { require(owned.contentEquals(canonical)) { "NONCANONICAL_SETTINGS_IMAGE" } } finally { canonical.fill(0) }
                return result
            } catch (_: IOException) { throw IllegalArgumentException("MALFORMED_SETTINGS_IMAGE") }
            catch (_: IllegalArgumentException) { throw IllegalArgumentException("MALFORMED_SETTINGS_IMAGE") }
            finally { owned.fill(0) }
        }
    }
}

/** Deliberately incomplete. PRESET has no fake identifier and cannot become a TunnelPreferences until composition. */
private data class NonsecretTunnelFields(val ipMode: IpMode, val dnsMode: ResolverPolicy, val customDns: String,
    val mtu: Int, val metered: Boolean, val showSpeedInNotification: Boolean, val secondaryCustomDns: String) {
    init {
        require(mtu in 1280..1500)
        if (dnsMode == ResolverPolicy.CUSTOM) {
            require(NumericAddress(customDns).value == customDns)
            require(secondaryCustomDns.isEmpty() || NumericAddress(secondaryCustomDns).value == secondaryCustomDns)
        } else require(customDns.isEmpty() && secondaryCustomDns.isEmpty())
    }
    fun resolve(id: CatalogId?) = TunnelPreferences(ipMode, dnsMode, customDns, mtu, metered, showSpeedInNotification, id, secondaryCustomDns)
}

private data class NonsecretSettingsFields(val theme: ThemePreference, val highContrast: Boolean, val reducedMotion: Boolean,
    val connection: ConnectionPreferences, val tunnel: NonsecretTunnelFields, val routing: RoutingPreferences,
    val updates: UpdatePreferences, val probes: ProbePreferences, val diagnostics: DiagnosticPreferences, val expert: ExpertPreferences,
    val tunnelMode: TunnelMode, val networkMeteredPolicy: NetworkMeteredPolicy, val pausePolicy: PausePolicy,
    val localProxy: LocalProxyPreferences, val privacy: PrivacyPreferences, val notifications: NotificationPreferences,
    val automation: AutomationPreferences, val networkTrust: NetworkTrustPreferences,
    val manualReference: Boolean, val resolverReference: Boolean, val probeReference: Boolean) {
    init {
        require(!manualReference || connection.selectionMode == SelectionMode.MANUAL_STRATEGY)
        require(resolverReference == (tunnel.dnsMode == ResolverPolicy.PRESET))
        require(routing.validatedMetadata() == routing)
    }
    fun resolve(ids: SettingsIdentifiers): ProductSettings {
        require(manualReference == (ids.manualStrategy != null) && resolverReference == (ids.resolver != null) &&
            probeReference == (ids.probeTarget != null)) { "SETTINGS_REFERENCE_MISMATCH" }
        return ProductSettings(theme, highContrast, reducedMotion, connection.copy(manualStrategyId = ids.manualStrategy),
            tunnel.resolve(ids.resolver), routing, updates, probes.copy(signedTargetId = ids.probeTarget), diagnostics, expert,
            ProfilePreferences(), tunnelMode, networkMeteredPolicy, pausePolicy, localProxy, privacy, notifications, automation, networkTrust)
    }
    companion object {
        fun from(s: ProductSettings) = NonsecretSettingsFields(s.theme, s.highContrast, s.reducedMotion,
            s.connection.copy(manualStrategyId = null), s.tunnel.let { NonsecretTunnelFields(it.ipMode, it.dnsMode, it.customDns, it.mtu,
                it.metered, it.showSpeedInNotification, it.secondaryCustomDns) }, s.routing, s.updates, s.probes.copy(signedTargetId = null),
            s.diagnostics, s.expert, s.tunnelMode, s.networkMeteredPolicy, s.pausePolicy, s.localProxy, s.privacy, s.notifications,
            s.automation, s.networkTrust, s.connection.manualStrategyId != null, s.tunnel.resolverCatalogId != null, s.probes.signedTargetId != null)
    }
}
