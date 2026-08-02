// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.settings

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
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

private val Context.phase9Preferences by preferencesDataStore(name = "phase9_nonsecret_settings")

class Phase9SettingsStore(
    private val context: Context,
) {
    val settings: Flow<Phase9Settings> =
        context.phase9Preferences.data.map(::decodePhase9Settings)

    internal fun decode(values: Preferences): Phase9Settings = decodePhase9Settings(values)

    suspend fun setTheme(theme: ThemePreference) {
        context.phase9Preferences.edit { it[THEME] = theme.name }
    }

    suspend fun setHighContrast(enabled: Boolean) {
        context.phase9Preferences.edit { it[HIGH_CONTRAST] = enabled }
    }

    suspend fun setReducedMotion(enabled: Boolean) {
        context.phase9Preferences.edit { it[REDUCED_MOTION] = enabled }
    }

    suspend fun setConnection(value: ConnectionPreferences) {
        context.phase9Preferences.edit {
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
        context.phase9Preferences.edit {
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
        context.phase9Preferences.edit {
            it[ROUTING_MODE] = valid.mode.name
            it.remove(ROUTING_PACKAGES)
            it[EXCLUDED_CIDRS] = valid.excludedCidrs.toSet()
        }
    }

    suspend fun clearLegacyRoutingPackages() {
        context.phase9Preferences.edit { it.remove(ROUTING_PACKAGES) }
    }

    suspend fun setUpdates(value: UpdatePreferences) {
        val valid = value.validated()
        context.phase9Preferences.edit {
            it[AUTO_UPDATE] = valid.automatic
            it[UPDATE_INTERVAL] = valid.intervalHours
            it[UPDATE_ON_LAUNCH] = valid.onLaunch
            it[NOTIFY_ON_CHANGE] = valid.notifyOnChange
            it[PROBE_AFTER_UPDATE] = valid.probeAfterUpdate
        }
    }

    suspend fun setProbes(value: ProbePreferences) {
        val valid = value.validated()
        context.phase9Preferences.edit {
            it[PROBE_METHOD] = valid.method.name
            it[PROBE_DISPLAY] = valid.display.name
            it[TEST_URL] = valid.testUrl
            it[PROBE_TIMEOUT] = valid.timeoutSeconds
        }
    }

    suspend fun setDiagnostics(value: DiagnosticPreferences) {
        context.phase9Preferences.edit {
            it[LOG_LEVEL] = value.level.name
            it[LOG_RETENTION] = value.retention.name
        }
    }

    suspend fun setExpert(value: ExpertPreferences) {
        val valid = value.validated()
        context.phase9Preferences.edit {
            it[IDLE_TIMEOUT] = valid.idleTimeoutSeconds
            it[TCP_LIMIT] = valid.tcpConnectionLimit
            it[UDP_LIMIT] = valid.udpConnectionLimit
            it[MEMORY_LIMIT] = valid.memoryLimitMb
        }
    }

    suspend fun setProfiles(value: ProfilePreferences) {
        val valid = value.validated()
        context.phase9Preferences.edit {
            val active = valid.activeLocalRecordId
            if (active == null) it.remove(ACTIVE_PROFILE)
            else it[ACTIVE_PROFILE] = active
            it[FAVORITE_PROFILES] = valid.favoriteLocalRecordIds
        }
    }

    suspend fun resetAll() {
        context.phase9Preferences.edit { it.clear() }
    }

    suspend fun resetSettings() {
        context.phase9Preferences.edit {
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
        context.phase9Preferences.edit {
            it.remove(ACTIVE_PROFILE)
            it.remove(FAVORITE_PROFILES)
        }
    }

    suspend fun resetRouting() {
        context.phase9Preferences.edit {
            it.remove(ROUTING_MODE)
            it.remove(ROUTING_PACKAGES)
            it.remove(EXCLUDED_CIDRS)
        }
    }

    suspend fun resetDiagnostics() {
        context.phase9Preferences.edit {
            it.remove(LOG_LEVEL)
            it.remove(LOG_RETENTION)
        }
    }

    private companion object {
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
