// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

enum class SelectionMode { AUTOMATIC, KURD_ONLY, MANUAL_STRATEGY }
enum class ManualSelectionAvailability { NOT_REQUESTED, UNAVAILABLE, SELECTED }

enum class IpMode { AUTO, IPV4_ONLY, IPV6_ONLY, DUAL_STACK }

enum class ResolverPolicy { INTERNAL, PROFILE_DEFINED, PRESET, CUSTOM }

/** Profile-derived request references are protected; a CatalogId is not a privacy classification. */
data class SettingsIdentifiers(val manualStrategy: CatalogId? = null, val resolver: CatalogId? = null, val probeTarget: CatalogId? = null) {
    override fun toString(): String = "SettingsIdentifiers(redacted)"
    companion object { fun from(value: ProductSettings) = SettingsIdentifiers(value.connection.manualStrategyId, value.tunnel.resolverCatalogId, value.probes.signedTargetId) }
}

enum class ProbeMethod { KURD_SESSION, TCP_CONNECT, HTTP_HEAD, HTTP_GET, ICMP }

enum class ProbeDisplay { MILLISECONDS, HEALTH_DOTS }

enum class DiagnosticLogLevel { NONE, ERROR, WARNING, INFO, DEBUG }

enum class DiagnosticRetention { ONE_HOUR, SIX_HOURS, ONE_DAY, SEVEN_DAYS }

enum class ResetScope {
    SETTINGS, PROFILES_AND_TRUST, ROUTING, DIAGNOSTICS, EVERYTHING, PENDING_CREDENTIALS, LOCAL_CREDENTIALS;
    // The legacy reset adapter cannot clear all local credentials. Never widen pending-key reset.
    val unavailableReason: OperationError? get() =
        if (this == LOCAL_CREDENTIALS) OperationError.AUTHORITY_UNAVAILABLE else null
}

enum class PerAppSelectionMode { ALL_APPS, INCLUDE_ONLY, EXCLUDE_SELECTED }

enum class SettingsField {
    TUNNEL_MTU,
    CUSTOM_DNS,
    ROUTING_PACKAGES,
    EXCLUDED_ROUTES,
    UPDATE_INTERVAL,
    PROBE_URL,
    PROBE_TIMEOUT,
    IDLE_TIMEOUT,
    TCP_LIMIT,
    UDP_LIMIT,
    MEMORY_LIMIT,
    PROFILE_IDENTIFIERS,
}

class SettingsValidationException(
    val field: SettingsField,
    val category: String,
) : IllegalArgumentException("${field.name}:$category")

private fun requireSetting(condition: Boolean, field: SettingsField, category: String) {
    if (!condition) throw SettingsValidationException(field, category)
}

data class ConnectionPreferences(
    val selectionMode: SelectionMode = SelectionMode.AUTOMATIC,
    val autoConnectOnLaunch: Boolean = false,
    val reconnectOnFailure: Boolean = false,
    val allowLan: Boolean = false,
    val connectOnlyOnUntrustedNetworks: Boolean = false,
    val manualStrategyId: CatalogId? = null,
    val reconnectMaximum: Int = 3,
) {
    init {
        require(reconnectMaximum in 1..10)
        require(selectionMode == SelectionMode.MANUAL_STRATEGY || manualStrategyId == null)
    }
    val reconnectPolicy: ReconnectPreferences get() = ReconnectPreferences(reconnectOnFailure, reconnectMaximum)
    // Legacy requested settings retained only the mode. A missing identity is never effective authority.
    val manualSelectionAvailability: ManualSelectionAvailability get() = when {
        selectionMode != SelectionMode.MANUAL_STRATEGY -> ManualSelectionAvailability.NOT_REQUESTED
        manualStrategyId == null -> ManualSelectionAvailability.UNAVAILABLE
        else -> ManualSelectionAvailability.SELECTED
    }
    fun effectiveStrategy(signed: Set<CatalogId>, native: Set<CatalogId>): StrategySelection = when (selectionMode) {
        SelectionMode.AUTOMATIC -> StrategySelection.Automatic
        SelectionMode.KURD_ONLY -> StrategySelection.KurdOnly
        SelectionMode.MANUAL_STRATEGY -> StrategySelection.Manual(requireNotNull(manualStrategyId)).validatedAgainst(signed, native)
    }
}

data class TunnelPreferences(
    val ipMode: IpMode = IpMode.AUTO,
    val dnsMode: ResolverPolicy = ResolverPolicy.INTERNAL,
    val customDns: String = "",
    val mtu: Int = 1500,
    val metered: Boolean = false,
    val showSpeedInNotification: Boolean = false,
    val resolverCatalogId: CatalogId? = null,
    val secondaryCustomDns: String = "",
) {
    init {
        requireSetting(mtu in 1280..1500, SettingsField.TUNNEL_MTU, "OUT_OF_RANGE")
        requireSetting((dnsMode == ResolverPolicy.PRESET) == (resolverCatalogId != null), SettingsField.CUSTOM_DNS, "INVALID_CATALOG")
        if (dnsMode == ResolverPolicy.CUSTOM) {
            requireSetting(isValidIpLiteral(customDns), SettingsField.CUSTOM_DNS, "INVALID_IP_LITERAL")
            requireSetting(secondaryCustomDns.isEmpty() || isValidIpLiteral(secondaryCustomDns), SettingsField.CUSTOM_DNS, "INVALID_IP_LITERAL")
        } else {
            requireSetting(customDns.isBlank() && secondaryCustomDns.isBlank(), SettingsField.CUSTOM_DNS, "UNEXPECTED_VALUE")
        }
    }
    fun validated(): TunnelPreferences {
        requireSetting(mtu in 1280..1500, SettingsField.TUNNEL_MTU, "OUT_OF_RANGE")
        if (dnsMode == ResolverPolicy.CUSTOM) {
            requireSetting(isValidIpLiteral(customDns), SettingsField.CUSTOM_DNS, "INVALID_IP_LITERAL")
            requireSetting(secondaryCustomDns.isEmpty() || isValidIpLiteral(secondaryCustomDns), SettingsField.CUSTOM_DNS, "INVALID_IP_LITERAL")
        } else {
            requireSetting(customDns.isBlank(), SettingsField.CUSTOM_DNS, "UNEXPECTED_VALUE")
            requireSetting(secondaryCustomDns.isBlank(), SettingsField.CUSTOM_DNS, "UNEXPECTED_VALUE")
        }
        requireSetting((dnsMode == ResolverPolicy.PRESET) == (resolverCatalogId != null), SettingsField.CUSTOM_DNS, "INVALID_CATALOG")
        return copy(
            customDns = customDns.trim().let { if (it.isBlank()) it else canonicalizeIpLiteral(it)!! },
            secondaryCustomDns = secondaryCustomDns.trim().let { if (it.isBlank()) it else canonicalizeIpLiteral(it)!! },
        )
    }
    override fun toString(): String = "TunnelPreferences(redacted)"
}

class RoutingPreferences(
    val mode: PerAppSelectionMode = PerAppSelectionMode.ALL_APPS,
    packages: Set<String> = emptySet(),
    excludedCidrs: List<String> = emptyList(),
) {
    init {
        requireSetting(packages.size <= 256, SettingsField.ROUTING_PACKAGES, "TOO_MANY")
        requireSetting(packages.all(::isValidPackageName), SettingsField.ROUTING_PACKAGES, "INVALID_PACKAGE")
        requireSetting(excludedCidrs.size <= 64, SettingsField.EXCLUDED_ROUTES, "TOO_MANY")
        requireSetting(excludedCidrs.all { canonicalizeCidr(it) != null }, SettingsField.EXCLUDED_ROUTES, "INVALID_CIDR")
    }
    val packages: Set<String> = java.util.Collections.unmodifiableSet(packages.toSet())
    val excludedCidrs: List<String> = java.util.Collections.unmodifiableList(excludedCidrs.toList())
    fun copy(mode: PerAppSelectionMode = this.mode, packages: Set<String> = this.packages,
        excludedCidrs: List<String> = this.excludedCidrs): RoutingPreferences = RoutingPreferences(mode, packages, excludedCidrs)
    override fun equals(other: Any?): Boolean = other is RoutingPreferences && mode == other.mode && packages == other.packages && excludedCidrs == other.excludedCidrs
    override fun hashCode(): Int = listOf(mode, packages, excludedCidrs).hashCode()
    override fun toString(): String = "RoutingPreferences(redacted)"
    fun validatedMetadata(): RoutingPreferences {
        requireSetting(packages.size <= 256, SettingsField.ROUTING_PACKAGES, "TOO_MANY")
        requireSetting(packages.all(::isValidPackageName), SettingsField.ROUTING_PACKAGES, "INVALID_PACKAGE")
        requireSetting(excludedCidrs.size <= 64, SettingsField.EXCLUDED_ROUTES, "TOO_MANY")
        val canonicalRoutes = excludedCidrs.map {
            canonicalizeCidr(it) ?: throw SettingsValidationException(
                SettingsField.EXCLUDED_ROUTES,
                "INVALID_CIDR",
            )
        }
        return copy(
            packages = packages.toSortedSet(),
            excludedCidrs = canonicalRoutes.distinct().sorted(),
        )
    }

    fun validated(): RoutingPreferences {
        val normalized = validatedMetadata()
        if (normalized.mode == PerAppSelectionMode.INCLUDE_ONLY) {
            requireSetting(normalized.packages.isNotEmpty(), SettingsField.ROUTING_PACKAGES, "EMPTY_INCLUDE_SET")
        }
        if (normalized.mode == PerAppSelectionMode.ALL_APPS) {
            requireSetting(normalized.packages.isEmpty(), SettingsField.ROUTING_PACKAGES, "UNEXPECTED_RULES")
        }
        return normalized
    }
    fun effective(nativeMaximum: Int, installedPackages: Set<String>, signedBypassable: Set<CanonicalRoute>): RoutingPreferences {
        require(nativeMaximum >= 0 && installedPackages.size <= 65536)
        require(packages.size <= minOf(256, nativeMaximum))
        ExcludedRoutes(excludedCidrs.map(::CanonicalRoute)).validatedAgainst(signedBypassable)
        return copy(packages = packages.intersect(installedPackages)).validated()
    }
}

data class UpdatePreferences(
    val automatic: Boolean = false,
    val intervalHours: Int = 2,
    val onLaunch: Boolean = false,
    val notifyOnChange: Boolean = true,
    val probeAfterUpdate: Boolean = false,
) {
    init { requireSetting(intervalHours in 1..168, SettingsField.UPDATE_INTERVAL, "OUT_OF_RANGE") }
    fun validated(): UpdatePreferences {
        requireSetting(intervalHours in 1..168, SettingsField.UPDATE_INTERVAL, "OUT_OF_RANGE")
        return this
    }
}

data class ProbePreferences(
    val method: ProbeMethod = ProbeMethod.KURD_SESSION,
    val display: ProbeDisplay = ProbeDisplay.MILLISECONDS,
    val signedTargetId: CatalogId? = null,
    val timeoutSeconds: Int = 3,
) {
    init { requireSetting(timeoutSeconds in 1..30, SettingsField.PROBE_TIMEOUT, "OUT_OF_RANGE") }
    fun validated(): ProbePreferences {
        requireSetting(timeoutSeconds in 1..30, SettingsField.PROBE_TIMEOUT, "OUT_OF_RANGE")
        return this
    }
    fun validatedAgainst(signedTargets: Set<CatalogId>, signedMethods: Set<ProbeMethod>, nativeMethods: Set<ProbeMethod>): ProbePreferences {
        validated()
        require(signedTargets.size <= 256 && signedTargetId != null && signedTargetId in signedTargets)
        require(method in signedMethods && method in nativeMethods)
        return this
    }
    override fun toString(): String = "ProbePreferences(redacted)"
}

data class DiagnosticPreferences(
    val level: DiagnosticLogLevel = DiagnosticLogLevel.WARNING,
    val retention: DiagnosticRetention = DiagnosticRetention.ONE_DAY,
)

data class ExpertPreferences(
    val idleTimeoutSeconds: Int = 300,
    val tcpConnectionLimit: Int = 256,
    val udpConnectionLimit: Int = 128,
    val memoryLimitMb: Int = 80,
) {
    init {
        requireSetting(idleTimeoutSeconds in 30..3600, SettingsField.IDLE_TIMEOUT, "OUT_OF_RANGE")
        requireSetting(tcpConnectionLimit in 16..4096, SettingsField.TCP_LIMIT, "OUT_OF_RANGE")
        requireSetting(udpConnectionLimit in 0..2048, SettingsField.UDP_LIMIT, "OUT_OF_RANGE")
        requireSetting(memoryLimitMb == 0 || memoryLimitMb in 40..512, SettingsField.MEMORY_LIMIT, "OUT_OF_RANGE")
    }
    fun validated(): ExpertPreferences {
        requireSetting(idleTimeoutSeconds in 30..3600, SettingsField.IDLE_TIMEOUT, "OUT_OF_RANGE")
        requireSetting(tcpConnectionLimit in 16..4096, SettingsField.TCP_LIMIT, "OUT_OF_RANGE")
        requireSetting(udpConnectionLimit in 0..2048, SettingsField.UDP_LIMIT, "OUT_OF_RANGE")
        requireSetting(memoryLimitMb == 0 || memoryLimitMb in 40..512, SettingsField.MEMORY_LIMIT, "OUT_OF_RANGE")
        return this
    }
}

class ProfilePreferences(
    val activeLocalRecordId: String? = null,
    favoriteLocalRecordIds: Set<String> = emptySet(),
) {
    init { require(favoriteLocalRecordIds.size <= 1024) }
    val favoriteLocalRecordIds: Set<String> = java.util.Collections.unmodifiableSet(favoriteLocalRecordIds.toSet())
    fun copy(activeLocalRecordId: String? = this.activeLocalRecordId, favoriteLocalRecordIds: Set<String> = this.favoriteLocalRecordIds): ProfilePreferences = ProfilePreferences(activeLocalRecordId, favoriteLocalRecordIds)
    override fun equals(other: Any?): Boolean = other is ProfilePreferences && activeLocalRecordId == other.activeLocalRecordId && favoriteLocalRecordIds == other.favoriteLocalRecordIds
    override fun hashCode(): Int = listOf(activeLocalRecordId, favoriteLocalRecordIds).hashCode()
    override fun toString(): String = "ProfilePreferences(redacted)"
    fun validated(): ProfilePreferences {
        val values = favoriteLocalRecordIds + listOfNotNull(activeLocalRecordId)
        requireSetting(values.size <= 1024, SettingsField.PROFILE_IDENTIFIERS, "TOO_MANY")
        requireSetting(
            values.all { it.matches(Regex("[a-z0-9-]{1,64}")) },
            SettingsField.PROFILE_IDENTIFIERS,
            "INVALID_IDENTIFIER",
        )
        return copy(favoriteLocalRecordIds = favoriteLocalRecordIds.toSortedSet())
    }
}

data class ProductCapability(
    val id: String,
    val available: Boolean,
    val explanation: String,
)

data class ProductCapabilities(
    val vpnRuntime: ProductCapability,
    val publicRelay: ProductCapability,
    val providerNetworkUpdates: ProductCapability,
    val localProxy: ProductCapability,
    val hotspotProxy: ProductCapability,
)

enum class ProjectionStatus { VERIFIED, UNAVAILABLE, REVOKED, EXPIRED, INCOMPATIBLE }

data class InstalledApplication(
    val packageName: String,
    val label: String,
    val systemApp: Boolean,
)

sealed interface ProbeExecutionState {
    data object Idle : ProbeExecutionState
    data object Running : ProbeExecutionState
    data class Succeeded(val latencyMillis: Long) : ProbeExecutionState
    data class Failed(val category: OperationError) : ProbeExecutionState
}

enum class DiagnosticComponent { PROFILE, RUNTIME, STORAGE, UPDATE, PROBE, APP }

data class DiagnosticEvent(
    val sequence: Long,
    val level: DiagnosticLogLevel,
    val component: DiagnosticComponent,
    val category: String,
    val coarseEpochMinutes: Long = 0,
    val sessionAlias: String? = null,
    val metricValue: Long? = null,
) {
    init {
        require(sequence > 0)
        require(category.matches(Regex("[A-Z0-9_]{1,64}")))
        require(coarseEpochMinutes >= 0)
        require(sessionAlias == null || sessionAlias.matches(Regex("[a-z0-9-]{1,32}")))
    }
    override fun toString(): String = "DiagnosticEvent(redacted)"
}

/** Opt-in route suggestions only. Inclusion still requires signed bypass authority. */
val SAFE_EXCLUDED_ROUTES: List<String> = listOf(
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

fun ProductSettings.validated(): ProductSettings = copy(
    tunnel = tunnel.validated(),
    routing = routing.validated(),
    updates = updates.validated(),
    probes = probes.validated(),
    expert = expert.validated(),
    profiles = profiles.validated(),
)

private fun isValidPackageName(value: String): Boolean =
    value.length in 3..255 && value.split('.').size >= 2 &&
        value.split('.').all { segment ->
            segment.isNotEmpty() &&
                (segment.first().isLetter() || segment.first() == '_') &&
                segment.all { it.isLetterOrDigit() || it == '_' }
        }

private fun isValidIpLiteral(value: String): Boolean = canonicalizeIpLiteral(value) != null

internal fun canonicalizeIpLiteral(value: String): String? {
    val candidate = value.trim()
    if (candidate.isEmpty() || candidate.length > 45 || '%' in candidate || '[' in candidate || ']' in candidate) {
        return null
    }
    parseIpv4(candidate)?.let { bytes -> return bytes.joinToString(".") { (it.toInt() and 0xff).toString() } }
    return parseIpv6(candidate)?.let(::renderIpv6)
}

internal fun canonicalizeCidr(value: String): String? {
    val candidate = value.trim()
    val slash = candidate.indexOf('/')
    if (slash <= 0 || slash != candidate.lastIndexOf('/')) return null
    val address = candidate.substring(0, slash)
    val prefix = candidate.substring(slash + 1).toIntOrNull() ?: return null
    parseIpv4(address)?.let { bytes ->
        if (prefix !in 0..32) return null
        clearHostBits(bytes, prefix)
        return "${bytes.joinToString(".") { (it.toInt() and 0xff).toString() }}/$prefix"
    }
    parseIpv6(address)?.let { words ->
        if (prefix !in 0..128) return null
        val bytes = ByteArray(16)
        words.forEachIndexed { index, word ->
            bytes[index * 2] = (word ushr 8).toByte()
            bytes[index * 2 + 1] = word.toByte()
        }
        clearHostBits(bytes, prefix)
        val networkWords = IntArray(8) { index ->
            ((bytes[index * 2].toInt() and 0xff) shl 8) or (bytes[index * 2 + 1].toInt() and 0xff)
        }
        return "${renderIpv6(networkWords)}/$prefix"
    }
    return null
}

private fun clearHostBits(bytes: ByteArray, prefix: Int) {
    for (bit in prefix until bytes.size * 8) {
        val byteIndex = bit / 8
        val mask = 1 shl (7 - (bit % 8))
        bytes[byteIndex] = (bytes[byteIndex].toInt() and mask.inv()).toByte()
    }
}

internal fun parseIpv4(value: String): ByteArray? {
    val parts = value.split('.')
    if (parts.size != 4) return null
    val result = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.isEmpty() || part.length > 3 || part.any { !it.isDigit() }) return null
        if (part.length > 1 && part.first() == '0') return null
        val number = part.toIntOrNull() ?: return null
        if (number !in 0..255) return null
        result[index] = number.toByte()
    }
    return result
}

internal fun parseIpv6(value: String): IntArray? {
    if (value.isEmpty() || value.any { !(it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.') }) {
        return null
    }
    var candidate = value.lowercase()
    if ('.' in candidate) {
        val separator = candidate.lastIndexOf(':')
        if (separator < 0) return null
        val tail = parseIpv4(candidate.substring(separator + 1)) ?: return null
        val high = ((tail[0].toInt() and 0xff) shl 8) or (tail[1].toInt() and 0xff)
        val low = ((tail[2].toInt() and 0xff) shl 8) or (tail[3].toInt() and 0xff)
        candidate = candidate.substring(0, separator + 1) + high.toString(16) + ":" + low.toString(16)
    }
    if (candidate.indexOf("::") != candidate.lastIndexOf("::")) return null
    val compressed = "::" in candidate
    val halves = if (compressed) candidate.split("::", limit = 2) else listOf(candidate)
    fun groups(part: String): List<Int>? {
        if (part.isEmpty()) return emptyList()
        return part.split(':').map { group ->
            if (group.isEmpty() || group.length > 4) return null
            group.toIntOrNull(16) ?: return null
        }
    }
    val left = groups(halves[0]) ?: return null
    val right = if (compressed) groups(halves[1]) ?: return null else emptyList()
    if ((!compressed && left.size != 8) || (compressed && left.size + right.size >= 8)) return null
    val zeros = 8 - left.size - right.size
    return (left + List(zeros) { 0 } + right).toIntArray()
}

private fun renderIpv6(words: IntArray): String {
    var bestStart = -1
    var bestLength = 0
    var index = 0
    while (index < words.size) {
        if (words[index] != 0) {
            index++
            continue
        }
        val start = index
        while (index < words.size && words[index] == 0) index++
        val length = index - start
        if (length >= 2 && length > bestLength) {
            bestStart = start
            bestLength = length
        }
    }
    val output = StringBuilder()
    index = 0
    while (index < words.size) {
        if (index == bestStart) {
            output.append("::")
            index += bestLength
            continue
        }
        if (output.isNotEmpty() && output.last() != ':') output.append(':')
        output.append(words[index].toString(16))
        index++
    }
    return output.ifEmpty { "::" }.toString()
}
