// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

enum class SelectionMode { AUTOMATIC, KURD_ONLY, MANUAL_STRATEGY }

enum class IpMode { AUTO, IPV4_ONLY, IPV6_ONLY, DUAL_STACK }

enum class DnsMode { INTERNAL_TUN, CLOUDFLARE_GOOGLE, GOOGLE, CLOUDFLARE, QUAD9, CUSTOM }

enum class ProbeMethod { KURD_SESSION, TCP_CONNECT, HTTP_HEAD, HTTP_GET, ICMP }

enum class ProbeDisplay { MILLISECONDS, HEALTH_DOTS }

enum class DiagnosticLogLevel { NONE, ERROR, WARNING, INFO, DEBUG }

enum class DiagnosticRetention { ONE_HOUR, SIX_HOURS, ONE_DAY, SEVEN_DAYS }

enum class ResetScope { SETTINGS, PROFILES_PROVIDERS, ROUTING, DIAGNOSTICS, EVERYTHING }

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
    val autoConnectOnBoot: Boolean = false,
    val reconnectOnFailure: Boolean = false,
    val killSwitchRequested: Boolean = false,
    val allowLan: Boolean = false,
    val connectOnlyOnUntrustedNetworks: Boolean = false,
)

data class TunnelPreferences(
    val ipMode: IpMode = IpMode.AUTO,
    val dnsMode: DnsMode = DnsMode.INTERNAL_TUN,
    val customDns: String = "",
    val mtu: Int = 1500,
    val metered: Boolean = false,
    val showSpeedInNotification: Boolean = false,
) {
    fun validated(): TunnelPreferences {
        requireSetting(mtu in 1280..1500, SettingsField.TUNNEL_MTU, "OUT_OF_RANGE")
        if (dnsMode == DnsMode.CUSTOM) {
            requireSetting(isValidIpLiteral(customDns), SettingsField.CUSTOM_DNS, "INVALID_IP_LITERAL")
        } else {
            requireSetting(customDns.isBlank(), SettingsField.CUSTOM_DNS, "UNEXPECTED_VALUE")
        }
        return copy(customDns = customDns.trim().let { if (it.isBlank()) it else canonicalizeIpLiteral(it)!! })
    }
}

data class RoutingPreferences(
    val mode: PerAppSelectionMode = PerAppSelectionMode.ALL_APPS,
    val packages: Set<String> = emptySet(),
    val excludedCidrs: List<String> = SAFE_EXCLUDED_ROUTES,
) {
    fun validatedMetadata(): RoutingPreferences {
        requireSetting(packages.size <= 64, SettingsField.ROUTING_PACKAGES, "TOO_MANY")
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
}

data class UpdatePreferences(
    val automatic: Boolean = false,
    val intervalHours: Int = 2,
    val onLaunch: Boolean = false,
    val notifyOnChange: Boolean = true,
    val probeAfterUpdate: Boolean = false,
) {
    fun validated(): UpdatePreferences {
        requireSetting(intervalHours in 1..168, SettingsField.UPDATE_INTERVAL, "OUT_OF_RANGE")
        return this
    }
}

data class ProbePreferences(
    val method: ProbeMethod = ProbeMethod.KURD_SESSION,
    val display: ProbeDisplay = ProbeDisplay.MILLISECONDS,
    val testUrl: String = "",
    val timeoutSeconds: Int = 3,
) {
    fun validated(): ProbePreferences {
        requireSetting(timeoutSeconds in 1..30, SettingsField.PROBE_TIMEOUT, "OUT_OF_RANGE")
        if (method == ProbeMethod.HTTP_GET || method == ProbeMethod.HTTP_HEAD) {
            requireSetting(isValidHttpsProbeUrl(testUrl), SettingsField.PROBE_URL, "INVALID_HTTPS_URL")
        }
        return copy(testUrl = testUrl.trim())
    }
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
    fun validated(): ExpertPreferences {
        requireSetting(idleTimeoutSeconds in 30..3600, SettingsField.IDLE_TIMEOUT, "OUT_OF_RANGE")
        requireSetting(tcpConnectionLimit in 16..4096, SettingsField.TCP_LIMIT, "OUT_OF_RANGE")
        requireSetting(udpConnectionLimit in 0..2048, SettingsField.UDP_LIMIT, "OUT_OF_RANGE")
        requireSetting(memoryLimitMb == 0 || memoryLimitMb in 40..512, SettingsField.MEMORY_LIMIT, "OUT_OF_RANGE")
        return this
    }
}

data class ProfilePreferences(
    val activeLocalRecordId: String? = null,
    val favoriteLocalRecordIds: Set<String> = emptySet(),
) {
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

data class OperatorClientProjection(
    val providerAlias: String,
    val publicationGeneration: ULong?,
    val profileGeneration: ULong?,
    val profileExpiryEpochSeconds: Long?,
    val relayCompatibility: ProjectionStatus,
    val rotationState: ProjectionStatus,
    val updateCapability: ProjectionStatus,
    val lastVerifiedUpdateCategory: String?,
    val emergencyDenyState: ProjectionStatus,
) {
    init {
        require(providerAlias.length in 1..96)
        require(lastVerifiedUpdateCategory == null || lastVerifiedUpdateCategory.matches(Regex("[A-Z0-9_]{1,64}")))
    }
}

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
}

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

fun Phase9Settings.validated(): Phase9Settings = copy(
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

private fun canonicalizeIpLiteral(value: String): String? {
    val candidate = value.trim()
    if (candidate.isEmpty() || candidate.length > 45 || '%' in candidate || '[' in candidate || ']' in candidate) {
        return null
    }
    parseIpv4(candidate)?.let { bytes -> return bytes.joinToString(".") { (it.toInt() and 0xff).toString() } }
    return parseIpv6(candidate)?.let(::renderIpv6)
}

private fun canonicalizeCidr(value: String): String? {
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

private fun parseIpv4(value: String): ByteArray? {
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

private fun parseIpv6(value: String): IntArray? {
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

private fun isValidHttpsProbeUrl(value: String): Boolean {
    val candidate = value.trim()
    if (candidate.length !in 9..2048 || !candidate.startsWith("https://")) return false
    val authority = candidate.substringAfter("https://").substringBefore('/').substringBefore('?').substringBefore('#')
    if (authority.isEmpty() || '@' in authority || authority.any { it.isWhitespace() }) return false
    val host = authority.substringBeforeLast(':', authority)
    if (host.isEmpty() || host.length > 253) return false
    return host == "localhost" || isValidIpLiteral(host) || host.split('.').all { label ->
        label.length in 1..63 && label.first().isLetterOrDigit() && label.last().isLetterOrDigit() &&
            label.all { it.isLetterOrDigit() || it == '-' }
    }
}
