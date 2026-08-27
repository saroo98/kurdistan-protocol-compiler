// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

import org.kurdistanvpn.core.model.RuntimeAvailability
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.SelectionMode

data class UnavailableRuntime(
    val reason: RuntimeAvailability = RuntimeAvailability.PHASE_9_NO_RUNTIME,
)

enum class VpnRuntimeState {
    IDLE,
    PREPARING,
    AWAITING_VPN_CONSENT,
    CONNECTING,
    ACTIVE_LOCAL_ONLY,
    ACTIVE_KURD_LOOPBACK,
    ACTIVE_KURD_LIVE,
    DEGRADED,
    FALLING_BACK,
    RECONNECTING,
    STOPPING,
    RECOVERING,
    BLOCKED,
    REVOKED,
    FAILED,
}

data class VpnRuntimeSnapshot(
    val state: VpnRuntimeState = VpnRuntimeState.IDLE,
    val packetsRead: Long = 0,
    val packetsWritten: Long = 0,
    val alwaysOn: Boolean = false,
    val lockdown: Boolean = false,
    val failure: String? = null,
    val packetDisposition: String? = null,
    val perAppRoutingMode: PerAppRoutingMode = PerAppRoutingMode.ALL_APPS,
    val startedAtElapsedRealtime: Long = 0,
    val dnsMode: DnsMode = DnsMode.INTERNAL_TUN,
    val ipMode: IpMode = IpMode.AUTO,
    val mtu: Int = 1500,
    val profileGeneration: Long = 0,
    val planDigest: String? = null,
    val profileFingerprint: String? = null,
    val strategyFingerprint: String? = null,
    val relayFingerprint: String? = null,
    val maxReconnectAttempts: Int = 0,
    val runtimeRequestId: String? = null,
    val diagnostics: VpnRuntimeDiagnostics = VpnRuntimeDiagnostics(),
)

data class VpnRuntimeDiagnostics(
    val tunPacketsRead: Long = 0,
    val outboundPacketsAccepted: Long = 0,
    val carrierRecordsWritten: Long = 0,
    val carrierRecordsRead: Long = 0,
    val authenticatedOperations: Long = 0,
    val innerPacketsAccepted: Long = 0,
    val innerPacketsRejected: Long = 0,
    val tunWriteAttempts: Long = 0,
    val tunWriteFailures: Long = 0,
    val tunWriteFailureCode: Long = 0,
    val tunWriteErrno: Long = 0,
    val tunPacketsWritten: Long = 0,
    val rejectedTunPackets: Long = 0,
    val rejectedTunPacketCode: Long = 0,
)

/** Sanitizes display data only. No status message is an authority or traffic proof. */
fun VpnRuntimeSnapshot.validatedForDisplay(): VpnRuntimeSnapshot {
    val digests = listOf(planDigest, profileFingerprint, strategyFingerprint, relayFingerprint)
    val counters = listOf(packetsRead, packetsWritten, diagnostics.tunPacketsRead, diagnostics.outboundPacketsAccepted,
        diagnostics.carrierRecordsWritten, diagnostics.carrierRecordsRead, diagnostics.authenticatedOperations,
        diagnostics.innerPacketsAccepted, diagnostics.innerPacketsRejected, diagnostics.tunWriteAttempts,
        diagnostics.tunWriteFailures, diagnostics.tunWriteFailureCode, diagnostics.tunWriteErrno,
        diagnostics.tunPacketsWritten, diagnostics.rejectedTunPackets, diagnostics.rejectedTunPacketCode)
    val wellFormed = counters.all { it >= 0 } && mtu in 1280..1500 && maxReconnectAttempts in 0..5 &&
        profileGeneration >= 0 && startedAtElapsedRealtime >= 0 &&
        (failure == null || failure.matches(Regex("[A-Z][A-Z0-9_]{0,63}"))) &&
        (packetDisposition == null || packetDisposition.matches(Regex("[A-Z][A-Z0-9_]{0,63}"))) &&
        (runtimeRequestId == null || RuntimeAuthorityLimits.validId(runtimeRequestId)) &&
        digests.all { it == null || it.matches(Regex("[0-9a-f]{64}")) }
    val completeActive = state != VpnRuntimeState.ACTIVE_KURD_LIVE ||
        (runtimeRequestId != null && startedAtElapsedRealtime > 0 && profileGeneration > 0 &&
            digests.all { it != null } && failure == null)
    return if (wellFormed && completeActive) this else VpnRuntimeSnapshot(state = VpnRuntimeState.BLOCKED,
        alwaysOn = alwaysOn, lockdown = lockdown, failure = "INVALID_RUNTIME_STATUS")
}

data class VpnRuntimeConfig(
    val routingPolicy: VpnRoutingPolicy,
    val selectionMode: SelectionMode = SelectionMode.AUTOMATIC,
    val manualStrategyId: String = "",
    val ipMode: IpMode = IpMode.AUTO,
    val dnsMode: DnsMode = DnsMode.INTERNAL_TUN,
    val customDns: String = "",
    val mtu: Int = 1500,
    val metered: Boolean = false,
    val allowLan: Boolean = false,
) {
    fun validatedForLiveTransport(): VpnRuntimeConfig {
        routingPolicy.validate()
        require(mtu in 1280..1500) { "INVALID_MTU" }
        require(ipMode in setOf(IpMode.AUTO, IpMode.IPV4_ONLY, IpMode.IPV6_ONLY, IpMode.DUAL_STACK)) {
            "INVALID_IP_MODE"
        }
        when (dnsMode) {
            DnsMode.INTERNAL_TUN -> require(customDns.isBlank()) { "UNEXPECTED_CUSTOM_DNS" }
            DnsMode.CUSTOM -> require(isNumericAddress(customDns)) { "INVALID_CUSTOM_DNS" }
            else -> require(false) { "EXTERNAL_DNS_REQUIRES_PROFILE_AUTHORITY" }
        }
        require(!allowLan) { "LAN_POLICY_NOT_IMPLEMENTED" }
        if (selectionMode == SelectionMode.MANUAL_STRATEGY) {
            require(manualStrategyId.matches(Regex("[!-~]{1,256}"))) {
                "INVALID_MANUAL_STRATEGY"
            }
        } else {
            require(manualStrategyId.isBlank()) { "UNEXPECTED_MANUAL_STRATEGY" }
        }
        return copy(
            routingPolicy = routingPolicy.validate(),
            manualStrategyId = manualStrategyId.trim(),
            customDns = customDns.trim(),
        )
    }

    /** Historical Phase 11 compatibility. Current release code uses [validatedForLiveTransport]. */
    fun validatedForLoopbackTransport(): VpnRuntimeConfig {
        val validated = validatedForLiveTransport()
        require(validated.ipMode != IpMode.IPV6_ONLY && validated.ipMode != IpMode.DUAL_STACK) {
            "IPV6_NOT_AVAILABLE"
        }
        require(validated.dnsMode == DnsMode.INTERNAL_TUN && validated.customDns.isBlank()) {
            "EXTERNAL_DNS_REQUIRES_RELAY_EGRESS"
        }
        return validated
    }

    private fun isNumericAddress(value: String): Boolean {
        val candidate = value.trim()
        if (candidate.isEmpty()) return false
        if (':' in candidate) {
            if (candidate.any { it !in '0'..'9' && it.lowercaseChar() !in 'a'..'f' && it != ':' }) {
                return false
            }
            return runCatching { java.net.InetAddress.getByName(candidate).address.size == 16 }
                .getOrDefault(false)
        }
        val parts = candidate.split('.')
        return parts.size == 4 && parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) &&
                (part == "0" || !part.startsWith('0')) && part.toIntOrNull() in 0..255
        }
    }
}

object VpnRuntimeContract {
    const val ACTION_START = "org.kurdistanvpn.runtime.action.START"
    const val ACTION_STOP = "org.kurdistanvpn.runtime.action.STOP"
    const val ACTION_QUERY_STATUS = "org.kurdistanvpn.runtime.action.QUERY_STATUS"
    const val ACTION_STATUS = "org.kurdistanvpn.runtime.action.STATUS"
    const val EXTRA_STATE = "state"
    const val EXTRA_PACKETS = "packets"
    const val EXTRA_PACKETS_WRITTEN = "packets_written"
    const val EXTRA_ALWAYS_ON = "always_on"
    const val EXTRA_LOCKDOWN = "lockdown"
    const val EXTRA_FAILURE = "failure"
    const val EXTRA_PACKET_DISPOSITION = "packet_disposition"
    const val EXTRA_PER_APP_MODE = "per_app_mode"
    const val EXTRA_PACKAGES = "packages"
    const val EXTRA_IP_MODE = "ip_mode"
    const val EXTRA_DNS_MODE = "dns_mode"
    const val EXTRA_CUSTOM_DNS = "custom_dns"
    const val EXTRA_MTU = "mtu"
    const val EXTRA_METERED = "metered"
    const val EXTRA_ALLOW_LAN = "allow_lan"
    const val EXTRA_STARTED_AT = "started_at_elapsed_realtime"
    const val EXTRA_AUTHORITY_REQUEST = "authority_request"
    const val EXTRA_RUNTIME_REQUEST = "runtime_request"
    const val EXTRA_STATUS_QUERY = "status_query"
    const val EXTRA_PLAN_DIGEST = "plan_digest"
    const val EXTRA_PROFILE_GENERATION = "profile_generation"
    const val EXTRA_PROFILE_FINGERPRINT = "profile_fingerprint"
    const val EXTRA_STRATEGY_FINGERPRINT = "strategy_fingerprint"
    const val EXTRA_RELAY_FINGERPRINT = "relay_fingerprint"
    const val EXTRA_MAX_RECONNECT_ATTEMPTS = "max_reconnect_attempts"
    const val EXTRA_DIAGNOSTIC_TUN_READ = "diagnostic_tun_read"
    const val EXTRA_DIAGNOSTIC_OUTBOUND = "diagnostic_outbound"
    const val EXTRA_DIAGNOSTIC_CARRIER_WRITE = "diagnostic_carrier_write"
    const val EXTRA_DIAGNOSTIC_CARRIER_READ = "diagnostic_carrier_read"
    const val EXTRA_DIAGNOSTIC_AUTHENTICATED = "diagnostic_authenticated"
    const val EXTRA_DIAGNOSTIC_INNER_ACCEPTED = "diagnostic_inner_accepted"
    const val EXTRA_DIAGNOSTIC_INNER_REJECTED = "diagnostic_inner_rejected"
    const val EXTRA_DIAGNOSTIC_TUN_ATTEMPTS = "diagnostic_tun_attempts"
    const val EXTRA_DIAGNOSTIC_TUN_FAILURES = "diagnostic_tun_failures"
    const val EXTRA_DIAGNOSTIC_TUN_FAILURE_CODE = "diagnostic_tun_failure_code"
    const val EXTRA_DIAGNOSTIC_TUN_ERRNO = "diagnostic_tun_errno"
    const val EXTRA_DIAGNOSTIC_TUN_WRITTEN = "diagnostic_tun_written"
    const val EXTRA_DIAGNOSTIC_REJECTED = "diagnostic_rejected"
    const val EXTRA_DIAGNOSTIC_REJECTION_CODE = "diagnostic_rejection_code"
}
