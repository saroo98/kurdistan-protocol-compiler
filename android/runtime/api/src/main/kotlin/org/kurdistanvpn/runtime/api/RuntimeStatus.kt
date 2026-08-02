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
)

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
    fun validatedForLoopbackTransport(): VpnRuntimeConfig {
        routingPolicy.validate()
        require(mtu in 1280..1500) { "INVALID_MTU" }
        require(ipMode != IpMode.IPV6_ONLY && ipMode != IpMode.DUAL_STACK) {
            "IPV6_NOT_AVAILABLE"
        }
        require(dnsMode == DnsMode.INTERNAL_TUN && customDns.isBlank()) {
            "EXTERNAL_DNS_REQUIRES_RELAY_EGRESS"
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
        )
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
    const val EXTRA_PLAN_DIGEST = "plan_digest"
    const val EXTRA_PROFILE_GENERATION = "profile_generation"
    const val EXTRA_PROFILE_FINGERPRINT = "profile_fingerprint"
    const val EXTRA_STRATEGY_FINGERPRINT = "strategy_fingerprint"
    const val EXTRA_RELAY_FINGERPRINT = "relay_fingerprint"
}
