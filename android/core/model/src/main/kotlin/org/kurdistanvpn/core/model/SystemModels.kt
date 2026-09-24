// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import java.util.Collections

enum class NetworkIdentityCategory { KNOWN, UNKNOWN, REDACTED }
class NetworkTrustPreferences(val enabled: Boolean = false, protectedRuleIds: Set<CatalogId> = emptySet()) {
    init { require(protectedRuleIds.size <= 256) }
    val protectedRuleIds: Set<CatalogId> = Collections.unmodifiableSet(protectedRuleIds.toSet())
    fun isTrusted(identity: NetworkIdentityCategory, matchingRule: CatalogId?): Boolean =
        enabled && identity == NetworkIdentityCategory.KNOWN && matchingRule in protectedRuleIds
    fun copy(enabled: Boolean = this.enabled, protectedRuleIds: Set<CatalogId> = this.protectedRuleIds): NetworkTrustPreferences =
        NetworkTrustPreferences(enabled, protectedRuleIds)
    override fun equals(other: Any?): Boolean = other is NetworkTrustPreferences && enabled == other.enabled && protectedRuleIds == other.protectedRuleIds
    override fun hashCode(): Int = 31 * enabled.hashCode() + protectedRuleIds.hashCode()
    override fun toString(): String = "NetworkTrustPreferences(redacted)"
}

enum class ProbeStability { UNKNOWN, STABLE, UNSTABLE }
data class ProbeSample(val coarseEpochMinutes: Long, val latencyMillis: Int, val jitterMillis: Int,
    val lossBasisPoints: Int, val stability: ProbeStability, val failure: ProductFailureCode?,
    val method: ProbeMethod = ProbeMethod.KURD_SESSION,
) {
    init { require(coarseEpochMinutes >= 0 && latencyMillis in 0..30000 && jitterMillis in 0..30000 && lossBasisPoints in 0..10000) }
}
class ProbeHistory(samples: List<ProbeSample>, val currentEpochMinutes: Long) {
    init {
        require(samples.size <= 200 && currentEpochMinutes >= 0)
        require(samples.all { it.coarseEpochMinutes <= currentEpochMinutes && currentEpochMinutes - it.coarseEpochMinutes <= 30 * 24 * 60 })
    }
    val samples: List<ProbeSample> = Collections.unmodifiableList(samples.toList())
    fun copy(samples: List<ProbeSample> = this.samples, currentEpochMinutes: Long = this.currentEpochMinutes): ProbeHistory = ProbeHistory(samples, currentEpochMinutes)
    override fun equals(other: Any?): Boolean = other is ProbeHistory && samples == other.samples && currentEpochMinutes == other.currentEpochMinutes
    override fun hashCode(): Int = 31 * samples.hashCode() + currentEpochMinutes.hashCode()
    override fun toString(): String = "ProbeHistory(redacted)"
}
data class DiagnosticBudget(val maximumEvents: Int = 4096, val maximumBytes: Int = 2 * 1024 * 1024) {
    init { require(maximumEvents in 1..4096 && maximumBytes in 1..(2 * 1024 * 1024)) }
}

enum class TunnelMode {
    TUN_ONLY, TUN_PLUS_PROXY, PROXY_ONLY;
    fun isAvailable(admittedModes: Set<TunnelMode>): Boolean = this in admittedModes
}

enum class NetworkMeteredPolicy {
    ALLOW, ASK, WAIT_FOR_UNMETERED;
    fun permits(metered: Boolean, liveUserConnect: Boolean, confirmedOverride: Boolean): Boolean =
        !metered || this == ALLOW || (liveUserConnect && confirmedOverride)
}

enum class PausePolicy {
    NOT_PAUSED, UNTIL_RESUMED;
    val permitsAutoConnect: Boolean get() = this == NOT_PAUSED
}

enum class LoopbackBinding { IPV4, IPV6 }

data class NotificationPreferences(val showSpeed: Boolean = false, val notifyOnUpdates: Boolean = true)

data class ProxyLimits(
    val clients: Int = 4,
    val streams: Int = 16,
    val idleSeconds: Int = 300,
    val memoryMiB: Int = 64,
) {
    init {
        require(clients in 1..16)
        require(streams in 1..64)
        require(idleSeconds in 30..3600)
        require(memoryMiB in 16..128)
    }

    fun narrowedBy(signed: ProxyLimits, native: ProxyLimits): ProxyLimits = ProxyLimits(
        minOf(clients, signed.clients, native.clients),
        minOf(streams, signed.streams, native.streams),
        minOf(idleSeconds, signed.idleSeconds, native.idleSeconds),
        minOf(memoryMiB, signed.memoryMiB, native.memoryMiB),
    )
}

data class LocalProxyPreferences(
    val socksPort: Int = 10808,
    val httpConnectPort: Int = 10809,
    val limits: ProxyLimits = ProxyLimits(),
) {
    init {
        require(socksPort in 1024..65535)
        require(httpConnectPort in 1024..65535)
        require(socksPort != httpConnectPort)
    }
    // No address-string constructor can turn a local proxy into a non-loopback listener.
    val bindings: Set<LoopbackBinding> get() =
        Collections.unmodifiableSet(setOf(LoopbackBinding.IPV4, LoopbackBinding.IPV6))
}

data class ReconnectPreferences(val enabled: Boolean = false, val requestedMaximum: Int = 3) {
    init { require(requestedMaximum in 1..10) }
    fun effectiveMaximum(signedMaximum: Int, nativeMaximum: Int): Int {
        require(signedMaximum >= 0 && nativeMaximum >= 0)
        return if (enabled) minOf(requestedMaximum, signedMaximum, nativeMaximum) else 0
    }
}
