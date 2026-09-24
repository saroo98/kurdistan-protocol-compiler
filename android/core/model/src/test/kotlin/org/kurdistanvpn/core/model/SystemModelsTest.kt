// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import org.junit.Assert.*
import org.junit.Test

class SystemModelsTest {

    @Test fun defaultProxyBudgetUsesAdmittedCapacityWithoutWideningExplicitRequests() {
        val authority = ProxyLimits(16, 64, 3600, 128)
        assertEquals(64, LocalProxyPreferences().limits.narrowedBy(authority, authority).memoryMiB)
        assertEquals(48, LocalProxyPreferences().limits.narrowedBy(authority.copy(memoryMiB = 48), authority).memoryMiB)
        assertEquals(32, ProxyLimits(memoryMiB = 32).narrowedBy(authority, authority).memoryMiB)
    }
    @Test fun redactedNetworkIdentityIsUntrustedAndRuleIdsAreImmutable() {
        val id = CatalogId("rule-1")
        val ids = mutableSetOf(id)
        val policy = NetworkTrustPreferences(true, ids)
        ids.clear()
        assertFalse(policy.isTrusted(NetworkIdentityCategory.UNKNOWN, id))
        assertFalse(policy.isTrusted(NetworkIdentityCategory.REDACTED, id))
        assertTrue(policy.isTrusted(NetworkIdentityCategory.KNOWN, id))
        assertFalse(policy.isTrusted(NetworkIdentityCategory.KNOWN, CatalogId("other")))
        assertThrows(UnsupportedOperationException::class.java) { (policy.protectedRuleIds as MutableSet).clear() }
    }

    @Test fun historyAndDiagnosticBudgetsEnforceBothTimeAndCountBounds() {
        val sample = ProbeSample(100, 20, 3, 0, ProbeStability.STABLE, null)
        assertEquals(listOf(sample), ProbeHistory(listOf(sample), 101).samples)
        assertThrows(IllegalArgumentException::class.java) { ProbeHistory(List(201) { sample }, 101) }
        assertThrows(IllegalArgumentException::class.java) { ProbeHistory(listOf(sample), 100 + 30 * 24 * 60 + 1) }
        assertThrows(IllegalArgumentException::class.java) { ProbeHistory(listOf(sample), 99) }
        assertThrows(IllegalArgumentException::class.java) { ProbeSample(100, 30001, 0, 0, ProbeStability.UNKNOWN, null) }
        assertThrows(IllegalArgumentException::class.java) { DiagnosticBudget(maximumEvents = 4097) }
        assertThrows(IllegalArgumentException::class.java) { DiagnosticBudget(maximumBytes = 2 * 1024 * 1024 + 1) }
    }

    @Test fun proxyLimitsRejectOutOfRangeAndNarrowToBothAuthorities() {
        assertThrows(IllegalArgumentException::class.java) { LocalProxyPreferences(socksPort = 1023) }
        assertThrows(IllegalArgumentException::class.java) { LocalProxyPreferences(httpConnectPort = 65536) }
        assertThrows(IllegalArgumentException::class.java) { LocalProxyPreferences(httpConnectPort = 10808) }
        listOf(0, 17).forEach { assertThrows(IllegalArgumentException::class.java) { ProxyLimits(clients = it) } }
        listOf(0, 65).forEach { assertThrows(IllegalArgumentException::class.java) { ProxyLimits(streams = it) } }
        listOf(29, 3601).forEach { assertThrows(IllegalArgumentException::class.java) { ProxyLimits(idleSeconds = it) } }
        listOf(15, 129).forEach { assertThrows(IllegalArgumentException::class.java) { ProxyLimits(memoryMiB = it) } }
        val request = ProxyLimits(16, 64, 3600, 128)
        assertEquals(ProxyLimits(2, 5, 40, 16), request.narrowedBy(ProxyLimits(2, 8, 40, 24), ProxyLimits(4, 5, 60, 16)))
        assertEquals(setOf(LoopbackBinding.IPV4, LoopbackBinding.IPV6), LocalProxyPreferences().bindings)
    }

    @Test fun meteredOverrideIsOnlyForLiveConnectAndUnavailableModesFailClosed() {
        assertTrue(NetworkMeteredPolicy.WAIT_FOR_UNMETERED.permits(true, true, true))
        assertFalse(NetworkMeteredPolicy.WAIT_FOR_UNMETERED.permits(true, false, true))
        assertFalse(NetworkMeteredPolicy.ASK.permits(true, true, false))
        assertTrue(NetworkMeteredPolicy.WAIT_FOR_UNMETERED.permits(false, false, false))
        assertFalse(TunnelMode.PROXY_ONLY.isAvailable(setOf(TunnelMode.TUN_ONLY)))
    }

    @Test fun pauseAndReconnectRequireCurrentBoundedAuthority() {
        assertFalse(PausePolicy.UNTIL_RESUMED.permitsAutoConnect)
        assertTrue(PausePolicy.NOT_PAUSED.permitsAutoConnect)
        assertEquals(2, ReconnectPreferences(enabled = true, requestedMaximum = 8).effectiveMaximum(3, 2))
        assertEquals(0, ReconnectPreferences().effectiveMaximum(3, 2))
        assertEquals(0, ReconnectPreferences(enabled = true).effectiveMaximum(0, 4))
        listOf(0, 11).forEach { assertThrows(IllegalArgumentException::class.java) { ReconnectPreferences(requestedMaximum = it) } }
        assertThrows(IllegalArgumentException::class.java) { ReconnectPreferences().effectiveMaximum(-1, 1) }
    }
}
