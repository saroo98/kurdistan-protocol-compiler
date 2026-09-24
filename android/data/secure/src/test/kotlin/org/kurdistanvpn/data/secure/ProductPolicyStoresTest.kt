// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class ProductPolicyStoresTest {
    @Test fun malformedPolicyFieldsAndSetOrderingFailClosed() {
        val lock = StoredAppLockState(1, false, emptySet(), 0, 0).encode()
        checkMalformed(lock, listOf({ putLong(it, 6, 0) }, { it[14] = 2 }, { putShort(it, 15, 3) },
            { it[17] = 11 }, { putLong(it, 18, -1) })) { StoredAppLockState.decode(it) }
        val both = StoredAppLockState(1, true, setOf(AllowedAuthenticator.STRONG_BIOMETRIC, AllowedAuthenticator.DEVICE_CREDENTIAL), 0, 0).encode()
        // DEVICE_CREDENTIAL = 17 bytes, STRONG_BIOMETRIC = 16 bytes, each with a two-byte length.
        val unsorted = both.copyOfRange(0, 17) + both.copyOfRange(36, 54) + both.copyOfRange(17, 36) + both.copyOfRange(54, both.size)
        assertThrows(IllegalArgumentException::class.java) { StoredAppLockState.decode(unsorted) }
        val proxy = StoredProxyPolicy(1, LocalProxyPreferences()).encode()
        checkMalformed(proxy, listOf({ putLong(it, 6, 0) }, { putInt(it, 14, 1023) }, { putInt(it, 18, 65536) },
            { putInt(it, 18, 10808) }, { putInt(it, 22, 17) }, { putInt(it, 26, 65) },
            { putInt(it, 30, 29) }, { putInt(it, 34, 129) })) { StoredProxyPolicy.decode(it) }
        val usage = StoredUsageAggregates(30, listOf(UsageAggregate(30, 0, 0, 0))).encode()
        checkMalformed(usage, listOf({ putLong(it, 6, -1) }, { putShort(it, 14, 31) }, { putLong(it, 16, 0) },
            { putLong(it, 16, 31) }, { putLong(it, 24, -1) }, { putLong(it, 32, -1) }, { putLong(it, 40, 86401) })) { StoredUsageAggregates.decode(it) }
        val ordered = StoredUsageAggregates(30, listOf(UsageAggregate(29, 0, 0, 0), UsageAggregate(30, 0, 0, 0))).encode()
        for (bad in listOf(ordered.copyOfRange(0, 16) + ordered.copyOfRange(48, 80) + ordered.copyOfRange(16, 48),
            ordered.clone().also { putLong(it, 48, 29) })) assertThrows(IllegalArgumentException::class.java) { StoredUsageAggregates.decode(bad) }
        val input = mutableSetOf(AllowedAuthenticator.STRONG_BIOMETRIC)
        val owned = StoredAppLockState(1, true, input, 0, 0); input.clear()
        assertEquals(setOf(AllowedAuthenticator.STRONG_BIOMETRIC), owned.allowedAuthenticators)
        assertEquals(listOf(30L), StoredUsageAggregates(30, listOf(UsageAggregate(1, 0, 0, 0), UsageAggregate(30, 0, 0, 0))).retained(1).entries.map { it.epochDay })
        assertThrows(IllegalArgumentException::class.java) { StoredUsageAggregates(0, emptyList()).retained(0) }
    }
    @Test fun policiesRoundTripAndUseExistingModelBounds() {
        val lock = StoredAppLockState(1, true, setOf(AllowedAuthenticator.STRONG_BIOMETRIC, AllowedAuthenticator.DEVICE_CREDENTIAL), 10, Long.MAX_VALUE)
        checkRecord(lock.encode(), 25, 1024) { StoredAppLockState.decode(it).encode() }
        val proxy = StoredProxyPolicy(1, LocalProxyPreferences())
        checkRecord(proxy.encode(), 28, 1024) { StoredProxyPolicy.decode(it).encode() }
        assertEquals(setOf(LoopbackBinding.IPV4, LoopbackBinding.IPV6), StoredProxyPolicy.decode(proxy.encode()).preferences.bindings)
        val usage = StoredUsageAggregates(30, listOf(UsageAggregate(30, Long.MAX_VALUE, 2, 86400), UsageAggregate(1, 0, 0, 0)))
        checkRecord(usage.encode(), 24, 2048) { StoredUsageAggregates.decode(it).encode() }
        assertThrows(ArithmeticException::class.java) { usage.entries.last().plus(UsageAggregate(30, 1, 0, 0)) }
        for (bad in listOf<() -> Any>({ StoredAppLockState(0, false, emptySet(), 0, 0) },
            { StoredAppLockState(1, true, emptySet(), 0, 0) }, { StoredAppLockState(1, false, emptySet(), 11, 0) },
            { StoredProxyPolicy(0, LocalProxyPreferences()) }, { UsageAggregate(0, -1, 0, 0) },
            { UsageAggregate(0, 0, 0, 86401) }, { StoredUsageAggregates(30, listOf(UsageAggregate(0, 0, 0, 0))) },
            { StoredUsageAggregates(30, listOf(UsageAggregate(31, 0, 0, 0))) },
            { StoredUsageAggregates(1, listOf(UsageAggregate(1, 0, 0, 0), UsageAggregate(1, 0, 0, 0))) }))
            assertThrows(IllegalArgumentException::class.java) { bad() }
    }
    @Test fun policyWrapperContracts() {
        val lock = StoredAppLockState(1, false, emptySet(), 0, 0)
        checkStore("app-lock-current", SecureDataClass.APP_LOCK_STATE, lock.encode(),
            { AppLockStateStore(it).save(lock) }, { AppLockStateStore(it).load()?.encode() }, { AppLockStateStore(it).delete() },
            { AppLockStateStore.readOnly(it).save(lock) }, { AppLockStateStore.readOnly(it).delete() })
        val proxy = StoredProxyPolicy(1, LocalProxyPreferences())
        checkStore("local-proxy-current", SecureDataClass.LOCAL_PROXY_POLICY, proxy.encode(),
            { LocalProxyPolicyStore(it).save(proxy) }, { LocalProxyPolicyStore(it).load()?.encode() }, { LocalProxyPolicyStore(it).delete() },
            { LocalProxyPolicyStore.readOnly(it).save(proxy) }, { LocalProxyPolicyStore.readOnly(it).delete() })
        val usage = StoredUsageAggregates(0, emptyList())
        checkStore("usage-aggregates-current", SecureDataClass.USAGE_AGGREGATES, usage.encode(),
            { UsageAggregatesStore(it).save(usage) }, { UsageAggregatesStore(it).load()?.encode() }, { UsageAggregatesStore(it).delete() },
            { UsageAggregatesStore.readOnly(it).save(usage) }, { UsageAggregatesStore.readOnly(it).delete() })
    }
}
