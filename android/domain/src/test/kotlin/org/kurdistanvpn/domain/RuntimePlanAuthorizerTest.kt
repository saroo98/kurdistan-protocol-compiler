// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class RuntimePlanAuthorizerTest {
    private val binding = RuntimeBinding(CatalogId("profile-a"), 7u, 3, 4, 5)
    private val strategy = CatalogId("kurd-tls")
    private val route = CanonicalRoute("0.0.0.0/0")
    private val dns = NumericAddress("10.0.0.53")

    private fun scope(
        routes: Set<CanonicalRoute> = setOf(route),
        strategies: Set<CatalogId> = setOf(strategy),
        resolvers: Set<ResolverConfiguration> = setOf(ResolverConfiguration.Internal),
        dnsAddresses: Set<NumericAddress> = setOf(dns),
        bypassable: Set<CanonicalRoute> = emptySet(),
    ) = SignedRuntimePlan(binding, setOf(IpFamily.IPV4), routes, dnsAddresses, strategies,
        strategies, resolvers, bypassable, setOf(TunnelMode.TUN_ONLY), 1280..1500, 3, ProxyLimits())

    private fun native(strategies: Set<CatalogId> = setOf(strategy)) = NativePlanCapabilities(
        setOf(IpFamily.IPV4), strategies, setOf(TunnelMode.TUN_ONLY), 1280..1400, 2, 64, ProxyLimits())

    private fun os(packages: Set<String> = setOf("org.example.app"), revision: Long = 5) =
        OsPlanCapabilities(setOf(IpFamily.IPV4), setOf(TunnelMode.TUN_ONLY), packages, revision)

    private inner class Boundary : RuntimeAuthorityBoundary {
        var signed = scope()
        var capabilities = native()
        var system = os()
        var failStage: String? = null
        var receiptForOtherPlan = false
        val calls = mutableListOf<String>()
        var received: NarrowedRuntimePlan? = null
        override fun validateSignedPlan(binding: RuntimeBinding): DomainResult<SignedRuntimePlan> {
            calls += "signed"
            return if (failStage == "signed") rejected(ProductFailureCode.PROFILE_REVOKED) else DomainResult.Success(signed)
        }
        override fun validateCompatibility(plan: SignedRuntimePlan): DomainResult<NativePlanCapabilities> {
            calls += "native"
            return if (failStage == "native") rejected(ProductFailureCode.PROFILE_INCOMPATIBLE) else DomainResult.Success(capabilities)
        }
        override fun validateOsCapability(binding: RuntimeBinding): DomainResult<OsPlanCapabilities> {
            calls += "os"
            return if (failStage == "os") rejected(ProductFailureCode.VPN_CONSENT_REQUIRED) else DomainResult.Success(system)
        }
        override fun canonicalDigest(plan: NarrowedRuntimePlan): DomainResult<CanonicalPlanReceipt> {
            calls += "digest"
            received = plan
            if (failStage == "digest") return rejected(ProductFailureCode.ROUTE_POLICY_REJECTED)
            return DomainResult.Success(CanonicalPlanReceipt(
                if (receiptForOtherPlan) NarrowedRuntimePlan(plan.binding, plan.ipMode, plan.routes,
                    plan.dnsAddresses, plan.strategies, plan.resolver, plan.routing, plan.tunnelMode,
                    plan.mtu, plan.reconnectMaximum, plan.proxy) else plan,
                "a".repeat(64),
            ))
        }
        fun authorize(settings: ProductSettings = ProductSettings(), revision: Long = 4) =
            RuntimePlanAuthorizer(this).authorize(binding, SettingsRevision(revision, settings))
    }

    private fun rejected(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
    private fun failure(result: DomainResult<*>): ProductFailureCode = (result as DomainResult.Rejected).failure.code

    @Test fun orderAndEffectiveValuesAreBoundToExactProjection() {
        val boundary = Boundary()
        val result = boundary.authorize(ProductSettings(connection = ConnectionPreferences(
            reconnectOnFailure = true, reconnectMaximum = 8))) as DomainResult.Success
        assertEquals(listOf("signed", "native", "os", "digest"), boundary.calls)
        assertSame(boundary.received, result.value.plan)
        assertEquals(binding, result.value.plan.binding)
        assertEquals(1400, result.value.plan.mtu)
        assertEquals(2, result.value.plan.reconnectMaximum)
        assertEquals(IpMode.IPV4_ONLY, result.value.plan.ipMode)
        assertEquals(setOf(route), result.value.plan.routes)
        assertEquals(setOf(dns), result.value.plan.dnsAddresses)
        assertEquals("a".repeat(64), result.value.canonicalDigest)
    }

    @Test fun eachFailedStagePreventsAllLaterStages() {
        val expected = listOf(
            Triple("signed", ProductFailureCode.PROFILE_REVOKED, listOf("signed")),
            Triple("native", ProductFailureCode.PROFILE_INCOMPATIBLE, listOf("signed", "native")),
            Triple("os", ProductFailureCode.VPN_CONSENT_REQUIRED, listOf("signed", "native", "os")),
            Triple("digest", ProductFailureCode.ROUTE_POLICY_REJECTED, listOf("signed", "native", "os", "digest")),
        )
        expected.forEach { (stage, code, calls) ->
            val boundary = Boundary().also { it.failStage = stage }
            assertEquals(code, failure(boundary.authorize()))
            assertEquals(calls, boundary.calls)
        }
    }

    @Test fun emptyRouteDnsAndStrategyIntersectionsNeverReachDigest() {
        listOf(
            scope(routes = emptySet()) to ProductFailureCode.ROUTE_POLICY_REJECTED,
            scope(dnsAddresses = emptySet()) to ProductFailureCode.DNS_POLICY_REJECTED,
            scope(strategies = emptySet()) to ProductFailureCode.NO_PERMITTED_STRATEGY,
        ).forEach { (signed, code) ->
            val boundary = Boundary().also { it.signed = signed }
            assertEquals(code, failure(boundary.authorize()))
            assertFalse(boundary.calls.contains("digest"))
        }
        val boundary = Boundary().also { it.capabilities = native(setOf(CatalogId("other"))) }
        assertEquals(ProductFailureCode.NO_PERMITTED_STRATEGY, failure(boundary.authorize()))
        assertFalse(boundary.calls.contains("digest"))
    }

    @Test fun unsupportedIpv6NeverSilentlyFallsBack() {
        for (mode in listOf(IpMode.IPV6_ONLY, IpMode.DUAL_STACK)) {
            val boundary = Boundary()
            assertEquals(ProductFailureCode.ROUTE_POLICY_REJECTED,
                failure(boundary.authorize(ProductSettings(tunnel = TunnelPreferences(ipMode = mode)))))
            assertFalse(boundary.calls.contains("digest"))
        }
    }

    @Test fun disallowedResolverAndUnsignedManualStrategyAreRejected() {
        val dnsBoundary = Boundary()
        assertEquals(ProductFailureCode.DNS_POLICY_REJECTED, failure(dnsBoundary.authorize(
            ProductSettings(tunnel = TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = "1.1.1.1")))))
        assertFalse(dnsBoundary.calls.contains("digest"))
        val strategyBoundary = Boundary()
        assertEquals(ProductFailureCode.NO_PERMITTED_STRATEGY, failure(strategyBoundary.authorize(
            ProductSettings(connection = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY,
                manualStrategyId = CatalogId("unsigned"))))))
        assertFalse(strategyBoundary.calls.contains("digest"))
    }

    @Test fun exclusionsCannotWidenBypassAuthorityOrRemoveAllRoutes() {
        for (excluded in listOf("0.0.0.0/0", "192.168.0.0/16")) {
            val boundary = Boundary().also { it.signed = scope(bypassable = setOf(CanonicalRoute("10.0.0.0/8"))) }
            assertEquals(ProductFailureCode.ROUTE_POLICY_REJECTED, failure(boundary.authorize(
                ProductSettings(routing = RoutingPreferences(excludedCidrs = listOf(excluded))))))
            assertFalse(boundary.calls.contains("digest"))
        }
        val boundary = Boundary().also { it.signed = scope(bypassable = setOf(route)) }
        assertEquals(ProductFailureCode.ROUTE_POLICY_REJECTED, failure(boundary.authorize(
            ProductSettings(routing = RoutingPreferences(excludedCidrs = listOf("0.0.0.0/0"))))))
        assertFalse(boundary.calls.contains("digest"))
    }

    @Test fun packageDriftNeverBecomesAllAppsOrSilentlyDropsSelectedPackages() {
        for (mode in listOf(PerAppSelectionMode.INCLUDE_ONLY, PerAppSelectionMode.EXCLUDE_SELECTED)) {
            val boundary = Boundary()
            assertEquals(ProductFailureCode.APP_POLICY_DRIFT, failure(boundary.authorize(
                ProductSettings(routing = RoutingPreferences(mode, setOf("org.missing.app"))))))
            assertFalse(boundary.calls.contains("digest"))
        }
        val boundary = Boundary().also { it.system = os(revision = 6) }
        assertEquals(ProductFailureCode.APP_POLICY_DRIFT, failure(boundary.authorize()))
    }

    @Test fun staleSettingsAndProfileTrustBindingAreRejected() {
        val settings = Boundary()
        assertEquals(ProductFailureCode.OPERATION_INTERRUPTED, failure(settings.authorize(revision = 3)))
        assertEquals(listOf("signed", "native", "os"), settings.calls)
        val otherBinding = binding.copy(trustRevision = 2)
        val signed = Boundary().also {
            it.signed = SignedRuntimePlan(otherBinding, setOf(IpFamily.IPV4), setOf(route), setOf(dns),
                setOf(strategy), setOf(strategy), setOf(ResolverConfiguration.Internal), emptySet(),
                setOf(TunnelMode.TUN_ONLY), 1280..1500, 3, ProxyLimits())
        }
        assertEquals(ProductFailureCode.PROFILE_UNTRUSTED, failure(signed.authorize()))
        assertEquals(listOf("signed"), signed.calls)
    }

    @Test fun wrongDigestReceiptCannotBeAttachedToAnEquivalentOrDifferentPlan() {
        val boundary = Boundary().also { it.receiptForOtherPlan = true }
        assertEquals(ProductFailureCode.INTERNAL_FAILURE, failure(boundary.authorize()))
    }

    @Test fun authorityCollectionsAndResultResistCallerMutation() {
        val routes = mutableSetOf(route)
        val strategies = mutableSetOf(strategy)
        val boundary = Boundary().also { it.signed = scope(routes = routes, strategies = strategies) }
        routes.clear()
        strategies.clear()
        val result = (boundary.authorize() as DomainResult.Success).value
        assertEquals(setOf(route), result.plan.routes)
        assertEquals(setOf(strategy), result.plan.strategies)
        try {
            (result.plan.routes as MutableSet<CanonicalRoute>).clear()
            fail("mutable result")
        } catch (_: UnsupportedOperationException) { }
        assertFalse(result.toString().contains("profile-a"))
        assertFalse(result.plan.toString().contains("10.0.0.53"))
    }

    @Test fun duplicateCustomDnsIsCategoricallyRejectedWithoutThrowing() {
        val boundary = Boundary()
        assertEquals(ProductFailureCode.DNS_POLICY_REJECTED, failure(boundary.authorize(
            ProductSettings(tunnel = TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM,
                customDns = "10.0.0.53", secondaryCustomDns = "10.0.0.53")))))
        assertFalse(boundary.calls.contains("digest"))
    }

    @Test fun twoDisjointExclusionsCannotTogetherEraseTheRoute() {
        val boundary = Boundary().also { it.signed = scope(bypassable = setOf(route)) }
        assertEquals(ProductFailureCode.ROUTE_POLICY_REJECTED, failure(boundary.authorize(
            ProductSettings(routing = RoutingPreferences(excludedCidrs = listOf("0.0.0.0/1", "128.0.0.0/1"))))))
        assertFalse(boundary.calls.contains("digest"))
    }

    @Test fun partialBypassSubtractsOnlyTheSignedRangeBeforeCanonicalRecheck() {
        val boundary = Boundary().also { it.signed = scope(
            routes = setOf(CanonicalRoute("10.0.0.0/24")),
            bypassable = setOf(CanonicalRoute("10.0.0.0/24"))) }
        val result = boundary.authorize(ProductSettings(routing = RoutingPreferences(
            excludedCidrs = listOf("10.0.0.64/26", "10.0.0.80/28")))) as DomainResult.Success
        assertEquals(setOf("10.0.0.0/26", "10.0.0.128/25"), result.value.plan.routes.map { it.value }.toSet())
        assertSame(boundary.received, result.value.plan)
    }

    @Test fun supportedNarrowingPreservesResolverRoutingAndProxyLimitsForCanonicalRecheck() {
        val boundary = Boundary().also { it.signed = scope(bypassable = setOf(CanonicalRoute("10.0.0.0/8")),
            resolvers = setOf(ResolverConfiguration.Custom(listOf(dns)))) }
        val settings = ProductSettings(
            connection = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY, manualStrategyId = strategy),
            tunnel = TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM, customDns = "10.0.0.53", mtu = 1280),
            routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf("org.example.app"), listOf("10.1.1.2/16")),
            localProxy = LocalProxyPreferences(12000, 12001, ProxyLimits(16, 64, 3600, 128)),
        )
        val result = (boundary.authorize(settings) as DomainResult.Success).value.plan
        assertEquals(setOf(strategy), result.strategies)
        assertEquals(setOf(dns), result.dnsAddresses)
        assertEquals(ResolverConfiguration.Custom(listOf(dns)), result.resolver)
        assertEquals(listOf("10.1.0.0/16"), result.routing.excludedCidrs)
        assertEquals(setOf("org.example.app"), result.routing.packages)
        assertEquals(PerAppSelectionMode.INCLUDE_ONLY, result.routing.mode)
        assertEquals(1280, result.mtu)
        assertEquals(12000, result.proxy.socksPort)
        assertEquals(12001, result.proxy.httpConnectPort)
        assertEquals(ProxyLimits(), result.proxy.limits)
        assertEquals(0, result.reconnectMaximum)
    }

    @Test fun unsupportedModeAndEmptyIncludeSetAndLanBypassAreRejected() {
        listOf(
            ProductSettings(tunnelMode = TunnelMode.PROXY_ONLY) to ProductFailureCode.PROFILE_INCOMPATIBLE,
            ProductSettings(routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY)) to ProductFailureCode.APP_POLICY_DRIFT,
            ProductSettings(connection = ConnectionPreferences(allowLan = true)) to ProductFailureCode.ROUTE_POLICY_REJECTED,
        ).forEach { (settings, code) ->
            val boundary = Boundary()
            assertEquals(code, failure(boundary.authorize(settings)))
            assertFalse(boundary.calls.contains("digest"))
        }
    }

    @Test fun nativeAndOsCollectionInputsAreSnapshots() {
        val packages = mutableSetOf("org.example.app")
        val strategies = mutableSetOf(strategy)
        val boundary = Boundary().also { it.capabilities = native(strategies); it.system = os(packages) }
        packages.clear()
        strategies.clear()
        assertTrue(boundary.authorize(ProductSettings(routing = RoutingPreferences(
            PerAppSelectionMode.INCLUDE_ONLY, setOf("org.example.app")))) is DomainResult.Success)
    }

    @Test fun everyProfileGenerationTrustSettingsAndPackageBindingMismatchStopsBeforeCompatibility() {
        listOf(binding.copy(profileId = CatalogId("other")), binding.copy(profileGeneration = 6u),
            binding.copy(trustRevision = 2), binding.copy(settingsRevision = 3), binding.copy(packageRevision = 4)).forEach { other ->
            val boundary = Boundary()
            val result = RuntimePlanAuthorizer(boundary).authorize(other, SettingsRevision(4, ProductSettings()))
            assertEquals(ProductFailureCode.PROFILE_UNTRUSTED, failure(result))
            assertEquals(listOf("signed"), boundary.calls)
        }
    }

    @Test fun ipv4Ipv6DualAndAutoRequireAddressRouteDnsNativeAndOsAgreement() {
        val v6Route = CanonicalRoute("::/0")
        val v6Dns = NumericAddress("fd00::53")
        val both = setOf(IpFamily.IPV4, IpFamily.IPV6)
        for (mode in IpMode.entries) {
            val boundary = Boundary().also {
                it.signed = SignedRuntimePlan(binding, both, setOf(route, v6Route), setOf(dns, v6Dns),
                    setOf(strategy), setOf(strategy), setOf(ResolverConfiguration.Internal), emptySet(),
                    setOf(TunnelMode.TUN_ONLY), 1280..1500, 3, ProxyLimits())
                it.capabilities = NativePlanCapabilities(both, setOf(strategy), setOf(TunnelMode.TUN_ONLY),
                    1280..1400, 2, 64, ProxyLimits())
                it.system = OsPlanCapabilities(both, setOf(TunnelMode.TUN_ONLY), emptySet(), 5)
            }
            val plan = (boundary.authorize(ProductSettings(tunnel = TunnelPreferences(ipMode = mode))) as DomainResult.Success).value.plan
            assertEquals(if (mode == IpMode.AUTO) IpMode.DUAL_STACK else mode, plan.ipMode)
            assertEquals(if (mode == IpMode.IPV4_ONLY) setOf(route) else if (mode == IpMode.IPV6_ONLY) setOf(v6Route) else setOf(route, v6Route), plan.routes)
            assertEquals(if (mode == IpMode.IPV4_ONLY) setOf(dns) else if (mode == IpMode.IPV6_ONLY) setOf(v6Dns) else setOf(dns, v6Dns), plan.dnsAddresses)
        }
        val osMissing = Boundary().also { it.system = OsPlanCapabilities(emptySet(), setOf(TunnelMode.TUN_ONLY), emptySet(), 5) }
        assertEquals(ProductFailureCode.ROUTE_POLICY_REJECTED, failure(osMissing.authorize()))
        assertFalse(osMissing.calls.contains("digest"))
    }

    @Test fun malformedDigestAndUnboundedAuthorityAreNotRepresentable() {
        val boundary = Boundary()
        val plan = (boundary.authorize() as DomainResult.Success).value.plan
        listOf("", "a".repeat(63), "A".repeat(64), "0".repeat(64)).forEach { digest ->
            try { CanonicalPlanReceipt(plan, digest); fail("invalid digest") } catch (_: IllegalArgumentException) { }
        }
        try { RuntimeBinding(binding.profileId, 0u, 0, 0, 0); fail("zero generation") } catch (_: IllegalArgumentException) { }
        try { RuntimeBinding(binding.profileId, 1u, -1, 0, 0); fail("negative revision") } catch (_: IllegalArgumentException) { }
        try { NativePlanCapabilities(emptySet(), emptySet(), emptySet(), 1280..1500, 3, 257, ProxyLimits()); fail("unbounded packages") }
        catch (_: IllegalArgumentException) { }
    }
}
