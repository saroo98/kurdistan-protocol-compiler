// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import java.util.Collections
import org.kurdistanvpn.core.model.*

/** Local revision identities, not native handles, hashes of user identities, or execution authority. */
data class RuntimeBinding(val profileId: CatalogId, val profileGeneration: ULong,
    val trustRevision: Long, val settingsRevision: Long, val packageRevision: Long) {
    init { require(profileGeneration > 0u && trustRevision >= 0 && settingsRevision >= 0 && packageRevision >= 0) }
    override fun toString(): String = "RuntimeBinding(redacted)"
}

private fun <T> frozen(values: Set<T>): Set<T> = Collections.unmodifiableSet(values.toSet())

/** Safe policy projection from fresh adapter verification. This object alone proves no signature. */
class SignedRuntimePlan(
    val binding: RuntimeBinding,
    addressFamilies: Set<IpFamily>, routes: Set<CanonicalRoute>, dnsAddresses: Set<NumericAddress>,
    strategies: Set<CatalogId>, kurdStrategies: Set<CatalogId>, resolvers: Set<ResolverConfiguration>,
    bypassable: Set<CanonicalRoute>, tunnelModes: Set<TunnelMode>, val mtu: IntRange,
    val reconnectMaximum: Int, val proxyMaximum: ProxyLimits,
) {
    val addressFamilies = frozen(addressFamilies)
    val routes = frozen(routes)
    val dnsAddresses = frozen(dnsAddresses)
    val strategies = frozen(strategies)
    val kurdStrategies = frozen(kurdStrategies)
    val resolvers = frozen(resolvers)
    val bypassable = frozen(bypassable)
    val tunnelModes = frozen(tunnelModes)
    init {
        require(routes.size <= 256 && dnsAddresses.size <= 2 && strategies.size <= 256 && kurdStrategies.size <= 256)
        require(resolvers.size <= 256 && bypassable.size <= 64 && reconnectMaximum in 0..10)
        require(!mtu.isEmpty() && mtu.first >= 1280 && mtu.last <= 1500)
        require(strategies.containsAll(kurdStrategies))
    }
    override fun toString(): String = "SignedRuntimePlan(redacted)"
}

class NativePlanCapabilities(families: Set<IpFamily>, strategies: Set<CatalogId>,
    tunnelModes: Set<TunnelMode>, val mtu: IntRange, val reconnectMaximum: Int,
    val packageMaximum: Int, val proxyMaximum: ProxyLimits) {
    val families = frozen(families)
    val strategies = frozen(strategies)
    val tunnelModes = frozen(tunnelModes)
    init {
        require(strategies.size <= 256 && reconnectMaximum in 0..10 && packageMaximum in 0..256)
        require(!mtu.isEmpty() && mtu.first >= 1280 && mtu.last <= 1500)
    }
    override fun toString(): String = "NativePlanCapabilities(redacted)"
}

class OsPlanCapabilities(families: Set<IpFamily>, tunnelModes: Set<TunnelMode>,
    installedPackages: Set<String>, val packageRevision: Long) {
    val families = frozen(families)
    val tunnelModes = frozen(tunnelModes)
    val installedPackages = frozen(installedPackages)
    init { require(installedPackages.size <= 65536 && packageRevision >= 0) }
    override fun toString(): String = "OsPlanCapabilities(redacted)"
}

/** Non-executable candidate. No endpoint, key, signature bytes, file or JNI handle is exposed. */
class NarrowedRuntimePlan internal constructor(
    val binding: RuntimeBinding, val ipMode: IpMode, routes: Set<CanonicalRoute>,
    dnsAddresses: Set<NumericAddress>, strategies: Set<CatalogId>, val resolver: ResolverConfiguration,
    val routing: RoutingPreferences, val tunnelMode: TunnelMode, val mtu: Int,
    val reconnectMaximum: Int, val proxy: LocalProxyPreferences,
) {
    val routes = frozen(routes)
    val dnsAddresses = frozen(dnsAddresses)
    val strategies = frozen(strategies)
    override fun toString(): String = "NarrowedRuntimePlan(redacted)"
}

/** The trusted adapter must bind the receipt to the identical immutable candidate instance. */
class CanonicalPlanReceipt(val plan: NarrowedRuntimePlan, val digest: String) {
    init { require(digest.matches(Regex("[0-9a-f]{64}")) && digest.any { it != '0' }) }
    override fun toString(): String = "CanonicalPlanReceipt(redacted)"
}

class CheckedRuntimeProjection internal constructor(val plan: NarrowedRuntimePlan, val canonicalDigest: String) {
    override fun toString(): String = "CheckedRuntimeProjection(redacted,non-executable)"
}

/**
 * Mandatory trusted adapter boundary, deliberately without a production implementation here.
 * validateSignedPlan freshly checks signature, expiry, rollback, revocation, device, activation receipt
 * and every RuntimeBinding identity. Compatibility and OS results must belong to that same attempt.
 * canonicalDigest rechecks those identities and the exact complete narrowing, including package set
 * and revision. It must use sessionplan.BuildV2At / ValidateV2At and the admitted adapter's policy gates,
 * never hash this Kotlin projection or accept an externally supplied digest as authorization.
 * The existing V2 contract permits exact per-family default routes and signed internal DNS, MTU 1280;
 * unsupported narrowing (including bypass/preset/proxy semantics) must be rejected, not approximated.
 * Local settings/trust/package revisions are adapter lease bindings, NOT fields invented in V2 hashing.
 * No checked projection or receipt may be serialized as authority or passed to connect/dispatch.
 */
interface RuntimeAuthorityBoundary {
    fun validateSignedPlan(binding: RuntimeBinding): DomainResult<SignedRuntimePlan>
    fun validateCompatibility(plan: SignedRuntimePlan): DomainResult<NativePlanCapabilities>
    fun validateOsCapability(binding: RuntimeBinding): DomainResult<OsPlanCapabilities>
    fun canonicalDigest(plan: NarrowedRuntimePlan): DomainResult<CanonicalPlanReceipt>
}

/** Deterministic domain orchestration/intersection; no Android, native calls, I/O, clock or crypto. */
class RuntimePlanAuthorizer(private val authority: RuntimeAuthorityBoundary) {
    fun authorize(binding: RuntimeBinding, requested: SettingsRevision): DomainResult<CheckedRuntimeProjection> {
        // These three gates are deliberately sequential. Later gates cannot hide a revoked profile.
        val signed = when (val result = authority.validateSignedPlan(binding)) {
            is DomainResult.Success -> result.value
            is DomainResult.Rejected -> return result
        }
        if (signed.binding != binding) return reject(ProductFailureCode.PROFILE_UNTRUSTED)
        val native = when (val result = authority.validateCompatibility(signed)) {
            is DomainResult.Success -> result.value
            is DomainResult.Rejected -> return result
        }
        val os = when (val result = authority.validateOsCapability(binding)) {
            is DomainResult.Success -> result.value
            is DomainResult.Rejected -> return result
        }

        // User settings only narrow the admitted projections, and never repair stale identity silently.
        if (requested.revision != binding.settingsRevision) return reject(ProductFailureCode.OPERATION_INTERRUPTED)
        if (os.packageRevision != binding.packageRevision) return reject(ProductFailureCode.APP_POLICY_DRIFT)
        val settings = requested.settings
        if (settings.tunnelMode !in signed.tunnelModes || settings.tunnelMode !in native.tunnelModes ||
            settings.tunnelMode !in os.tunnelModes) return reject(ProductFailureCode.PROFILE_INCOMPATIBLE)
        if (settings.connection.allowLan) return reject(ProductFailureCode.ROUTE_POLICY_REJECTED)
        val permittedStrategies = signed.strategies.intersect(native.strategies)
        val strategies = when (settings.connection.selectionMode) {
            SelectionMode.AUTOMATIC -> permittedStrategies
            SelectionMode.KURD_ONLY -> permittedStrategies.intersect(signed.kurdStrategies)
            SelectionMode.MANUAL_STRATEGY -> setOfNotNull(settings.connection.manualStrategyId).intersect(permittedStrategies)
        }
        val resolver = when (settings.tunnel.dnsMode) {
            ResolverPolicy.INTERNAL -> ResolverConfiguration.Internal
            ResolverPolicy.PROFILE_DEFINED -> ResolverConfiguration.ProfileDefined
            ResolverPolicy.PRESET -> ResolverConfiguration.Preset(settings.tunnel.resolverCatalogId!!)
            ResolverPolicy.CUSTOM -> {
                val addresses = listOf(settings.tunnel.customDns, settings.tunnel.secondaryCustomDns)
                    .filter { it.isNotEmpty() }.map(::NumericAddress)
                if (addresses.distinct().size != addresses.size) return reject(ProductFailureCode.DNS_POLICY_REJECTED)
                ResolverConfiguration.Custom(addresses)
            }
        }
        if (resolver !in signed.resolvers) return reject(ProductFailureCode.DNS_POLICY_REJECTED)
        val selectedDns = if (resolver is ResolverConfiguration.Custom) resolver.addresses.toSet() else signed.dnsAddresses
        if (!signed.dnsAddresses.containsAll(selectedDns)) return reject(ProductFailureCode.DNS_POLICY_REJECTED)
        val routing = settings.routing
        if (!os.installedPackages.containsAll(routing.packages) || routing.packages.size > native.packageMaximum ||
            (routing.mode == PerAppSelectionMode.INCLUDE_ONLY && routing.packages.isEmpty()) ||
            (routing.mode == PerAppSelectionMode.ALL_APPS && routing.packages.isNotEmpty())) return reject(ProductFailureCode.APP_POLICY_DRIFT)
        val exclusions = ExcludedRoutes(routing.excludedCidrs.map(::CanonicalRoute))
        if (exclusions.routes.any { excluded -> signed.bypassable.none { it.contains(excluded) } })
            return reject(ProductFailureCode.ROUTE_POLICY_REJECTED)

        // Final nonempty family-complete route, DNS and strategy intersection.
        val routes = try { CanonicalRoute.subtract(signed.routes, exclusions.routes) }
            catch (_: IllegalArgumentException) { return reject(ProductFailureCode.ROUTE_POLICY_REJECTED) }
        if (routes.isEmpty()) return reject(ProductFailureCode.ROUTE_POLICY_REJECTED)
        if (selectedDns.isEmpty()) return reject(ProductFailureCode.DNS_POLICY_REJECTED)
        if (strategies.isEmpty()) return reject(ProductFailureCode.NO_PERMITTED_STRATEGY)
        val families = signed.addressFamilies.intersect(native.families).intersect(os.families)
            .intersect(routes.map { family(it.value) }.toSet()).intersect(selectedDns.map { family(it.value) }.toSet())
        val wanted = when (settings.tunnel.ipMode) {
            IpMode.AUTO -> families
            IpMode.IPV4_ONLY -> setOf(IpFamily.IPV4)
            IpMode.IPV6_ONLY -> setOf(IpFamily.IPV6)
            IpMode.DUAL_STACK -> setOf(IpFamily.IPV4, IpFamily.IPV6)
        }
        if (wanted.isEmpty() || !families.containsAll(wanted)) return reject(ProductFailureCode.ROUTE_POLICY_REJECTED)
        val mode = if (wanted.size == 2) IpMode.DUAL_STACK else if (IpFamily.IPV4 in wanted) IpMode.IPV4_ONLY else IpMode.IPV6_ONLY
        val lowerMtu = maxOf(signed.mtu.first, native.mtu.first)
        val upperMtu = minOf(signed.mtu.last, native.mtu.last)
        if (lowerMtu > upperMtu) return reject(ProductFailureCode.ROUTE_POLICY_REJECTED)
        val narrowed = NarrowedRuntimePlan(binding, mode, routes.filter { family(it.value) in wanted }.toSet(),
            selectedDns.filter { family(it.value) in wanted }.toSet(), strategies, resolver, routing.validated(),
            settings.tunnelMode, RequestedMtu(settings.tunnel.mtu).effective(signed.mtu, native.mtu),
            settings.connection.reconnectPolicy.effectiveMaximum(signed.reconnectMaximum, native.reconnectMaximum),
            settings.localProxy.copy(limits = settings.localProxy.limits.narrowedBy(signed.proxyMaximum, native.proxyMaximum)))
        return when (val receipt = authority.canonicalDigest(narrowed)) {
            is DomainResult.Rejected -> receipt
            is DomainResult.Success -> if (receipt.value.plan !== narrowed) reject(ProductFailureCode.INTERNAL_FAILURE)
                else DomainResult.Success(CheckedRuntimeProjection(narrowed, receipt.value.digest))
        }
    }

    private fun reject(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
    private fun family(value: String) = if (':' in value) IpFamily.IPV6 else IpFamily.IPV4

}
