// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import java.util.Collections

enum class IpFamily { IPV4, IPV6 }
fun effectiveIpMode(request: IpMode, signedAddresses: Set<IpFamily>, signedRoutes: Set<IpFamily>,
    signedDns: Set<IpFamily>, nativeFamilies: Set<IpFamily>): IpMode {
    val available = signedAddresses.intersect(signedRoutes).intersect(signedDns).intersect(nativeFamilies)
    val requested = when (request) {
        IpMode.AUTO -> available
        IpMode.IPV4_ONLY -> setOf(IpFamily.IPV4)
        IpMode.IPV6_ONLY -> setOf(IpFamily.IPV6)
        IpMode.DUAL_STACK -> setOf(IpFamily.IPV4, IpFamily.IPV6)
    }
    require(requested.isNotEmpty() && available.containsAll(requested))
    return when {
        requested.size == 2 -> IpMode.DUAL_STACK
        IpFamily.IPV4 in requested -> IpMode.IPV4_ONLY
        else -> IpMode.IPV6_ONLY
    }
}

class NumericAddress(input: String) {
    val value: String = requireNotNull(canonicalizeIpLiteral(input))
    override fun equals(other: Any?): Boolean = other is NumericAddress && value == other.value
    override fun hashCode(): Int = value.hashCode()
    override fun toString(): String = "NumericAddress(redacted)"
}

sealed interface ResolverConfiguration {
    data object Internal : ResolverConfiguration
    data object ProfileDefined : ResolverConfiguration
    data class Preset(val catalogId: CatalogId) : ResolverConfiguration
    class Custom(addresses: List<NumericAddress>) : ResolverConfiguration {
        init { require(addresses.size in 1..2 && addresses.distinct().size == addresses.size) }
        val addresses: List<NumericAddress> = Collections.unmodifiableList(addresses.toList())
        fun copy(addresses: List<NumericAddress> = this.addresses): Custom = Custom(addresses)
        override fun equals(other: Any?): Boolean = other is Custom && addresses == other.addresses
        override fun hashCode(): Int = addresses.hashCode()
        override fun toString(): String = "ResolverConfiguration.Custom(redacted)"
    }
}

class CanonicalRoute(input: String) {
    val value: String = requireNotNull(canonicalizeCidr(input))
    private val prefix: Int = value.substringAfter('/').toInt()
    private val bits: String = value.substringBefore('/').let { address ->
        parseIpv4(address)?.joinToString("") { (it.toInt() and 255).toString(2).padStart(8, '0') }
            ?: requireNotNull(parseIpv6(address)).joinToString("") { it.toString(2).padStart(16, '0') }
    }
    fun contains(other: CanonicalRoute): Boolean = bits.length == other.bits.length &&
        prefix <= other.prefix && bits.take(prefix) == other.bits.take(prefix)
    override fun equals(other: Any?): Boolean = other is CanonicalRoute && value == other.value
    override fun hashCode(): Int = value.hashCode()
    override fun toString(): String = "CanonicalRoute(redacted)"

    companion object {
        /** Exact union minus exclusions. The bound applies to the final disjoint CIDRs. */
        fun subtract(routes: Set<CanonicalRoute>, exclusions: List<CanonicalRoute>, maximum: Int = 256): Set<CanonicalRoute> {
            require(routes.size <= 256 && exclusions.size <= 64 && maximum in 1..256)
            val result = linkedSetOf<CanonicalRoute>()
            for (width in listOf(32, 128)) {
                val roots = linkedSetOf<String>()
                for (route in routes.filter { it.bits.length == width }.sortedBy { it.prefix }) {
                    val path = route.bits.take(route.prefix)
                    if (roots.none { path.startsWith(it) }) roots.add(path)
                }
                // Collapse adjacent siblings before subtraction, including two halves of /0.
                for (depth in width downTo 1) {
                    for (path in roots.filter { it.length == depth && it.endsWith('0') }) {
                        val parent = path.dropLast(1)
                        if (roots.remove(parent + '1')) { roots.remove(path); roots.add(parent) }
                    }
                }
                val holes = exclusions.filter { it.bits.length == width }.map { it.bits.take(it.prefix) }
                fun visit(path: String) {
                    if (holes.any { path.startsWith(it) }) return
                    if (holes.any { it.startsWith(path) }) {
                        visit(path + '0'); visit(path + '1')
                    } else {
                        require(result.size < maximum)
                        val padded = path.padEnd(width, '0')
                        val address = if (width == 32) padded.chunked(8).joinToString(".") { it.toInt(2).toString() }
                            else padded.chunked(16).joinToString(":") { it.toInt(2).toString(16) }
                        result.add(CanonicalRoute("$address/${path.length}"))
                    }
                }
                roots.sorted().forEach(::visit)
            }
            return Collections.unmodifiableSet(result)
        }
    }
}

class ExcludedRoutes(routes: List<CanonicalRoute> = emptyList()) {
    init { require(routes.size <= 64) }
    val routes: List<CanonicalRoute> = Collections.unmodifiableList(routes.distinct().sortedBy { it.value })
    fun validatedAgainst(signedBypassable: Set<CanonicalRoute>): ExcludedRoutes {
        require(signedBypassable.size <= 64)
        require(routes.all { route -> signedBypassable.any { it.contains(route) } })
        return this
    }
    fun copy(routes: List<CanonicalRoute> = this.routes): ExcludedRoutes = ExcludedRoutes(routes)
    override fun equals(other: Any?): Boolean = other is ExcludedRoutes && routes == other.routes
    override fun hashCode(): Int = routes.hashCode()
    override fun toString(): String = "ExcludedRoutes(redacted)"
}

data class RequestedMtu(val value: Int = 1500) {
    init { require(value in 1280..1500) }
    fun effective(signed: IntRange, native: IntRange): Int {
        require(!signed.isEmpty() && !native.isEmpty())
        val lower = maxOf(1280, signed.first, native.first)
        val upper = minOf(1500, signed.last, native.last)
        require(lower <= upper)
        return value.coerceIn(lower, upper)
    }
}
