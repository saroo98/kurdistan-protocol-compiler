// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.TunnelMode
import org.kurdistanvpn.core.model.LocalProxyPreferences
import org.kurdistanvpn.core.model.ProxyLimits
import org.kurdistanvpn.core.model.NetworkMeteredPolicy
import org.kurdistanvpn.core.model.PausePolicy
import org.kurdistanvpn.core.nativeapi.NativeOpeningSnapshot
import org.kurdistanvpn.runtime.api.LiveIpPrefix
import org.kurdistanvpn.runtime.api.LiveTunConfiguration
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

/** Extracts Android-only package names AFTER native validation of this exact captured KPS1.
 * Not a settings validator or execution grant. The opening must also agree on mode/count. */
internal data class RuntimeCapturedPlatformSettingsV1(
    val routing: VpnRoutingPolicy,
    val tunnelMode: TunnelMode,
    val meteredPolicy: NetworkMeteredPolicy,
    val pausePolicy: PausePolicy,
    val proxy: LocalProxyPreferences,
    val showSpeed: Boolean,
)

internal fun readCapturedRoutingV1(settings: ByteBuffer): VpnRoutingPolicy =
    readCapturedPlatformSettingsV1(settings).routing

internal fun readCapturedPlatformSettingsV1(settings: ByteBuffer): RuntimeCapturedPlatformSettingsV1 {
    val input = settings.duplicate().order(ByteOrder.BIG_ENDIAN)
    require(input.remaining() in 12..196608)
    val length = input.remaining()
    fun u8(): Int { require(input.hasRemaining()); return input.get().toInt() and 255 }
    fun u16(): Int = (u8() shl 8) or u8()
    fun bool(): Boolean = when (u8()) { 0 -> false; 1 -> true; else -> throw IllegalArgumentException("CAPTURE_BOOLEAN_REJECTED") }
    fun skip(count: Int) { require(count in 0..input.remaining()); input.position(input.position() + count) }
    fun id() { val count = u8(); require(count <= 64); skip(count) }
    fun address() { skip(when (u8()) { 0 -> 0; 4 -> 4; 6 -> 16; else -> throw IllegalArgumentException("CAPTURE_ADDRESS_REJECTED") }) }
    require(input.int == 0x4b505331 && u8() == 1 && u8() == 0 && u16() == 0 && input.int == length)
    skip(3) // theme, contrast, motion
    skip(5); id(); skip(1) // connection preferences, strategy ID, retry maximum
    skip(2); address(); skip(4); id(); address() // IP/DNS, primary, MTU/metered/speed, catalog, secondary
    val mode = when (u8()) {
        1 -> PerAppRoutingMode.ALL_APPS
        2 -> PerAppRoutingMode.INCLUDE_ONLY
        3 -> PerAppRoutingMode.EXCLUDE_SELECTED
        else -> throw IllegalArgumentException("CAPTURE_ROUTING_REJECTED")
    }
    val count = u16()
    require(count <= 256)
    val packages = linkedSetOf<String>()
    var previous = ""
    repeat(count) {
        val size = u16()
        require(size in 3..255 && size <= input.remaining())
        val raw = ByteArray(size)
        val name = try {
            input.get(raw)
            require(raw.all { it.toInt() in 0..127 })
            raw.toString(Charsets.US_ASCII)
        } finally { raw.fill(0) }
        require(name > previous) // KPS1 mandates strict unsigned-ASCII order and uniqueness.
        packages.add(name); previous = name
    }
    val routes = u8(); require(routes <= 64)
    repeat(routes) { address(); skip(1) }
    skip(6) // update policy
    skip(2); id(); skip(1) // probe policy
    skip(10) // diagnostics and expert limits
    id()
    val favorites = u16(); require(favorites <= 1024); repeat(favorites) { id() }
    val tunnelMode = when (u8()) {
        1 -> TunnelMode.TUN_ONLY; 2 -> TunnelMode.TUN_PLUS_PROXY; 3 -> TunnelMode.PROXY_ONLY
        else -> throw IllegalArgumentException("CAPTURE_MODE_REJECTED")
    }
    val metered = when (u8()) {
        1 -> NetworkMeteredPolicy.ALLOW; 2 -> NetworkMeteredPolicy.ASK; 3 -> NetworkMeteredPolicy.WAIT_FOR_UNMETERED
        else -> throw IllegalArgumentException("CAPTURE_METERED_REJECTED")
    }
    val pause = when (u8()) {
        1 -> PausePolicy.NOT_PAUSED; 2 -> PausePolicy.UNTIL_RESUMED
        else -> throw IllegalArgumentException("CAPTURE_PAUSE_REJECTED")
    }
    val proxy = LocalProxyPreferences(u16(), u16(), ProxyLimits(u8(), u8(), u16(), u16()))
    skip(4) // privacy preferences remain owned by the sensitive-action authorizer
    val speed = bool()
    skip(3) // update notification, automation, network-trust enabled
    val trustRules = u16(); require(trustRules <= 256); repeat(trustRules) { id() }
    require(!input.hasRemaining())
    return RuntimeCapturedPlatformSettingsV1(VpnRoutingPolicy(mode, packages).validate(256),
        tunnelMode, metered, pause, proxy, speed)
}

/** NativeOpeningSnapshot already validates canonical addresses, DNS families and signed route shape. */
internal fun productionTunConfigurationV1(snapshot: NativeOpeningSnapshot, routing: VpnRoutingPolicy,
    ownPackage: String): LiveTunConfiguration {
    require(snapshot.effectiveMode != TunnelMode.PROXY_ONLY)
    val mode = when (snapshot.perAppMode) {
        PerAppSelectionMode.ALL_APPS -> PerAppRoutingMode.ALL_APPS
        PerAppSelectionMode.INCLUDE_ONLY -> PerAppRoutingMode.INCLUDE_ONLY
        PerAppSelectionMode.EXCLUDE_SELECTED -> PerAppRoutingMode.EXCLUDE_SELECTED
    }
    require(routing.perAppMode == mode && routing.packages.size == snapshot.effectivePackageCount)
    require(ownPackage !in routing.packages)
    val checked = routing.validate(snapshot.effectivePackageCount)
    return LiveTunConfiguration(
        buildList {
            snapshot.clientV4?.let { add(LiveIpPrefix(it.value, 32)) }
            snapshot.clientV6?.let { add(LiveIpPrefix(it.value, 128)) }
        },
        snapshot.routes.map { LiveIpPrefix(it.value.substringBeforeLast('/'), it.value.substringAfterLast('/').toInt()) },
        snapshot.dnsAddresses.map { it.value }, snapshot.effectiveMtu, snapshot.metered, checked)
}
