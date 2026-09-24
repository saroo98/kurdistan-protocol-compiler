// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeProductResult

internal enum class ProductionOpeningPurposeV1 { SESSION, MAINTENANCE }

internal class ProductionOpeningInputV1(
    val purpose: ProductionOpeningPurposeV1,
    val settings: ProductSettings,
    val verifyRequest: ByteBuffer,
    val activationRecord: ByteBuffer,
    val recipientRequest: ByteBuffer,
    val recipientPrivate: ByteBuffer,
) { override fun toString() = "ProductionOpeningInputV1(redacted)" }

internal object ProductionOpeningCodecV1 {
    private const val SETTINGS_MAX = 196608
    private const val OPENING_MAX = 2721575

    fun encodeSettings(settings: ProductSettings, output: ByteBuffer): NativeProductResult<Int> {
        if (output.isReadOnly) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        val bytes = try { settingsBytesV1(settings) } catch (_: IllegalArgumentException) {
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        }
        return try { atomicWriteV1(bytes, output, SETTINGS_MAX) } finally { bytes.fill(0) }
    }

    fun encodeOpening(input: ProductionOpeningInputV1, output: ByteBuffer): NativeProductResult<Int> {
        if (output.isReadOnly) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        val settingsBytes = try { settingsBytesV1(input.settings) } catch (_: IllegalArgumentException) {
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        }
        return try {
            encodeOpening(input.purpose, ByteBuffer.wrap(settingsBytes), input.verifyRequest,
                input.activationRecord, input.recipientRequest, input.recipientPrivate, output)
        } finally {
            settingsBytes.fill(0)
        }
    }

    /** Packs the trusted capture's canonical KPS bytes without reconstructing settings. */
    fun encodeOpening(purpose: ProductionOpeningPurposeV1, settings: ByteBuffer,
        verifyRequest: ByteBuffer, activationRecord: ByteBuffer, recipientRequest: ByteBuffer,
        recipientPrivate: ByteBuffer, output: ByteBuffer): NativeProductResult<Int> {
            if (output.isReadOnly) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
            val settingsLength = settings.validSpanLength(SETTINGS_MAX)
                ?: return NativeProductResult.Failure(sizeOrInput(settings, SETTINGS_MAX))
            val verifyLength = verifyRequest.validSpanLength(1405996)
                ?: return NativeProductResult.Failure(sizeOrInput(verifyRequest, 1405996))
            val activationLength = activationRecord.validSpanLength(1118299)
                ?: return NativeProductResult.Failure(sizeOrInput(activationRecord, 1118299))
            val recipientLength = recipientRequest.validSpanLength(512)
                ?: return NativeProductResult.Failure(sizeOrInput(recipientRequest, 512))
            val privateLength = recipientPrivate.validSpanLength(128)
                ?: return NativeProductResult.Failure(sizeOrInput(recipientPrivate, 128))
            val total = 32L + settingsLength + verifyLength + activationLength + recipientLength + privateLength
            if (total > OPENING_MAX || output.remaining().toLong() < total) {
                return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
            }
            val header = ProductionWriterV1(maximum = 32, initialCapacity = 32).use { writer ->
                writer.bytes("KPO1".toByteArray(Charsets.US_ASCII)); writer.u8(1)
                writer.u8(if (purpose == ProductionOpeningPurposeV1.SESSION) 1 else 2); writer.u16(0)
                writer.u32(total); writer.u32(settingsLength.toLong()); writer.u32(verifyLength.toLong())
                writer.u32(activationLength.toLong()); writer.u16(recipientLength); writer.u16(privateLength); writer.u32(0)
                writer.result()
            }
            try {
                output.duplicate().apply {
                    put(header); put(settings.duplicate()); put(verifyRequest.duplicate()); put(activationRecord.duplicate())
                    put(recipientRequest.duplicate()); put(recipientPrivate.duplicate())
                }
            } finally {
                header.fill(0)
            }
            return NativeProductResult.Success(total.toInt())
    }

    private fun ByteBuffer.validSpanLength(maximum: Int) = remaining().takeIf { it in 1..maximum }

    private fun sizeOrInput(buffer: ByteBuffer, maximum: Int) =
        if (buffer.remaining() > maximum) ProductFailureCode.SIZE_LIMIT else ProductFailureCode.INVALID_INPUT

    private fun settingsBytesV1(settings: ProductSettings): ByteArray {
        val temporaries = mutableListOf<ByteArray>()
        val writers = mutableListOf<ProductionWriterV1>()
        return try {
        val c = settings.connection; val t = settings.tunnel; val r = settings.routing; val u = settings.updates
        val p = settings.probes; val e = settings.expert; val profiles = settings.profiles
        require(c.reconnectMaximum in 1..10)
        require((c.selectionMode == SelectionMode.MANUAL_STRATEGY) == (c.manualStrategyId != null))
        val packages = r.packages.map { value -> value.toByteArray(Charsets.UTF_8).also { raw -> temporaries += raw; require(validPackage(value, raw)) } }.sortedWith(::compareUnsignedV1)
        require(packages.size <= 256 && (r.mode != PerAppSelectionMode.ALL_APPS || packages.isEmpty()) && (r.mode != PerAppSelectionMode.INCLUDE_ONLY || packages.isNotEmpty()))
        val routes = r.excludedCidrs.map { raw ->
            val encoded = encodedPrefixV1(raw) ?: throw IllegalArgumentException()
            require(CanonicalRoute(raw).value == raw); temporaries += encoded; encoded
        }.sortedWith(::compareUnsignedV1)
        require(routes.size <= 64 && routes.zipWithNext().none { compareUnsignedV1(it.first,it.second)==0 })
        val primary = optionalDns(t.customDns).also { temporaries += it }; val secondary = optionalDns(t.secondaryCustomDns).also { temporaries += it }
        when (t.dnsMode) {
            ResolverPolicy.CUSTOM -> require(primary.isNotEmpty() && t.resolverCatalogId == null && (secondary.isEmpty() || !primary.contentEquals(secondary)))
            ResolverPolicy.PRESET -> require(primary.isEmpty() && secondary.isEmpty() && t.resolverCatalogId != null)
            else -> require(primary.isEmpty() && secondary.isEmpty() && t.resolverCatalogId == null)
        }
        val favorites = profiles.favoriteLocalRecordIds.sorted(); val allLocal = favorites + listOfNotNull(profiles.activeLocalRecordId)
        require(favorites.size <= 1024 && allLocal.toSet().size <= 1024 && allLocal.all { it.matches(Regex("[a-z0-9-]{1,64}")) })
        val trust = settings.networkTrust.protectedRuleIds.map { it.value }.sorted()
        require(trust.size <= 256)

        val body = ProductionWriterV1(maximum = SETTINGS_MAX).also { writers += it }
        body.u8(mapTheme(settings.theme)); body.bool(settings.highContrast); body.bool(settings.reducedMotion)
        body.u8(mapSelection(c.selectionMode)); body.bool(c.autoConnectOnLaunch); body.bool(c.reconnectOnFailure); body.bool(c.allowLan); body.bool(c.connectOnlyOnUntrustedNetworks); body.id(c.manualStrategyId?.value); body.u8(c.reconnectMaximum)
        body.u8(mapIp(t.ipMode))
        body.u8(mapDns(t.dnsMode))
        body.bytes(if(primary.isEmpty()) byteArrayOf(0) else primary)
        body.u16(t.mtu)
        body.bool(t.metered)
        body.bool(t.showSpeedInNotification)
        body.id(t.resolverCatalogId?.value)
        body.bytes(if(secondary.isEmpty()) byteArrayOf(0) else secondary)
        body.u8(mapPerApp(r.mode)); body.u16(packages.size); packages.forEach { body.u16(it.size); body.bytes(it) }; body.u8(routes.size); routes.forEach(body::bytes)
        body.bool(u.automatic); body.u16(u.intervalHours); body.bool(u.onLaunch); body.bool(u.notifyOnChange); body.bool(u.probeAfterUpdate)
        body.u8(mapProbeMethod(p.method)); body.u8(if(p.display==ProbeDisplay.MILLISECONDS)1 else 2); body.id(p.signedTargetId?.value); body.u8(p.timeoutSeconds)
        body.u8(mapLog(settings.diagnostics.level)); body.u8(mapRetention(settings.diagnostics.retention))
        body.u16(e.idleTimeoutSeconds); body.u16(e.tcpConnectionLimit); body.u16(e.udpConnectionLimit); body.u16(e.memoryLimitMb)
        body.localId(profiles.activeLocalRecordId); body.u16(favorites.size); favorites.forEach { body.localIdRequired(it) }
        body.u8(mapTunnel(settings.tunnelMode)); body.u8(mapMetered(settings.networkMeteredPolicy)); body.u8(if(settings.pausePolicy==PausePolicy.NOT_PAUSED)1 else 2)
        body.u16(settings.localProxy.socksPort); body.u16(settings.localProxy.httpConnectPort); body.u8(settings.localProxy.limits.clients); body.u8(settings.localProxy.limits.streams); body.u16(settings.localProxy.limits.idleSeconds); body.u16(settings.localProxy.limits.memoryMiB)
        body.bool(settings.privacy.collectUsageAggregates); body.u8(settings.privacy.usageRetentionDays); body.bool(settings.privacy.appLockEnabled)
        val authMask=settings.privacy.allowedAuthenticators.sumOf { if(it==AllowedAuthenticator.STRONG_BIOMETRIC)1 else 2 }; require(authMask in 0..3 && (!settings.privacy.appLockEnabled || authMask!=0)); body.u8(authMask)
        body.bool(settings.notifications.showSpeed); body.bool(settings.notifications.notifyOnUpdates)
        body.bool(settings.automation.enabled)
        body.bool(settings.networkTrust.enabled); body.u16(trust.size); trust.forEach { body.localIdRequired(it) }
        val payload=body.result().also { temporaries += it }; val total=12+payload.size; require(total<=SETTINGS_MAX)
        ProductionWriterV1(maximum = SETTINGS_MAX).also { writers += it }.apply { bytes("KPS1".toByteArray(Charsets.US_ASCII));u8(1);u8(0);u16(0);u32(total.toLong());bytes(payload) }.result()
        } finally { writers.forEach { it.close() }; temporaries.forEach { it.fill(0) } }
    }

    private fun ProductionWriterV1.id(value:String?) { if(value==null)u8(0) else localIdRequired(value) }
    private fun ProductionWriterV1.localId(value:String?) { if(value==null)u8(0) else localIdRequired(value) }
    private fun ProductionWriterV1.localIdRequired(value:String) {
        require(value.matches(Regex("[a-z0-9-]{1,64}")))
        val raw=value.toByteArray(Charsets.US_ASCII)
        try { u8(raw.size);bytes(raw) } finally { raw.fill(0) }
    }
    private fun optionalDns(value:String):ByteArray { if(value.isEmpty())return byteArrayOf();require(NumericAddress(value).value==value);return encodedAddressV1(value)?:throw IllegalArgumentException() }
    private fun validPackage(value:String, raw:ByteArray):Boolean = raw.size in 3..255 && raw.all{(it.toInt() and 255)<128} && value.split('.').size>=2 && value.split('.').all{it.isNotEmpty()&&(it[0] in 'a'..'z'||it[0] in 'A'..'Z'||it[0]=='_')&&it.all{c->c in 'a'..'z'||c in 'A'..'Z'||c in '0'..'9'||c=='_'}}
    private fun mapTheme(v:ThemePreference)=when(v){ThemePreference.SYSTEM->1;ThemePreference.LIGHT->2;ThemePreference.DARK->3}
    private fun mapSelection(v:SelectionMode)=when(v){SelectionMode.AUTOMATIC->1;SelectionMode.KURD_ONLY->2;SelectionMode.MANUAL_STRATEGY->3}
    private fun mapIp(v:IpMode)=when(v){IpMode.AUTO->1;IpMode.IPV4_ONLY->2;IpMode.IPV6_ONLY->3;IpMode.DUAL_STACK->4}
    private fun mapDns(v:ResolverPolicy)=when(v){ResolverPolicy.INTERNAL->1;ResolverPolicy.PROFILE_DEFINED->2;ResolverPolicy.PRESET->3;ResolverPolicy.CUSTOM->4}
    private fun mapPerApp(v:PerAppSelectionMode)=when(v){PerAppSelectionMode.ALL_APPS->1;PerAppSelectionMode.INCLUDE_ONLY->2;PerAppSelectionMode.EXCLUDE_SELECTED->3}
    private fun mapProbeMethod(v:ProbeMethod)=when(v){ProbeMethod.KURD_SESSION->1;ProbeMethod.TCP_CONNECT->2;ProbeMethod.HTTP_HEAD->3;ProbeMethod.HTTP_GET->4;ProbeMethod.ICMP->5}
    private fun mapLog(v:DiagnosticLogLevel)=when(v){DiagnosticLogLevel.NONE->1;DiagnosticLogLevel.ERROR->2;DiagnosticLogLevel.WARNING->3;DiagnosticLogLevel.INFO->4;DiagnosticLogLevel.DEBUG->5}
    private fun mapRetention(v:DiagnosticRetention)=when(v){DiagnosticRetention.ONE_HOUR->1;DiagnosticRetention.SIX_HOURS->2;DiagnosticRetention.ONE_DAY->3;DiagnosticRetention.SEVEN_DAYS->4}
    private fun mapTunnel(v:TunnelMode)=when(v){TunnelMode.TUN_ONLY->1;TunnelMode.TUN_PLUS_PROXY->2;TunnelMode.PROXY_ONLY->3}
    private fun mapMetered(v:NetworkMeteredPolicy)=when(v){NetworkMeteredPolicy.ALLOW->1;NetworkMeteredPolicy.ASK->2;NetworkMeteredPolicy.WAIT_FOR_UNMETERED->3}
}
