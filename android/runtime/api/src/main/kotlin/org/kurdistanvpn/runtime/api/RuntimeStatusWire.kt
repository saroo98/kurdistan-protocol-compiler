// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.ResolverPolicy

/** Android display IPC only. Never a native wire, persisted state or session authority. */
object RuntimeStatusWire {
    const val VERSION = 6
    const val MAX_BYTES = 4096
    private const val MAGIC = 0x4b525331 // KRS1

    fun encode(value: VpnRuntimeSnapshot): ByteArray {
        requireValid(value)
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeInt(MAGIC); out.writeInt(VERSION)
            out.text(value.state.name)
            out.writeLong(value.packetsRead); out.writeLong(value.packetsWritten)
            out.writeLong(value.bytesSent); out.writeLong(value.bytesReceived)
            out.writeByte(value.alwaysOn?.let { if (it) 1 else 0 } ?: 2)
            out.writeByte(value.lockdown?.let { if (it) 1 else 0 } ?: 2)
            out.text(value.failure); out.text(value.packetDisposition); out.text(value.perAppRoutingMode.name)
            out.writeLong(value.startedAtElapsedRealtime)
            out.text(value.dnsMode.name); out.text(value.ipMode.name); out.writeInt(value.mtu)
            out.writeLong(value.profileGeneration.toLong())
            out.text(value.planDigest); out.text(value.profileFingerprint)
            out.text(value.strategyFingerprint); out.text(value.relayFingerprint)
            out.writeInt(value.maxReconnectAttempts); out.text(value.runtimeRequestId)
            out.writeLong(value.appliedRevision); out.writeInt(value.routeCount); out.writeInt(value.perAppCount)
            out.writeBoolean(value.lanBypass); out.text(value.metering.name)
            with(value.diagnostics) {
                longArrayOf(tunPacketsRead, outboundPacketsAccepted, carrierRecordsWritten, carrierRecordsRead,
                    authenticatedOperations, innerPacketsAccepted, innerPacketsRejected, tunWriteAttempts,
                    tunWriteFailures, tunWriteFailureCode, tunWriteErrno, tunPacketsWritten,
                    rejectedTunPackets, rejectedTunPacketCode).forEach(out::writeLong)
            }
            out.writeBoolean(value.presentation != null)
            value.presentation?.let { evidence ->
                out.text(evidence.sessionId)
                with(evidence.binding) {
                    out.text(profileId); out.writeLong(profileGeneration.toLong())
                    out.writeLong(trustRevision); out.writeLong(settingsRevision); out.writeLong(packageRevision)
                }
                out.text(evidence.nativeSessionId); out.text(evidence.tunSessionId)
                out.optionalRevision(evidence.routeRevision); out.optionalRevision(evidence.dnsRevision)
                out.text(evidence.proxySessionId)
            }
        }
        return bytes.toByteArray().also { require(it.size <= MAX_BYTES) }
    }

    fun decode(bytes: ByteArray): VpnRuntimeSnapshot {
        require(bytes.size in 8..MAX_BYTES) { "INVALID_RUNTIME_STATUS" }
        try {
            val input = DataInputStream(ByteArrayInputStream(bytes))
            require(input.readInt() == MAGIC && input.readInt() == VERSION)
            val value = VpnRuntimeSnapshot(
                state = enumValueOf<VpnRuntimeState>(requireNotNull(input.text())),
                packetsRead = input.readLong(), packetsWritten = input.readLong(),
                bytesSent = input.readLong(), bytesReceived = input.readLong(),
                alwaysOn = input.optionalFlag(), lockdown = input.optionalFlag(),
                failure = input.text(), packetDisposition = input.text(),
                perAppRoutingMode = enumValueOf<PerAppRoutingMode>(requireNotNull(input.text())),
                startedAtElapsedRealtime = input.readLong(),
                dnsMode = enumValueOf<ResolverPolicy>(requireNotNull(input.text())),
                ipMode = enumValueOf<IpMode>(requireNotNull(input.text())), mtu = input.readInt(),
                profileGeneration = input.readLong().toULong(), planDigest = input.text(), profileFingerprint = input.text(),
                strategyFingerprint = input.text(), relayFingerprint = input.text(),
                maxReconnectAttempts = input.readInt(), runtimeRequestId = input.text(),
                appliedRevision = input.readLong(), routeCount = input.readInt(), perAppCount = input.readInt(),
                lanBypass = input.flag(), metering = enumValueOf<VpnMeteringState>(requireNotNull(input.text())),
                diagnostics = VpnRuntimeDiagnostics(
                    input.readLong(), input.readLong(), input.readLong(), input.readLong(), input.readLong(),
                    input.readLong(), input.readLong(), input.readLong(), input.readLong(), input.readLong(),
                    input.readLong(), input.readLong(), input.readLong(), input.readLong()),
                presentation = if (!input.flag()) null else RuntimePresentationEvidence(
                    requireNotNull(input.text()), RuntimePresentationBinding(requireNotNull(input.text()),
                        input.readLong().toULong(), input.readLong(), input.readLong(), input.readLong()),
                    input.text(), input.text(), input.optionalRevision(), input.optionalRevision(), input.text()))
            require(input.available() == 0)
            requireValid(value)
            return value
        } catch (_: IOException) {
            throw IllegalArgumentException("INVALID_RUNTIME_STATUS")
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("INVALID_RUNTIME_STATUS")
        }
    }

    private fun requireValid(value: VpnRuntimeSnapshot) {
        require(value.validatedForDisplay() == value) {
            "INVALID_RUNTIME_STATUS"
        }
    }

    private fun DataOutputStream.text(value: String?) {
        if (value == null) { writeByte(255); return }
        require(value.length <= 64 && value.all { it.code in 0x21..0x7e })
        writeByte(value.length); write(value.toByteArray(Charsets.US_ASCII))
    }
    private fun DataInputStream.text(): String? {
        val length = readUnsignedByte()
        if (length == 255) return null
        require(length <= 64 && length <= available())
        val bytes = ByteArray(length).also(::readFully)
        require(bytes.all { it.toInt() in 0x21..0x7e })
        return String(bytes, Charsets.US_ASCII)
    }
    private fun DataInputStream.flag(): Boolean {
        val flag = readUnsignedByte(); require(flag in 0..1); return flag == 1
    }
    private fun DataOutputStream.optionalRevision(value: Long?) {
        writeBoolean(value != null); if (value != null) writeLong(value)
    }
    private fun DataInputStream.optionalRevision(): Long? = if (flag()) readLong() else null
    private fun DataInputStream.optionalFlag(): Boolean? = when (readUnsignedByte()) {
        0 -> false; 1 -> true; 2 -> null; else -> throw IllegalArgumentException("INVALID_RUNTIME_STATUS")
    }
}
