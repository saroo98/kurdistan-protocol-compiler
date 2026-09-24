// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import org.junit.Assert.*
import org.junit.Test

class RuntimeStatusWireTest {
    @Test fun independentEvidenceRetainsMissingOwnersAndRejectsForeignSessions() {
        val binding = RuntimePresentationBinding("profile-1", 3u, 6, 8, 12)
        val evidence = RuntimePresentationEvidence("1".repeat(32), binding,
            nativeSessionId = "1".repeat(32), tunSessionId = null, routeRevision = null, dnsRevision = null)
        val value = active().copy(presentation = evidence)
        assertEquals(value, RuntimeStatusWire.decode(RuntimeStatusWire.encode(value)))
        rejected { RuntimeStatusWire.encode(value.copy(presentation = evidence.copy(sessionId = "6".repeat(32)))) }
        rejected { RuntimeStatusWire.encode(value.copy(presentation = evidence.copy(nativeSessionId = "6".repeat(32)))) }
        val proxy = value.copy(presentation = evidence.copy(proxySessionId = evidence.sessionId))
        assertEquals(proxy, RuntimeStatusWire.decode(RuntimeStatusWire.encode(proxy)))
        rejected { RuntimeStatusWire.encode(value.copy(presentation = evidence.copy(proxySessionId = "6".repeat(32)))) }
        rejected { RuntimeStatusWire.encode(value.copy(presentation = evidence.copy(routeRevision = -1))) }
        rejected { RuntimeStatusWire.encode(VpnRuntimeSnapshot(presentation = evidence)) }
        val bytes = RuntimeStatusWire.encode(value)
        rejected { RuntimeStatusWire.decode(bytes.copyOf().also { it[7] = 4 }) }
    }
    @Test fun unknownSystemVpnPolicyRemainsUnknownAcrossIpc() {
        val observed = RuntimeStatusWire.decode(RuntimeStatusWire.encode(VpnRuntimeSnapshot()))
        assertNull(observed.alwaysOn)
        assertNull(observed.lockdown)
    }
    @Test fun effectivePolicyRoundTripsWithoutExposingAddressesOrPackageNames() {
        val value = active().copy(appliedRevision = 8, routeCount = 2, perAppCount = 256,
            metering = VpnMeteringState.OS_CONTROLLED)
        assertEquals(value, RuntimeStatusWire.decode(RuntimeStatusWire.encode(value)))
        rejected { RuntimeStatusWire.encode(value.copy(perAppCount = 257)) }
        rejected { RuntimeStatusWire.encode(value.copy(routeCount = -1)) }
        rejected { RuntimeStatusWire.encode(value.copy(appliedRevision = 7)) }
    }
    @Test fun byteCountersRoundTripWithoutAllowingNegativeOrOverflowedValues() {
        val value = active().copy(bytesSent = Long.MAX_VALUE, bytesReceived = 44)
        assertEquals(value, RuntimeStatusWire.decode(RuntimeStatusWire.encode(value)))
        rejected { RuntimeStatusWire.encode(value.copy(bytesSent = -1)) }
        rejected { RuntimeStatusWire.encode(value.copy(bytesReceived = -1)) }
    }
    @Test fun productionGenerationPreservesTheWholeUnsignedNativeRange() {
        val value = active().copy(profileGeneration = ULong.MAX_VALUE)
        assertEquals(ULong.MAX_VALUE, RuntimeStatusWire.decode(RuntimeStatusWire.encode(value)).profileGeneration)
    }
    @Test fun productionFingerprintsKeepTheirExactSixteenByteIdentity() {
        val value = active().copy(profileFingerprint = "3".repeat(32),
            strategyFingerprint = "4".repeat(32), relayFingerprint = "5".repeat(32))
        assertEquals(value, RuntimeStatusWire.decode(RuntimeStatusWire.encode(value)))
        rejected { RuntimeStatusWire.encode(value.copy(planDigest = "2".repeat(32))) }
        rejected { RuntimeStatusWire.encode(value.copy(relayFingerprint = "5".repeat(40))) }
        rejected { RuntimeStatusWire.encode(value.copy(relayFingerprint = "5".repeat(64))) }
    }
    private fun active() = VpnRuntimeSnapshot(
        state = VpnRuntimeState.ACTIVE_KURD_LIVE, packetsRead = 7, packetsWritten = 5,
        alwaysOn = true, startedAtElapsedRealtime = 20, profileGeneration = 3uL,
        runtimeRequestId = "1".repeat(32), planDigest = "2".repeat(64),
        profileFingerprint = "3".repeat(64), strategyFingerprint = "4".repeat(64),
        relayFingerprint = "5".repeat(64), diagnostics = VpnRuntimeDiagnostics(tunPacketsRead = 7))

    @Test fun preservesSafeActiveStatusAndTerminalFailure() {
        for (value in listOf(active(), VpnRuntimeSnapshot(),
            VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED, failure = "NETWORK_UNAVAILABLE"))) {
            assertEquals(value, RuntimeStatusWire.decode(RuntimeStatusWire.encode(value)))
        }
    }

    @Test fun rejectsUnknownVersionTruncationTrailingBytesAndOversizedInput() {
        val bytes = RuntimeStatusWire.encode(active())
        for (size in 0 until bytes.size) rejected { RuntimeStatusWire.decode(bytes.copyOf(size)) }
        rejected { RuntimeStatusWire.decode(bytes + 0) }
        rejected { RuntimeStatusWire.decode(ByteArray(4097)) }
        rejected { RuntimeStatusWire.decode(bytes.copyOf().also { it[7] = 99 }) }
        rejected { RuntimeStatusWire.decode(bytes.copyOf().also { it[0] = 0 }) }
    }

    @Test fun refusesMalformedOrIncompleteActiveStatusInsteadOfPublishingIt() {
        for (value in listOf(active().copy(packetsRead = -1), active().copy(profileGeneration = 0uL),
            active().copy(failure = "secret / unbounded message"), active().copy(runtimeRequestId = null))) {
            rejected { RuntimeStatusWire.encode(value) }
        }
    }

    @Test fun refusesHistoricalConformanceStatesOnTheProductionControlChannel() {
        val idle = RuntimeStatusWire.encode(VpnRuntimeSnapshot())
        for (state in listOf("ACTIVE_LOCAL_ONLY", "ACTIVE_KURD_LOOPBACK")) {
            // Retain a wire rejection check even though these states no longer exist in the product enum.
            val historical = idle.copyOfRange(0, 8) + byteArrayOf(state.length.toByte()) +
                state.toByteArray(Charsets.US_ASCII) + idle.copyOfRange(13, idle.size)
            rejected { RuntimeStatusWire.decode(historical) }
        }
    }

    private fun rejected(block: () -> Unit) {
        try { block(); fail("Malformed runtime status accepted") }
        catch (_: IllegalArgumentException) { }
    }
}
