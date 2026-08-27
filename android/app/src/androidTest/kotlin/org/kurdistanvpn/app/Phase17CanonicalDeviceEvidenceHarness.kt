// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** These are JVM contract checks, not device qualification journeys. */
class Phase17CanonicalDeviceEvidenceHarnessContractTest {
    private fun invocation() = Phase17CanonicalDeviceEvidenceHarness.Invocation(
        "1".repeat(64), "2".repeat(64), "3".repeat(32), "4".repeat(32), "5".repeat(32), "D01",
    )

    @Test
    fun signedBytesHaveDefensiveOwnershipAndNoSuccessConclusion() {
        val bytes = byteArrayOf(1, 2, 3)
        val observation = Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation(
            invocation(), Phase17CanonicalDeviceEvidenceHarness.Role.HOST,
            Phase17CanonicalDeviceEvidenceHarness.Fact.PROCESS, 1, bytes,
        )
        bytes[0] = 9
        observation.copySignedEnvelope()[1] = 9
        assertArrayEquals(byteArrayOf(1, 2, 3), observation.copySignedEnvelope())
        assertEquals("UnverifiedSignedObservation(HOST, PROCESS)", observation.toString())
    }

    @Test
    fun roleConfusionAndNumericBoundsAreRejectedBeforeRetention() {
        for (sequence in listOf(Long.MIN_VALUE, 0, 4097, Long.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) {
                Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation(
                    invocation(), Phase17CanonicalDeviceEvidenceHarness.Role.HOST,
                    Phase17CanonicalDeviceEvidenceHarness.Fact.PROCESS, sequence, byteArrayOf(1),
                )
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation(
                invocation(), Phase17CanonicalDeviceEvidenceHarness.Role.DEFAULT,
                Phase17CanonicalDeviceEvidenceHarness.Fact.PROCESS, 1, byteArrayOf(1),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation(
                invocation(), Phase17CanonicalDeviceEvidenceHarness.Role.HOST,
                Phase17CanonicalDeviceEvidenceHarness.Fact.PROCESS, 1, ByteArray(65537),
            )
        }
    }
}

/** Adapter contracts only. This file installs nothing and runs no shell or network commands.
 * Signatures identify provisioned observers; they do not establish observer honesty.
 * Only the offline Go verifier can derive a tier or validate a terminal ledger.
 */
class Phase17CanonicalDeviceEvidenceHarness private constructor() {
    enum class Role { CONTROLLER, CUSTODY, LEDGER, HOST, OS, DEFAULT, VPN, INSTRUMENTATION, GATEWAY, REMOTE, DNS }
    enum class Fact {
        INSTALL, PROCESS, SERVICE, RUNTIME, TUN, ROUTE, EGRESS, CAPTURE, PACKET, PROBE, DNS, DNS_RECEIPT,
        LIFECYCLE, INTERFACE, CASE, COMMAND, TRACE, BOUNDARY, RESOURCE, STATUS, FLOW,
    }
    enum class Tier { CONTROLLED_PROBE, ROUTE_TUN, DNS_TRANSACTION, PER_UID, DEVICE_WIDE }

    /** IDs are opaque 128-bit values, never endpoints, authority keys, or APK paths. */
    class Invocation(
        val subjectSha256: String,
        val authorizationSha256: String,
        val invocationId: String,
        val bootId: String,
        val sessionId: String,
        val journeyId: String,
    ) {
        init {
            require(subjectSha256.matches(HEX_256) && authorizationSha256.matches(HEX_256))
            require(listOf(invocationId, bootId, sessionId).all { it.matches(HEX_128) })
            require(journeyId.matches(Regex("D0[1-8]")))
        }
    }

    /** Exact signed bytes, deliberately labelled unverified. No parsing/re-encoding here. */
    class UnverifiedSignedObservation(
        val invocation: Invocation,
        val claimedRole: Role,
        val claimedFact: Fact,
        val observerSequence: Long,
        signedEnvelope: ByteArray,
    ) {
        private val bytes: ByteArray
        init {
            require(observerSequence in 1..MAX_RECORDS.toLong())
            require(signedEnvelope.isNotEmpty() && signedEnvelope.size <= MAX_OBSERVATION_BYTES)
            require(roleMayObserve(claimedRole, claimedFact))
            bytes = signedEnvelope.copyOf()
        }
        fun copySignedEnvelope(): ByteArray = bytes.copyOf()
        override fun toString(): String = "UnverifiedSignedObservation($claimedRole, $claimedFact)"
    }

    /** An app instrumentation callback cannot supply HOST, OS or network observer facts. */
    interface AppRuntimeAdapter {
        val role: Role
        fun snapshot(invocation: Invocation): List<UnverifiedSignedObservation>
    }

    /** Implementations are independently provisioned outside the app under test. */
    interface ExternalObserverAdapter {
        val role: Role
        fun snapshot(invocation: Invocation): List<UnverifiedSignedObservation>
    }

    /**
     * External provisioning supplies only already-signed raw envelopes. This
     * AndroidTest module neither creates observers nor interprets their bytes.
     */
    interface AuthenticatedRawObservationSource {
        val capabilities: Set<Fact>
        fun observations(invocation: Invocation): List<UnverifiedSignedObservation>
    }

    class RawObservationAdmission(private val expected: Invocation) {
        fun admit(source: AuthenticatedRawObservationSource, required: Set<Fact>): List<UnverifiedSignedObservation> {
            require(source.capabilities.containsAll(required))
            val observations = source.observations(expected)
            require(observations.isNotEmpty() && observations.size <= MAX_RECORDS)
            val sequences = mutableSetOf<Pair<Role, Long>>()
            observations.forEach { observation ->
                require(Phase17CanonicalDeviceEvidenceHarness.sameInvocation(expected, observation.invocation))
                require(sequences.add(observation.claimedRole to observation.observerSequence))
                require(observation.copySignedEnvelope().size <= MAX_OBSERVATION_BYTES)
            }
            require(required.all { fact -> observations.any { it.claimedFact == fact } })
            return observations.toList()
        }
    }

    /**
     * Provisioned system collectors expose only signed, read-only records.
     * These names are collection boundaries, not journey verdicts: they cannot
     * start a VPN, inject traffic, change policy, or emit PASS/FAIL.
     */
    interface ReadOnlySystemObservationEndpoints : ExternalObserverAdapter {
        fun installation(invocation: Invocation): List<UnverifiedSignedObservation>
        fun processState(invocation: Invocation): List<UnverifiedSignedObservation>
        fun serviceDispatch(invocation: Invocation): List<UnverifiedSignedObservation>
        fun lifecycle(invocation: Invocation): List<UnverifiedSignedObservation>
        fun tunAndRoute(invocation: Invocation): List<UnverifiedSignedObservation>
        fun effectiveUidFlow(invocation: Invocation): List<UnverifiedSignedObservation>
        fun interfaceAvailability(invocation: Invocation): List<UnverifiedSignedObservation>
        fun gatewayCapture(invocation: Invocation): List<UnverifiedSignedObservation>
    }

    interface CalibratedClockAdapter {
        /** Signed DEVICE_CLOCK receipt with the observer boot ID and controller nonce. */
        fun signedClockReceipt(invocation: Invocation, controllerNonce: String): ByteArray
    }

    interface CustodyReceiver {
        /** Preserve arrival order; append a signed DEVICE_RECEIVED record without sorting. */
        fun append(observation: UnverifiedSignedObservation)
    }

    interface TerminalLedger {
        /** Receives the offline verifier-produced terminal, never caller-authored PASS checks. */
        fun appendUnverifiedTerminal(signedTerminalEnvelope: ByteArray)
    }

    companion object {
        const val MAX_RECORDS = 4096
        const val MAX_OBSERVATION_BYTES = 64 * 1024
        const val MAX_BUNDLE_BYTES = 4 * 1024 * 1024
        private val HEX_128 = Regex("[0-9a-f]{32}")
        private val HEX_256 = Regex("[0-9a-f]{64}")

        fun validateAppAdapter(adapter: AppRuntimeAdapter) {
            require(adapter.role == Role.DEFAULT || adapter.role == Role.VPN)
        }

        fun validateExternalAdapter(adapter: ExternalObserverAdapter) {
            require(adapter.role in setOf(Role.HOST, Role.OS, Role.INSTRUMENTATION, Role.GATEWAY, Role.REMOTE, Role.DNS))
        }

        private fun sameInvocation(left: Invocation, right: Invocation): Boolean =
            left.subjectSha256 == right.subjectSha256 &&
                left.authorizationSha256 == right.authorizationSha256 &&
                left.invocationId == right.invocationId && left.bootId == right.bootId &&
                left.sessionId == right.sessionId && left.journeyId == right.journeyId

        private fun roleMayObserve(role: Role, fact: Fact): Boolean = when (fact) {
            Fact.INSTALL, Fact.SERVICE, Fact.COMMAND, Fact.TUN, Fact.ROUTE, Fact.EGRESS,
            Fact.LIFECYCLE, Fact.INTERFACE, Fact.STATUS, Fact.FLOW -> role == Role.OS
            Fact.CASE -> role == Role.CONTROLLER
            Fact.TRACE, Fact.BOUNDARY, Fact.RESOURCE -> role == Role.INSTRUMENTATION
            Fact.PROCESS -> role == Role.HOST
            Fact.RUNTIME -> role == Role.DEFAULT || role == Role.VPN
            Fact.CAPTURE, Fact.PACKET, Fact.DNS -> role == Role.GATEWAY
            Fact.PROBE -> role == Role.REMOTE
            Fact.DNS_RECEIPT -> role == Role.DNS
        }
    }
}
