// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.assertThrows
import org.junit.Assert.assertEquals
import org.junit.Test
import org.kurdistanvpn.app.Phase17CanonicalDeviceEvidenceHarness.Fact

/** Contract failures are the expected local result without external observers. */
class Phase17BootQualificationDeviceTest {
    private fun invocation(journey: String) = Phase17CanonicalDeviceEvidenceHarness.Invocation(
        "1".repeat(64), "2".repeat(64), "3".repeat(32), "4".repeat(32), "5".repeat(32), journey,
    )

    private val unavailable = object : Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource {
        override val capabilities = emptySet<Phase17CanonicalDeviceEvidenceHarness.Fact>()
        override fun observations(invocation: Phase17CanonicalDeviceEvidenceHarness.Invocation) = emptyList<Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation>()
    }

    @Test
    fun d01RequiresExternalColdStartObservers() = assertUnavailable("D01") { it.collectD01(unavailable) }
    @Test
    fun d02RequiresExternalDefaultDeathObservers() = assertUnavailable("D02") { it.collectD02(unavailable) }
    @Test
    fun d03RequiresExternalVpnReissueObservers() = assertUnavailable("D03") { it.collectD03(unavailable) }
    @Test
    fun d04RequiresExternalNegativeMatrixObservers() = assertUnavailable("D04") { it.collectD04(unavailable) }
    @Test
    fun d05RequiresExternalOverlapObservers() = assertUnavailable("D05") { it.collectD05(unavailable) }
    @Test
    fun d06RequiresExternalDeathRecoveryObservers() = assertUnavailable("D06") { it.collectD06(unavailable) }
    @Test
    fun d07RequiresExternalBootUnlockObservers() = assertUnavailable("D07") { it.collectD07(unavailable) }
    @Test
    fun d08RequiresExternalFailureCleanupObservers() = assertUnavailable("D08") { it.collectD08(unavailable) }

    @Test
    fun d01AdmitsOnlyExternallySuppliedColdStartEnvelopeFixture() = assertFixture("D01") { it.collectD01(fixtureSource("D01")) }
    @Test
    fun d02AdmitsOnlyExternallySuppliedDeathEnvelopeFixture() = assertFixture("D02") { it.collectD02(fixtureSource("D02")) }
    @Test
    fun d03AdmitsOnlyExternallySuppliedReissueEnvelopeFixture() = assertFixture("D03") { it.collectD03(fixtureSource("D03")) }
    @Test
    fun d04AdmitsOnlyExternallySuppliedNegativeEnvelopeFixture() = assertFixture("D04") { it.collectD04(fixtureSource("D04")) }
    @Test
    fun d05AdmitsOnlyExternallySuppliedOverlapEnvelopeFixture() = assertFixture("D05") { it.collectD05(fixtureSource("D05")) }
    @Test
    fun d06AdmitsOnlyExternallySuppliedRecoveryEnvelopeFixture() = assertFixture("D06") { it.collectD06(fixtureSource("D06")) }
    @Test
    fun d07AdmitsOnlyExternallySuppliedBootEnvelopeFixture() = assertFixture("D07") { it.collectD07(fixtureSource("D07")) }
    @Test
    fun d08AdmitsOnlyExternallySuppliedCleanupEnvelopeFixture() = assertFixture("D08") { it.collectD08(fixtureSource("D08")) }

    @Test
    fun d04SourceContractNamesEveryUnauthorizedAndInvalidAuthorityCase() {
        assertEquals(25, Phase17BootQualificationCollectors.D04_CASES.size)
        assertEquals(
            setOf(
                "D04_MALFORMED_FRAME", "D04_REPLAYED_FRAME", "D04_WRONG_REQUEST", "D04_WRONG_PURPOSE",
                "D04_WRONG_EPOCH", "D04_WRONG_GENERATION", "D04_WRONG_REVISION", "D04_EXPIRED_DEADLINE",
                "D04_WRONG_CAPABILITY_CHANNEL", "D04_WRONG_FRAME_CHANNEL",
            ),
            Phase17BootQualificationCollectors.D04_CASES.filter {
                it in setOf(
                    "D04_MALFORMED_FRAME", "D04_REPLAYED_FRAME", "D04_WRONG_REQUEST", "D04_WRONG_PURPOSE",
                    "D04_WRONG_EPOCH", "D04_WRONG_GENERATION", "D04_WRONG_REVISION", "D04_EXPIRED_DEADLINE",
                    "D04_WRONG_CAPABILITY_CHANNEL", "D04_WRONG_FRAME_CHANNEL",
                )
            }.toSet(),
        )
    }

    @Test
    fun d08SourceContractNamesEveryFallibleActivationBoundary() {
        assertEquals(24, Phase17BootQualificationCollectors.D08_CASES.size)
        assertEquals(
            setOf(
                "PARSING", "AUTHORITY_OPEN", "SOCKET_CREATION", "SOCKET_PROTECTION", "NETWORK_BINDING",
                "CONNECTION", "AUTHENTICATION", "TUN_CONSTRUCTION", "TUN_ESTABLISHMENT", "TUN_DETACH",
                "TUN_ATTACHMENT", "CALLBACK_REGISTRATION", "NOTIFICATION_PREPARATION",
                "HEALTH_MONITOR_INSTALLATION", "REVISION_VALIDATION", "ACTIVE_COMMIT",
            ),
            Phase17BootQualificationCollectors.D08_BOUNDARIES,
        )
    }

    private fun assertUnavailable(
        journey: String,
        collect: (Phase17BootQualificationCollectors) -> Unit,
    ) {
        assertThrows(IllegalArgumentException::class.java) { collect(Phase17BootQualificationCollectors(invocation(journey))) }
    }

    private fun assertFixture(journey: String, collect: (Phase17BootQualificationCollectors) -> List<Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation>) {
        val observations = collect(Phase17BootQualificationCollectors(invocation(journey)))
        assertEquals(Phase17CanonicalDeviceEvidenceHarness.Fact.values().size, observations.size)
    }

    private fun fixtureSource(journey: String) = object : Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource {
        override val capabilities = Phase17CanonicalDeviceEvidenceHarness.Fact.values().toSet()
        override fun observations(invocation: Phase17CanonicalDeviceEvidenceHarness.Invocation) =
            Phase17CanonicalDeviceEvidenceHarness.Fact.values().mapIndexed { index, fact ->
                Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation(
                    invocation, roleFor(fact), fact, (index + 1).toLong(), byteArrayOf((index + 1).toByte()),
                )
            }
        private fun roleFor(fact: Phase17CanonicalDeviceEvidenceHarness.Fact) = when (fact) {
            Fact.CASE -> Phase17CanonicalDeviceEvidenceHarness.Role.CONTROLLER
            Fact.TRACE, Fact.BOUNDARY, Fact.RESOURCE -> Phase17CanonicalDeviceEvidenceHarness.Role.INSTRUMENTATION
            Fact.PROCESS -> Phase17CanonicalDeviceEvidenceHarness.Role.HOST
            Fact.RUNTIME -> Phase17CanonicalDeviceEvidenceHarness.Role.DEFAULT
            Fact.CAPTURE, Fact.PACKET, Fact.DNS -> Phase17CanonicalDeviceEvidenceHarness.Role.GATEWAY
            Fact.PROBE -> Phase17CanonicalDeviceEvidenceHarness.Role.REMOTE
            Fact.DNS_RECEIPT -> Phase17CanonicalDeviceEvidenceHarness.Role.DNS
            else -> Phase17CanonicalDeviceEvidenceHarness.Role.OS
        }
    }
}

/**
 * Compile-only admission entrypoints for separately provisioned device
 * observers. They execute no lifecycle, VPN, network, policy, or fault action.
 * Returned envelopes remain unverified until the offline Go verifier consumes
 * their exact bytes with the external roster, clocks, custody, and terminal.
 */
class Phase17BootQualificationCollectors(
    private val invocation: Phase17CanonicalDeviceEvidenceHarness.Invocation,
) {
    private val admission = Phase17CanonicalDeviceEvidenceHarness.RawObservationAdmission(invocation)

    fun collectD01(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.SERVICE, Fact.LIFECYCLE, Fact.TUN, Fact.ROUTE, Fact.CAPTURE, Fact.PACKET, Fact.PROBE))
    fun collectD02(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.PROCESS, Fact.LIFECYCLE, Fact.TUN))
    fun collectD03(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.PROCESS, Fact.LIFECYCLE, Fact.RUNTIME, Fact.TUN, Fact.CAPTURE, Fact.PACKET, Fact.PROBE))
    fun collectD04(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.CASE, Fact.COMMAND, Fact.LIFECYCLE, Fact.FLOW, Fact.INTERFACE, Fact.CAPTURE, Fact.TRACE, Fact.BOUNDARY, Fact.RESOURCE, Fact.STATUS))
    fun collectD05(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.SERVICE, Fact.LIFECYCLE, Fact.RUNTIME, Fact.TUN))
    fun collectD06(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.PROCESS, Fact.LIFECYCLE, Fact.RUNTIME))
    fun collectD07(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.LIFECYCLE, Fact.PROCESS, Fact.RUNTIME, Fact.TUN, Fact.CAPTURE, Fact.PACKET, Fact.PROBE))
    fun collectD08(source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource) =
        collect(source, setOf(Fact.CASE, Fact.COMMAND, Fact.LIFECYCLE, Fact.TUN, Fact.FLOW, Fact.INTERFACE, Fact.CAPTURE, Fact.TRACE, Fact.BOUNDARY, Fact.RESOURCE, Fact.STATUS))

    private fun collect(
        source: Phase17CanonicalDeviceEvidenceHarness.AuthenticatedRawObservationSource,
        required: Set<Phase17CanonicalDeviceEvidenceHarness.Fact>,
    ): List<Phase17CanonicalDeviceEvidenceHarness.UnverifiedSignedObservation> = admission.admit(source, required)

    companion object {
        val D04_CASES = listOf(
            "D04_NULL_INTENT", "D04_UNKNOWN_ACTION", "D04_UNAUTHORIZED_MARKER", "D04_MISSING_AUTHORITY",
            "D04_MALFORMED_FRAME", "D04_SHORT_FRAME", "D04_TRAILING_FRAME", "D04_OVERSIZE_FRAME",
            "D04_TAMPERED_FRAME", "D04_REPLAYED_FRAME", "D04_WRONG_REQUEST", "D04_WRONG_PURPOSE",
            "D04_WRONG_EPOCH", "D04_WRONG_GENERATION", "D04_WRONG_REVISION", "D04_EXPIRED_DEADLINE",
            "D04_WRONG_CAPABILITY_CHANNEL", "D04_WRONG_FRAME_CHANNEL", "D04_EXPIRED_AUTHORITY",
            "D04_REVOKED_AUTHORITY", "D04_WRONG_RECIPIENT", "D04_WRONG_IDENTITY",
            "D04_KEY_INVALID_AUTHORITY", "D04_CONSENT_UNAVAILABLE", "D04_PREPARED_UNAVAILABLE",
        )
        val D08_CASES = listOf(
            "D08_PARSING_THROW", "D08_AUTHORITY_OPEN_THROW", "D08_SOCKET_CREATE_THROW",
            "D08_SOCKET_PROTECT_FALSE", "D08_NETWORK_BIND_THROW", "D08_CONNECT_THROW",
            "D08_AUTHENTICATE_THROW", "D08_TUN_BUILD_THROW", "D08_TUN_ESTABLISH_NULL",
            "D08_TUN_ESTABLISH_THROW", "D08_TUN_DETACH_THROW", "D08_TUN_ATTACH_THROW",
            "D08_CALLBACK_REGISTER_THROW", "D08_NOTIFICATION_PREPARE_THROW",
            "D08_HEALTH_MONITOR_INSTALL_THROW", "D08_REVISION_VALIDATE_STALE",
            "D08_ACTIVE_COMMIT_THROW", "D08_STOP", "D08_REVOKE", "D08_BINDER_DEATH",
            "D08_PROVIDER_DEATH", "D08_TIMEOUT", "D08_CLEANUP_RETRYABLE", "D08_CLEANUP_UNPROVEN",
        )
        val D08_BOUNDARIES = setOf(
            "PARSING", "AUTHORITY_OPEN", "SOCKET_CREATION", "SOCKET_PROTECTION", "NETWORK_BINDING",
            "CONNECTION", "AUTHENTICATION", "TUN_CONSTRUCTION", "TUN_ESTABLISHMENT", "TUN_DETACH",
            "TUN_ATTACHMENT", "CALLBACK_REGISTRATION", "NOTIFICATION_PREPARATION",
            "HEALTH_MONITOR_INSTALLATION", "REVISION_VALIDATION", "ACTIVE_COMMIT",
        )
    }
}
