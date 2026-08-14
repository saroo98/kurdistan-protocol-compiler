// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.test.platform.app.InstrumentationRegistry
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertTrue
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.secure.AdmissionResult
import org.kurdistanvpn.data.secure.ClientKeyResult
import org.kurdistanvpn.platform.importing.ArtifactClass
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.platform.importing.IngressKind
import org.kurdistanvpn.platform.importing.VerifyRequestEncoder
import org.kurdistanvpn.runtime.api.RuntimeStartWire
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

/**
 * Test-only owner-field bridge. It moves only public enrollment material and an
 * owner-supplied sealed profile through app-private files. Production variants
 * never contain this class or its fixed field-test protocol.
 */
internal object Phase17FieldHarness {
    private const val ARG_ACTION = "phase17FieldAction"
    private const val ARG_ATTEMPT_ID = "phase17AttemptId"
    private const val FIELD_DIRECTORY = "phase17-field"
    private const val RECIPIENT_REQUEST = "recipient-request.bin"
    private const val SEALED_PROFILE = "sealed-profile.bin"
    private const val RESULT = "result.txt"
    private const val ATTEMPT = "attempt.txt"
    private const val MAX_RECIPIENT_REQUEST_BYTES = 512
    private const val MAX_PROFILE_BYTES = 1_500_000
    private const val ARG_PROBE_URL = "phase17ProbeUrl"
    private const val ARG_EXPECTED_RESPONSE_SHA256 = "phase17ExpectedResponseSha256"
    private const val ARG_DNS_FAMILY = "phase17DnsFamily"
    private const val ARG_EXPECT_DNS_AVAILABLE = "phase17ExpectDnsAvailable"
    private const val ARG_VERIFY_IPV6 = "phase17VerifyIPv6"
    private const val MAX_PROBE_RESPONSE_BYTES = 64
    private const val VPN_NETWORK_READY_TIMEOUT_MILLIS = 10_000L
    private const val VPN_DNS_RESOLVER_READY_TIMEOUT_MILLIS = 10_000L
    private const val LIVE_RECONNECT_READY_TIMEOUT_MILLIS = 120_000L
    private const val VPN_NETWORK_TEARDOWN_TIMEOUT_MILLIS = 15_000L
    private const val VPN_NETWORK_POLL_MILLIS = 50L
    private const val BOUNDARY_ANDROID_SCHEMA = "kurdistan-phase17-boundary-android-v1"

    internal data class BoundarySnapshot(
        val vpnActive: Boolean,
        val ipv4Default: Boolean,
        val ipv6Default: Boolean,
        val dnsPinned: Boolean,
        val bypassBlocked: Boolean,
        val coverageGap: Boolean,
    )

    internal fun evaluateBoundarySnapshot(
        value: BoundarySnapshot,
        verifyIpv6: Boolean,
    ): Boolean =
        value.vpnActive &&
            value.ipv4Default &&
            (!verifyIpv6 || value.ipv6Default) &&
            value.dnsPinned &&
            value.bypassBlocked &&
            !value.coverageGap

    internal fun isExpectedDnsUnavailableFailure(
        expectAvailable: Boolean,
        failure: Throwable,
    ): Boolean = !expectAvailable && failure is IOException

    internal fun runDnsExchange(
        expectAvailable: Boolean,
        exchange: () -> Unit,
    ): Boolean = try {
        exchange()
        true
    } catch (failure: IOException) {
        check(isExpectedDnsUnavailableFailure(expectAvailable, failure)) {
            "DNS_UNAVAILABLE"
        }
        false
    }

    internal fun isExpectedDnsStartupFailure(
        expectAvailable: Boolean,
        state: VpnRuntimeState,
        failure: String?,
        packetDisposition: String?,
    ): Boolean =
        !expectAvailable &&
            state == VpnRuntimeState.FAILED &&
            failure in setOf("LIVE_TLS_REJECTED", "LIVE_FALLBACK_EXHAUSTED") &&
            packetDisposition == "LIVE_STAGE_SOCKET_PROTECTED"

    internal suspend fun awaitNetworkScopedDnsReadiness(
        timeoutMillis: Long,
        pollMillis: Long,
        resolve: suspend () -> Unit,
    ): Int {
        require(timeoutMillis > 0 && pollMillis > 0) { "DNS_READINESS_POLICY_REJECTED" }
        var attempts = 0
        val ready = withTimeoutOrNull(timeoutMillis) {
            while (true) {
                attempts++
                try {
                    resolve()
                    return@withTimeoutOrNull true
                } catch (_: UnknownHostException) {
                    delay(pollMillis)
                }
            }
            @Suppress("UNREACHABLE_CODE")
            false
        } ?: false
        if (!ready) {
            throw UnknownHostException("VPN_DNS_RESOLVER_NOT_READY")
        }
        return attempts
    }

    internal suspend fun <T> runVerifiedProbeWithReconnect(
        initialSnapshot: VpnRuntimeSnapshot,
        runtimeSnapshots: StateFlow<VpnRuntimeSnapshot>,
        authorityPreparationCount: () -> Int,
        reconnectTimeoutMillis: Long,
        acquireNetwork: suspend () -> T,
        verify: suspend (T) -> Unit,
    ): Int {
        require(reconnectTimeoutMillis > 0) { "FIELD_RECONNECT_TIMEOUT_REJECTED" }
        validateActiveReconnectSnapshot(initialSnapshot, previous = null, signedMaximum = null)
        val signedMaximum = initialSnapshot.maxReconnectAttempts
        var current = initialSnapshot
        var observedAuthorityCount = authorityPreparationCount()
        check(observedAuthorityCount > 0) { "FIELD_RECONNECT_AUTHORITY_MISSING" }
        var consumedRetries = 0

        while (true) {
            val network = acquireNetwork()
            try {
                verify(network)
                return consumedRetries
            } catch (failure: IOException) {
                if (consumedRetries >= signedMaximum) {
                    throw IllegalStateException("FIELD_RECONNECT_EXHAUSTED", failure)
                }
                val next = withTimeoutOrNull(reconnectTimeoutMillis) {
                    runtimeSnapshots.first { candidate ->
                        isFreshSessionCandidate(candidate, current) ||
                            isTerminalReconnectObservation(candidate)
                    }
                } ?: throw IllegalStateException("FIELD_RECONNECT_TIMEOUT", failure)

                when {
                    next.state == VpnRuntimeState.REVOKED ->
                        throw IllegalStateException("FIELD_RECONNECT_REVOKED", failure)
                    next.state == VpnRuntimeState.IDLE || next.state == VpnRuntimeState.STOPPING ->
                        throw IllegalStateException("FIELD_RECONNECT_CANCELLED", failure)
                    next.failure == "RECONNECT_EXHAUSTED" ->
                        throw IllegalStateException("FIELD_RECONNECT_EXHAUSTED", failure)
                    next.state == VpnRuntimeState.FAILED || next.state == VpnRuntimeState.BLOCKED ->
                        throw IllegalStateException("FIELD_RECONNECT_NOT_RETRYABLE", failure)
                }

                validateActiveReconnectSnapshot(next, current, signedMaximum)
                val nextAuthorityCount = authorityPreparationCount()
                if (nextAuthorityCount <= observedAuthorityCount) {
                    throw IllegalStateException("FIELD_RECONNECT_AUTHORITY_NOT_FRESH", failure)
                }
                val newlyConsumed = nextAuthorityCount - observedAuthorityCount
                if (newlyConsumed > signedMaximum - consumedRetries) {
                    throw IllegalStateException("FIELD_RECONNECT_EXHAUSTED", failure)
                }
                consumedRetries += newlyConsumed
                observedAuthorityCount = nextAuthorityCount
                current = next
            }
        }
    }

    private fun isFreshSessionCandidate(
        candidate: VpnRuntimeSnapshot,
        previous: VpnRuntimeSnapshot,
    ): Boolean =
        candidate.state == VpnRuntimeState.ACTIVE_KURD_LIVE &&
            !candidate.runtimeRequestId.isNullOrBlank() &&
            candidate.runtimeRequestId != previous.runtimeRequestId

    private fun isTerminalReconnectObservation(candidate: VpnRuntimeSnapshot): Boolean = when {
        candidate.state == VpnRuntimeState.REVOKED -> true
        candidate.state == VpnRuntimeState.IDLE || candidate.state == VpnRuntimeState.STOPPING -> true
        candidate.state == VpnRuntimeState.FAILED || candidate.state == VpnRuntimeState.BLOCKED ->
            !isRetryableRuntimeFailure(candidate.failure)
        else -> false
    }

    private fun validateActiveReconnectSnapshot(
        candidate: VpnRuntimeSnapshot,
        previous: VpnRuntimeSnapshot?,
        signedMaximum: Int?,
    ) {
        check(candidate.state == VpnRuntimeState.ACTIVE_KURD_LIVE) {
            "FIELD_RECONNECT_SESSION_NOT_ACTIVE"
        }
        check(!candidate.runtimeRequestId.isNullOrBlank()) { "FIELD_RECONNECT_REQUEST_MISSING" }
        check(candidate.startedAtElapsedRealtime > 0) { "FIELD_RECONNECT_START_TIME_MISSING" }
        check(candidate.profileGeneration > 0 && !candidate.planDigest.isNullOrBlank()) {
            "FIELD_RECONNECT_AUTHORITY_EVIDENCE_MISSING"
        }
        check(candidate.maxReconnectAttempts in 1..5) { "FIELD_RECONNECT_POLICY_REJECTED" }
        if (previous == null) return

        check(candidate.runtimeRequestId != previous.runtimeRequestId) {
            "FIELD_RECONNECT_REQUEST_NOT_FRESH"
        }
        check(candidate.startedAtElapsedRealtime > previous.startedAtElapsedRealtime) {
            "FIELD_RECONNECT_START_TIME_NOT_FRESH"
        }
        check(candidate.profileGeneration == previous.profileGeneration) {
            "FIELD_RECONNECT_AUTHORITY_CHANGED"
        }
        check(candidate.planDigest == previous.planDigest) { "FIELD_RECONNECT_AUTHORITY_CHANGED" }
        check(candidate.profileFingerprint == previous.profileFingerprint) {
            "FIELD_RECONNECT_AUTHORITY_CHANGED"
        }
        check(candidate.strategyFingerprint == previous.strategyFingerprint) {
            "FIELD_RECONNECT_AUTHORITY_CHANGED"
        }
        check(candidate.relayFingerprint == previous.relayFingerprint) {
            "FIELD_RECONNECT_AUTHORITY_CHANGED"
        }
        check(candidate.maxReconnectAttempts <= requireNotNull(signedMaximum)) {
            "FIELD_RECONNECT_POLICY_WIDENED"
        }
    }

    suspend fun runIfRequested(): Boolean {
        val action = InstrumentationRegistry.getArguments().getString(ARG_ACTION)
            ?.trim()
            .orEmpty()
        if (action.isEmpty()) return false

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as KurdistanApplication
        val fieldRoot = File(application.filesDir, FIELD_DIRECTORY).apply {
            check(isDirectory || mkdirs()) { "FIELD_DIRECTORY_UNAVAILABLE" }
        }
        val attemptId = InstrumentationRegistry.getArguments()
            .getString(ARG_ATTEMPT_ID)
            ?.trim()
            .orEmpty()
        check(attemptId.matches(Regex("[0-9a-f]{32}"))) { "FIELD_ATTEMPT_ID_REJECTED" }
        writeAtomic(File(fieldRoot, ATTEMPT), "STARTED:$attemptId\n".encodeToByteArray())
        val root = application.compositionRoot
        when (action) {
            "export-recipient" -> exportRecipient(root, fieldRoot)
            "import-profile" -> importProfile(root, fieldRoot)
            "connect" -> connect(application, root, fieldRoot, shouldVerifyDataPlane = false)
            "data-plane" -> connect(application, root, fieldRoot, shouldVerifyDataPlane = true)
            "traffic" -> {
                val verifyIPv6 = InstrumentationRegistry.getArguments()
                    .getString(ARG_VERIFY_IPV6)
                    ?.toBooleanStrictOrNull()
                    ?: error("DNS_EXPECTATION_REJECTED")
                connect(
                    application,
                    root,
                    fieldRoot,
                    shouldVerifyDataPlane = true,
                    trafficDnsFamilies = if (verifyIPv6) listOf(4, 6) else listOf(4),
                )
            }
            "boundary" -> {
                val verifyIPv6 = InstrumentationRegistry.getArguments()
                    .getString(ARG_VERIFY_IPV6)
                    ?.toBooleanStrictOrNull()
                    ?: error("DNS_EXPECTATION_REJECTED")
                connect(
                    application,
                    root,
                    fieldRoot,
                    shouldVerifyDataPlane = false,
                    verifyBoundary = true,
                    boundaryVerifyIPv6 = verifyIPv6,
                    attemptId = attemptId,
                )
            }
            "dns-probe" -> {
                val arguments = InstrumentationRegistry.getArguments()
                val family = arguments.getString(ARG_DNS_FAMILY)?.toIntOrNull()
                    ?: error("DNS_FAMILY_REJECTED")
                val expectedAvailable = arguments.getString(ARG_EXPECT_DNS_AVAILABLE)
                    ?.toBooleanStrictOrNull()
                    ?: error("DNS_EXPECTATION_REJECTED")
                connect(
                    application,
                    root,
                    fieldRoot,
                    shouldVerifyDataPlane = false,
                    dnsFamily = family,
                    expectDnsAvailable = expectedAvailable,
                )
            }
            else -> error("UNKNOWN_PHASE17_FIELD_ACTION")
        }
        return true
    }

    private suspend fun exportRecipient(root: Phase9CompositionRoot, fieldRoot: File) {
        assertTrue("protected state reset failed", root.resetProtectedState())
        val coordinators = Phase13Coordinators.create(root)
        val now = System.currentTimeMillis() / 1000
        val created = coordinators.profiles.createEnrollment(
            validitySeconds = 24 * 60 * 60,
            nowEpochSeconds = now,
        )
        val summary = when (created) {
            is ClientKeyResult.Success -> created.summary
            is ClientKeyResult.Failure -> error("RECIPIENT_CREATE_FAILED:${created.error}")
        }
        val request = requireNotNull(
            coordinators.profiles.enrollmentRequest(summary.localRecordId),
        ) { "RECIPIENT_REQUEST_UNAVAILABLE" }
        try {
            require(request.size in 1..MAX_RECIPIENT_REQUEST_BYTES) {
                "RECIPIENT_REQUEST_SIZE_REJECTED"
            }
            writeAtomic(File(fieldRoot, RECIPIENT_REQUEST), request)
            coordinators.profiles.markEnrollmentRequestExported(summary.localRecordId)
            writeAtomic(File(fieldRoot, RESULT), "RECIPIENT_READY\n".encodeToByteArray())
        } finally {
            request.fill(0)
        }
    }

    private suspend fun importProfile(root: Phase9CompositionRoot, fieldRoot: File) {
        val profileFile = File(fieldRoot, SEALED_PROFILE)
        require(profileFile.isFile && profileFile.length() in 1..MAX_PROFILE_BYTES.toLong()) {
            "SEALED_PROFILE_UNAVAILABLE"
        }
        val profileBytes = withContext(Dispatchers.IO) { profileFile.readBytes() }
        val request = VerifyRequestEncoder.encode(
            ImportCandidate(
                ingress = IngressKind.FILE,
                artifactClass = ArtifactClass.DEVICE_RECIPIENT,
                parts = listOf(profileBytes),
            ),
        )
        try {
            val coordinators = Phase13Coordinators.create(root)
            val resolved = when (val result = coordinators.profiles.resolvePreview(request)) {
                is NativeResult.Success -> result.value
                is NativeResult.Failure -> error("PROFILE_PREVIEW_FAILED:${result.error}")
            }
            val expected = resolved.verified.preview
            root.nativeCore.releaseVerified(resolved.verified)
            val admission = requireNotNull(root.admissionJournal).admit(
                verifyRequest = request,
                expectedPreview = expected,
                recipientKeyLocalId = resolved.recipientKeyLocalId,
            )
            val outcome = when (admission) {
                is AdmissionResult.Success -> admission.outcome
                is AdmissionResult.Failure -> error("PROFILE_ADMISSION_FAILED:${admission.error}")
            }
            coordinators.settings.setProfiles(
                ProfilePreferences(activeLocalRecordId = outcome.localRecordId),
            )
            writeAtomic(File(fieldRoot, RESULT), "PROFILE_ACTIVE\n".encodeToByteArray())
        } finally {
            request.fill(0)
            profileBytes.fill(0)
        }
    }

    private suspend fun connect(
        application: KurdistanApplication,
        root: Phase9CompositionRoot,
        fieldRoot: File,
        shouldVerifyDataPlane: Boolean,
        dnsFamily: Int? = null,
        expectDnsAvailable: Boolean = true,
        trafficDnsFamilies: List<Int> = emptyList(),
        verifyBoundary: Boolean = false,
        boundaryVerifyIPv6: Boolean = false,
        attemptId: String = "",
    ) {
        val coordinators = Phase13Coordinators.create(root)
        val localRecordId = root.settingsStore.settings.first().profiles.activeLocalRecordId
            ?: error("ACTIVE_PROFILE_UNAVAILABLE")
        val config = VpnRuntimeConfig(
            routingPolicy = VpnRoutingPolicy(),
            mtu = 1280,
        )
        val authorityPreparations = AtomicInteger()
        val authorityProvider = FreshRuntimeAuthorityProvider {
            authorityPreparations.incrementAndGet()
            when (val result = coordinators.runtime.openLiveAuthority(localRecordId)) {
                is org.kurdistanvpn.data.secure.RuntimeAuthorityResult.Success ->
                    result.material.use { material ->
                        FreshRuntimeAuthority.Ready(
                            RuntimeStartWire.encode(
                                verifyRequest = material.verifyRequest,
                                activationRecord = material.activationRecord,
                                recipientRequest = material.recipientRequest,
                                recipientPrivate = material.recipientPrivate,
                                config = config,
                            ),
                        )
                    }
                is org.kurdistanvpn.data.secure.RuntimeAuthorityResult.Failure ->
                    FreshRuntimeAuthority.Rejected(result.error.name)
                null -> FreshRuntimeAuthority.Rejected("STORAGE_FAILURE")
            }
        }
        val encoded = when (val prepared = authorityProvider.prepare()) {
            is FreshRuntimeAuthority.Ready -> prepared.encoded
            is FreshRuntimeAuthority.Rejected ->
                error("RUNTIME_AUTHORITY_FAILED:${prepared.failure}")
        }
        val controller = VpnRuntimeController(application)
        try {
            check(controller.prepareIntent() == null) { "VPN_CONSENT_REQUIRED" }
            controller.stageAuthority(encoded, authorityProvider)
            controller.startStaged()
            val snapshot = withTimeoutOrNull(120_000) {
                controller.snapshot.first { value ->
                    value.state == VpnRuntimeState.ACTIVE_KURD_LIVE ||
                        value.state == VpnRuntimeState.FAILED ||
                        value.state == VpnRuntimeState.BLOCKED ||
                        value.state == VpnRuntimeState.REVOKED
                }
            } ?: error(
                "LIVE_CONNECT_TIMEOUT:${controller.snapshot.value.state.name}:" +
                    (controller.snapshot.value.packetDisposition
                        ?: controller.snapshot.value.failure
                        ?: "NONE"),
            )
            if (
                dnsFamily != null &&
                isExpectedDnsStartupFailure(
                    expectAvailable = expectDnsAvailable,
                    state = snapshot.state,
                    failure = snapshot.failure,
                    packetDisposition = snapshot.packetDisposition,
                )
            ) {
                writeAtomic(
                    File(fieldRoot, RESULT),
                    "DNS_IPV${dnsFamily}_FAIL_CLOSED\n".encodeToByteArray(),
                )
                return
            }
            check(snapshot.state == VpnRuntimeState.ACTIVE_KURD_LIVE) {
                "LIVE_CONNECT_FAILED:${snapshot.failure ?: snapshot.state.name}:" +
                    (snapshot.packetDisposition ?: "NONE")
            }
            check(snapshot.profileGeneration > 0 && !snapshot.planDigest.isNullOrBlank()) {
                "LIVE_SESSION_EVIDENCE_MISSING"
            }
            check(snapshot.maxReconnectAttempts in 1..5) {
                "LIVE_RECONNECT_POLICY_MISSING"
            }
            if (shouldVerifyDataPlane || dnsFamily != null || trafficDnsFamilies.isNotEmpty() || verifyBoundary) {
                val requiredDnsFamilies = when {
                    trafficDnsFamilies.isNotEmpty() -> trafficDnsFamilies
                    dnsFamily != null -> listOf(dnsFamily)
                    else -> listOf(4)
                }
                val stable = controller.snapshot.value
                check(stable.state == VpnRuntimeState.ACTIVE_KURD_LIVE) {
                    "LIVE_RUNTIME_UNSTABLE:${stable.failure ?: stable.state.name}:" +
                        (stable.packetDisposition ?: "NONE")
                }
                try {
                    var boundarySnapshot: BoundarySnapshot? = null
                    runVerifiedProbeWithReconnect(
                        initialSnapshot = stable,
                        runtimeSnapshots = controller.snapshot,
                        authorityPreparationCount = authorityPreparations::get,
                        reconnectTimeoutMillis = LIVE_RECONNECT_READY_TIMEOUT_MILLIS,
                        acquireNetwork = {
                            if (verifyBoundary) {
                                awaitVpnNetwork(application)
                            } else {
                                awaitVerifiedVpnNetwork(application, requiredDnsFamilies)
                            }
                        },
                        verify = { vpnNetwork ->
                            val observedBoundary = observeNetworkBoundary(
                                application,
                                vpnNetwork,
                                verifyIpv6 = if (verifyBoundary) boundaryVerifyIPv6 else trafficDnsFamilies.contains(6),
                            )
                            boundarySnapshot = observedBoundary
                            if (!verifyBoundary) {
                                check(
                                    evaluateBoundarySnapshot(
                                        observedBoundary,
                                        verifyIpv6 = trafficDnsFamilies.contains(6),
                                    ),
                                ) { "BOUNDARY_LEAK" }
                            }
                            if (trafficDnsFamilies.isNotEmpty()) {
                                trafficDnsFamilies.forEach { family ->
                                    verifyDnsPlane(vpnNetwork, family, expectAvailable = true)
                                }
                                verifyDataPlane(vpnNetwork)
                            } else if (dnsFamily == null) {
                                verifyDataPlane(vpnNetwork)
                            } else {
                                verifyDnsPlane(vpnNetwork, dnsFamily, expectDnsAvailable)
                            }
                        },
                    )
                    if (verifyBoundary) {
                        writeBoundaryObservation(
                            fieldRoot = fieldRoot,
                            attemptId = attemptId,
                            value = requireNotNull(boundarySnapshot) { "BOUNDARY_COVERAGE_GAP" },
                        )
                    } else if (trafficDnsFamilies.isNotEmpty()) {
                        writeAtomic(File(fieldRoot, RESULT), "TRAFFIC_VERIFIED\n".encodeToByteArray())
                    } else if (dnsFamily == null) {
                        writeAtomic(File(fieldRoot, RESULT), "DATA_PLANE_VERIFIED\n".encodeToByteArray())
                    } else {
                        val outcome = if (expectDnsAvailable) "VERIFIED" else "FAIL_CLOSED"
                        writeAtomic(
                            File(fieldRoot, RESULT),
                            "DNS_IPV${dnsFamily}_$outcome\n".encodeToByteArray(),
                        )
                    }
                } catch (failure: Throwable) {
                    if (failure.message == "BOUNDARY_LEAK") {
                        writeAtomic(File(fieldRoot, RESULT), "BOUNDARY_LEAK\n".encodeToByteArray())
                        throw failure
                    }
                    val category = if (failure is SocketTimeoutException) "TIMEOUT" else "PROBE_FAILED"
                    val diagnostics = controller.snapshot.value.diagnostics.let { value ->
                            ":tun-read=${value.tunPacketsRead}" +
                                ":outbound=${value.outboundPacketsAccepted}" +
                                ":carrier-write=${value.carrierRecordsWritten}" +
                                ":carrier-read=${value.carrierRecordsRead}" +
                                ":authenticated=${value.authenticatedOperations}" +
                                ":inner-accepted=${value.innerPacketsAccepted}" +
                                ":inner-rejected=${value.innerPacketsRejected}" +
                                ":tun-attempts=${value.tunWriteAttempts}" +
                                ":tun-failures=${value.tunWriteFailures}" +
                                ":tun-failure-code=${value.tunWriteFailureCode}" +
                                ":tun-errno=${value.tunWriteErrno}" +
                                ":tun-write=${value.tunPacketsWritten}" +
                                ":rejected=${value.rejectedTunPackets}" +
                                ":rejection-code=${value.rejectedTunPacketCode}"
                    }
                    writeAtomic(
                        File(fieldRoot, RESULT),
                        "DATA_PLANE_$category$diagnostics\n".encodeToByteArray(),
                    )
                    throw failure
                }
            } else {
                writeAtomic(File(fieldRoot, RESULT), "CONNECTED\n".encodeToByteArray())
            }
        } finally {
            encoded.fill(0)
            try {
                controller.stop()
                check(
                    withTimeoutOrNull(15_000) {
                        controller.snapshot.first { value -> value.state == VpnRuntimeState.IDLE }
                    } != null,
                ) { "LIVE_STOP_TIMEOUT" }
                check(awaitVpnNetworkTeardown(application)) {
                    "VPN_NETWORK_TEARDOWN_TIMEOUT"
                }
            } finally {
                controller.close()
            }
        }
    }

    private suspend fun awaitVpnNetworkTeardown(context: Context): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        return VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
            timeoutMillis = VPN_NETWORK_TEARDOWN_TIMEOUT_MILLIS,
            pollMillis = VPN_NETWORK_POLL_MILLIS,
            vpnTransportSnapshot = {
                VpnNetworkTeardownBarrier.snapshot(connectivity)
            },
        )
    }

    private suspend fun awaitVerifiedVpnNetwork(
        context: Context,
        requiredDnsFamilies: List<Int>,
    ): Network {
        require(requiredDnsFamilies.isNotEmpty() && requiredDnsFamilies.all { it == 4 || it == 6 }) {
            "DNS_FAMILY_REJECTED"
        }
        val expectedDns = requiredDnsFamilies.map { family ->
            InetAddress.getByName(if (family == 4) "10.77.0.1" else "fd4b:7572:6400::1")
        }.toSet()
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        return withTimeoutOrNull(VPN_NETWORK_READY_TIMEOUT_MILLIS) {
            while (true) {
                val network = connectivity.activeNetwork
                val capabilities = network?.let(connectivity::getNetworkCapabilities)
                val properties = network?.let(connectivity::getLinkProperties)
                if (
                    network != null &&
                    capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                    properties != null &&
                    properties.dnsServers.containsAll(expectedDns)
                ) {
                    return@withTimeoutOrNull network
                }
                delay(50)
            }
            @Suppress("UNREACHABLE_CODE")
            null
        } ?: error("VPN_NETWORK_NOT_READY")
    }

    private suspend fun awaitVpnNetwork(context: Context): Network {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        return withTimeoutOrNull(VPN_NETWORK_READY_TIMEOUT_MILLIS) {
            while (true) {
                val network = connectivity.activeNetwork
                val capabilities = network?.let(connectivity::getNetworkCapabilities)
                if (network != null && capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    return@withTimeoutOrNull network
                }
                delay(VPN_NETWORK_POLL_MILLIS)
            }
            @Suppress("UNREACHABLE_CODE")
            null
        } ?: error("VPN_NETWORK_NOT_READY")
    }

    @Suppress("DEPRECATION")
    private fun observeNetworkBoundary(
        context: Context,
        vpnNetwork: Network,
        verifyIpv6: Boolean,
    ): BoundarySnapshot {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = connectivity.getNetworkCapabilities(vpnNetwork)
        val properties = connectivity.getLinkProperties(vpnNetwork)
        val expectedDns = buildSet {
            add(InetAddress.getByName("10.77.0.1"))
            if (verifyIpv6) add(InetAddress.getByName("fd4b:7572:6400::1"))
        }
        val routes = properties?.routes.orEmpty()
        val underlying = connectivity.allNetworks.filter { network ->
            if (network == vpnNetwork) return@filter false
            val value = connectivity.getNetworkCapabilities(network) ?: return@filter false
            !value.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                value.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        val bypassBlocked = underlying.isNotEmpty() && underlying.all { network ->
            DatagramSocket().use { socket ->
                runCatching { network.bindSocket(socket) }.isFailure
            }
        }
        return BoundarySnapshot(
            vpnActive = connectivity.activeNetwork == vpnNetwork &&
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true,
            ipv4Default = routes.any { route ->
                route.destination.prefixLength == 0 && route.destination.address is Inet4Address
            },
            ipv6Default = routes.any { route ->
                route.destination.prefixLength == 0 && route.destination.address is Inet6Address
            },
            dnsPinned = properties != null && properties.dnsServers.toSet() == expectedDns,
            bypassBlocked = bypassBlocked,
            coverageGap = properties == null || underlying.isEmpty(),
        )
    }

    private fun writeBoundaryObservation(
        fieldRoot: File,
        attemptId: String,
        value: BoundarySnapshot,
    ) {
        check(attemptId.matches(Regex("[0-9a-f]{32}"))) { "FIELD_ATTEMPT_ID_REJECTED" }
        val raw = buildString(320) {
            append("{\"schema\":\"")
            append(BOUNDARY_ANDROID_SCHEMA)
            append("\",\"attemptId\":\"")
            append(attemptId)
            append("\",\"vpnActive\":")
            append(value.vpnActive)
            append(",\"ipv4Default\":")
            append(value.ipv4Default)
            append(",\"ipv6Default\":")
            append(value.ipv6Default)
            append(",\"dnsPinned\":")
            append(value.dnsPinned)
            append(",\"bypassBlocked\":")
            append(value.bypassBlocked)
            append(",\"coverageGap\":")
            append(value.coverageGap)
            append('}')
        }.encodeToByteArray()
        try {
            writeAtomic(File(fieldRoot, RESULT), raw)
        } finally {
            raw.fill(0)
        }
    }

    private suspend fun verifyDataPlane(vpnNetwork: Network) = withContext(Dispatchers.IO) {
        val arguments = InstrumentationRegistry.getArguments()
        val rawUrl = arguments.getString(ARG_PROBE_URL)?.trim().orEmpty()
        val expectedDigest = arguments.getString(ARG_EXPECTED_RESPONSE_SHA256)?.trim().orEmpty()
        require(expectedDigest.matches(Regex("^[0-9a-f]{64}$"))) { "PROBE_DIGEST_REJECTED" }
        val uri = runCatching { URI(rawUrl) }.getOrElse { error("PROBE_URL_REJECTED") }
        require(
            rawUrl.length in 1..2048 && uri.scheme == "https" && !uri.host.isNullOrBlank() &&
                uri.host.any(Char::isLetter) && uri.userInfo == null && uri.fragment == null,
        ) { "PROBE_URL_REJECTED" }
        awaitNetworkScopedDnsReadiness(
            timeoutMillis = VPN_DNS_RESOLVER_READY_TIMEOUT_MILLIS,
            pollMillis = VPN_NETWORK_POLL_MILLIS,
        ) {
            if (vpnNetwork.getAllByName(uri.host).isEmpty()) {
                throw UnknownHostException("VPN_DNS_RESOLVER_NOT_READY")
            }
        }
        val connection = (vpnNetwork.openConnection(uri.toURL()) as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 10_000
            instanceFollowRedirects = false
            requestMethod = "GET"
            useCaches = false
        }
        try {
            require(connection.responseCode == HttpURLConnection.HTTP_OK) {
                "PROBE_RESPONSE_REJECTED"
            }
            val body = connection.inputStream.use { input ->
                input.readNBytes(MAX_PROBE_RESPONSE_BYTES + 1)
            }
            try {
                require(body.size in 1..MAX_PROBE_RESPONSE_BYTES) { "PROBE_RESPONSE_REJECTED" }
                val normalized = body.toString(Charsets.US_ASCII).trim().encodeToByteArray()
                try {
                    val actual = MessageDigest.getInstance("SHA-256")
                        .digest(normalized)
                        .joinToString("") { byte -> "%02x".format(byte) }
                    require(actual == expectedDigest) { "PROBE_IDENTITY_MISMATCH" }
                } finally {
                    normalized.fill(0)
                }
            } finally {
                body.fill(0)
            }
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun verifyDnsPlane(
        vpnNetwork: Network,
        family: Int,
        expectAvailable: Boolean,
    ) =
        withContext(Dispatchers.IO) {
            require(family == 4 || family == 6) { "DNS_FAMILY_REJECTED" }
            val server = InetAddress.getByName(
                if (family == 4) "10.77.0.1" else "fd4b:7572:6400::1",
            )
            val identifier = SecureRandom().nextInt(0x10000)
            val query = buildDnsQuery(identifier, if (family == 4) 1 else 28)
            val response = ByteArray(512)
            try {
                runDnsExchange(expectAvailable) {
                    DatagramSocket().use { socket ->
                        vpnNetwork.bindSocket(socket)
                        socket.soTimeout = 5_000
                        socket.send(DatagramPacket(query, query.size, server, 53))
                        val packet = DatagramPacket(response, response.size)
                        socket.receive(packet)
                        check(expectAvailable) { "DNS_FAIL_CLOSED_BYPASSED" }
                        check(packet.length >= 12) { "DNS_RESPONSE_REJECTED" }
                        val observedIdentifier =
                            ((response[0].toInt() and 0xff) shl 8) or
                                (response[1].toInt() and 0xff)
                        check(observedIdentifier == identifier) { "DNS_RESPONSE_REJECTED" }
                        check(response[2].toInt() and 0x80 != 0) { "DNS_RESPONSE_REJECTED" }
                    }
                }
            } finally {
                query.fill(0)
                response.fill(0)
            }
        }

    private fun buildDnsQuery(identifier: Int, queryType: Int): ByteArray {
        require(identifier in 0..0xffff && (queryType == 1 || queryType == 28)) {
            "DNS_QUERY_REJECTED"
        }
        val name = arrayOf("example", "com")
        val size = 12 + name.sumOf { label -> 1 + label.length } + 1 + 4
        return ByteArray(size).also { query ->
            query[0] = (identifier ushr 8).toByte()
            query[1] = identifier.toByte()
            query[2] = 0x01
            query[5] = 0x01
            var offset = 12
            name.forEach { label ->
                query[offset++] = label.length.toByte()
                label.forEach { character -> query[offset++] = character.code.toByte() }
            }
            query[offset++] = 0
            query[offset++] = (queryType ushr 8).toByte()
            query[offset++] = queryType.toByte()
            query[offset++] = 0
            query[offset] = 1
        }
    }

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val temporary = File(target.parentFile, ".${target.name}.tmp")
        check(!temporary.exists() || temporary.delete()) { "FIELD_TEMP_DELETE_FAILED" }
        FileOutputStream(temporary).use { stream ->
            stream.write(bytes)
            stream.fd.sync()
        }
        check(temporary.renameTo(target)) { "FIELD_ATOMIC_RENAME_FAILED" }
    }
}
