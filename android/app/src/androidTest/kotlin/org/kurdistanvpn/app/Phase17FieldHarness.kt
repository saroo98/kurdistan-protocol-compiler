// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertTrue
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedExternalPreviewResult
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
    private const val UNRELATED_UID_BOUNDARY_TIMEOUT_MILLIS = 20_000L
    private const val BOUNDARY_COVERAGE_MAX_ATTEMPTS = 3
    private const val BOUNDARY_COVERAGE_RETRY_DELAY_MILLIS = 100L
    private const val UNDERLAY_PROBE_CONNECT_TIMEOUT_MILLIS = 2_000
    private const val OWNER_SOCKET_PROTECTION_TIMEOUT_MILLIS = 2_000L
    private const val BOUNDARY_ANDROID_SCHEMA = "kurdistan-phase17-boundary-android-v1"

    /** Fixed-category failure evidence only. No path, inode, payload, key, or authority byte leaves the test process. */
    fun protectedStateSetupState(context: Context, setup: String): String {
        require(setup.matches(Regex("[A-Z0-9_]{1,64}")))
        val evidence = arrayListOf(setup)
        val credentialRoot = runCatching {
            context.applicationInfo::class.java.getField("credentialProtectedDataDir")
                .get(context.applicationInfo) as? String
        }.getOrNull()
        if (credentialRoot == null) return (evidence + "CREDENTIAL_ROOT_UNAVAILABLE").joinToString(",")
        val root = File(credentialRoot, "no_backup/protected-state")
        val stat = runCatching { android.system.Os.lstat(root.absolutePath) }.getOrNull()
        if (stat == null) return (evidence + "PROTECTED_ROOT_ABSENT").joinToString(",")
        val canonical = runCatching { root.canonicalFile == root.absoluteFile }.getOrDefault(false)
        val directory = android.system.OsConstants.S_ISDIR(stat.st_mode)
        val owned = stat.st_uid == context.applicationInfo.uid
        val privateMode = stat.st_mode and 511 == 448
        evidence += if (canonical) "ROOT_CANONICAL" else "ROOT_ALIAS_OR_SUBSTITUTION"
        evidence += if (directory) "ROOT_DIRECTORY" else "ROOT_NOT_DIRECTORY"
        evidence += if (owned) "ROOT_OWNER_MATCH" else "ROOT_OWNER_MISMATCH"
        evidence += if (privateMode) "ROOT_MODE_0700" else "ROOT_MODE_MISMATCH"
        if (!canonical || !directory || !owned || !privateMode) return evidence.joinToString(",")
        val leaves = root.list()?.toSet()
            ?: return (evidence + "ROOT_LIST_UNAVAILABLE").joinToString(",")
        if (leaves.isEmpty()) evidence += "ROOT_EMPTY"
        fun present(token: String, predicate: (String) -> Boolean) {
            if (leaves.any(predicate)) evidence += token
        }
        present("LOCK") { it == "protected-state.lock" }
        present("STORE_IDENTITY") { it == "journal-store.blob" }
        present("CONTROL") { it == "journal-control.blob" }
        present("INTENT") { it.startsWith("journal-intent-") && it.endsWith(".blob") }
        present("CHECKPOINT") { it.startsWith("journal-checkpoint-") && it.endsWith(".blob") }
        present("PROJECTION_WITNESS") { it.startsWith("journal-projection-") && it.endsWith(".blob") }
        present("PENDING") { it.startsWith("pending-") }
        present("ROOM_MAIN") { it == "protected-metadata.db" }
        present("ROOM_JOURNAL") { it == "protected-metadata.db-journal" }
        present("ROOM_WAL") { it == "protected-metadata.db-wal" }
        present("ROOM_SHM") { it == "protected-metadata.db-shm" }
        present("SETTINGS") { it == "protected-settings.preferences_pb" }
        val known = leaves.all { leaf ->
            leaf == "protected-state.lock" || leaf == "journal-store.blob" || leaf == "journal-control.blob" ||
                (leaf.startsWith("journal-intent-") && leaf.endsWith(".blob")) ||
                (leaf.startsWith("journal-checkpoint-") && leaf.endsWith(".blob")) ||
                (leaf.startsWith("journal-projection-") && leaf.endsWith(".blob")) || leaf.startsWith("pending-") ||
                leaf == "protected-metadata.db" || leaf == "protected-metadata.db-journal" ||
                leaf == "protected-metadata.db-wal" || leaf == "protected-metadata.db-shm" ||
                leaf == "protected-settings.preferences_pb"
        }
        if (!known) evidence += "UNKNOWN_LEAF"
        return evidence.joinToString(",").also { check(it.length <= 256) }
    }

    internal data class BoundarySnapshot(
        val vpnActive: Boolean,
        val ipv4Default: Boolean,
        val ipv6Default: Boolean,
        val dnsPinned: Boolean,
        val bypassBlocked: Boolean,
        val coverageGap: Boolean,
    )

    internal data class UnrelatedUidBoundaryObservation(
        val tunneledTraffic: Boolean,
        val bypassBlocked: Boolean,
        val coverageGap: Boolean,
    )

    internal data class BoundaryObservation(
        val boundary: BoundarySnapshot,
        val unrelatedUidBoundary: UnrelatedUidBoundaryObservation?,
    )

    private data class UnderlayProbeTarget(
        val address: ByteArray,
        val port: Int,
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

    internal fun boundaryFailureCategory(
        value: BoundarySnapshot,
        verifyIpv6: Boolean,
        unrelatedUidBoundary: UnrelatedUidBoundaryObservation?,
    ): String? {
        if (evaluateBoundarySnapshot(value, verifyIpv6)) return null

        fun result(passed: Boolean): String = if (passed) "PASS" else "FAIL"
        val ipv6 = if (verifyIpv6) result(value.ipv6Default) else "NA"
        val tunneled = unrelatedUidBoundary?.let { result(it.tunneledTraffic) } ?: "NA"
        return "BOUNDARY_LEAK" +
            ":VPN_${result(value.vpnActive)}" +
            ":IPV4_${result(value.ipv4Default)}" +
            ":IPV6_$ipv6" +
            ":DNS_${result(value.dnsPinned)}" +
            ":BYPASS_${result(value.bypassBlocked)}" +
            ":TUNNEL_$tunneled" +
            ":COVERAGE_${result(!value.coverageGap)}"
    }

    internal fun evaluateUnrelatedUidBoundary(
        value: UnrelatedUidBoundaryObservation,
    ): Boolean = value.tunneledTraffic && value.bypassBlocked && !value.coverageGap

    internal suspend fun awaitCompleteBoundaryObservation(
        verifyIpv6: Boolean,
        maximumCoverageAttempts: Int,
        retryDelayMillis: Long,
        observe: suspend () -> BoundaryObservation,
    ): BoundaryObservation {
        require(maximumCoverageAttempts > 0 && retryDelayMillis >= 0) {
            "BOUNDARY_COVERAGE_RETRY_POLICY_REJECTED"
        }
        var observed = observe()
        repeat(maximumCoverageAttempts - 1) {
            // A cross-UID probe spans several Android network snapshots. Reobserve
            // only when every concrete predicate passed and completeness alone
            // changed; a concrete leak remains terminal on its first observation.
            if (!isCoverageOnlyBoundaryFailure(observed, verifyIpv6)) {
                return observed
            }
            if (retryDelayMillis > 0) {
                delay(retryDelayMillis)
            }
            observed = observe()
        }
        return observed
    }

    private fun isCoverageOnlyBoundaryFailure(
        observed: BoundaryObservation,
        verifyIpv6: Boolean,
    ): Boolean {
        val boundary = observed.boundary
        val unrelatedUid = observed.unrelatedUidBoundary
        return boundary.coverageGap &&
            boundary.vpnActive &&
            boundary.ipv4Default &&
            (!verifyIpv6 || boundary.ipv6Default) &&
            boundary.dnsPinned &&
            boundary.bypassBlocked &&
            (unrelatedUid == null ||
                (unrelatedUid.tunneledTraffic && unrelatedUid.bypassBlocked))
    }

    internal fun isIndependentProbeIdentity(
        targetPackage: String,
        targetUid: Int,
        probePackage: String,
        probeUid: Int,
    ): Boolean = targetPackage != probePackage && targetUid != probeUid

    internal fun isExpectedProbeResultIdentity(
        expectedPackage: String,
        expectedUid: Int,
        observedPackage: String?,
        observedUid: Int,
    ): Boolean = expectedPackage == observedPackage && expectedUid == observedUid

    internal suspend fun prepareOwnerUnderlaySocket(
        socket: Socket,
        protect: suspend (Socket) -> Boolean,
        bind: (Socket) -> Unit,
    ): Boolean = runCatching {
        check(protect(socket)) { "OWNER_UNDERLAY_SOCKET_PROTECT_FAILED" }
        bind(socket)
    }.isSuccess

    internal fun requiresUnrelatedUidBoundary(
        shouldVerifyDataPlane: Boolean,
        dnsFamily: Int?,
        trafficDnsFamilies: List<Int>,
        verifyBoundary: Boolean,
    ): Boolean {
        if (
            dnsFamily != null && !shouldVerifyDataPlane &&
            trafficDnsFamilies.isEmpty() && !verifyBoundary
        ) {
            return false
        }
        return shouldVerifyDataPlane || trafficDnsFamilies.isNotEmpty() || verifyBoundary
    }

    internal fun requiresDirectDataPlaneProbe(
        shouldVerifyDataPlane: Boolean,
        dnsFamily: Int?,
        trafficDnsFamilies: List<Int>,
    ): Boolean =
        trafficDnsFamilies.isNotEmpty() ||
            (shouldVerifyDataPlane && dnsFamily == null)

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

    internal fun isTerminalFieldConnectOutcome(
        expectDnsAvailable: Boolean,
        snapshot: VpnRuntimeSnapshot,
    ): Boolean = when (snapshot.state) {
        VpnRuntimeState.ACTIVE_KURD_LIVE,
        VpnRuntimeState.REVOKED,
        VpnRuntimeState.IDLE,
        VpnRuntimeState.STOPPING,
        VpnRuntimeState.BLOCKED,
        -> true
        VpnRuntimeState.FAILED -> isExpectedDnsStartupFailure(
            expectAvailable = expectDnsAvailable,
            state = snapshot.state,
            failure = snapshot.failure,
            packetDisposition = snapshot.packetDisposition,
        )
        else -> false
    }

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
            true // The service retries internally; these states are terminal after its budget.
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
        assertTrue("protected state initialization failed", root.initializeProtectedStateForExplicitUserAction())
        assertTrue("protected state reset failed", root.resetProtectedStateConfirmed() is ProtectedStateApplicationFacade.CommandResult.Committed)
        check(root.protectedStateFacade() == null) { "RESET_RECREATED_STATE" }
        assertTrue("explicit replacement initialization failed", root.initializeProtectedStateForExplicitUserAction())
        val coordinators = Phase13Coordinators.create(root)
        val now = System.currentTimeMillis() / 1000
        val created = coordinators.profiles.createEnrollment(
            validitySeconds = 24 * 60 * 60,
            now = now,
        )
        val summary = when (created) {
            is ProtectedStateApplicationFacade.CommandResult.Committed -> created.value
            else -> error("RECIPIENT_CREATE_FAILED")
        }
        val request = requireNotNull(
            coordinators.profiles.enrollmentRequest(summary.localRecordId),
        ) { "RECIPIENT_REQUEST_UNAVAILABLE" }
        try {
            require(request.size in 1..MAX_RECIPIENT_REQUEST_BYTES) {
                "RECIPIENT_REQUEST_SIZE_REJECTED"
            }
            writeAtomic(File(fieldRoot, RECIPIENT_REQUEST), request)
            check(coordinators.profiles.markEnrollmentRequestExported(summary.localRecordId) is
                ProtectedStateApplicationFacade.CommandResult.Committed) { "RECIPIENT_EXPORT_STATE_UNPROVEN" }
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
            val facade = requireNotNull(root.protectedStateFacade())
            val resolved = when (val result = facade.previewExternalImport(request, { false }, android.os.SystemClock::elapsedRealtime)) {
                is ProtectedExternalPreviewResult.Ready -> result.preview
                is ProtectedExternalPreviewResult.Rejected -> error("PROFILE_PREVIEW_FAILED")
            }
            val outcome = resolved.use { pending ->
                // This field action is a separately authorized import, not an external preview.
                pending.confirm().use { confirmed ->
                    when (val admission = facade.confirmImport(confirmed)) {
                        is ProtectedStateApplicationFacade.CommandResult.Committed -> admission.value
                        else -> error("PROFILE_ADMISSION_FAILED")
                    }
                }
            }
            coordinators.settings.setProfiles(
                ProfilePreferences(activeLocalRecordId = outcome),
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
        val settings = coordinators.settings.settings.first()
        check(settings.profiles.activeLocalRecordId != null) { "ACTIVE_PROFILE_UNAVAILABLE" }
        coordinators.settings.setTunnel(settings.tunnel.copy(mtu = 1280))
        val reissue = (application as RuntimeAuthorityReissueOwner).runtimeAuthorityReissue
        val controller = VpnRuntimeController(application)
        try {
            check(controller.prepareIntent() == null) { "VPN_CONSENT_REQUIRED" }
            controller.stageManualStart()
            controller.startStaged()
            val snapshot = withTimeoutOrNull(120_000) {
                controller.snapshot.first { candidate ->
                    isTerminalFieldConnectOutcome(
                        expectDnsAvailable = expectDnsAvailable,
                        snapshot = candidate,
                    )
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
                var boundaryFailure: String? = null
                try {
                    var boundarySnapshot: BoundarySnapshot? = null
                    runVerifiedProbeWithReconnect(
                        initialSnapshot = stable,
                        runtimeSnapshots = controller.snapshot,
                        authorityPreparationCount = reissue::completedFullAuthorityCount,
                        reconnectTimeoutMillis = LIVE_RECONNECT_READY_TIMEOUT_MILLIS,
                        acquireNetwork = {
                            if (verifyBoundary) {
                                awaitVpnNetwork(application)
                            } else {
                                awaitVerifiedVpnNetwork(application, requiredDnsFamilies)
                            }
                        },
                        verify = { vpnNetwork ->
                            val requireUnrelatedUidBoundary =
                                requiresUnrelatedUidBoundary(
                                    shouldVerifyDataPlane = shouldVerifyDataPlane,
                                    dnsFamily = dnsFamily,
                                    trafficDnsFamilies = trafficDnsFamilies,
                                    verifyBoundary = verifyBoundary,
                                )
                            val verifyBoundaryIpv6 =
                                if (verifyBoundary) boundaryVerifyIPv6 else trafficDnsFamilies.contains(6)
                            val observation = awaitCompleteBoundaryObservation(
                                verifyIpv6 = verifyBoundaryIpv6,
                                maximumCoverageAttempts = BOUNDARY_COVERAGE_MAX_ATTEMPTS,
                                retryDelayMillis = BOUNDARY_COVERAGE_RETRY_DELAY_MILLIS,
                                observe = {
                                    val unrelatedUidBoundary = if (requireUnrelatedUidBoundary) {
                                        awaitUnrelatedUidBoundary(application, vpnNetwork)
                                    } else {
                                        null
                                    }
                                    BoundaryObservation(
                                        boundary = observeNetworkBoundary(
                                            application,
                                            vpnNetwork,
                                            verifyIpv6 = verifyBoundaryIpv6,
                                            unrelatedUidBoundary = unrelatedUidBoundary,
                                        ),
                                        unrelatedUidBoundary = unrelatedUidBoundary,
                                    )
                                },
                            )
                            val observedBoundary = observation.boundary
                            val unrelatedUidBoundary = observation.unrelatedUidBoundary
                            boundarySnapshot = observedBoundary
                            if (!verifyBoundary) {
                                boundaryFailure = boundaryFailureCategory(
                                    value = observedBoundary,
                                    verifyIpv6 = trafficDnsFamilies.contains(6),
                                    unrelatedUidBoundary = unrelatedUidBoundary,
                                )
                                boundaryFailure?.let(::error)
                            }
                            if (trafficDnsFamilies.isNotEmpty()) {
                                trafficDnsFamilies.forEach { family ->
                                    verifyDnsPlane(vpnNetwork, family, expectAvailable = true)
                                }
                                verifyDataPlane(vpnNetwork)
                            } else if (
                                requiresDirectDataPlaneProbe(
                                    shouldVerifyDataPlane = shouldVerifyDataPlane,
                                    dnsFamily = dnsFamily,
                                    trafficDnsFamilies = trafficDnsFamilies,
                                )
                            ) {
                                verifyDataPlane(vpnNetwork)
                            } else if (dnsFamily != null) {
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
                    if (boundaryFailure != null && failure.message == boundaryFailure) {
                        writeAtomic(File(fieldRoot, RESULT), "$boundaryFailure\n".encodeToByteArray())
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

    private suspend fun awaitUnrelatedUidBoundary(
        context: Context,
        vpnNetwork: Network,
    ): UnrelatedUidBoundaryObservation {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val probeContext = instrumentation.context
        val probePackage = probeContext.packageName
        val probeUid = probeContext.applicationInfo.uid
        if (
            !probePackage.endsWith(".test") ||
            !isIndependentProbeIdentity(
                targetPackage = context.packageName,
                targetUid = context.applicationInfo.uid,
                probePackage = probePackage,
                probeUid = probeUid,
            )
        ) {
            return UnrelatedUidBoundaryObservation(false, false, true)
        }
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val underlying = unrelatedUidUnderlyingNetworks(connectivity, vpnNetwork)
        if (underlying.isEmpty()) {
            return UnrelatedUidBoundaryObservation(false, false, true)
        }
        val ownerProbeTargets = resolveOwnerProbeTargets(vpnNetwork)
        if (ownerProbeTargets.isEmpty()) {
            return UnrelatedUidBoundaryObservation(false, false, true)
        }
        val target = selectReachableUnderlayProbeTarget(context, ownerProbeTargets)
        if (target == null) {
            ownerProbeTargets.forEach { candidate -> candidate.address.fill(0) }
            return UnrelatedUidBoundaryObservation(false, false, true)
        }
        try {
            val observed = awaitUnrelatedUidBoundaryForTarget(
                context = context,
                probePackage = probePackage,
                probeUid = probeUid,
                target = target,
            )
            val ownerStillReachable = withContext(Dispatchers.IO) {
                canReachUnderlayTarget(context, target)
            }
            val topologyStable =
                unrelatedUidUnderlyingNetworks(connectivity, vpnNetwork).toSet() == underlying.toSet()
            return UnrelatedUidBoundaryObservation(
                tunneledTraffic = observed.tunneledTraffic,
                bypassBlocked = observed.bypassBlocked,
                coverageGap = observed.coverageGap || !ownerStillReachable || !topologyStable,
            )
        } finally {
            target.address.fill(0)
            ownerProbeTargets.forEach { candidate -> candidate.address.fill(0) }
        }
    }

    private suspend fun awaitUnrelatedUidBoundaryForTarget(
        context: Context,
        probePackage: String,
        probeUid: Int,
        target: UnderlayProbeTarget,
    ): UnrelatedUidBoundaryObservation {
        val tokenBytes = ByteArray(16).also(SecureRandom()::nextBytes)
        val token = tokenBytes.joinToString("") { byte -> "%02x".format(byte) }
        tokenBytes.fill(0)
        val deferred = CompletableDeferred<UnrelatedUidBoundaryObservation>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(receiverContext: Context?, intent: Intent?) {
                if (
                    intent?.action != VpnProbeActivity.ACTION_RESULT ||
                    intent.getStringExtra(VpnProbeActivity.EXTRA_TOKEN) != token ||
                    !intent.hasExtra(VpnProbeActivity.EXTRA_SUCCESS) ||
                    !intent.hasExtra(VpnProbeActivity.EXTRA_BYPASS_BLOCKED) ||
                    !intent.hasExtra(VpnProbeActivity.EXTRA_COVERAGE_GAP) ||
                    !intent.hasExtra(VpnProbeActivity.EXTRA_PROBE_PACKAGE) ||
                    !intent.hasExtra(VpnProbeActivity.EXTRA_PROBE_UID) ||
                    !isExpectedProbeResultIdentity(
                        expectedPackage = probePackage,
                        expectedUid = probeUid,
                        observedPackage = intent.getStringExtra(VpnProbeActivity.EXTRA_PROBE_PACKAGE),
                        observedUid = intent.getIntExtra(VpnProbeActivity.EXTRA_PROBE_UID, -1),
                    )
                ) {
                    return
                }
                deferred.complete(
                    UnrelatedUidBoundaryObservation(
                        tunneledTraffic = intent.getBooleanExtra(VpnProbeActivity.EXTRA_SUCCESS, false),
                        bypassBlocked = intent.getBooleanExtra(
                            VpnProbeActivity.EXTRA_BYPASS_BLOCKED,
                            false,
                        ),
                        coverageGap = intent.getBooleanExtra(
                            VpnProbeActivity.EXTRA_COVERAGE_GAP,
                            true,
                        ),
                    ),
                )
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(VpnProbeActivity.ACTION_RESULT),
            ContextCompat.RECEIVER_EXPORTED,
        )
        return try {
            context.startActivity(
                Intent()
                    .setComponent(ComponentName(probePackage, VpnProbeActivity::class.java.name))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    .putExtra(VpnProbeActivity.EXTRA_TOKEN, token)
                    .putExtra(VpnProbeActivity.EXTRA_TARGET_PACKAGE, context.packageName)
                    .putExtra(VpnProbeActivity.EXTRA_UNDERLAY_TARGET_ADDRESS, target.address)
                    .putExtra(VpnProbeActivity.EXTRA_UNDERLAY_TARGET_PORT, target.port),
            )
            withTimeoutOrNull(UNRELATED_UID_BOUNDARY_TIMEOUT_MILLIS) {
                deferred.await()
            } ?: UnrelatedUidBoundaryObservation(false, false, true)
        } catch (_: Throwable) {
            UnrelatedUidBoundaryObservation(false, false, true)
        } finally {
            runCatching { context.unregisterReceiver(receiver) }
        }
    }

    private suspend fun resolveOwnerProbeTargets(
        vpnNetwork: Network,
    ): List<UnderlayProbeTarget> = withContext(Dispatchers.IO) {
        val uri = verifiedProbeUri()
        val port = if (uri.port == -1) 443 else uri.port
        vpnNetwork.getAllByName(uri.host).mapNotNull { address ->
            val encoded = address.address
            if (encoded.size != 4 && encoded.size != 16) {
                null
            } else {
                UnderlayProbeTarget(encoded.copyOf(), port)
            }
        }
    }

    private suspend fun selectReachableUnderlayProbeTarget(
        context: Context,
        candidates: List<UnderlayProbeTarget>,
    ): UnderlayProbeTarget? = withContext(Dispatchers.IO) {
        for (candidate in candidates) {
            val target = UnderlayProbeTarget(candidate.address.copyOf(), candidate.port)
            if (canReachUnderlayTarget(context, target)) {
                return@withContext target
            }
            target.address.fill(0)
        }
        null
    }

    private suspend fun canReachUnderlayTarget(
        context: Context,
        target: UnderlayProbeTarget,
    ): Boolean = runCatching {
        Socket().use { socket ->
            check(
                prepareOwnerUnderlaySocket(
                    socket = socket,
                    protect = { candidate ->
                        protectAndBindOwnerSocket(context, candidate)
                    },
                    bind = {},
                ),
            ) { "OWNER_UNDERLAY_SOCKET_PREPARATION_FAILED" }
            socket.connect(
                InetSocketAddress(InetAddress.getByAddress(target.address), target.port),
                UNDERLAY_PROBE_CONNECT_TIMEOUT_MILLIS,
            )
        }
    }.isSuccess

    internal suspend fun protectAndBindOwnerSocket(
        context: Context,
        socket: Socket,
    ): Boolean {
        val descriptor = runCatching {
            if (!socket.isBound) socket.bind(InetSocketAddress(0))
            // The extra dup is required on API 26-28 because fromSocket did not
            // yet duplicate the Socket's descriptor on those releases.
            ParcelFileDescriptor.fromSocket(socket).dup()
        }.getOrNull() ?: return false
        val outcome = CompletableDeferred<Boolean>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                outcome.complete(
                    service?.let { remote ->
                        transactSocketProtection(remote, descriptor)
                    } == true,
                )
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                outcome.complete(false)
            }

            override fun onNullBinding(name: ComponentName?) {
                outcome.complete(false)
            }

            override fun onBindingDied(name: ComponentName?) {
                outcome.complete(false)
            }
        }
        var bound = false
        return try {
            bound = runCatching {
                context.bindService(
                    Intent(context, InternalVpnSocketProtectionService::class.java)
                        .setAction(InternalVpnSocketProtectionService.ACTION_BIND),
                    connection,
                    Context.BIND_AUTO_CREATE,
                )
            }.getOrDefault(false)
            if (!bound) {
                false
            } else {
                withTimeoutOrNull(OWNER_SOCKET_PROTECTION_TIMEOUT_MILLIS) {
                    outcome.await()
                } ?: false
            }
        } finally {
            if (bound) runCatching { context.unbindService(connection) }
            runCatching { descriptor.close() }
        }
    }

    private fun transactSocketProtection(
        remote: IBinder,
        descriptor: ParcelFileDescriptor,
    ): Boolean {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        return try {
            request.writeInterfaceToken(InternalVpnSocketProtectionService.DESCRIPTOR)
            request.writeInt(1)
            descriptor.writeToParcel(request, 0)
            if (
                !remote.transact(
                    InternalVpnSocketProtectionService.TRANSACTION_PROTECT_SOCKET,
                    request,
                    response,
                    0,
                )
            ) {
                return false
            }
            response.readException()
            response.readInt() == 1
        } catch (_: Throwable) {
            false
        } finally {
            request.recycle()
            response.recycle()
        }
    }

    @Suppress("DEPRECATION")
    private fun unrelatedUidUnderlyingNetworks(
        connectivity: ConnectivityManager,
        vpnNetwork: Network,
    ): List<Network> = connectivity.allNetworks.filter { network ->
        if (network == vpnNetwork) return@filter false
        val value = connectivity.getNetworkCapabilities(network) ?: return@filter false
        !value.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            value.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    @Suppress("DEPRECATION")
    private fun observeNetworkBoundary(
        context: Context,
        vpnNetwork: Network,
        verifyIpv6: Boolean,
        unrelatedUidBoundary: UnrelatedUidBoundaryObservation?,
    ): BoundarySnapshot {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = connectivity.getNetworkCapabilities(vpnNetwork)
        val properties = connectivity.getLinkProperties(vpnNetwork)
        val expectedDns = buildSet {
            add(InetAddress.getByName("10.77.0.1"))
            if (verifyIpv6) add(InetAddress.getByName("fd4b:7572:6400::1"))
        }
        val routes = properties?.routes.orEmpty()
        val underlying = unrelatedUidUnderlyingNetworks(connectivity, vpnNetwork)
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
            bypassBlocked = unrelatedUidBoundary?.bypassBlocked ?: true,
            coverageGap = properties == null || underlying.isEmpty() ||
                unrelatedUidBoundary?.let { value ->
                    value.coverageGap || !value.tunneledTraffic
                } == true,
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

    private fun verifiedProbeUri(): URI {
        val arguments = InstrumentationRegistry.getArguments()
        val rawUrl = arguments.getString(ARG_PROBE_URL)?.trim().orEmpty()
        val uri = runCatching { URI(rawUrl) }.getOrElse { error("PROBE_URL_REJECTED") }
        require(
            rawUrl.length in 1..2048 && uri.scheme == "https" && !uri.host.isNullOrBlank() &&
                uri.host.any(Char::isLetter) && !uri.host.contains(':') &&
                uri.userInfo == null && uri.fragment == null &&
                (uri.port == -1 || uri.port in 1..65535),
        ) { "PROBE_URL_REJECTED" }
        return uri
    }

    private suspend fun verifyDataPlane(vpnNetwork: Network) = withContext(Dispatchers.IO) {
        val arguments = InstrumentationRegistry.getArguments()
        val uri = verifiedProbeUri()
        val expectedDigest = arguments.getString(ARG_EXPECTED_RESPONSE_SHA256)?.trim().orEmpty()
        require(expectedDigest.matches(Regex("^[0-9a-f]{64}$"))) { "PROBE_DIGEST_REJECTED" }
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
