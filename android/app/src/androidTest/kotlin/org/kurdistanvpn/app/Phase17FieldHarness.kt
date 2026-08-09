// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
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
import org.kurdistanvpn.runtime.api.VpnRuntimeState

/**
 * Test-only owner-field bridge. It moves only public enrollment material and an
 * owner-supplied sealed profile through app-private files. Production variants
 * never contain this class or its fixed field-test protocol.
 */
internal object Phase17FieldHarness {
    private const val ARG_ACTION = "phase17FieldAction"
    private const val FIELD_DIRECTORY = "phase17-field"
    private const val RECIPIENT_REQUEST = "recipient-request.bin"
    private const val SEALED_PROFILE = "sealed-profile.bin"
    private const val RESULT = "result.txt"
    private const val MAX_RECIPIENT_REQUEST_BYTES = 512
    private const val MAX_PROFILE_BYTES = 1_500_000
    private const val ARG_PROBE_URL = "phase17ProbeUrl"
    private const val ARG_EXPECTED_RESPONSE_SHA256 = "phase17ExpectedResponseSha256"
    private const val ARG_DNS_FAMILY = "phase17DnsFamily"
    private const val ARG_EXPECT_DNS_AVAILABLE = "phase17ExpectDnsAvailable"
    private const val MAX_PROBE_RESPONSE_BYTES = 64

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

    suspend fun runIfRequested(): Boolean {
        val action = InstrumentationRegistry.getArguments().getString(ARG_ACTION)
            ?.trim()
            .orEmpty()
        if (action.isEmpty()) return false

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as KurdistanApplication
        val root = application.compositionRoot
        val fieldRoot = File(application.filesDir, FIELD_DIRECTORY).apply {
            check(isDirectory || mkdirs()) { "FIELD_DIRECTORY_UNAVAILABLE" }
        }
        when (action) {
            "export-recipient" -> exportRecipient(root, fieldRoot)
            "import-profile" -> importProfile(root, fieldRoot)
            "connect" -> connect(application, root, fieldRoot, shouldVerifyDataPlane = false)
            "data-plane" -> connect(application, root, fieldRoot, shouldVerifyDataPlane = true)
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
    ) {
        val coordinators = Phase13Coordinators.create(root)
        val localRecordId = root.settingsStore.settings.first().profiles.activeLocalRecordId
            ?: error("ACTIVE_PROFILE_UNAVAILABLE")
        val authority = when (val result = coordinators.runtime.openLiveAuthority(localRecordId)) {
            is org.kurdistanvpn.data.secure.RuntimeAuthorityResult.Success -> result
            is org.kurdistanvpn.data.secure.RuntimeAuthorityResult.Failure ->
                error("RUNTIME_AUTHORITY_FAILED:${result.error}")
            null -> error("RUNTIME_AUTHORITY_UNAVAILABLE")
        }
        val encoded = authority.material.use { material ->
            RuntimeStartWire.encode(
                verifyRequest = material.verifyRequest,
                activationRecord = material.activationRecord,
                recipientRequest = material.recipientRequest,
                recipientPrivate = material.recipientPrivate,
                config = VpnRuntimeConfig(
                    routingPolicy = VpnRoutingPolicy(),
                    mtu = 1280,
                ),
            )
        }
        val controller = VpnRuntimeController(application)
        try {
            check(controller.prepareIntent() == null) { "VPN_CONSENT_REQUIRED" }
            controller.stageAuthority(encoded)
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
            if (shouldVerifyDataPlane || dnsFamily != null) {
                delay(1_000)
                val stable = controller.snapshot.value
                check(stable.state == VpnRuntimeState.ACTIVE_KURD_LIVE) {
                    "LIVE_RUNTIME_UNSTABLE:${stable.failure ?: stable.state.name}:" +
                        (stable.packetDisposition ?: "NONE")
                }
                try {
                    if (dnsFamily == null) {
                        verifyDataPlane()
                        writeAtomic(File(fieldRoot, RESULT), "DATA_PLANE_VERIFIED\n".encodeToByteArray())
                    } else {
                        verifyDnsPlane(dnsFamily, expectDnsAvailable)
                        val outcome = if (expectDnsAvailable) "VERIFIED" else "FAIL_CLOSED"
                        writeAtomic(
                            File(fieldRoot, RESULT),
                            "DNS_IPV${dnsFamily}_$outcome\n".encodeToByteArray(),
                        )
                    }
                } catch (failure: Throwable) {
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
                                ":rejected=${value.rejectedTunPackets}"
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
            } finally {
                controller.close()
            }
        }
    }

    private suspend fun verifyDataPlane() = withContext(Dispatchers.IO) {
        val arguments = InstrumentationRegistry.getArguments()
        val rawUrl = arguments.getString(ARG_PROBE_URL)?.trim().orEmpty()
        val expectedDigest = arguments.getString(ARG_EXPECTED_RESPONSE_SHA256)?.trim().orEmpty()
        require(expectedDigest.matches(Regex("^[0-9a-f]{64}$"))) { "PROBE_DIGEST_REJECTED" }
        val uri = runCatching { URI(rawUrl) }.getOrElse { error("PROBE_URL_REJECTED") }
        require(
            rawUrl.length in 1..2048 && uri.scheme == "https" && !uri.host.isNullOrBlank() &&
                uri.host.any(Char::isLetter) && uri.userInfo == null && uri.fragment == null,
        ) { "PROBE_URL_REJECTED" }
        val connection = (uri.toURL().openConnection() as HttpURLConnection).apply {
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

    private suspend fun verifyDnsPlane(family: Int, expectAvailable: Boolean) =
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
