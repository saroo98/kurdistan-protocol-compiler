// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.Manifest
import android.content.ComponentName
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.android.LiveTunnelInvariantProbe
import org.kurdistanvpn.runtime.api.LiveTunnelFailure
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class Phase17LiveDataPlaneDeviceTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected() {
        assertTrue(
            Phase17FieldHarness.isExpectedDnsUnavailableFailure(
                expectAvailable = false,
                failure = SocketTimeoutException("fixture"),
            ),
        )
        assertTrue(
            Phase17FieldHarness.isExpectedDnsUnavailableFailure(
                expectAvailable = false,
                failure = IOException("fixture"),
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedDnsUnavailableFailure(
                expectAvailable = true,
                failure = SocketTimeoutException("fixture"),
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedDnsUnavailableFailure(
                expectAvailable = false,
                failure = IllegalStateException("fixture"),
            ),
        )

        assertFalse(
            Phase17FieldHarness.runDnsExchange(expectAvailable = false) {
                throw IOException("send failed before receive")
            },
        )

        assertTrue(
            Phase17FieldHarness.isExpectedDnsStartupFailure(
                expectAvailable = false,
                state = VpnRuntimeState.FAILED,
                failure = "LIVE_TLS_REJECTED",
                packetDisposition = "LIVE_STAGE_SOCKET_PROTECTED",
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedDnsStartupFailure(
                expectAvailable = true,
                state = VpnRuntimeState.FAILED,
                failure = "LIVE_TLS_REJECTED",
                packetDisposition = "LIVE_STAGE_SOCKET_PROTECTED",
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedDnsStartupFailure(
                expectAvailable = false,
                state = VpnRuntimeState.FAILED,
                failure = "LIVE_TLS_REJECTED",
                packetDisposition = "LIVE_STAGE_TUN_ESTABLISHED",
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedDnsStartupFailure(
                expectAvailable = false,
                state = VpnRuntimeState.FAILED,
                failure = "LIVE_AUTHORITY_REJECTED",
                packetDisposition = "LIVE_STAGE_SOCKET_PROTECTED",
            ),
        )
    }

    @Test
    fun teardownBarrierRequiresActiveVpnTransportToDisappearBeforeNextSession() = runBlocking {
        var samples = 0
        assertTrue(
            VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                timeoutMillis = 1_000,
                pollMillis = 1,
                vpnTransportSnapshot = {
                    samples += 1
                    listOf(samples < 3)
                },
            ),
        )
        assertEquals(3, samples)

        assertFalse(
            VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                timeoutMillis = 10,
                pollMillis = 1,
                vpnTransportSnapshot = { listOf(true) },
            ),
        )
    }

    @Test
    fun teardownBarrierWaitsForEveryRegisteredVpnTransport() = runBlocking {
        var samples = 0
        assertTrue(
            VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                timeoutMillis = 1_000,
                pollMillis = 1,
                vpnTransportSnapshot = {
                    samples += 1
                    if (samples < 3) {
                        // The default network has already fallen back to the
                        // underlay, but Android still retains the old VPN.
                        listOf(false, true)
                    } else {
                        listOf(false, false)
                    }
                },
            ),
        )
        assertEquals(3, samples)
    }

    @Test
    fun liveIpv4LifecycleProtectsSocketBeforeConnectAndStopsCleanly() {
        val success = LiveTunnelInvariantProbe.exercise(protectSucceeds = true)
        assertTrue(success.runningBeforeStop)
        assertFalse(success.runningAfterStop)
        assertNull(success.failure)
        assertOrdered(
            success.events,
            "protect:37",
            "bind:37",
            "connect",
            "tls",
            "kurd",
            "establish",
            "attach:71",
            "stage:RUNNING",
            "stop",
            "close",
            "stage:STOPPED",
        )

        val rejected = LiveTunnelInvariantProbe.exercise(protectSucceeds = false)
        assertFalse(rejected.runningBeforeStop)
        assertFalse(rejected.runningAfterStop)
        assertEquals(LiveTunnelFailure.SOCKET_PROTECT_FAILED, rejected.failure)
        assertTrue(rejected.events.contains("protect:37"))
        assertTrue(rejected.events.contains("commit-false"))
        assertFalse(rejected.events.contains("connect"))
        assertFalse(rejected.events.contains("establish"))
    }

    @Test
    fun permissionRevocationAndProcessDeathRequireFreshAuthority() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val staged = ByteArray(64) { 0x5a }
        VpnRuntimeController(context).use { controller ->
            controller.stageAuthority(staged)
            controller.permissionRejected()
            assertTrue(staged.all { it == 0.toByte() })
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("CONSENT_REJECTED", controller.snapshot.value.failure)
            controller.startStaged()
            assertEquals("MISSING_VERIFIED_AUTHORITY", controller.snapshot.value.failure)
        }

        VpnRuntimeController(context).use { recreated ->
            recreated.startStaged()
            assertEquals(VpnRuntimeState.FAILED, recreated.snapshot.value.state)
            assertEquals("MISSING_VERIFIED_AUTHORITY", recreated.snapshot.value.failure)
        }
    }

    @Test
    fun emergencyStopLeavesNoRuntimeOrSecretEvidence() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val staged = ByteArray(48) { 0x6b }
        VpnRuntimeController(context).use { controller ->
            controller.stageAuthority(staged)
            controller.authorityRejected("PROFILE_REVOKED")
            assertTrue(staged.all { it == 0.toByte() })
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("PROFILE_REVOKED", controller.snapshot.value.failure)
            assertNoAuthorityEvidence(controller.snapshot.value)

            controller.stop()
            assertEquals(VpnRuntimeState.IDLE, controller.snapshot.value.state)
            assertNull(controller.snapshot.value.failure)
            assertNoAuthorityEvidence(controller.snapshot.value)
        }
    }

    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun dualStackDnsHandoverAndReconnectRemainPolicyBound() {
        val permitted = VpnRuntimeConfig(
            routingPolicy = VpnRoutingPolicy(),
            ipMode = IpMode.DUAL_STACK,
            dnsMode = DnsMode.INTERNAL_TUN,
            mtu = 1280,
        ).validatedForLiveTransport()
        assertEquals(IpMode.DUAL_STACK, permitted.ipMode)
        assertEquals(DnsMode.INTERNAL_TUN, permitted.dnsMode)
        assertEquals(1280, permitted.mtu)

        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                dnsMode = DnsMode.CLOUDFLARE,
            ).validatedForLiveTransport()
        }
        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                dnsMode = DnsMode.CUSTOM,
                customDns = "resolver.example",
            ).validatedForLiveTransport()
        }
        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                allowLan = true,
            ).validatedForLiveTransport()
        }
        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                mtu = 1279,
            ).validatedForLiveTransport()
        }
    }

    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun fieldProbeReacquiresOnlyAfterFreshControlledReconnect() = runBlocking {
        val initial = activeFieldSnapshot(
            requestId = "request-1",
            startedAt = 1_000,
            maxAttempts = 2,
        )
        val snapshots = MutableStateFlow(initial)
        var authorityPreparations = 1
        var networkAcquisitions = 0
        var probeAttempts = 0

        val consumedRetries = Phase17FieldHarness.runVerifiedProbeWithReconnect(
            initialSnapshot = initial,
            runtimeSnapshots = snapshots,
            authorityPreparationCount = { authorityPreparations },
            reconnectTimeoutMillis = 1_000,
            acquireNetwork = { "network-${++networkAcquisitions}" },
            verify = { network ->
                probeAttempts++
                if (probeAttempts == 1) {
                    authorityPreparations++
                    snapshots.value = VpnRuntimeSnapshot(VpnRuntimeState.RECONNECTING)
                    snapshots.value = activeFieldSnapshot(
                        requestId = "request-2",
                        startedAt = 2_000,
                        maxAttempts = 2,
                    )
                    throw SocketException("old VPN network was replaced")
                }
                assertEquals("network-2", network)
            },
        )

        assertEquals(1, consumedRetries)
        assertEquals(2, authorityPreparations)
        assertEquals(2, networkAcquisitions)
        assertEquals(2, probeAttempts)

        assertFieldReconnectFailure("FIELD_RECONNECT_AUTHORITY_NOT_FRESH") {
            val stale = MutableStateFlow(initial)
            Phase17FieldHarness.runVerifiedProbeWithReconnect(
                initialSnapshot = initial,
                runtimeSnapshots = stale,
                authorityPreparationCount = { 1 },
                reconnectTimeoutMillis = 100,
                acquireNetwork = { Unit },
                verify = {
                    stale.value = activeFieldSnapshot(
                        requestId = "request-2",
                        startedAt = 2_000,
                        maxAttempts = 2,
                    )
                    throw SocketException("stale authority")
                },
            )
        }
        assertFieldReconnectFailure("FIELD_RECONNECT_REVOKED") {
            val revoked = MutableStateFlow(initial)
            Phase17FieldHarness.runVerifiedProbeWithReconnect(
                initialSnapshot = initial,
                runtimeSnapshots = revoked,
                authorityPreparationCount = { 1 },
                reconnectTimeoutMillis = 100,
                acquireNetwork = { Unit },
                verify = {
                    revoked.value = VpnRuntimeSnapshot(
                        state = VpnRuntimeState.REVOKED,
                        failure = "PROFILE_REVOKED",
                    )
                    throw SocketException("revoked")
                },
            )
        }
        assertFieldReconnectFailure("FIELD_RECONNECT_NOT_RETRYABLE") {
            val failed = MutableStateFlow(initial)
            Phase17FieldHarness.runVerifiedProbeWithReconnect(
                initialSnapshot = initial,
                runtimeSnapshots = failed,
                authorityPreparationCount = { 1 },
                reconnectTimeoutMillis = 100,
                acquireNetwork = { Unit },
                verify = {
                    failed.value = VpnRuntimeSnapshot(
                        state = VpnRuntimeState.FAILED,
                        failure = "LIVE_TLS_REJECTED",
                    )
                    throw SocketException("non-retryable")
                },
            )
        }
        assertFieldReconnectFailure("FIELD_RECONNECT_CANCELLED") {
            val stopped = MutableStateFlow(initial)
            Phase17FieldHarness.runVerifiedProbeWithReconnect(
                initialSnapshot = initial,
                runtimeSnapshots = stopped,
                authorityPreparationCount = { 1 },
                reconnectTimeoutMillis = 100,
                acquireNetwork = { Unit },
                verify = {
                    stopped.value = VpnRuntimeSnapshot(VpnRuntimeState.IDLE)
                    throw SocketException("manual disconnect")
                },
            )
        }
        assertFieldReconnectFailure("FIELD_RECONNECT_EXHAUSTED") {
            val oneAttempt = activeFieldSnapshot(
                requestId = "request-1",
                startedAt = 1_000,
                maxAttempts = 1,
            )
            val exhausted = MutableStateFlow(oneAttempt)
            var preparations = 1
            var attempts = 0
            Phase17FieldHarness.runVerifiedProbeWithReconnect(
                initialSnapshot = oneAttempt,
                runtimeSnapshots = exhausted,
                authorityPreparationCount = { preparations },
                reconnectTimeoutMillis = 100,
                acquireNetwork = { Unit },
                verify = {
                    attempts++
                    if (attempts == 1) {
                        preparations++
                        exhausted.value = activeFieldSnapshot(
                            requestId = "request-2",
                            startedAt = 2_000,
                            maxAttempts = 1,
                        )
                    }
                    throw SocketException("probe interrupted")
                },
            )
        }

        val cancellation = runCatching {
            Phase17FieldHarness.runVerifiedProbeWithReconnect(
                initialSnapshot = initial,
                runtimeSnapshots = MutableStateFlow(initial),
                authorityPreparationCount = { 1 },
                reconnectTimeoutMillis = 100,
                acquireNetwork = { Unit },
                verify = { throw CancellationException("cancelled") },
            )
        }.exceptionOrNull()
        assertTrue(cancellation is CancellationException)
    }

    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun networkScopedDnsReadinessWaitsForResolverAfterRapidVpnTransitions() = runBlocking {
        var attempts = 0

        val observedAttempts = Phase17FieldHarness.awaitNetworkScopedDnsReadiness(
            timeoutMillis = 1_000,
            pollMillis = 1,
            resolve = {
                attempts++
                if (attempts < 3) {
                    throw UnknownHostException("resolver is not attached to the new VPN network yet")
                }
            },
        )

        assertEquals(3, observedAttempts)
        assertEquals(3, attempts)

        val timeoutFailure = runCatching {
            Phase17FieldHarness.awaitNetworkScopedDnsReadiness(
                timeoutMillis = 20,
                pollMillis = 1,
                resolve = { throw UnknownHostException("resolver remains unavailable") },
            )
        }.exceptionOrNull()
        assertTrue(timeoutFailure is UnknownHostException)
    }

    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun profileRevocationAndBackupRestoreFailClosed() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as KurdistanApplication
        val root = application.compositionRoot

        VpnRuntimeController(application).use { controller ->
            controller.authorityRejected("PROFILE_REVOKED")
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("PROFILE_REVOKED", controller.snapshot.value.failure)
            assertNoAuthorityEvidence(controller.snapshot.value)
        }

        assertTrue(root.resetProtectedState())
        val journal = requireNotNull(root.admissionJournal)
        val payload = journal.backupPayload()
        val passphrase = "phase17-device-backup".encodeToByteArray()
        var opened: BackupPreviewHandle? = null
        var backup = byteArrayOf()
        try {
            backup = requireSuccess(root.nativeCore.createBackup(payload, passphrase))
            opened = requireSuccess(root.nativeCore.openBackup(backup.copyOf(), passphrase))
            val restored = requireSuccess(root.nativeCore.restoreBackup(opened))
            try {
                assertArrayEquals(payload, restored)
            } finally {
                restored.fill(0)
            }
            assertTrue(root.nativeCore.releaseBackup(opened) is NativeResult.Success)
            opened = null

            val tampered = backup.copyOf()
            tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
            try {
                assertTrue(
                    "modified backup must fail before restore",
                    root.nativeCore.openBackup(tampered, passphrase) is NativeResult.Failure,
                )
            } finally {
                tampered.fill(0)
            }
            assertTrue(root.resetProtectedState())
            assertTrue(requireNotNull(root.admissionJournal).listProfiles().isEmpty())
        } finally {
            opened?.let(root.nativeCore::releaseBackup)
            backup.fill(0)
            payload.fill(0)
            passphrase.fill(0)
        }
    }

    @SdkSuppress(minSdkVersion = 36)
    @Test
    fun completeCurrentManifestAccessibilityAndLifecycleRemainTruthful() {
        val activity = compose.activity
        val packageManager = activity.packageManager
        val requested = requireNotNull(
            packageManager.getPackageInfo(activity.packageName, PackageManager.GET_PERMISSIONS)
                .requestedPermissions,
        ).toSet()
        assertTrue(requested.contains(Manifest.permission.INTERNET))
        assertTrue(requested.contains(Manifest.permission.ACCESS_NETWORK_STATE))
        assertTrue(requested.contains(Manifest.permission.FOREGROUND_SERVICE))

        val service = packageManager.getServiceInfo(
            ComponentName(activity, KurdVpnService::class.java),
            PackageManager.GET_META_DATA,
        )
        assertFalse(service.exported)
        assertEquals(Manifest.permission.BIND_VPN_SERVICE, service.permission)
        assertTrue(service.processName.endsWith(":vpn"))
        assertTrue(
            service.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE != 0,
        )
        assertFalse(
            service.metaData.getBoolean("android.net.VpnService.SUPPORTS_ALWAYS_ON", true),
        )

        compose.onNodeWithTag("connection_hero").assertIsDisplayed()
        compose.onNodeWithTag("connect_button").assertIsDisplayed().assertHasClickAction()
        assertFalse(activity.appStateSnapshotForTesting().toString().contains("PRODUCTION_READY"))
    }

    private fun assertOrdered(events: List<String>, vararg expected: String) {
        var previous = -1
        expected.forEach { event ->
            val index = events.indexOf(event)
            assertTrue("missing event $event in $events", index >= 0)
            assertTrue("event $event is out of order in $events", index > previous)
            previous = index
        }
    }

    private fun assertPolicyRejected(block: () -> Unit) {
        val error = runCatching(block).exceptionOrNull()
        assertTrue("unsafe policy was accepted", error is IllegalArgumentException)
    }

    private suspend fun assertFieldReconnectFailure(
        expected: String,
        block: suspend () -> Unit,
    ) {
        val failure = runCatching { block() }.exceptionOrNull()
        assertTrue("expected $expected but was $failure", failure is IllegalStateException)
        assertEquals(expected, failure?.message)
    }

    private fun activeFieldSnapshot(
        requestId: String,
        startedAt: Long,
        maxAttempts: Int,
    ) = VpnRuntimeSnapshot(
        state = VpnRuntimeState.ACTIVE_KURD_LIVE,
        startedAtElapsedRealtime = startedAt,
        profileGeneration = 7,
        planDigest = "a".repeat(64),
        profileFingerprint = "profile",
        strategyFingerprint = "strategy",
        relayFingerprint = "relay",
        maxReconnectAttempts = maxAttempts,
        runtimeRequestId = requestId,
    )

    private fun assertNoAuthorityEvidence(snapshot: org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot) {
        assertEquals(0, snapshot.profileGeneration)
        assertNull(snapshot.planDigest)
        assertNull(snapshot.profileFingerprint)
        assertNull(snapshot.strategyFingerprint)
        assertNull(snapshot.relayFingerprint)
    }

    private fun <T> requireSuccess(result: NativeResult<T>): T = when (result) {
        is NativeResult.Success -> result.value
        is NativeResult.Failure -> throw AssertionError("native operation failed: ${result.error}")
    }
}
