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
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedBackupEnumeration
import org.kurdistanvpn.data.secure.BackupPayloadCodec
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
    fun ownerUnderlayProtectionBridgeIsPrivateAndRunsInTheVpnProcess() {
        val activity = compose.activity
        val packageManager = activity.packageManager
        val vpnService = packageManager.getServiceInfo(
            ComponentName(activity, KurdVpnService::class.java),
            PackageManager.GET_META_DATA,
        )
        val bridgeService = runCatching {
            packageManager.getServiceInfo(
                ComponentName(activity, InternalVpnSocketProtectionService::class.java),
                PackageManager.GET_META_DATA,
            )
        }.getOrNull()

        assertNotNull("internal owner-underlay protection bridge is missing", bridgeService)
        requireNotNull(bridgeService)
        assertFalse(bridgeService.exported)
        assertNull(bridgeService.permission)
        assertEquals(vpnService.processName, bridgeService.processName)
    }

    @Test
    fun ownerUnderlayReachabilityProtectsBeforeBindingAndFailsClosed() = runBlocking {
        val events = mutableListOf<String>()
        Socket().use { socket ->
            assertTrue(
                Phase17FieldHarness.prepareOwnerUnderlaySocket(
                    socket = socket,
                    protect = { candidate ->
                        assertTrue(candidate === socket)
                        events += "protect"
                        true
                    },
                    bind = { candidate ->
                        assertTrue(candidate === socket)
                        events += "bind"
                    },
                ),
            )
        }
        assertEquals(listOf("protect", "bind"), events)

        events.clear()
        Socket().use { socket ->
            assertFalse(
                Phase17FieldHarness.prepareOwnerUnderlaySocket(
                    socket = socket,
                    protect = {
                        events += "protect"
                        false
                    },
                    bind = { events += "bind" },
                ),
            )
        }
        assertEquals(listOf("protect"), events)

        events.clear()
        Socket().use { socket ->
            assertFalse(
                Phase17FieldHarness.prepareOwnerUnderlaySocket(
                    socket = socket,
                    protect = {
                        events += "protect"
                        true
                    },
                    bind = {
                        events += "bind"
                        throw IOException("synthetic bind failure")
                    },
                ),
            )
        }
        assertEquals(listOf("protect", "bind"), events)
    }

    @Test
    fun boundaryObserverFailsClosedForRoutesDnsBypassAndCoverage() {
        val passing = Phase17FieldHarness.BoundarySnapshot(
            vpnActive = true,
            ipv4Default = true,
            ipv6Default = true,
            dnsPinned = true,
            bypassBlocked = true,
            coverageGap = false,
        )
        assertTrue(Phase17FieldHarness.evaluateBoundarySnapshot(passing, verifyIpv6 = true))

        listOf<(Phase17FieldHarness.BoundarySnapshot) -> Phase17FieldHarness.BoundarySnapshot>(
            { it.copy(vpnActive = false) },
            { it.copy(ipv4Default = false) },
            { it.copy(ipv6Default = false) },
            { it.copy(dnsPinned = false) },
            { it.copy(bypassBlocked = false) },
            { it.copy(coverageGap = true) },
        ).forEach { mutation ->
            assertFalse(Phase17FieldHarness.evaluateBoundarySnapshot(mutation(passing), verifyIpv6 = true))
        }

        assertTrue(
            Phase17FieldHarness.evaluateBoundarySnapshot(
                passing.copy(ipv6Default = false),
                verifyIpv6 = false,
            ),
        )
    }

    @Test
    fun boundaryFailureCategoryPreservesOnlyBoundedPredicateResults() {
        val passingBoundary = Phase17FieldHarness.BoundarySnapshot(
            vpnActive = true,
            ipv4Default = true,
            ipv6Default = true,
            dnsPinned = true,
            bypassBlocked = true,
            coverageGap = false,
        )
        val passingUnrelatedUid = Phase17FieldHarness.UnrelatedUidBoundaryObservation(
            tunneledTraffic = true,
            bypassBlocked = true,
            coverageGap = false,
        )

        assertNull(
            Phase17FieldHarness.boundaryFailureCategory(
                value = passingBoundary,
                verifyIpv6 = true,
                unrelatedUidBoundary = passingUnrelatedUid,
            ),
        )
        assertEquals(
            "BOUNDARY_LEAK:VPN_FAIL:IPV4_PASS:IPV6_FAIL:DNS_FAIL:BYPASS_FAIL:TUNNEL_FAIL:COVERAGE_FAIL",
            Phase17FieldHarness.boundaryFailureCategory(
                value = passingBoundary.copy(
                    vpnActive = false,
                    ipv6Default = false,
                    dnsPinned = false,
                    bypassBlocked = false,
                    coverageGap = true,
                ),
                verifyIpv6 = true,
                unrelatedUidBoundary = passingUnrelatedUid.copy(
                    tunneledTraffic = false,
                    bypassBlocked = false,
                    coverageGap = true,
                ),
            ),
        )
        assertEquals(
            "BOUNDARY_LEAK:VPN_PASS:IPV4_PASS:IPV6_NA:DNS_PASS:BYPASS_PASS:TUNNEL_NA:COVERAGE_FAIL",
            Phase17FieldHarness.boundaryFailureCategory(
                value = passingBoundary.copy(ipv6Default = false, coverageGap = true),
                verifyIpv6 = false,
                unrelatedUidBoundary = null,
            ),
        )
    }

    @Test
    fun coverageOnlyBoundaryInstabilityIsReobservedUntilComplete() = runBlocking {
        val passingBoundary = Phase17FieldHarness.BoundarySnapshot(
            vpnActive = true,
            ipv4Default = true,
            ipv6Default = true,
            dnsPinned = true,
            bypassBlocked = true,
            coverageGap = false,
        )
        val passingUnrelatedUid = Phase17FieldHarness.UnrelatedUidBoundaryObservation(
            tunneledTraffic = true,
            bypassBlocked = true,
            coverageGap = false,
        )
        val observations = ArrayDeque(
            listOf(
                Phase17FieldHarness.BoundaryObservation(
                    boundary = passingBoundary.copy(coverageGap = true),
                    unrelatedUidBoundary = passingUnrelatedUid.copy(coverageGap = true),
                ),
                Phase17FieldHarness.BoundaryObservation(
                    boundary = passingBoundary,
                    unrelatedUidBoundary = passingUnrelatedUid,
                ),
            ),
        )
        var attempts = 0

        val result = Phase17FieldHarness.awaitCompleteBoundaryObservation(
            verifyIpv6 = true,
            maximumCoverageAttempts = 3,
            retryDelayMillis = 0,
            observe = {
                attempts++
                observations.removeFirst()
            },
        )

        assertEquals(2, attempts)
        assertFalse(result.boundary.coverageGap)
        assertFalse(requireNotNull(result.unrelatedUidBoundary).coverageGap)
    }

    @Test
    fun boundaryReobservationNeverRetriesConcreteLeak() = runBlocking {
        val concreteLeak = Phase17FieldHarness.BoundaryObservation(
            boundary = Phase17FieldHarness.BoundarySnapshot(
                vpnActive = true,
                ipv4Default = true,
                ipv6Default = true,
                dnsPinned = true,
                bypassBlocked = false,
                coverageGap = true,
            ),
            unrelatedUidBoundary = Phase17FieldHarness.UnrelatedUidBoundaryObservation(
                tunneledTraffic = true,
                bypassBlocked = false,
                coverageGap = true,
            ),
        )
        var attempts = 0

        val result = Phase17FieldHarness.awaitCompleteBoundaryObservation(
            verifyIpv6 = true,
            maximumCoverageAttempts = 3,
            retryDelayMillis = 0,
            observe = {
                attempts++
                concreteLeak
            },
        )

        assertEquals(1, attempts)
        assertFalse(result.boundary.bypassBlocked)
    }

    @Test
    fun persistentCoverageGapRemainsFailClosedAfterBoundedAttempts() = runBlocking {
        val persistentGap = Phase17FieldHarness.BoundaryObservation(
            boundary = Phase17FieldHarness.BoundarySnapshot(
                vpnActive = true,
                ipv4Default = true,
                ipv6Default = true,
                dnsPinned = true,
                bypassBlocked = true,
                coverageGap = true,
            ),
            unrelatedUidBoundary = Phase17FieldHarness.UnrelatedUidBoundaryObservation(
                tunneledTraffic = true,
                bypassBlocked = true,
                coverageGap = true,
            ),
        )
        var attempts = 0

        val result = Phase17FieldHarness.awaitCompleteBoundaryObservation(
            verifyIpv6 = true,
            maximumCoverageAttempts = 3,
            retryDelayMillis = 0,
            observe = {
                attempts++
                persistentGap
            },
        )

        assertEquals(3, attempts)
        assertTrue(result.boundary.coverageGap)
        assertFalse(Phase17FieldHarness.evaluateBoundarySnapshot(result.boundary, verifyIpv6 = true))
    }

    @Test
    fun unrelatedUidBoundaryRequiresTunneledTrafficAndBlockedUnderlay() {
        assertTrue(
            Phase17FieldHarness.isIndependentProbeIdentity(
                targetPackage = "org.kurdistanvpn.app.internal",
                targetUid = 10_001,
                probePackage = "org.kurdistanvpn.app.internal.test",
                probeUid = 10_002,
            ),
        )
        assertFalse(
            Phase17FieldHarness.isIndependentProbeIdentity(
                targetPackage = "org.kurdistanvpn.app.internal",
                targetUid = 10_001,
                probePackage = "org.kurdistanvpn.app.internal.test",
                probeUid = 10_001,
            ),
        )
        assertFalse(
            Phase17FieldHarness.isIndependentProbeIdentity(
                targetPackage = "org.kurdistanvpn.app.internal",
                targetUid = 10_001,
                probePackage = "org.kurdistanvpn.app.internal",
                probeUid = 10_002,
            ),
        )
        assertTrue(
            Phase17FieldHarness.isExpectedProbeResultIdentity(
                expectedPackage = "org.kurdistanvpn.app.internal.test",
                expectedUid = 10_002,
                observedPackage = "org.kurdistanvpn.app.internal.test",
                observedUid = 10_002,
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedProbeResultIdentity(
                expectedPackage = "org.kurdistanvpn.app.internal.test",
                expectedUid = 10_002,
                observedPackage = "org.kurdistanvpn.app.internal.test",
                observedUid = 10_003,
            ),
        )
        assertFalse(
            Phase17FieldHarness.isExpectedProbeResultIdentity(
                expectedPackage = "org.kurdistanvpn.app.internal.test",
                expectedUid = 10_002,
                observedPackage = "org.kurdistanvpn.app.internal.other",
                observedUid = 10_002,
            ),
        )
        val passing = Phase17FieldHarness.UnrelatedUidBoundaryObservation(
            tunneledTraffic = true,
            bypassBlocked = true,
            coverageGap = false,
        )
        assertTrue(Phase17FieldHarness.evaluateUnrelatedUidBoundary(passing))
        assertFalse(
            Phase17FieldHarness.evaluateUnrelatedUidBoundary(
                passing.copy(tunneledTraffic = false),
            ),
        )
        assertFalse(
            Phase17FieldHarness.evaluateUnrelatedUidBoundary(
                passing.copy(bypassBlocked = false),
            ),
        )
        assertFalse(
            Phase17FieldHarness.evaluateUnrelatedUidBoundary(
                passing.copy(coverageGap = true),
            ),
        )
    }

    @Test
    fun unrelatedUidProbePackageDeclaresNetworkStateAccess() {
        val probeContext = InstrumentationRegistry.getInstrumentation().context
        assertTrue(probeContext.packageName.endsWith(".test"))
        assertEquals(
            PackageManager.PERMISSION_GRANTED,
            probeContext.packageManager.checkPermission(
                Manifest.permission.ACCESS_NETWORK_STATE,
                probeContext.packageName,
            ),
        )
    }

    @Test
    fun unrelatedUidTunnelProbeUsesTheSuppliedLiveEndpoint() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            assertTrue(
                VpnProbeActivity.tcpAttempt(
                    InetAddress.getLoopbackAddress(),
                    server.localPort,
                ),
            )
        }
    }

    @Test
    fun unrelatedUidDnsProbeBuildsAndValidatesThePhase17Query() {
        val identifier = 0x1234
        val query = VpnProbeActivity.buildDnsQuery(identifier)
        assertArrayEquals(
            byteArrayOf(
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
                'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
                0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
                0x00, 0x00, 0x01, 0x00, 0x01,
            ),
            query,
        )

        val response = query.copyOf().also { bytes -> bytes[2] = 0x81.toByte() }
        assertTrue(VpnProbeActivity.isDnsResponseValid(response, response.size, identifier))
        assertFalse(VpnProbeActivity.isDnsResponseValid(response, response.size, 0xabcd))
        response[2] = 0x01
        assertFalse(VpnProbeActivity.isDnsResponseValid(response, response.size, identifier))
        assertFalse(VpnProbeActivity.isDnsResponseValid(response, 11, identifier))
    }

    @Test
    fun unrelatedUidBoundaryRunsForTrafficAndBoundaryButNotDnsOnlyActions() {
        assertTrue(
            Phase17FieldHarness.requiresUnrelatedUidBoundary(
                shouldVerifyDataPlane = true,
                dnsFamily = null,
                trafficDnsFamilies = emptyList(),
                verifyBoundary = false,
            ),
        )
        assertTrue(
            Phase17FieldHarness.requiresUnrelatedUidBoundary(
                shouldVerifyDataPlane = false,
                dnsFamily = null,
                trafficDnsFamilies = listOf(4, 6),
                verifyBoundary = false,
            ),
        )
        assertTrue(
            Phase17FieldHarness.requiresUnrelatedUidBoundary(
                shouldVerifyDataPlane = false,
                dnsFamily = null,
                trafficDnsFamilies = emptyList(),
                verifyBoundary = true,
            ),
        )
        assertFalse(
            Phase17FieldHarness.requiresUnrelatedUidBoundary(
                shouldVerifyDataPlane = false,
                dnsFamily = 4,
                trafficDnsFamilies = emptyList(),
                verifyBoundary = false,
            ),
        )
    }

    @Test
    fun dedicatedBoundaryDoesNotRequireResponseDigestDataPlaneProbe() {
        assertTrue(
            Phase17FieldHarness.requiresDirectDataPlaneProbe(
                shouldVerifyDataPlane = true,
                dnsFamily = null,
                trafficDnsFamilies = emptyList(),
            ),
        )
        assertTrue(
            Phase17FieldHarness.requiresDirectDataPlaneProbe(
                shouldVerifyDataPlane = false,
                dnsFamily = null,
                trafficDnsFamilies = listOf(4, 6),
            ),
        )
        assertFalse(
            Phase17FieldHarness.requiresDirectDataPlaneProbe(
                shouldVerifyDataPlane = false,
                dnsFamily = null,
                trafficDnsFamilies = emptyList(),
            ),
        )
        assertFalse(
            Phase17FieldHarness.requiresDirectDataPlaneProbe(
                shouldVerifyDataPlane = false,
                dnsFamily = 4,
                trafficDnsFamilies = emptyList(),
            ),
        )
    }

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

        assertTrue(
            Phase17FieldHarness.isTerminalFieldConnectOutcome(
                expectDnsAvailable = false,
                snapshot = VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = "LIVE_FALLBACK_EXHAUSTED",
                    packetDisposition = "LIVE_STAGE_SOCKET_PROTECTED",
                ),
            ),
        )
        assertFalse(
            Phase17FieldHarness.isTerminalFieldConnectOutcome(
                expectDnsAvailable = true,
                snapshot = VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = "LIVE_FALLBACK_EXHAUSTED",
                    packetDisposition = "LIVE_STAGE_SOCKET_PROTECTED",
                ),
            ),
        )
        assertFalse(
            Phase17FieldHarness.isTerminalFieldConnectOutcome(
                expectDnsAvailable = false,
                snapshot = VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = "NETWORK_UNAVAILABLE",
                ),
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
            "model:PRE_ACTIVE",
            "model:NATIVE_READY",
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
        VpnRuntimeController(context).use { controller ->
            controller.stageManualStart()
            controller.permissionRejected()
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("CONSENT_REJECTED", controller.snapshot.value.failure)
            controller.startStaged()
            assertEquals("MISSING_USER_START", controller.snapshot.value.failure)
        }

        VpnRuntimeController(context).use { recreated ->
            recreated.startStaged()
            assertEquals(VpnRuntimeState.FAILED, recreated.snapshot.value.state)
            assertEquals("MISSING_USER_START", recreated.snapshot.value.failure)
        }
    }

    @Test
    fun emergencyStopLeavesNoRuntimeOrSecretEvidence() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        VpnRuntimeController(context).use { controller ->
            controller.stageManualStart()
            controller.authorityRejected("PROFILE_REVOKED")
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

        assertTrue(root.initializeProtectedStateForExplicitUserAction())
        assertTrue(root.resetProtectedStateConfirmed() is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertNull(root.protectedStateFacade())
        assertTrue(root.initializeProtectedStateForExplicitUserAction())
        val facade = requireNotNull(root.protectedStateFacade())
        val plan = when (val enumeration = facade.enumerateBackup(null, { false }, android.os.SystemClock::elapsedRealtime)) {
            is ProtectedBackupEnumeration.Ready -> enumeration.plan
            is ProtectedBackupEnumeration.Rejected -> error("BACKUP_ENUMERATION_UNPROVEN")
        }
        assertEquals(0, plan.profileCount)
        assertEquals(0, plan.keyCount)
        val payload = BackupPayloadCodec.encode(emptyList())
        val passphrase = "phase17-device-backup".encodeToByteArray()
        var opened: BackupPreviewHandle? = null
        var backup = byteArrayOf()
        try {
            backup = plan.use { requireSuccess(it.confirmEncryptedExport(passphrase)) }
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
            assertTrue(root.resetProtectedStateConfirmed() is ProtectedStateApplicationFacade.CommandResult.Committed)
            assertNull(root.protectedStateFacade())
            assertTrue(root.initializeProtectedStateForExplicitUserAction())
            assertTrue(requireNotNull(root.protectedStateFacade()?.readProjection()).profiles.isEmpty())
        } finally {
            plan.close()
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
        assertTrue(
            service.metaData.getBoolean("android.net.VpnService.SUPPORTS_ALWAYS_ON", false),
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
